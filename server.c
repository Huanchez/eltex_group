#define _POSIX_C_SOURCE 200809L

#include "source/headers/server.h"
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define SERVER_EPOLL_MAX_EVENTS 1024
#define SERVER_EPOLL_TIMEOUT_MS 500

FILE *g_logf = NULL;

// Защита от сигналов
static server_ctx_t *g_srv_for_signal = NULL;

static void server_signal_handler(int sig)
{
    (void)sig;
    if (!g_srv_for_signal) return;

    // Просим сервер завершиться корректно
    g_srv_for_signal->stop_flag = 1;

    // Разбудить воркеры
    pthread_cond_broadcast(&g_srv_for_signal->queues.cond);

    // Разбудить accept() / epoll() 
    if (g_srv_for_signal->listen_fd >= 0) {
        close(g_srv_for_signal->listen_fd);
        g_srv_for_signal->listen_fd = -1;
    }
}

static void server_setup_signals(server_ctx_t *srv)
{
    g_srv_for_signal = srv;

    // Игнорируем SIGPIPE 
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = server_signal_handler;
    sigemptyset(&sa.sa_mask);

    // сигналы остановки
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL); 
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
}


char server_db_init(server_ctx_t *srv){
    problem_info_t* problems;
    size_t problems_count;

    char result = server_db_get_problem_list(srv->problems_dir,&problems, &problems_count);

    switch(result){
        case SERVER_ERR_NOMEM:{
            return result;
        }
        case SERVER_ERR_DB:{
            return result;
        }
        default:{
            for(int i = 0; i < problems_count; i++){
                char load = server_problem_add(srv,&problems[i]);
                if(load==SERVER_ERR_GENERIC) //Загружаем в hash-таблицу
                    SERVER_LOG_WARN("Error. Problem %d was added early", problems[i].problem_id);
                else if (load==SERVER_ERR_NOMEM){
                    SERVER_LOG_ERROR("Couldn't add problem %d. Memory error.", problems[i].problem_id);
                    return load;
                }
            }

            SERVER_LOG_INFO("Problems was loaded",NULL);
            break;
        }
    }

    server_client_info_t* clients;
    size_t clients_count;

    result = server_db_get_users_list(srv->users_dir,&clients, &clients_count);

    switch(result){
        case SERVER_ERR_NOMEM:{
            return result;
        }
        case SERVER_ERR_DB:{
            return result;
            break;
        }
        default:{
            for(int i = 0; i < clients_count; i++){
                char load = server_user_add(srv,&clients[i]);
                if(load==SERVER_ERR_GENERIC) //Загружаем в hash-таблицу
                    SERVER_LOG_ERROR("Error. User %d was added early", clients[i].id);
                else if (load==SERVER_ERR_NOMEM){
                    SERVER_LOG_ERROR("Couldn't add user %d. Memory error.", clients[i].id);
                    return load;
                }
            }
        
            SERVER_LOG_INFO("Users was loaded",NULL);
            break;
        }
    }
    return SERVER_OK;
}

void server_db_close(server_ctx_t *srv) {
    if (!srv) return;
    // Освобождаем таблицу соединений (conns_by_fd)
    if (srv->conns_by_fd) {
        conn_hash_entry_t *conn_item, *conn_tmp;
        HASH_ITER(hh, srv->conns_by_fd, conn_item, conn_tmp) {
            HASH_DEL(srv->conns_by_fd, conn_item);
            if (conn_item->conn) {
                // Освобождаем само соединение
                free_connection(conn_item->conn);
            }
            free(conn_item);
        }
        srv->conns_by_fd = NULL;
    }
    
    // Освобождаем таблицу сессий
    if (srv->sessions) {
        session_hash_entry_t *session_item, *session_tmp;
        HASH_ITER(hh, srv->sessions, session_item, session_tmp) {
            HASH_DEL(srv->sessions, session_item);
            free(session_item);
        }
        srv->sessions = NULL;
    }
    
    // Освобождаем таблицу пользователей 
    if (srv->users_by_username) {
        client_hash_entry_t *user_item, *user_tmp;
        HASH_ITER(hh, srv->users_by_username, user_item, user_tmp) {
            HASH_DEL(srv->users_by_username, user_item);
            if (user_item->user) {
                free(user_item->user);  // Освобождаем структуру пользователя
            }
            free(user_item);
        }
        srv->users_by_username = NULL;
    }
    
    // Освобождаем таблицу задач 
    if (srv->problem_by_id) {
        problem_hash_entry_t *problem_item, *problem_tmp;
        HASH_ITER(hh, srv->problem_by_id, problem_item, problem_tmp) {
            HASH_DEL(srv->problem_by_id, problem_item);
            if (problem_item->problem) {
                // Освобождаем задачу и её тесты
            }
            free(problem_item);
        }
        srv->problem_by_id = NULL;
    }
    
}

void free_connection(server_conn_t *conn) {
    if (!conn) return;
    
    // Закрываем сокет
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    
    // Уничтожаем мьютекс
    pthread_mutex_destroy(&conn->write_mutex);
    
    // Освобождаем структуру
    free(conn);
}

char server_problem_add(server_ctx_t *srv, problem_info_t *problem){
    if (!srv || !problem) return SERVER_ERR_INVALID_ARG;
        
    // Проверяем, нет ли уже такой задачи
    if(server_problem_find(srv, problem->problem_id)!=NULL){
        return SERVER_ERR_GENERIC;
    }
    
    problem_hash_entry_t *item = malloc(sizeof(*item));
    if (!item) return SERVER_ERR_NOMEM;
        
    item->problem_id = problem->problem_id;
        
    // Сохраняем указатель на существующую задачу
    item->problem = problem;  // Используем существующий указатель
        
    // Добавляем в хеш-таблицу
    HASH_ADD_INT(srv->problem_by_id, problem_id, item);
        
    return SERVER_OK;
}

problem_info_t* server_problem_find(server_ctx_t *srv, int problem_id){
    if (!srv) return NULL;

    problem_hash_entry_t *item = NULL;
    
    // Используем HASH_FIND_INT для целочисленных ключей
    HASH_FIND_INT(srv->problem_by_id, &problem_id, item);
    
    // Возвращаем указатель на задачу или NULL
    return item ? item->problem : NULL;
}

char server_user_add(server_ctx_t *srv, const server_client_info_t *user){
    if (!srv || !user) return SERVER_ERR_INVALID_ARG;
        
    // Проверяем, нет ли уже такого пользователя
    if(server_user_find(srv, user->username)!=NULL){
        return SERVER_ERR_GENERIC;
    }
    
    // Создаем только элемент хеш-таблицы, а не нового пользователя
    client_hash_entry_t *item = (client_hash_entry_t*)malloc(sizeof(*item));
    if (!item) return SERVER_ERR_NOMEM;
    
    // Сохраняем указатель на существующего пользователя
    memset(item, 0, sizeof(*item)); 
    strncpy(item->username, user->username, sizeof(item->username) - 1);
    item->user = (server_client_info_t*)user;
        
    // Добавляем в хеш-таблицу
    HASH_ADD_STR(srv->users_by_username, username, item);
        
    return SERVER_OK;
}

server_client_info_t* server_user_find(server_ctx_t *srv, const char* user_username){
    if (!srv || !user_username) return NULL;
    
    client_hash_entry_t *item = NULL;

    // Используем HASH_FIND_INT для целочисленных ключей
    HASH_FIND_STR(srv->users_by_username, user_username, item);
    
    // Возвращаем указатель на задачу или NULL
    return item ? item->user : NULL;
}

// Обнуляем состояние очередей без освобождения памяти
static void server_zero_queues_state(server_work_queues_t *q) {

    if (!q) return;

    // Указатели на буферы очередей
    q->high_items = NULL;
    q->normal_items = NULL;
    q->low_items = NULL;

    // Сброс счётчиков
    for (int i = 0; i < 3; i++) {
        q->capacity[i] = 0;
        q->head[i] = 0;
        q->tail[i] = 0;
        q->count[i] = 0;
    }
}

// Освобождаем память очередей
static void server_free_queues_buffers(server_work_queues_t *q) {
    if (!q) return;

    free(q->high_items);
    free(q->normal_items);
    free(q->low_items);

    server_zero_queues_state(q);
}

static int safe_path_copy(char *dest, size_t dest_size, 
                          const char *base, const char *suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);
    
    if (base_len + suffix_len + 1 > dest_size) {
        return -1; // Ошибка: не хватает места
    }
    
    strcpy(dest, base);
    strcat(dest, suffix);
    return 0; // Успех
}

// Инициализация сервера
char server_init(server_ctx_t *srv,
                const char *bind_ip,
                uint16_t port,
                bool daemon_mode)
{
    if (!srv || !bind_ip || port == 0) {
        return (char)SERVER_ERR_INVALID_ARG;
    }

    // Полная очистка контекста
    memset(srv, 0, sizeof(*srv));

	 // Получаем базовый путь (текущая директория)
    char base_path[MAX_PATH_LEN] = {0};
    if (getcwd(base_path, sizeof(base_path)) == NULL) {
        // Если не получается, используем домашнюю директорию
        const char *home = getenv("HOME");
        if (home) {
            snprintf(base_path, sizeof(base_path), "%s", home);
        } else {
            strcpy(base_path, "/tmp");
        }
    }
    
    size_t base_len = strlen(base_path);
	size_t max_needed = base_len + strlen("/database/problems") + 1; // +1 для нулевого байта

	if (max_needed > sizeof(srv->database_dir)) {
		return SERVER_ERR_INVALID_ARG; 
	}

    // Базовые значения
    srv->listen_fd = -1;
    srv->epoll_fd = -1;
    srv->use_epoll = false;

    srv->state = SERVER_STATE_INIT;
    srv->daemon_mode = daemon_mode;
    srv->stop_flag = 0;

    // Сохраняем IP и порт
    snprintf(srv->bind_ip, sizeof(srv->bind_ip), "%s", bind_ip);
    srv->port = port;

    // Директории
    if (safe_path_copy(srv->database_dir, sizeof(srv->database_dir), 
                   base_path, "/database") != 0) {
		return SERVER_ERR_INVALID_ARG;
	}
	
	if (safe_path_copy(srv->problems_dir, sizeof(srv->problems_dir), 
                   base_path, "/database/problems") != 0) {
		return SERVER_ERR_INVALID_ARG;
	}
	
	if (safe_path_copy(srv->solutions_dir, sizeof(srv->solutions_dir), 
                   base_path, "/database/solutions") != 0) {
		return SERVER_ERR_INVALID_ARG;
	}
	
	if (safe_path_copy(srv->users_dir, sizeof(srv->users_dir), 
                   base_path, "/database/users") != 0) {
		return SERVER_ERR_INVALID_ARG;
	}
	
	if (safe_path_copy(srv->runtime_dir, sizeof(srv->runtime_dir), 
                   base_path, "/runtime") != 0) {
		return SERVER_ERR_INVALID_ARG;
	}

    SERVER_LOG_INFO("Base directory: %s", base_path);
    SERVER_LOG_INFO("Database directory: %s", srv->database_dir);
    SERVER_LOG_INFO("Problems directory: %s", srv->problems_dir);
    SERVER_LOG_INFO("Solutions directory: %s", srv->solutions_dir);
    SERVER_LOG_INFO("Users directory: %s", srv->users_dir);
    

    // Лимиты исполнения
    srv->limits.exec_time_limit_ms = SERVER_EXEC_TIME_LIMIT_MS_DEFAULT;
    srv->limits.exec_mem_limit_kb = SERVER_EXEC_MEM_LIMIT_KB_DEFAULT;
    srv->limits.compilation_timeout_ms = SERVER_COMPILATION_TIMEOUT_MS_DEFAULT;

    // Инициализация мьютексов контекста
    if (pthread_mutex_init(&srv->conns_mutex, NULL) != 0) {
        return (char)SERVER_ERR_NOMEM;
    }
    if (pthread_mutex_init(&srv->sessions_mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }
    if (pthread_mutex_init(&srv->users_mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }
    if (pthread_mutex_init(&srv->problems_mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->users_mutex);
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }
    if (pthread_mutex_init(&srv->solutions_mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->problems_mutex);
        pthread_mutex_destroy(&srv->users_mutex);
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    // Инициализация трех очередей работ
    server_zero_queues_state(&srv->queues);

    if (pthread_mutex_init(&srv->queues.mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->solutions_mutex);
        pthread_mutex_destroy(&srv->problems_mutex);
        pthread_mutex_destroy(&srv->users_mutex);
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    if (pthread_cond_init(&srv->queues.cond, NULL) != 0) {
        pthread_mutex_destroy(&srv->queues.mutex);
        pthread_mutex_destroy(&srv->solutions_mutex);
        pthread_mutex_destroy(&srv->problems_mutex);
        pthread_mutex_destroy(&srv->users_mutex);
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    // Размеры очередей
    size_t high_cap = 128;
    size_t normal_cap = 512;
    size_t low_cap = 128;

    // Память на очереди
    srv->queues.high_items = calloc(high_cap, sizeof(server_work_item_t));
    srv->queues.normal_items = calloc(normal_cap, sizeof(server_work_item_t));
    srv->queues.low_items = calloc(low_cap, sizeof(server_work_item_t));

    // Проверяем правильно ли выделилась память
    if (!srv->queues.high_items || !srv->queues.normal_items || !srv->queues.low_items) {
        server_free_queues_buffers(&srv->queues);
        pthread_cond_destroy(&srv->queues.cond);
        pthread_mutex_destroy(&srv->queues.mutex);

        pthread_mutex_destroy(&srv->solutions_mutex);
        pthread_mutex_destroy(&srv->problems_mutex);
        pthread_mutex_destroy(&srv->users_mutex);
        pthread_mutex_destroy(&srv->sessions_mutex);
        pthread_mutex_destroy(&srv->conns_mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    srv->queues.capacity[PRIORITY_HIGH] = high_cap;
    srv->queues.capacity[PRIORITY_NORMAL] = normal_cap;
    srv->queues.capacity[PRIORITY_LOW] = low_cap;

    // Создание директорий
    char *dirs[] = {
        srv->database_dir,
        srv->problems_dir,
        srv->solutions_dir,
        srv->users_dir,
        srv->runtime_dir,
        NULL
    }; 

	for (int i = 0; dirs[i] != NULL; i++) {
    SERVER_LOG_INFO("Creating directory: %s", dirs[i]);
    
    // Пробуем создать директорию
    int mkdir_result = mkdir(dirs[i], TASKDIR_MODE); // rwxr-xr-x
    
    if (mkdir_result == 0) {
        // Успешно создали
        SERVER_LOG_INFO("Directory created successfully: %s", dirs[i]);
    } else {
        // mkdir вернул ошибку
        if (errno == EEXIST) {
            // Директория уже существует - это нормально
            SERVER_LOG_INFO("Directory already exists: %s", dirs[i]);
        } else {
            // Серьёзная ошибка создания
            SERVER_LOG_ERROR("Failed to create directory %s", 
                            dirs[i]);
            
            // Проверяем специфичные ошибки
            if (errno == EACCES || errno == EPERM) {
                SERVER_LOG_ERROR("Permission denied! Check write access.",NULL);
            } else if (errno == ENOSPC) {
                SERVER_LOG_ERROR("No space left on device.",NULL);
            } else if (errno == ENAMETOOLONG) {
                SERVER_LOG_ERROR("Path too long.",NULL);
            } else if (errno == ENOENT) {
                SERVER_LOG_ERROR("Parent directory doesn't exist.",NULL);
            }
            
            // Cleanup и возврат ошибки
            server_free_queues_buffers(&srv->queues);
            pthread_cond_destroy(&srv->queues.cond);
            pthread_mutex_destroy(&srv->queues.mutex);
            pthread_mutex_destroy(&srv->solutions_mutex);
            pthread_mutex_destroy(&srv->problems_mutex);
            pthread_mutex_destroy(&srv->users_mutex);
            pthread_mutex_destroy(&srv->sessions_mutex);
            pthread_mutex_destroy(&srv->conns_mutex);
            
            return (char)SERVER_ERR_IO;
        }
    }
}


    srv->worker_count = SERVER_WORKER_THREADS_DEFAULT;
    srv->workers = NULL;

    // Статистика
    srv->connected_clients = 0;
    srv->processed_requests = 0;
    srv->evaluated_solutions = 0;

    // Готов к запуску
    srv->state = SERVER_STATE_LISTENING;
    return SERVER_OK;
}

// Освобождение ресурсов
void server_cleanup(server_ctx_t *srv)
{
    if (!srv) return;

    server_stop_workers(srv);

    // Закрываем слушающий сокет
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }

    // Закрываем epoll
    if (srv->epoll_fd >= 0) {
        close(srv->epoll_fd);
        srv->epoll_fd = -1;
    }

    // Освобождаем очереди
    free(srv->queues.high_items);
    free(srv->queues.normal_items);
    free(srv->queues.low_items);

    srv->queues.high_items = NULL;
    srv->queues.normal_items = NULL;
    srv->queues.low_items = NULL;

    for (int i = 0; i < 3; i++) {
        srv->queues.capacity[i] = 0;
        srv->queues.head[i] = 0;
        srv->queues.tail[i] = 0;
        srv->queues.count[i] = 0;
    }

    pthread_cond_destroy(&srv->queues.cond);
    pthread_mutex_destroy(&srv->queues.mutex);

    // Уничтожаем мьютексы контекста
    pthread_mutex_destroy(&srv->solutions_mutex);
    pthread_mutex_destroy(&srv->problems_mutex);
    pthread_mutex_destroy(&srv->users_mutex);
    pthread_mutex_destroy(&srv->sessions_mutex);
    pthread_mutex_destroy(&srv->conns_mutex);

    // Сбрасываем поля на безопасные значения
    srv->use_epoll = false;
    srv->state = SERVER_STATE_SHUTTING_DOWN;
}

void generate_salt(uint8_t salt[SERVER_MAX_SALT_LEN]) {
    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)getpid();
    srand(seed);
    
    for(int i = 0; i < SERVER_MAX_SALT_LEN; i++) {  
        salt[i] = rand() % 256;
    }
}

int server_verify_proof(const uint8_t proof[SHA_LEN],
                        const uint8_t hashA_from_db[SHA_LEN]) {
    return memcmp(proof, hashA_from_db, SHA_LEN) == 0;
}


char server_log_init() {
    g_logf = fopen(SERVER_LOG_FILE, "a");
    if (!g_logf) return -1;
    setvbuf(g_logf, NULL, _IOLBF, 0);
    SERVER_LOG_INFO("Logging initialized", NULL);
    return 0;
}

void server_log_msg(server_log_level_t level, const char *fmt, ...) {
    //  Статический указатель - сохраняется между вызовами
    static FILE *log_file = NULL;
    
    // Открываем файл при каждом вызове если он закрыт
    if (!log_file || log_file == stdout || log_file == stderr) {
        // Пробуем открыть файл
        log_file = fopen(SERVER_LOG_FILE, "a");
        if (!log_file) {
            // Если не получилось, используем stderr
            log_file = stderr;
        }
    }
    
    // 3. Проверяем что файл ещё валиден
    if (ferror(log_file)) {
        // Файл испорчен, открываем заново
        if (log_file != stdout && log_file != stderr) {
            fclose(log_file);
        }
        log_file = fopen(SERVER_LOG_FILE, "a");
        if (!log_file) {
            log_file = stderr;
        }
    }
    
    va_list ap;
    va_start(ap, fmt);
    
    // 4. Пишем логи
    fprintf(log_file, "[%d] ", level);
    vfprintf(log_file, fmt, ap);
    fprintf(log_file, "\n");
    
    // 5. Сбрасываем буфер если это файл
    if (log_file != stdout && log_file != stderr) {
        fflush(log_file);
    }
    
    va_end(ap);
}

void server_log_close() {
    if (g_logf) fclose(g_logf);
}

void generate_session_token(char *token, size_t size) {
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint8_t random_bytes[MAX_TOKEN_LEN - 1];
    
    // Генерируем случайные байты
    srand(time(NULL));
    for (int i = 0; i < sizeof(random_bytes); i++) {
        random_bytes[i] = rand() % 256;
    }
    
    // Конвертируем в hex строку
    for (int i = 0; i < sizeof(random_bytes) && i * 2 + 1 < size; i++) {
        sprintf(token + (i * 2), "%02x", random_bytes[i]);
    }
    token[size - 1] = '\0';
}

char server_handle_auth_start(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload) {
    SERVER_LOG_INFO("Start auth. seq_id client %d",header->seq_id);
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_WARN("Invalid args. seq_id client %d",header->seq_id);
        return SERVER_ERR_INVALID_ARG;
    }
    
    if (header->payload_size != sizeof(auth_start_request_t)) {
        SERVER_LOG_WARN("Invalid auth start size. seq_id client %d",header->seq_id);
        send_error_response(srv,conn, "Invalid auth start size");
        return SERVER_OK;
    }
    
    auth_start_request_t *start_req = (auth_start_request_t*)payload;
    
    // Ищем пользователя
    server_client_info_t *user = NULL;
    pthread_mutex_lock(&srv->users_mutex);
    user=server_user_find(srv,start_req->username);
    pthread_mutex_unlock(&srv->users_mutex);
    
    if (!user) {
        // Отправляем общий ответ, чтобы не раскрывать существование пользователя
        auth_challenge_t challenge;
        generate_salt(challenge.salt);

        SERVER_LOG_INFO("Send salt. seq id: %d",header->seq_id);
        send_auth_challenge(srv,conn, &challenge);
        return SERVER_OK;
    }
    
    auth_challenge_t challenge;

    // Используем соль из БД пользователя
    memcpy(challenge.salt, user->salt, sizeof(challenge.salt));

    // Сохраняем в соединении для верификации
    strncpy(conn->username, start_req->username, sizeof(conn->username) - 1);
    
    SERVER_LOG_INFO("Send salt to user: %s",start_req->username);
    // Отправляем клиенту
    send_auth_challenge(srv,conn, &challenge);
    return SERVER_OK;
}

char server_handle_auth_verify(server_ctx_t *srv, server_conn_t *conn,
                              const protocol_header_t *header, const uint8_t *payload) {
    SERVER_LOG_INFO("Start auth verify. seq_id client %d",header->seq_id);
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_WARN("Invalid args. seq_id client %d",header->seq_id);
        return SERVER_ERR_INVALID_ARG;
    }
    
    if (header->payload_size != sizeof(auth_verify_request_t)) {
        SERVER_LOG_WARN("Invalid auth verify size. seq_id client %d",header->seq_id);
        send_error_response(srv,conn, "Invalid auth verify size");
        return SERVER_OK;
    }
    
    auth_verify_request_t *verify_req = (auth_verify_request_t*)payload;
    
    // Ищем пользователя
    server_client_info_t *user = NULL;
    pthread_mutex_lock(&srv->users_mutex);
    user=server_user_find(srv,conn->username);
    pthread_mutex_unlock(&srv->users_mutex);
    
    if (!user) {
        SERVER_LOG_INFO("Client %s not found", conn->username);
        send_auth_failure(srv,conn,"User not found");
        return SERVER_OK;
    }
    
    // Вычисляем ожидаемый хэш
    char expected_hash[SHA_LEN];
    
    
    if (server_verify_proof(verify_req->password_hash,user->password_hash)==0){
        SERVER_LOG_INFO("Client %s sended invalid pass", conn->username);
        send_auth_failure(srv,conn, "Invalid password");
        return SERVER_OK;
    }

    // Аутентификация успешна
    auth_success_t success;
    generate_session_token(success.session_token, sizeof(success.session_token));
    success.expires_in = 600;  // 10 минут
    success.role = user->role;
    
    // Обновляем соединение
    conn->authenticated = true;
    conn->user_id = user->id;
    conn->role = user->role;
    strncpy(conn->username, user->username, sizeof(conn->username) - 1);
    strncpy(conn->session_token, success.session_token, sizeof(conn->session_token) - 1);
    conn->session_created_at = time(NULL);
    conn->session_expires_at = time(NULL) + success.expires_in;
    conn->last_activity = time(NULL);
    
    // Добавляем в хеш-таблицу сессий
    pthread_mutex_lock(&srv->sessions_mutex);
    session_hash_entry_t *session_entry = malloc(sizeof(session_hash_entry_t));
    
	if (session_entry) {
    // Копируем токен в структуру
    strncpy(session_entry->token, success.session_token, sizeof(session_entry->token) - 1);
    session_entry->token[sizeof(session_entry->token) - 1] = '\0'; // гарантируем null-terminated
    
    session_entry->conn = conn;
    session_entry->expires_at = conn->session_expires_at;
    
    // Добавляем в хеш-таблицу, используя поле token как ключ
    HASH_ADD_STR(srv->sessions, token, session_entry);
	}
    else{
        SERVER_LOG_ERROR("Coldn't create session for user %s. Memory error", conn->username);
        pthread_mutex_unlock(&srv->sessions_mutex);
        return SERVER_ERR_NOMEM;
    }
    pthread_mutex_unlock(&srv->sessions_mutex);
    
    SERVER_LOG_INFO("Client %s passed auth. New session was created", conn->username);
    // Отправляем успешный ответ
    send_auth_success(srv,conn, &success);
    return SERVER_OK;
}

char send_auth_challenge(server_ctx_t *srv, server_conn_t *conn, const auth_challenge_t *challenge) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_AUTH_START;
    header.flags = 0;
    header.payload_size = sizeof(*challenge);
    header.seq_id = srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)challenge);
    return SERVER_OK;
}

char send_auth_success(server_ctx_t *srv,server_conn_t *conn, const auth_success_t *success) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_AUTH_OK;
    header.flags = 0;
    header.payload_size = sizeof(*success);
    header.seq_id = srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)success);
    return SERVER_OK;
}

char send_auth_failure(server_ctx_t *srv,server_conn_t *conn, const char *reason) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_AUTH_FAIL;
    header.flags = 0;
    header.payload_size = strlen(reason);
    header.seq_id =srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)reason);
    return SERVER_OK;
}

char send_error_response(server_ctx_t *srv,server_conn_t *conn, const char *reason){
	protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_ERROR;
    header.flags = 0;
    header.payload_size = strlen(reason);
    header.seq_id =srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)reason);
    return SERVER_OK;
}

static char send_solution_result(server_ctx_t *srv, server_conn_t *conn, const solution_result_t *res)
{
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_SOLUTION_RESULT;
    header.flags = 0;
    header.payload_size = sizeof(*res);
    header.seq_id = srv->seq_id++;

    return server_send_packet(srv, conn, &header, (const uint8_t *)res);
}

static int write_text_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len)
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

// Нормализация
static void normalize_output_inplace(char *s)
{
    if (!s)
        return;

    //  убираем \r
    char *w = s;
    for (char *p = s; *p; p++)
    {
        if (*p != '\r')
            *w++ = *p;
    }
    *w = '\0';

    // обрезаем пробелы и табуляции перед каждой новой строкой
    for (char *p = s; *p; p++)
    {
        if (*p == '\n')
        {
            char *q = p - 1;
            while (q >= s && (*q == ' ' || *q == '\t'))
            {
                *q = '\0';
                q--;
            }
        }
    }

    // обрезаем пробелы и табуляции в конце всей строки
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n'))
    {
        s[n - 1] = '\0';
        n--;
    }
}


static int server_write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int server_read_file(const char *path, void *buf, size_t cap, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    if (out_len) *out_len = n;
    return 0;
}

static char *str_dup_range(const char *start, const char *end) {
    if (!start || !end || end < start) return NULL;
    size_t n = (size_t)(end - start);
    char *s = (char*)malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, start, n);
    s[n] = '\0';
    return s;
}

static int server_generate_problem_id(server_ctx_t *srv) {
    if (!srv) return 0;
    
    pthread_mutex_lock(&srv->problems_mutex);
    
    // Ищем максимальный существующий ID
    int max_id = 10000; // начальное значение
    
    problem_hash_entry_t *entry, *tmp;
    HASH_ITER(hh, srv->problem_by_id, entry, tmp) {
        if (entry->problem_id > max_id) {
            max_id = entry->problem_id;
        }
    }
    
    pthread_mutex_unlock(&srv->problems_mutex);
    
    return max_id + 1;
}

char server_handle_get_full_problem(server_ctx_t *srv, server_conn_t *conn,
                                   const protocol_header_t *header,
                                   const uint8_t *payload) {
    if (!srv || !conn || !header) return SERVER_ERR_INVALID_ARG;
    
    if (header->payload_size != sizeof(int)) {
        SERVER_LOG_ERROR("Invalid payload size for full problem request",NULL);
        return send_error_response(srv, conn, "Invalid payload");
    }
    
    int problem_id;
    memcpy(&problem_id, payload, sizeof(int));
    
    SERVER_LOG_INFO("Request for full problem %d", problem_id);
    
    pthread_mutex_lock(&srv->problems_mutex);
    
    // Ищем задачу в хэше
    problem_hash_entry_t *entry = NULL;
    HASH_FIND_INT(srv->problem_by_id, &problem_id, entry);
    
    if (!entry || !entry->problem) {
        pthread_mutex_unlock(&srv->problems_mutex);
        SERVER_LOG_ERROR("Problem %d not found in hash", problem_id);
        return send_error_response(srv, conn, "Problem not found");
    }
    
    // Копируем задачу (защищаем от модификации во время отправки)
    problem_info_t problem_copy;
    memcpy(&problem_copy, entry->problem, sizeof(problem_info_t));
    
    pthread_mutex_unlock(&srv->problems_mutex);
    
    // Гарантируем нулевое завершение строк
    problem_copy.title[sizeof(problem_copy.title) - 1] = '\0';
    problem_copy.description[sizeof(problem_copy.description) - 1] = '\0';
    
    if (problem_copy.header_size < MAX_CODE) {
        problem_copy.problem_header[problem_copy.header_size] = '\0';
    } else {
        problem_copy.problem_header[MAX_CODE - 1] = '\0';
    }
    
    // Отправляем полную структуру
    protocol_header_t resp_hdr = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_PROBLEM_INFO,
        .flags = 0,
        .payload_size = sizeof(problem_copy),
        .seq_id = header->seq_id
    };
    
    SERVER_LOG_INFO("Sending full problem %d from hash: ", problem_id);
    
    return server_send_packet(srv, conn, &resp_hdr, (const uint8_t*)&problem_copy);
}

char server_handle_problem_upsert(server_ctx_t *srv, server_conn_t *conn,
                                  const protocol_header_t *header,
                                  const uint8_t *payload) {
    if (!srv || !conn || !header) return SERVER_ERR_INVALID_ARG;
    
    SERVER_LOG_INFO("Payload size: %u", header->payload_size);
    
    // Проверяем аутентификацию
    if (!conn->authenticated || conn->role != ROLE_TEACHER) {
        send_error_response(srv, conn, "Teacher role required");
        return SERVER_OK;
    }
    
    // Проверяем размер пакета
    if (header->payload_size > MAX_PAYLOAD_LEN) {
        SERVER_LOG_ERROR("Payload too large: %u", header->payload_size);
        send_error_response(srv, conn, "Payload too large");
        return SERVER_OK;
    }
    
    // Создаем локальную копию задачи из данных клиента
    problem_info_t problem;
    memset(&problem, 0, sizeof(problem));
    memcpy(&problem, payload, sizeof(problem_info_t));
    
    // Проверяем данные
    if (problem.header_size > MAX_CODE) {
        SERVER_LOG_ERROR("Header too large: %zu", problem.header_size);
        send_error_response(srv, conn, "Header too large");
        return SERVER_OK;
    }
    
    if (problem.test_count > MAX_TEST_COUNT) {
        SERVER_LOG_ERROR("Too many tests: %zu", problem.test_count);
        send_error_response(srv, conn, "Too many tests");
        return SERVER_OK;
    }
    
    // Гарантируем корректное завершение строк
    problem.title[sizeof(problem.title) - 1] = '\0';
    problem.description[sizeof(problem.description) - 1] = '\0';
    
    if (problem.header_size < MAX_CODE) {
        problem.problem_header[problem.header_size] = '\0';
    } else {
        problem.problem_header[MAX_CODE - 1] = '\0';
    }
    
    // Гарантируем корректность строк в тестах
    for (size_t i = 0; i < problem.test_count; i++) {
        problem.test_cases[i].input[MAX_TEST_INPUT_LEN - 1] = '\0';
        problem.test_cases[i].expected[MAX_TEST_OUTPUT_LEN - 1] = '\0';
        problem.test_cases[i].problem_id = problem.problem_id;
        problem.test_cases[i].id = (int)(i + 1);
    }
    
    // Определяем CREATE или UPDATE
    int is_update = (problem.problem_id != 0);
    
    if (is_update) {
        // Для UPDATE проверяем существование задачи
        pthread_mutex_lock(&srv->problems_mutex);
        problem_info_t *exist = server_problem_find(srv, problem.problem_id);
        pthread_mutex_unlock(&srv->problems_mutex);
        
        if (!exist) {
            SERVER_LOG_ERROR("Problem %d not found for update", problem.problem_id);
            send_error_response(srv, conn, "Problem not found");
            return SERVER_OK;
        }
    } else {
        // Для CREATE генерируем новый ID
        problem.problem_id = server_generate_problem_id(srv);
        if (problem.problem_id == 0) {
            SERVER_LOG_ERROR("Failed to generate problem ID",NULL);
            send_error_response(srv, conn, "Failed to generate ID");
            return SERVER_OK;
        }
        SERVER_LOG_INFO("Generated new ID: %d", problem.problem_id);
    }
    
   // Генерируем имя файла
	char filename[SERVER_MAX_PATH_LEN];

	// Проверяем длину директории
	size_t dir_len = strlen(srv->problems_dir);
	if (dir_len + 20 > sizeof(filename)) { // 20: / + 11 цифр + .bin + \0
		return SERVER_ERR_INVALID_ARG;
	}

	// Собираем путь безопасно
	strcpy(filename, srv->problems_dir);
	strcat(filename, "/");
    
	// Преобразуем ID в строку
	char id_str[12]; // Для int32: -2147483648 (11 символов + \0)
	snprintf(id_str, sizeof(id_str), "%d", problem.problem_id);
	strcat(filename, id_str);
	strcat(filename, ".bin");
    SERVER_LOG_INFO("Saving problem %d to file", problem.problem_id);
    
    // Сохраняем в файл
    char save_rc = save_problem_to_bin_file(&problem, filename);
    if (save_rc != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to save problem to file: %s ", filename);
        send_error_response(srv, conn, "Failed to save to file");
        return SERVER_OK;
    }
    
    SERVER_LOG_INFO("File saved successfully",NULL);
    
    // ОБНОВЛЯЕМ в памяти
    SERVER_LOG_INFO("Updating problem in memory hash...",NULL);
    
    pthread_mutex_lock(&srv->problems_mutex);
    
    problem_info_t *old_problem = NULL;  // для освобождения старой задачи
    char replace_rc = server_problem_replace(srv, &problem, &old_problem);
    
    pthread_mutex_unlock(&srv->problems_mutex);
    
    if (replace_rc != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to update problem in memory: %d", replace_rc);
        send_error_response(srv, conn, "Failed to update in memory");
        return SERVER_OK;
    }
    
    // ОСВОБОЖДАЕМ старую задачу (если была)
    if (old_problem) {
        SERVER_LOG_INFO("Freeing old problem from memory",NULL);
        free(old_problem);
    }
    
    SERVER_LOG_INFO("Memory update successful",NULL);
    
    // Готовим ответ клиенту
    problem_info_t response;
    memset(&response, 0, sizeof(response));
    response.problem_id = problem.problem_id;
    strncpy(response.title, problem.title, sizeof(response.title) - 1);
    strncpy(response.description, problem.description, sizeof(response.description) - 1);
    response.time_limit_ms = problem.time_limit_ms;
    response.memory_limit_kb = problem.memory_limit_kb;
    response.header_size = problem.header_size;
    response.test_count = problem.test_count;
    
    // Отправляем ответ
    protocol_header_t resp_hdr = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_PROBLEM_SAVED,
        .flags = 0,
        .payload_size = sizeof(response),
        .seq_id = srv->seq_id++
    };
    
    SERVER_LOG_INFO("Sending response to client...",NULL);
    char send_rc = server_send_packet(srv, conn, &resp_hdr, (const uint8_t*)&response);
    
    if (send_rc != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to send response: %d", send_rc);
        // Но задача уже сохранена, так что не возвращаем ошибку
    } else {
        SERVER_LOG_INFO("Response sent successfully",NULL);
    }
    
    // Финальное логирование
    SERVER_LOG_INFO("Problem %s SUCCESS", is_update ? "UPDATED" : "CREATED");
    
    return SERVER_OK;
}


char server_problem_replace(server_ctx_t *srv, const problem_info_t *src, problem_info_t **old_problem_out) {
    if (!srv || !src) return SERVER_ERR_INVALID_ARG;
    
    SERVER_LOG_INFO("server_problem_replace_copy: id=%d", src->problem_id);
    
    // Создаем КОПИЮ задачи
    problem_info_t *copy = malloc(sizeof(problem_info_t));
    if (!copy) return SERVER_ERR_NOMEM;
    memcpy(copy, src, sizeof(problem_info_t));
    
    // Ищем существующую запись
    problem_hash_entry_t *existing = NULL;
    HASH_FIND_INT(srv->problem_by_id, &src->problem_id, existing);
    
    if (existing) {
        // Возвращаем старую задачу (чтобы caller мог ее освободить)
        if (old_problem_out) {
            *old_problem_out = existing->problem;
        } else {
            // Если caller не хочет старую - освобождаем тут
            if (existing->problem) {
                free(existing->problem);
            }
        }
        
        // Заменяем на новую копию
        existing->problem = copy;
        SERVER_LOG_INFO("Replaced problem %d in hash", src->problem_id);
    } else {
        // Создаем новую запись
        problem_hash_entry_t *item = malloc(sizeof(problem_hash_entry_t));
        if (!item) {
            free(copy);
            return SERVER_ERR_NOMEM;
        }
        
        item->problem_id = src->problem_id;
        item->problem = copy;
        
        HASH_ADD_INT(srv->problem_by_id, problem_id, item);
        SERVER_LOG_INFO("Added new problem %d to hash", src->problem_id);
        
        if (old_problem_out) {
            *old_problem_out = NULL;  // Не было старой задачи
        }
    }
    
    return SERVER_OK;
}

char server_handle_get_solution_results_list(server_ctx_t *srv, server_conn_t *conn,
                                             const protocol_header_t *header, const uint8_t *payload) {
    SERVER_LOG_INFO("Handle solution results list. seq_id=%d", header->seq_id);

    if (!srv || !conn || !header) {
        SERVER_LOG_ERROR("Invalid arguments",NULL);
        return SERVER_ERR_INVALID_ARG;
    }

    if (!conn->authenticated) {
        SERVER_LOG_WARN("Not authenticated",NULL);
        send_error_response(srv, conn, "Authentication required");
        return SERVER_OK;
    }

    // 1. ОПРЕДЕЛЯЕМ, ЧЬИ РЕШЕНИЯ ЗАПРАШИВАЮТСЯ
    const char *target_username;
    
    if (header->payload_size > 0 && payload != NULL) {
        // Есть payload - значит преподаватель запрашивает конкретного студента
        target_username = (const char *)payload;
        SERVER_LOG_INFO("Teacher requesting solutions for student %s", target_username);
        
        // Проверяем права преподавателя
        if (conn->role != ROLE_TEACHER) {
            SERVER_LOG_WARN("Student %s trying to access other student's solutions", 
                          conn->username);
            send_error_response(srv, conn, "Access denied");
            return SERVER_OK;
        }
    } else {
        // Нет payload - значит студент запрашивает свои решения
        target_username = conn->username;
        SERVER_LOG_INFO("Student %s requesting own solutions", target_username);
    }

    // 2. ПРОВЕРЯЕМ И СОЗДАЕМ ДИРЕКТОРИЮ ПОЛЬЗОВАТЕЛЯ
    SERVER_LOG_INFO("Getting solutions for: %s", target_username);
	char user_dir[MAX_FILE_LEN];

	// Копируем solutions_dir
	strncpy(user_dir, srv->solutions_dir, sizeof(user_dir));
	user_dir[sizeof(user_dir) - 1] = '\0'; // Гарантируем завершение строки

	// Проверяем длину
	size_t current_len = strlen(user_dir);
	if (current_len + 1 >= sizeof(user_dir)) { // Нет места для '/'
		SERVER_LOG_ERROR("Solutions directory path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

	// Добавляем '/'
	strcat(user_dir, "/");
	current_len++;

	// Проверяем, хватит ли места для имени пользователя
	size_t username_len = strlen(target_username);
	if (current_len + username_len >= sizeof(user_dir)) {
		SERVER_LOG_ERROR("Username too long for path",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

	// Добавляем имя пользователя
	strcat(user_dir, target_username);
	SERVER_LOG_INFO("User directory: %s", user_dir);
	
    // Создаем директорию, если не существует
    if (mkdir(user_dir, 0755) != 0 && errno != EEXIST) {
        SERVER_LOG_ERROR("Failed to create directory %s", user_dir);
        send_error_response(srv, conn, "Server error");
        return SERVER_OK;
    }

    // 3. СЧИТАЕМ КОЛИЧЕСТВО ФАЙЛОВ РЕШЕНИЙ
    size_t count = 0;
    DIR *dir = opendir(user_dir);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && strcmp(ext, ".bin") == 0) {
                SERVER_LOG_INFO("Found solution file: %s", entry->d_name);
                count++;
            }
        }
        closedir(dir);
    } else {
        SERVER_LOG_WARN("Cannot open directory %s", user_dir);
    }

    SERVER_LOG_INFO("Found %zu solution files", count);

    // 4. ЕСЛИ НЕТ ФАЙЛОВ - ОТПРАВЛЯЕМ ПУСТОЙ ОТВЕТ
    if (count == 0) {
        SERVER_LOG_INFO("No solutions, sending empty response",NULL);
        protocol_header_t resp = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_SOLUTION_RESULTS_LIST,
            .flags = 0,
            .payload_size = 0,
            .seq_id = header->seq_id
        };
        char rc = server_send_packet(srv, conn, &resp, NULL);
        SERVER_LOG_INFO("Empty response sent, rc=%d", rc);
        return rc;
    }

    // 5. ВЫДЕЛЯЕМ ПАМЯТЬ ДЛЯ МАССИВА ЗАДАЧ
    common_problem_t *arr = (common_problem_t*)calloc(count, sizeof(*arr));
    if (!arr) {
        SERVER_LOG_ERROR("Memory allocation failed for %zu items", count);
        send_error_response(srv, conn, "Server error: memory allocation failed");
        return SERVER_OK;
    }

    // 6. ЗАПОЛНЯЕМ МАССИВ ИНФОРМАЦИЕЙ О ЗАДАЧАХ
    size_t idx = 0;
    dir = opendir(user_dir);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (idx >= count) break;
            
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            
            const char *ext = strrchr(entry->d_name, '.');
            if (!ext || strcmp(ext, ".bin") != 0)
                continue;
            
            // Извлекаем problem_id из имени файла (формат: problem_id.bin)
            char filename[MAX_FILE_LEN];
            strncpy(filename, entry->d_name, sizeof(filename) - 1);
            filename[sizeof(filename) - 1] = '\0';
            
            char *dot = strrchr(filename, '.');
            if (dot) *dot = '\0';
            
            int problem_id = atoi(filename);
            SERVER_LOG_INFO("Processing file: %s", entry->d_name);
            
            if (problem_id <= 0) {
                SERVER_LOG_WARN("Invalid problem_id from filename: %s", entry->d_name);
                continue;
            }
            
            // Ищем информацию о задаче
            pthread_mutex_lock(&srv->problems_mutex);
            problem_info_t *problem = server_problem_find(srv, problem_id);
            pthread_mutex_unlock(&srv->problems_mutex);
            
            if (problem) {
                SERVER_LOG_INFO("Found problem: (id=%d)", problem->problem_id);
                
                // Заполняем структуру common_problem_t
                arr[idx].problem_id = problem->problem_id;
                strncpy(arr[idx].title, problem->title, sizeof(arr[idx].title) - 1);
                strncpy(arr[idx].description, problem->description, sizeof(arr[idx].description) - 1);
                arr[idx].time_limit_ms = problem->time_limit_ms;
                arr[idx].memory_limit_kb = problem->memory_limit_kb;
                
                // Получаем статус решения
                arr[idx].status = get_problem_status_for_user(srv, target_username, problem_id);
                SERVER_LOG_INFO("Solution status: %d", arr[idx].status);
                
                idx++;
            } else {
                SERVER_LOG_WARN("Problem not found for id=%d", problem_id);
            }
        }
        closedir(dir);
    }

    SERVER_LOG_INFO("Prepared %zu solutions to send", idx);

    // 7. ОТПРАВЛЯЕМ ОТВЕТ КЛИЕНТУ
    protocol_header_t resp = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULTS_LIST,
        .flags = 0,
        .payload_size = (uint32_t)(idx * sizeof(common_problem_t)),
        .seq_id = header->seq_id
    };
    
    
    char rc = server_send_packet(srv, conn, &resp, (const uint8_t*)arr);
    
    SERVER_LOG_INFO("Response sent, rc=%d", rc);
    
    // 8. ОСВОБОЖДАЕМ ПАМЯТЬ
    free(arr);
    
    return rc;
}

char server_handle_get_solution_result(server_ctx_t *srv, server_conn_t *conn,
                                       const protocol_header_t *header, const uint8_t *payload) {
    SERVER_LOG_INFO("Handle get solution result. seq_id=%d", header->seq_id);

    if (!srv || !conn || !header || !payload) return SERVER_ERR_INVALID_ARG;

    if (!conn->authenticated) {
        send_error_response(srv, conn, "Authentication required");
        return SERVER_OK;
    }

    if (header->payload_size != sizeof(int)) {
        send_error_response(srv, conn, "Invalid payload for result");
        return SERVER_OK;
    }

    int problem_id = 0;
    memcpy(&problem_id, payload, sizeof(int));

    char solution_file[MAX_FILE_LEN];
    int needed = snprintf(solution_file, sizeof(solution_file),
                     "%s/%s/%d.bin", srv->solutions_dir, conn->username, problem_id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format solution file path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(solution_file)) {
		SERVER_LOG_ERROR("Solution file path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    common_solution_result_t res;
    memset(&res, 0, sizeof(res));

    // если нет файла — ошибка
    FILE *f = fopen(solution_file, "rb");
    if (!f) {
        send_error_response(srv, conn, "No solution result found");
        return SERVER_OK;
    }

    size_t n = fread(&res, 1, sizeof(res), f);
    fclose(f);

    if (n != sizeof(res)) {
        send_error_response(srv, conn, "Corrupted solution result");
        return SERVER_OK;
    }

    protocol_header_t resp = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULT_FULL,
        .flags = 0,
        .payload_size = sizeof(res),
        .seq_id = header->seq_id
    };
    server_send_packet(srv, conn, &resp, (const uint8_t*)&res);

    return SERVER_OK;
}

char server_handle_message(server_ctx_t *srv,
                          server_conn_t *conn,
                          const protocol_header_t *hdr,
                          const uint8_t *payload){
    if (!srv || !conn || !hdr) {
        return SERVER_ERR_INVALID_ARG;
    }
    
    SERVER_LOG_INFO("Handling message type=%u", hdr->type);
    
    // Обрабатываем в зависимости от типа сообщения
    switch ((msg_type_t)hdr->type) {
            
        case MSG_AUTH_START:
            return server_handle_auth_start(srv, conn, hdr, payload);
            
        case MSG_AUTH_VERIFY:
            return server_handle_auth_verify(srv, conn, hdr, payload);
            
        case MSG_REGISTER_START:
            return server_handle_register_start(srv, conn, hdr, payload);
            
        case MSG_REGISTER_VERIFY:
            return server_handle_register_verify(srv, conn, hdr, payload);
            
        case MSG_GET_STUDENT_LIST:
            return server_handle_get_student_list(srv, conn);

        case MSG_GET_PROBLEM_LIST:
            return server_handle_get_problem_list(srv, conn, hdr, payload);

        case MSG_GET_PROBLEM:
			return server_handle_get_problem_info(srv, conn, hdr, payload);
		
		case MSG_PROBLEM_INFO:
			return server_handle_get_full_problem(srv, conn, hdr, payload);
		
		case MSG_GET_STUDENT_SOLUTION:
			return server_handle_get_student_solution(srv, conn, hdr, payload);
            
        case MSG_SEND_SOLUTION:
            return server_handle_send_solution(srv, conn, hdr, payload);
            
        case MSG_PROBLEM_CREATE:
		case MSG_PROBLEM_UPDATE:
			return server_handle_problem_upsert(srv, conn, hdr, payload);

        case MSG_GET_SOLUTION_RESULTS_LIST:
            return server_handle_get_solution_results_list(srv, conn, hdr, payload);

        case MSG_GET_SOLUTION_RESULT:
            return server_handle_get_solution_result(srv, conn, hdr, payload);
            
        case MSG_UPDATE_PROBLEM_STATUS:
            return server_handle_update_problem_status(srv, conn, hdr, payload);
            
        case MSG_PING:
            return server_handle_ping(srv, conn, hdr, payload);
        default:
            SERVER_LOG_WARN("Unknown message type fd=%d", conn->fd);
            return send_error_response(srv, conn, "Unknown message type");
    }
}


// Обработчик обновления статуса решения от преподавателя
char server_handle_update_problem_status(server_ctx_t *srv,
                       server_conn_t *conn,
                       const protocol_header_t *header, 
                       const uint8_t *payload) {
    
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_ERROR("Invalid arguments in handle_update_problem_status", NULL);
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем размер payload
    if (header->payload_size != sizeof(solution_update_stat_t)) {
        SERVER_LOG_WARN("Invalid payload size for update problem status: %u", header->payload_size);
        return send_error_response(srv, conn, "Invalid request format");
    }
    
    // Извлекаем данные обновления
    solution_update_stat_t update;
    memcpy(&update, payload, sizeof(solution_update_stat_t));
    
    // Гарантируем нулевое завершение строк
    update.student_login[sizeof(update.student_login) - 1] = '\0';
    update.teacher_comment[sizeof(update.teacher_comment) - 1] = '\0';
    
    SERVER_LOG_INFO("Update problem status request from '%s'", conn->username);
    
    // Проверяем авторизацию - только преподаватели могут обновлять статусы
    if (conn->role != ROLE_TEACHER) {
        SERVER_LOG_WARN("Access denied: user '%s' is not a teacher", conn->username);
        return send_error_response(srv, conn, "Access denied - teachers only");
    }
    
    // Проверяем валидность статуса
    if (update.status < PROBLEM_STATUS_NEW || update.status > PROBLEM_STATUS_UNKNOWN) {
        SERVER_LOG_WARN("Invalid status value: %d", update.status);
        return send_error_response(srv, conn, "Invalid status value");
    }
    
    // Проверяем, что студент существует
    
    client_hash_entry_t *entry = NULL;
    pthread_mutex_lock(&srv->users_mutex);
    HASH_FIND_STR(srv->users_by_username, update.student_login, entry);
    pthread_mutex_unlock(&srv->users_mutex);
    
    if (!entry || !entry->user) {
        SERVER_LOG_WARN("Student '%s' not found", update.student_login);
        return send_error_response(srv, conn, "Student not found");
    }
    
    // Проверяем, что задача существует
    problem_hash_entry_t *problem_entry = NULL;
    pthread_mutex_lock(&srv->problems_mutex);
    HASH_FIND_INT(srv->problem_by_id, &update.problem_id, problem_entry);
    pthread_mutex_unlock(&srv->problems_mutex);
    
    if (!problem_entry || !problem_entry->problem) {
        SERVER_LOG_WARN("Problem %d not found", update.problem_id);
        return send_error_response(srv, conn, "Problem not found");
    }
    
    // Формируем путь к файлу решения
    char solution_filename[MAX_FILE_LEN];

	int needed = snprintf(solution_filename, sizeof(solution_filename),
						"%s/%s/%d.bin", srv->solutions_dir, update.student_login, update.problem_id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format solution filename",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(solution_filename)) {
		SERVER_LOG_ERROR("Solution filename too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

    // Загружаем существующее решение (если есть)
    common_solution_result_t solution;
    memset(&solution, 0, sizeof(solution));
    
    int solution_exists = 0;
    if (access(solution_filename, F_OK) == 0) {
        if (load_solution_from_file(solution_filename, &solution) == SERVER_OK) {
            solution_exists = 1;
            SERVER_LOG_INFO("Existing solution loaded for update",NULL);
        }
    }
    
    // Если решения нет, создаем базовую структуру
    if (!solution_exists) {
        SERVER_LOG_WARN("Solution not found",NULL);
        send_error_response(srv, conn, "Solution not found");
    }
    
    // Обновляем поля решения
    solution.status = update.status;
    
    // Обновляем комментарий преподавателя, если он предоставлен
    if (strlen(update.teacher_comment) > 0) {
        strncpy(solution.teacher_comment, update.teacher_comment, MAX_COMMENT - 1);
        solution.teacher_comment[MAX_COMMENT - 1] = '\0';
    }
    
    // Обновляем финальную оценку, если она предоставлена
    if (update.final_score >= 0 && update.final_score <= 100) {
        solution.final_score = update.final_score;
    }
    
    // Если статус ACCEPTED и нет финальной оценки, используем автооценку
    if (update.status == PROBLEM_STATUS_ACCEPTED && solution.final_score == 0) {
        solution.final_score = solution.auto_score;
    }
    
    // Если статус REVIEW, сохраняем комментарий как требование доработки
    if (update.status == PROBLEM_STATUS_REVIEW && strlen(update.teacher_comment) == 0) {
        strncpy(solution.teacher_comment, "Решение требует доработки", MAX_COMMENT - 1);
        solution.teacher_comment[MAX_COMMENT - 1] = '\0';
    }
    
    // Сохраняем обновленное решение
    char save_result = save_solution_to_file(&solution, solution_filename);
    if (save_result != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to save updated solution to %s", solution_filename);
        return send_error_response(srv, conn, "Failed to save solution");
    }
    
    SERVER_LOG_INFO("Solution updated successfully: student='%s'",update.student_login);
    
    // Отправляем подтверждение клиенту
    protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_ACK,
        .flags = 0,
        .payload_size = 0,
        .seq_id = srv->seq_id++
    };
    
    char send_result = server_send_packet(srv, conn, &response_header, NULL);
    
    if (send_result == SERVER_OK) {
        SERVER_LOG_INFO("Update confirmation sent to teacher '%s'", conn->username);
    } else {
        SERVER_LOG_ERROR("Failed to send confirmation to teacher '%s'", conn->username);
    }
    
    return send_result;
}

char server_handle_ping(server_ctx_t *srv, server_conn_t *conn, const protocol_header_t *header, const uint8_t *payload) {
    (void)payload;
    protocol_header_t resp;
    resp.magic = PROTOCOL_MAGIC;
    resp.type = MSG_PONG;
    resp.flags = 0;
    resp.payload_size = 0;
    resp.seq_id = header->seq_id;

    return server_send_packet(srv, conn, &resp, NULL);
}

char server_handle_get_student_list(server_ctx_t *srv, server_conn_t *conn) {
    if (!srv || !conn) {
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Подсчитываем количество студентов
    size_t student_count = 0;
    pthread_mutex_lock(&srv->users_mutex);
    
    client_hash_entry_t *entry, *tmp;
    HASH_ITER(hh, srv->users_by_username, entry, tmp) {
        if (entry->user && entry->user->role == ROLE_STUDENT) {
            student_count++;
        }
    }
    
    // Отправляем размер списка
    protocol_header_t size_header;
    size_header.magic = PROTOCOL_MAGIC;
    size_header.type = MSG_STUDENT_LIST_SIZE;
    size_header.flags = 0;
    size_header.payload_size = sizeof(size_t);
    size_header.seq_id = srv->seq_id++;
    
    char result = server_send_packet(srv, conn, &size_header, (uint8_t*)&student_count);
    if (result != SERVER_OK) {
        pthread_mutex_unlock(&srv->users_mutex);
        return result;
    }
    
    if (student_count == 0) {
        pthread_mutex_unlock(&srv->users_mutex);
        return SERVER_OK;
    }
    
    // Подготавливаем буфер с логинами студентов
    size_t logins_buffer_size = student_count * SERVER_MAX_LOGIN_LEN;
    char *logins_buffer = malloc(logins_buffer_size);
    if (!logins_buffer) {
        pthread_mutex_unlock(&srv->users_mutex);
        return SERVER_ERR_NOMEM;
    }
    
    memset(logins_buffer, 0, logins_buffer_size);
    
    size_t idx = 0;
    HASH_ITER(hh, srv->users_by_username, entry, tmp) {
        if (entry->user && entry->user->role == ROLE_STUDENT) {
            if (idx < student_count) {
                strncpy(logins_buffer + (idx * SERVER_MAX_LOGIN_LEN),
                        entry->user->username,
                        SERVER_MAX_LOGIN_LEN - 1);
                idx++;
            }
        }
    }
    
    pthread_mutex_unlock(&srv->users_mutex);
    
    // Отправляем список логинов
    protocol_header_t list_header;
    list_header.magic = PROTOCOL_MAGIC;
    list_header.type = MSG_STUDENT_LIST;
    list_header.flags = 0;
    list_header.payload_size = logins_buffer_size;
    list_header.seq_id = srv->seq_id++;
    
    result = server_send_packet(srv, conn, &list_header, (uint8_t*)logins_buffer);
    free(logins_buffer);
        
    return result;
}


char server_handle_send_solution(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload) {
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_ERROR("Invalid arguments in handle_send_solution", NULL);
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем размер payload
    if (header->payload_size > MAX_PAYLOAD_LEN) {
        SERVER_LOG_WARN("Invalid payload size for send solution: %u", header->payload_size);
        return send_error_response(srv, conn, "Invalid request format");
    }
    
    // Извлекаем данные запроса
    solution_code_t *submission = (solution_code_t*)payload;
    
    SERVER_LOG_INFO("Received solution from user '%s'", conn->username);
    
    // Проверяем длину кода
    size_t code_len = strlen(submission->code);
    if (code_len == 0 || code_len > MAX_CODE - 1) {
        SERVER_LOG_WARN("Invalid code length: %zu", code_len);
        return send_error_response(srv, conn, "Invalid code length");
    }
    
    char image_name[MAX_FILE_LEN] = "";
    
    // Ищем задачу в хэше
    problem_hash_entry_t *problem_entry = NULL;
    pthread_mutex_lock(&srv->problems_mutex);
    HASH_FIND_INT(srv->problem_by_id, &submission->problem_id, problem_entry);
    pthread_mutex_unlock(&srv->problems_mutex);
    
    if (!problem_entry || !problem_entry->problem) {
        SERVER_LOG_WARN("Problem %d not found", submission->problem_id);
        return send_error_response(srv, conn, "Problem not found");
    }
    
    problem_info_t *problem = problem_entry->problem;
    
    // Создаем директорию пользователя
    char user_solution_dir[MAX_FILE_LEN];

	// Проверяем первый snprintf
	int needed = snprintf(user_solution_dir, sizeof(user_solution_dir), "%s/%s", 
						srv->solutions_dir, conn->username);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format user solution directory",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(user_solution_dir)) {
		SERVER_LOG_ERROR("User solution directory path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

    
    // Проверяем предыдущее решение
    char prev_solution_filename[MAX_FILE_LEN];

	// Проверяем второй snprintf
	needed = snprintf(prev_solution_filename, sizeof(prev_solution_filename), 
					"%s/%d.bin", user_solution_dir, submission->problem_id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format previous solution filename",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(prev_solution_filename)) {
		SERVER_LOG_ERROR("Previous solution filename too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    common_solution_result_t prev_solution;
    int has_previous_solution = 0;
    
    if (access(prev_solution_filename, F_OK) == 0) {
        if (load_solution_from_file(prev_solution_filename, &prev_solution) == SERVER_OK) {
            has_previous_solution = 1;
            SERVER_LOG_INFO("Previous solution found for user '%s'", conn->username);
        }
    }
    
    // Создаем новую структуру для решения
    common_solution_result_t new_solution;
    memset(&new_solution, 0, sizeof(common_solution_result_t));
    
    strncpy(new_solution.username, conn->username, MAX_LOGIN_LEN - 1);
    new_solution.username[MAX_LOGIN_LEN - 1] = '\0';
    new_solution.problem_id = submission->problem_id;
    strncpy(new_solution.code, submission->code, MAX_CODE - 1);
    new_solution.code[MAX_CODE - 1] = '\0';
    new_solution.status = PROBLEM_STATUS_SENT;
    
    // ========== ОБРАБОТКА В DOCKER ==========
    
    // СОЗДАЕМ ВРЕМЕННУЮ ДИРЕКТОРИЮ ДЛЯ РЕШЕНИЯ
    char temp_dir[MAX_FILE_LEN];
	needed = snprintf(temp_dir, sizeof(temp_dir), "%s/temp_%s_%d_%ld", 
						srv->solutions_dir, conn->username, 
						submission->problem_id, time(NULL));

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format temp directory path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(temp_dir)) {
		SERVER_LOG_ERROR("Temp directory path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    if (mkdir(temp_dir, TASKDIR_MODE) != 0) {
        SERVER_LOG_ERROR("Failed to create temp directory: %s", temp_dir);
        strcpy(new_solution.error_message, "Failed to create temp directory");
        new_solution.status = PROBLEM_STATUS_COMPILATION_ERROR;
        new_solution.auto_score = 0;
        
        
        return save_result(srv, conn, &new_solution, user_solution_dir, 
                                  submission->problem_id, has_previous_solution, 
                                  &prev_solution, 0);
    }
    
    SERVER_LOG_INFO("Created temp directory: %s", temp_dir);
    
    // 2. КОПИРУЕМ DOCKER ФАЙЛЫ ИЗ ПАПКИ source/docker/
    char source_docker_dir[MAX_FILE_LEN];
    needed = snprintf(source_docker_dir, sizeof(source_docker_dir), 
                  "%s/../source/docker", srv->solutions_dir);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format docker directory path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(source_docker_dir)) {
		SERVER_LOG_ERROR("Docker directory path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    // Копируем Dockerfile
  char dockerfile_src[MAX_FILE_LEN], dockerfile_dst[MAX_FILE_LEN];

	needed = snprintf(dockerfile_src, sizeof(dockerfile_src), 
						"%s/Dockerfile", source_docker_dir);
	if (needed < 0 || (size_t)needed >= sizeof(dockerfile_src)) {
		SERVER_LOG_ERROR("Dockerfile source path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

	needed = snprintf(dockerfile_dst, sizeof(dockerfile_dst), 
					"%s/Dockerfile", temp_dir);
	if (needed < 0 || (size_t)needed >= sizeof(dockerfile_dst)) {
		SERVER_LOG_ERROR("Dockerfile destination path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    if (copy_file(dockerfile_src, dockerfile_dst) != 0) {
        SERVER_LOG_ERROR("Failed to copy Dockerfile from %s", dockerfile_src);
        // Создаем минимальный Dockerfile если не найден
        FILE *df = fopen(dockerfile_dst, "w");
        if (df) {
             fprintf(df, "FROM gcc:latest\n");
			 fprintf(df, "RUN useradd -m -u 1000 runner\n");
			 fprintf(df, "WORKDIR /home/runner\n");
			 fprintf(df, "COPY --chown=runner:runner solution.c .\n");
			 fprintf(df, "USER runner\n");
			 fprintf(df, "RUN gcc -std=c11 -static -o solution solution.c 2>&1\n");
			 fprintf(df, "CMD [\"./solution\"]\n");
			 fclose(df);
        }
    }
    
    // Копируем runner.sh
    char runner_src[MAX_FILE_LEN], runner_dst[MAX_FILE_LEN];
    needed = snprintf(runner_src, sizeof(runner_src), 
					"%s/runner.sh", source_docker_dir);
	if (needed < 0 || (size_t)needed >= sizeof(runner_src)) {
		SERVER_LOG_ERROR("Runner source path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

	needed = snprintf(runner_dst, sizeof(runner_dst), 
					"%s/runner.sh", temp_dir);
	if (needed < 0 || (size_t)needed >= sizeof(runner_dst)) {
		SERVER_LOG_ERROR("Runner destination path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    if (copy_file(runner_src, runner_dst) != 0) {
        SERVER_LOG_WARN("Failed to copy runner.sh, creating default", NULL);
        FILE *rf = fopen(runner_dst, "w");
        if (rf) {
            fprintf(rf, "#!/bin/bash\n");
			fprintf(rf, "if [ $? -eq 0 ]; then\n");
			fprintf(rf, "    if [ -f \"/home/runner/input.txt\" ]; then\n");  // <-- ИЗМЕНИЛ ПУТЬ
			fprintf(rf, "        timeout $TIMEOUT_SECONDS ./solution < /home/runner/input.txt\n");  // <-- ИЗМЕНИЛ ПУТЬ
			fprintf(rf, "    else\n");
			fprintf(rf, "        timeout $TIMEOUT_SECONDS ./solution\n");
			fprintf(rf, "    fi\n");
			fprintf(rf, "fi\n");
            fclose(rf);
            chmod(runner_dst, TASKDIR_MODE);
        }
    } else {
        chmod(runner_dst, TASKDIR_MODE);
    }
    
    // 3. СОЗДАЕМ ФАЙЛ С КОДОМ ПОЛЬЗОВАТЕЛЯ
    char code_filename[MAX_FILE_LEN];
    needed = snprintf(code_filename, sizeof(code_filename), "%s/solution.c", temp_dir);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format code filename",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(code_filename)) {
		SERVER_LOG_ERROR("Code filename too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    FILE *code_file = fopen(code_filename, "w");
    if (!code_file) {
        SERVER_LOG_ERROR("Failed to create code file: %s", code_filename);
        strcpy(new_solution.error_message, "Failed to create code file");
        new_solution.status = PROBLEM_STATUS_COMPILATION_ERROR;
        new_solution.auto_score = 0;
        cleanup_temp_dir(temp_dir, image_name);
        
        protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULT,
        .flags = 0,
        .payload_size = sizeof(common_solution_result_t),
        .seq_id = srv->seq_id++
		};
    
		server_send_packet(srv, conn, &response_header, (uint8_t*)&new_solution);
        
        return save_result(srv, conn, &new_solution, user_solution_dir, 
                                  submission->problem_id, has_previous_solution, 
                                  &prev_solution, 0);
    }
    
    // Пишем код пользователя
    fprintf(code_file, "%s", submission->code);
    fclose(code_file);
    
    SERVER_LOG_INFO("User code saved to %s", code_filename);
	SERVER_LOG_INFO("Code content:\n%s", submission->code);
    
    // 4. КОМПИЛИРУЕМ И ЗАПУСКАЕМ В DOCKER
    SERVER_LOG_INFO("Building Docker image...", NULL);
    
    // Создаем безопасное имя для Docker образа
	// Генерируем уникальный ID на основе времени и PID
	unsigned long unique_id = (unsigned long)time(NULL) + (unsigned long)getpid();
	snprintf(image_name, sizeof(image_name), "solution_%lu", unique_id);
    
    char build_cmd[MAX_CMD_LEN];
    needed = snprintf(build_cmd, sizeof(build_cmd),
                     "docker build -t %s %s 2>&1",
                     image_name, temp_dir);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format docker build command",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(build_cmd)) {
		SERVER_LOG_ERROR("Docker build command too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

    
    SERVER_LOG_INFO("Docker build command: %s", build_cmd);
    
    char build_output[MAX_OUTPUT_LEN];
    FILE *build_pipe = popen(build_cmd, "r");
    if (!build_pipe) {
        SERVER_LOG_ERROR("Failed to start Docker build",NULL);
        strcpy(new_solution.error_message, "Failed to start Docker");
        new_solution.status = PROBLEM_STATUS_COMPILATION_ERROR;
        new_solution.auto_score = 0;
        cleanup_temp_dir(temp_dir, image_name);
        
        protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULT,
        .flags = 0,
        .payload_size = sizeof(common_solution_result_t),
        .seq_id = srv->seq_id++
		};
    
		server_send_packet(srv, conn, &response_header, (uint8_t*)&new_solution);
		
        return save_result(srv, conn, &new_solution, user_solution_dir, 
                                  submission->problem_id, has_previous_solution, 
                                  &prev_solution, 0);                      
                                  
    }
    
    build_output[0] = '\0';
    char buffer[MAX_FILE_LEN];
    while (fgets(buffer, sizeof(buffer), build_pipe)) {
        strncat(build_output, buffer, sizeof(build_output) - strlen(build_output) - 1);
    }
    
    int build_result = pclose(build_pipe);
    
    if (build_result != 0) {
        SERVER_LOG_WARN("Docker build failed: %s", build_output);
        // Извлекаем ошибку компиляции из вывода
        extract_compile_error(build_output, new_solution.error_message, 255);
        new_solution.status = PROBLEM_STATUS_COMPILATION_ERROR;
        new_solution.auto_score = 0;
        cleanup_temp_dir(temp_dir, image_name);
        protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULT,
        .flags = 0,
        .payload_size = sizeof(common_solution_result_t),
        .seq_id = srv->seq_id++
		};
    
		server_send_packet(srv, conn, &response_header, (uint8_t*)&new_solution);
		
        return save_result(srv, conn, &new_solution, user_solution_dir, 
                                  submission->problem_id, has_previous_solution, 
                                  &prev_solution, 0);
    }
    
    SERVER_LOG_INFO("Docker image built successfully", NULL);
    
    // 5. ЗАПУСКАЕМ ТЕСТЫ
	int total_score = 0;
	int max_score = problem->test_count;
    
	for (size_t i = 0; i < problem->test_count; i++) {
		test_case_t *test = &problem->test_cases[i];
    
		SERVER_LOG_INFO("Running test %zu", i + 1);
		
		SERVER_LOG_INFO("=== TEST %zu DEBUG ===", i + 1);
		SERVER_LOG_INFO("Test input: '%s'", test->input);
		SERVER_LOG_INFO("Test expected: '%s'", test->expected);
    
		// ОБЪЯВЛЯЕМ ПЕРЕМЕННЫЕ
		char input_filename[MAX_FILE_LEN];
		char output_filename[MAX_FILE_LEN];  
    
		// Создаем файл с входными данными
		needed = snprintf(input_filename, sizeof(input_filename), 
                     "%s/test_input.txt", temp_dir);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format input filename",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(input_filename)) {
		SERVER_LOG_ERROR("Input filename too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
		FILE *input_file = fopen(input_filename, "w");
		if (!input_file) {
			SERVER_LOG_ERROR("Failed to create input file for test %zu", i + 1);
			continue;
		}
		fprintf(input_file, "%s", test->input);  // используем поле input
		fclose(input_file);
    
		 FILE *check = fopen(input_filename, "r");
		if (check) {
			char content[1024];
			content[0] = '\0';
			fgets(content, sizeof(content), check);
			fclose(check);
			SERVER_LOG_INFO("Input file actual content: '%s'", content);
		}
    
		char run_cmd[MAX_COMMAND_LEN];

		// Таймаут задачи в секундах
		int task_timeout_seconds = problem->time_limit_ms / 1000;
		if (task_timeout_seconds < 1) task_timeout_seconds = 1;
		
		// Таймаут для Docker (немного больше)
		int docker_timeout = task_timeout_seconds + 1;  // +1 секунда на завершение

		needed = snprintf(run_cmd, sizeof(run_cmd),
			"echo '%s' | timeout %d docker run --rm "
			"--memory=%dm --memory-swap=%dm "
			"--cpus=1 "
			"--network=none "
			"--read-only --tmpfs /tmp "
			"-i "
			"--stop-timeout=%d "  // Таймаут для graceful shutdown
			"%s 2>&1",
			test->input,
			docker_timeout,
			problem->memory_limit_kb / 1024,
			problem->memory_limit_kb / 1024,
			task_timeout_seconds,  // stop-timeout для Docker
			image_name);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format docker run command",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(run_cmd)) {
		SERVER_LOG_ERROR("Docker run command too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
		SERVER_LOG_INFO("Docker run command: %s", run_cmd);
    
		FILE *run_pipe = popen(run_cmd, "r");
		if (!run_pipe) {
			SERVER_LOG_ERROR("Failed to run Docker for test %zu", i + 1);
			continue;
		}
    
		char test_output[MAX_OUTPUT_LEN];
		test_output[0] = '\0';
		char buffer[MAX_FILE_LEN];
		SERVER_LOG_INFO("Reading Docker output...",NULL);
		while (fgets(buffer, sizeof(buffer), run_pipe)) {
			strncat(test_output, buffer, sizeof(test_output) - strlen(test_output) - 1);
			SERVER_LOG_INFO("Docker chunk: %s", buffer); 
		}
    
		int run_result = pclose(run_pipe);
    
		SERVER_LOG_INFO("=== DOCKER TEST %zu RESULTS ===", i + 1);
		SERVER_LOG_INFO("Exit code: %d", run_result);
		SERVER_LOG_INFO("Full output:\n%s", test_output);
		SERVER_LOG_INFO("Output length: %zu", strlen(test_output));
		SERVER_LOG_INFO("=== END DOCKER RESULTS ===",NULL);
    
    
		// Анализируем результат
		char test_error[MAX_ERROR_MSG_LEN] = "";
		int test_passed = 0;
		
		if (WIFSIGNALED(run_result)) {
			int sig = WTERMSIG(run_result);
			if (sig == SIGKILL || sig == SIGXCPU || sig == EXIT_CODE_TIMEOUT) {
				snprintf(test_error, sizeof(test_error), 
						"Time limit exceeded on test %zu", i + 1);
				new_solution.status = PROBLEM_STATUS_OUT_OF_TIME; 
			}
			else if (sig == 137) {
				SERVER_LOG_WARN("Killed by SIGKILL (likely OOM) on test %zu", i + 1);
				snprintf(new_solution.error_message, sizeof(new_solution.error_message),
						"Memory limit exceeded on test %zu", i + 1);
				new_solution.status = PROBLEM_STATUS_OUT_OF_MEMORY;
			}
			else if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS) {
				snprintf(test_error, sizeof(test_error), 
						"Runtime error (signal %d) on test %zu", sig, i + 1);
				new_solution.status = PROBLEM_STATUS_RUNTIME_ERROR;
			} else {
				snprintf(test_error, sizeof(test_error), 
						"Unknown error (signal %d) on test %zu", sig, i + 1);
				new_solution.status = PROBLEM_STATUS_RUNTIME_ERROR;
			}
		} else if (run_result != 0) {
			if (strstr(test_output, "error:") != NULL || 
				strstr(test_output, "Error:") != NULL ||
				strstr(test_output, "undefined reference") != NULL) {
				snprintf(test_error, sizeof(test_error), 
						"Compilation error on test %zu", i + 1);
				new_solution.status = PROBLEM_STATUS_COMPILATION_ERROR;
			} else if (run_result == EXIT_CODE_TIMEOUT) {
				snprintf(test_error, sizeof(test_error), 
						"Time limit exceeded on test %zu", i + 1);
				new_solution.status = PROBLEM_STATUS_OUT_OF_TIME;  
			} else {
				snprintf(test_error, sizeof(test_error), 
						"Runtime error (exit code %d) on test %zu", run_result, i + 1);
				new_solution.status = PROBLEM_STATUS_RUNTIME_ERROR;
			}
		} else {
        // Успешное выполнение - сравниваем вывод
			char *expected_clean = normalize_string(test->expected);
			char *actual_clean = normalize_string(test_output);
        
			if (expected_clean && actual_clean) {
				if (strcmp(expected_clean, actual_clean) == 0) {
					test_passed = 1;
					total_score++;
					SERVER_LOG_INFO("Test %zu PASSED", i + 1);
				} else {
					SERVER_LOG_INFO("Test %zu FAILED", i + 1);
					snprintf(test_error, sizeof(test_error), 
							"Wrong answer on test %zu", i + 1);
					new_solution.status = PROBLEM_STATUS_WRONG;
				}
			} else {
				snprintf(test_error, sizeof(test_error), 
						"Cannot compare results on test %zu", i + 1);
				new_solution.status = PROBLEM_STATUS_WRONG;
			}
        
			if (expected_clean) free(expected_clean);
			if (actual_clean) free(actual_clean);
		}
    
		// Сохраняем первую ошибку
		if (test_error[0] != '\0' && new_solution.error_message[0] == '\0') {
			strncpy(new_solution.error_message, test_error, MAX_ERROR_MSG_LEN - 1);
			new_solution.error_message[MAX_ERROR_MSG_LEN - 1] = '\0';
		}
    
		// Если критическая ошибка - прерываем
		if (new_solution.status == PROBLEM_STATUS_COMPILATION_ERROR ||
			new_solution.status == PROBLEM_STATUS_RUNTIME_ERROR) {
			break;
		}
        
        // Удаляем временные файлы теста
        unlink(input_filename);
    }
    
    // ВЫЧИСЛЯЕМ ОЦЕНКУ
    if (max_score > 0) {
        new_solution.auto_score = (total_score * 100) / max_score;
    } else {
        new_solution.auto_score = 0;
    }
    
    // ОПРЕДЕЛЯЕМ ФИНАЛЬНЫЙ СТАТУС
    if (total_score == max_score && max_score > 0) {
        new_solution.status = PROBLEM_STATUS_COMPLETED;
    } else if (total_score > 0) {
        if (new_solution.status == PROBLEM_STATUS_SENT) {
            new_solution.status = PROBLEM_STATUS_WRONG;
        }
    }
    
    SERVER_LOG_INFO("Tests completed: score: %d", new_solution.auto_score);
    
    // ОЧИСТКА РЕСУРСОВ
    cleanup_temp_dir(temp_dir, image_name);
    
     // Отправляем результат клиенту
    protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SOLUTION_RESULT,
        .flags = 0,
        .payload_size = sizeof(common_solution_result_t),
        .seq_id = srv->seq_id++
    };
    
    server_send_packet(srv, conn, &response_header, (uint8_t*)&new_solution);
    
    
    // СРАВНЕНИЕ С ПРЕДЫДУЩИМ РЕШЕНИЕМ
    int should_keep_previous = compare_with_previous(&new_solution, has_previous_solution, 
                                                   &prev_solution);
    
    // СОХРАНЕНИЕ И ОТПРАВКА РЕЗУЛЬТАТА
    return save_result(srv, conn, &new_solution, user_solution_dir, 
                                  submission->problem_id, has_previous_solution, 
                                  &prev_solution, should_keep_previous);
}

int copy_file(const char *src, const char *dst) {
    FILE *src_file = fopen(src, "rb");
    if (!src_file) return -1;
    
    FILE *dst_file = fopen(dst, "wb");
    if (!dst_file) {
        fclose(src_file);
        return -1;
    }
    
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes, dst_file);
    }
    
    fclose(src_file);
    fclose(dst_file);
    return 0;
}

// Извлечение ошибки компиляции из вывода Docker
void extract_compile_error(const char *docker_output, char *error_msg, size_t max_len) {
    const char *error_start = strstr(docker_output, "error:");
    if (!error_start) error_start = strstr(docker_output, "Error:");
    if (!error_start) error_start = strstr(docker_output, "ERROR:");
    
    if (error_start) {
        // Берем следующую строку после error
        const char *line_end = strchr(error_start, '\n');
        if (line_end) {
            size_t len = line_end - error_start;
            if (len > max_len - 1) len = max_len - 1;
            strncpy(error_msg, error_start, len);
            error_msg[len] = '\0';
        } else {
            strncpy(error_msg, error_start, max_len - 1);
            error_msg[max_len - 1] = '\0';
        }
    } else {
        // Если не нашли error, берем первые 200 символов
        strncpy(error_msg, "Compilation failed", max_len - 1);
        error_msg[max_len - 1] = '\0';
    }
}

char* normalize_string(const char* str) {
    if (!str) return strdup("");
    
    char* result = malloc(strlen(str) + 1);
    if (!result) return NULL;
    
    char* dest = result;
    int in_space = 0;
    
    for (; *str; str++) {
        if (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') {
            if (!in_space && dest != result) {
                *dest++ = ' ';
                in_space = 1;
            }
        } else {
            *dest++ = *str;
            in_space = 0;
        }
    }
    
    if (in_space && dest > result) {
        dest--;
    }
    
    *dest = '\0';
    return result;
}

void cleanup_temp_dir(const char *temp_dir, const char *image_name) {
    if (image_name && image_name[0] != '\0') {
        // Очистка Docker образа
        char cleanup_cmd[MAX_FILE_LEN];
        snprintf(cleanup_cmd, sizeof(cleanup_cmd),
                 "docker rmi %s 2>/dev/null", 
                 image_name);
        system(cleanup_cmd);
    }
    
    // Удаление временной директории
    char rm_cmd[MAX_CMD_LEN];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", temp_dir);
    system(rm_cmd);
}

int compare_with_previous(common_solution_result_t *new_solution, 
                          int has_previous_solution, 
                          common_solution_result_t *prev_solution) {
    if (!has_previous_solution) {
        return 0;
    }
    
    if (prev_solution->auto_score > new_solution->auto_score) {
        SERVER_LOG_INFO("Previous solution is better, keeping it", NULL);
        memcpy(new_solution, prev_solution, sizeof(common_solution_result_t));
        return 1;
    } else if (prev_solution->auto_score == new_solution->auto_score) {
        if (new_solution->exec_time_ms < prev_solution->exec_time_ms || 
            new_solution->memory_used_kb < prev_solution->memory_used_kb) {
            SERVER_LOG_INFO("Scores equal, new solution is more efficient", NULL);
            return 0;
        } else {
            SERVER_LOG_INFO("Scores equal, keeping previous solution", NULL);
            memcpy(new_solution, prev_solution, sizeof(common_solution_result_t));
            return 1;
        }
    }
    
    return 0;
}

char save_result(server_ctx_t *srv, server_conn_t *conn,
                         common_solution_result_t *solution,
                         const char *user_dir, int problem_id,
                         int has_previous_solution,
                         common_solution_result_t *prev_solution,
                         int should_keep_previous) {
    
   
    // Если есть предыдущее решение и нужно его сохранить
    if (has_previous_solution && should_keep_previous) {
        memcpy(solution, prev_solution, sizeof(common_solution_result_t));
    }
    
    // Сохраняем решение в файл
    char solution_filename[MAX_FILE_LEN];
    snprintf(solution_filename, sizeof(solution_filename), "%s/%d.bin", user_dir, problem_id);
    
    SERVER_LOG_INFO("Saving solution to: %s", solution_filename);
    
    if (save_solution_to_file(solution, solution_filename) != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to save solution for user '%s'", conn->username);
    } else {
        SERVER_LOG_INFO("Solution saved successfully", NULL);
    }
    
	return SERVER_OK;
}

char server_handle_get_student_solution(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload){
	if (!srv || !conn || !header || !payload) {
        SERVER_LOG_ERROR("Invalid arguments in handle_get_student_solution",NULL);
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем размер payload
    if (header->payload_size != sizeof(solution_request_t)) { 
        SERVER_LOG_WARN("Invalid payload size for get student solution: %u", header->payload_size);
        return send_error_response(srv, conn, "Invalid request format");
    }
    
    solution_request_t request;
    
    memcpy(&request, payload, sizeof(solution_request_t));
    
    SERVER_LOG_INFO("Request for student solution from user='%s'", conn->username);
    
    // Проверяем авторизацию
    if (conn->role != ROLE_TEACHER) {
        // Студент может смотреть только свои решения
        if (strcmp(conn->username, request.student_login) != 0) {
            return send_error_response(srv, conn,"Access denied");
        }
    }
    
    // Формируем имя файла с решением
   char filename[MAX_PATH_LEN];
	int needed = snprintf(filename, sizeof(filename), "%s/%s/%d.bin", 
						srv->solutions_dir, request.student_login, request.problem_id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format filename",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(filename)) {
		SERVER_LOG_ERROR("Filename too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    // Загружаем решение из файла
    common_solution_result_t solution;
    char result = load_solution_from_file(filename, &solution);
    
    if (result != SERVER_OK) {
        SERVER_LOG_WARN("Solution not found or error loading file=%s", filename);
        
        // Если решение не найдено, создаем пустую структуру
        memset(&solution, 0, sizeof(common_solution_result_t));
        strncpy(solution.username, request.student_login, MAX_LOGIN_LEN - 1);
        solution.username[MAX_LOGIN_LEN - 1] = '\0';
        solution.problem_id = request.problem_id;
        solution.status = PROBLEM_STATUS_NEW;
        
        SERVER_LOG_INFO("Sending empty solution response for user='%s'", request.student_login);
    } else {
        // Проверяем, что загруженное решение соответствует запросу
        if (strcmp(solution.username, request.student_login) != 0) {
            SERVER_LOG_ERROR("Solution username mismatch", NULL);
            return send_error_response(srv, conn, "Data corruption error");
        }
        
        if (solution.problem_id != request.problem_id) {
            SERVER_LOG_ERROR("Solution problem_id mismatch",NULL);
            return send_error_response(srv, conn, "Data corruption error");
        }
        
        SERVER_LOG_INFO("Loaded solution: user='%s'", solution.username);
    }
    
    // Преобразуем common_solution_result_t в common_solution_result_t для отправки
    common_solution_result_t response;
    
    memcpy(&response, (const void*)&solution, sizeof(common_solution_result_t));
    
    // Дополнительные проверки целостности строк
    response.username[MAX_LOGIN_LEN - 1] = '\0';
    response.code[MAX_CODE - 1] = '\0';
    response.teacher_comment[MAX_COMMENT - 1] = '\0';
    response.error_message[MAX_ERROR_MSG_LEN - 1] = '\0';
    
    // Отправляем ответ клиенту
    protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_STUDENT_SOLUTION,
        .flags = 0,
        .payload_size = sizeof(common_solution_result_t),
        .seq_id = srv->seq_id++
    };
    
    result = server_send_packet(srv, conn, &response_header, (uint8_t*)&response);
    
    if (result == SERVER_OK) {
        SERVER_LOG_INFO("Sent solution to user='%s'", conn->username);
    } else {
        SERVER_LOG_ERROR("Failed to send solution to user='%s'", conn->username);
    }
    
    return result;
}								 

char server_handle_get_problem_info(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload){
	if (!srv || !conn || !header || !payload) {
        SERVER_LOG_ERROR("Invalid arguments in handle_get_problem_info", NULL);
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем размер payload
    if (header->payload_size < sizeof(int)) {
        SERVER_LOG_WARN("Invalid payload size for get problem info: %u", header->payload_size);
        
        // Отправляем ошибку клиенту
        protocol_header_t error_header = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_ERROR,
            .flags = 0,
            .payload_size = 0,
            .seq_id = srv->seq_id++
        };
        return server_send_packet(srv, conn, &error_header, NULL);
    }
    
    // Извлекаем ID задачи из payload
    int problem_id;
    memcpy(&problem_id, payload, sizeof(int));
    SERVER_LOG_INFO("Request for problem header from user=%s", conn->username);
    
    // Ищем задачу в хэше
    problem_hash_entry_t *entry = NULL;
    pthread_mutex_lock(&srv->problems_mutex);
    HASH_FIND_INT(srv->problem_by_id, &problem_id, entry);
    pthread_mutex_unlock(&srv->problems_mutex);
    
    // Если задача не найдена
    if (!entry || !entry->problem) {
        SERVER_LOG_WARN("Problem %d not found", problem_id);
        
        const char *error_msg = "Problem not found";
        size_t error_len = strlen(error_msg) + 1;
        
        protocol_header_t error_header = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_ERROR,
            .flags = 0,
            .payload_size = error_len,
            .seq_id = srv->seq_id++
        };
        
        return server_send_packet(srv, conn, &error_header, (uint8_t*)error_msg);
    }
    
    problem_info_t *problem = entry->problem;
    
    // Подготавливаем структуру с заголовком задачи
    common_problem_header_t response;
    
    // Копируем заголовок задачи
    size_t header_size = problem->header_size;
    if (header_size > MAX_PAYLOAD_LEN) {
        header_size = MAX_PAYLOAD_LEN;
        SERVER_LOG_WARN("Problem %d header truncated",problem_id);
    }
    
    memcpy(response.problem_header, problem->problem_header, header_size);
    response.header_size = header_size;
    
    // Отправляем заголовок задачи клиенту
    protocol_header_t response_header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_PROBLEM_INFO,
        .flags = 0,
        .payload_size = sizeof(common_problem_header_t),
        .seq_id = srv->seq_id++
    };
    
    char result = server_send_packet(srv, conn, &response_header, (uint8_t*)&response);
    
    if (result == SERVER_OK) {
        SERVER_LOG_INFO("Sent problem header to user %s", conn->username);
    } else {
        SERVER_LOG_ERROR("Failed to send problem header to user=%s", conn->username);
    }
    
    return result;
}

char server_handle_get_problem_list(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload){
	SERVER_LOG_INFO("Handle get problem list. seq_id client %d", header->seq_id);
    
    if (!srv || !conn || !header) {
        SERVER_LOG_WARN("Invalid args. seq_id client %d", header->seq_id);
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем аутентификацию
    if (!conn->authenticated) {
        SERVER_LOG_WARN("Client not authenticated. seq_id client %d", header->seq_id);
        send_error_response(srv, conn, "Authentication required");
        return SERVER_OK;
    }
    
    SERVER_LOG_INFO("Sending problem list to user %s", conn->username);
    
    // Получаем все задачи из хэша
    problem_hash_entry_t *current, *tmp;
    size_t problem_count = 0;
    
    pthread_mutex_lock(&srv->problems_mutex);
    
    // Считаем количество задач
    HASH_ITER(hh, srv->problem_by_id, current, tmp) {
        problem_count++;
    }
    
    if (problem_count == 0) {
        pthread_mutex_unlock(&srv->problems_mutex);
        SERVER_LOG_INFO("No problems in database",NULL);
        
        // Отправляем пустой список
        protocol_header_t response = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_PROBLEM_LIST,
            .flags = 0,
            .payload_size = 0,
            .seq_id = header->seq_id
        };
        
        server_send_packet(srv, conn, &response, NULL);
        conn->last_activity=time(NULL);
        return SERVER_OK;
    }
    
    // Выделяем память под common_problem_t массив
    common_problem_t *common_problems = malloc(problem_count * sizeof(common_problem_t));
    if (!common_problems) {
        pthread_mutex_unlock(&srv->problems_mutex);
        send_error_response(srv,conn,"Server error");
        conn->last_activity=time(NULL);
        SERVER_LOG_ERROR("Memory allocation failed for %zu problems", problem_count);
        return SERVER_ERR_NOMEM;
    }
    
    // Конвертируем задачи
    size_t idx = 0;
	HASH_ITER(hh, srv->problem_by_id, current, tmp) {
    problem_info_t *server_problem = current->problem;
    common_problem_t *common = &common_problems[idx];
    
    // Базовые поля ВСЕГДА
    common->problem_id = server_problem->problem_id;
    strncpy(common->title, server_problem->title, sizeof(common->title));
    common->title[sizeof(common->title) - 1] = '\0';
    
    strncpy(common->description, server_problem->description, sizeof(common->description));
    common->description[sizeof(common->description) - 1] = '\0';
    
    // По умолчанию - нет решения
    common->status = PROBLEM_STATUS_NEW;
    common->time_limit_ms = 0;      // exec_time_ms - фактическое время
    common->memory_limit_kb = 0;    // memory_used_kb - фактическая память
    
    char solution_file[MAX_FILE_LEN];
	int needed = snprintf(solution_file, sizeof(solution_file), 
						"%s/%d_%d.bin", srv->solutions_dir, conn->user_id, server_problem->problem_id);
	
	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format solution file path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(solution_file)) {
		SERVER_LOG_ERROR("Solution file path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    
    if (access(solution_file, F_OK) == 0) {
        // Загружаем решение с метриками
        common_solution_result_t solution;
        int exec_time_ms, memory_used_kb;
        
        if (load_solution_with_metrics(solution_file, &solution, 
                                    &exec_time_ms, &memory_used_kb) == SERVER_OK) {
            
            // Статус
            common->status = solution.status;
            
            common->time_limit_ms = exec_time_ms;        
            common->memory_limit_kb = memory_used_kb;    
            
            SERVER_LOG_INFO("Problem %d: has solution",common->problem_id);
        }
    } else {
        SERVER_LOG_INFO("Problem %d: no solution", common->problem_id);
    }
    
    idx++;
	}
    
    pthread_mutex_unlock(&srv->problems_mutex);
    
    // Отправляем ответ
    protocol_header_t response = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_PROBLEM_LIST,
        .flags = 0,
        .payload_size = (uint32_t)(problem_count * sizeof(common_problem_t)),
        .seq_id = header->seq_id
    };
    
    SERVER_LOG_INFO("Sending %zu problems to user)", problem_count);
    
    char result = server_send_packet(srv, conn, &response, (const uint8_t*)common_problems);
    conn->last_activity=time(NULL);
    
    //  Освобождаем память
    free(common_problems);
    
    if (result != SERVER_OK) {
        SERVER_LOG_ERROR("Failed to send problem list to %s", conn->username);
        return result;
    }
    
    SERVER_LOG_INFO("Problem list sent successfully to %s", conn->username);
    return SERVER_OK;
}

char server_handle_register_start(server_ctx_t *srv, server_conn_t *conn, 
                                 const protocol_header_t *header, const uint8_t *payload) {
    SERVER_LOG_INFO("Start register. seq_id client %d",header->seq_id);
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_WARN("Invalid args. seq_id client %d",header->seq_id);
        return SERVER_ERR_INVALID_ARG;
    }
    
    if (header->payload_size != sizeof(auth_start_request_t)) {
        SERVER_LOG_WARN("Invalid register start size. seq_id client %d",header->seq_id);
        send_error_response(srv,conn, "Invalid register start size");
        return SERVER_OK;
    }
    
    auth_start_request_t *start_req = (auth_start_request_t*)payload;
    
    server_client_info_t *user_entry;
    // Проверяем, не существует ли уже пользователь
    pthread_mutex_lock(&srv->users_mutex);
    user_entry=server_user_find(srv,start_req->username);
    if (user_entry) {
        pthread_mutex_unlock(&srv->users_mutex);
        SERVER_LOG_INFO("Couldn't create new user. User %s already exists", start_req->username);
        send_error_response(srv,conn, "User already exists");
        return SERVER_OK;
    }
    pthread_mutex_unlock(&srv->users_mutex);
    
    // Генерируем новую соль для пользователя
    auth_challenge_t challenge;
    generate_salt(challenge.salt);

    
    // Сохраняем временные данные для регистрации
    strncpy(conn->username, start_req->username, sizeof(conn->username) - 1);
    memcpy(conn->auth_salt, challenge.salt, sizeof(challenge.salt));
    conn->last_activity= time(NULL);
    
    SERVER_LOG_INFO("Send salt to new user %s",start_req->username);
    // Отправляем challenge клиенту
    send_register_challenge(srv,conn, &challenge);
    return SERVER_OK;
}

// Обработка завершения регистрации
char server_handle_register_verify(server_ctx_t *srv, server_conn_t *conn,
                                  const protocol_header_t *header, const uint8_t *payload) {							  
    SERVER_LOG_INFO("Start register verify. seq_id client %d",header->seq_id);
    if (!srv || !conn || !header || !payload) {
        SERVER_LOG_WARN("Invalid args. seq_id client %d",header->seq_id);
        return SERVER_ERR_INVALID_ARG;
    }
    
    if (header->payload_size != sizeof(auth_verify_request_t)) {
        SERVER_LOG_WARN("Invalid register verify size. seq_id client %d",header->seq_id);
        send_error_response(srv,conn, "Invalid register verify size");
        return SERVER_OK;
    }
    
    auth_verify_request_t verify_req;
    
    memcpy(&verify_req, payload, sizeof(verify_req));
    

    // Проверяем, не прошло ли слишком много времени
    if (time(NULL) - conn->last_activity > 90) { //1,5 минуты таймаут
        SERVER_LOG_INFO("Registration timeout. Client %s",conn->username);
        send_register_failure(srv,conn, "Registration timeout");
        return SERVER_OK;
    }
    
    // Проверяем еще раз, не создали ли уже пользователя
    pthread_mutex_lock(&srv->users_mutex);
    server_client_info_t *user_entry = NULL;
    user_entry=server_user_find(srv,conn->username);
    if (user_entry) {
        pthread_mutex_unlock(&srv->users_mutex);
        SERVER_LOG_INFO("Couldn't create new user. User %s already exists", conn->username);
        send_register_failure(srv,conn, "User already exists");
        return SERVER_OK;
    }
    pthread_mutex_unlock(&srv->users_mutex);
    
    // Создаем нового пользователя (учителя)
    server_client_info_t *new_user = malloc(sizeof(server_client_info_t));
    if (!new_user) {
        pthread_mutex_unlock(&srv->users_mutex);
        SERVER_LOG_ERROR("Couldn't create new user. Memory error",NULL);
        return SERVER_ERR_NOMEM;
    }
    
    memset(new_user, 0, sizeof(server_client_info_t));
    
    
    // Генерируем ID
    new_user->id = generate_new_user_id(srv);
    
    strncpy(new_user->username, conn->username, sizeof(new_user->username) - 1);
    memcpy(new_user->salt, conn->auth_salt, sizeof(new_user->salt));
    memcpy(new_user->password_hash, verify_req.password_hash, SHA_LEN);
    if (conn->authenticated)new_user->role = ROLE_STUDENT;
    else new_user->role = ROLE_TEACHER;
    new_user->online = false;
    
   // Добавляем в хеш-таблицу
	client_hash_entry_t *user_entry_hash = malloc(sizeof(client_hash_entry_t));
	if (!user_entry_hash) {
		free(new_user);
		free(new_user);
		pthread_mutex_unlock(&srv->users_mutex);
		SERVER_LOG_ERROR("Couldn't add new user to hash. Memory error", NULL);
		return SERVER_ERR_NOMEM;
	}	

	// Копируем username в структуру хеш-записи
	strncpy(user_entry_hash->username, new_user->username, sizeof(user_entry_hash->username) - 1);
	user_entry_hash->username[sizeof(user_entry_hash->username) - 1] = '\0'; // null-terminated
	user_entry_hash->user = new_user;

	
	HASH_ADD_STR(srv->users_by_username, username, user_entry_hash);

   char userfile[MAX_PATH_LEN];
	int needed = snprintf(userfile, sizeof(userfile), "%s/%d.bin", 
                     srv->users_dir, new_user->id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format user file path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(userfile)) {
		SERVER_LOG_ERROR("User file path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}

    if(save_user_to_bin_file(new_user,userfile)!=SERVER_OK){
        SERVER_LOG_ERROR("Couldn't save new user",NULL);
        send_register_failure(srv,conn, "Couldn't save the user");
        return SERVER_ERR_DB;
    }
    
    if(conn->authenticated==0){
		pthread_mutex_unlock(&srv->users_mutex);
    
		// Генерируем сессионный токен
		auth_success_t success;
		generate_session_token(success.session_token, sizeof(success.session_token));
		success.expires_in = 600;  
		success.role = ROLE_TEACHER;
    
		// Обновляем соединение
		conn->authenticated = true;
		conn->user_id = new_user->id;
		conn->role = ROLE_TEACHER;
		strncpy(conn->username, new_user->username, sizeof(conn->username) - 1);
		strncpy(conn->session_token, success.session_token, sizeof(conn->session_token) - 1);
		conn->session_created_at = time(NULL);
		conn->session_expires_at = time(NULL) + success.expires_in;
		conn->last_activity = time(NULL);
    
		// Добавляем в хеш-таблицу сессий
		pthread_mutex_lock(&srv->sessions_mutex);
		session_hash_entry_t *session_entry = malloc(sizeof(session_hash_entry_t));
		if (session_entry) {
			// Копируем токен в структуру
			strncpy(session_entry->token, success.session_token, sizeof(session_entry->token) - 1);
			session_entry->token[sizeof(session_entry->token) - 1] = '\0'; // гарантируем null-terminated
    
			session_entry->conn = conn;
			session_entry->expires_at = conn->session_expires_at;
    
			// Добавляем в хеш-таблицу, используя поле token как ключ
			HASH_ADD_STR(srv->sessions, token, session_entry);
		}
		else{
			SERVER_LOG_ERROR("Coldn't create session for user %s. Memory error", conn->username);
			pthread_mutex_unlock(&srv->sessions_mutex);
			return SERVER_ERR_NOMEM;
		}
    pthread_mutex_unlock(&srv->sessions_mutex);
    // Отправляем успешный ответ
    send_register_success(srv,conn, &success);
    }
    else{
        auth_success_t success;
		success.role = ROLE_STUDENT;
		send_register_success(srv,conn, &success);
	}
    
    return SERVER_OK;
}

// Вспомогательные функции
char send_register_challenge(server_ctx_t *srv,server_conn_t *conn, const auth_challenge_t *challenge) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_REGISTER_START;
    header.flags = 0;
    header.payload_size = sizeof(*challenge);
    header.seq_id = srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)challenge);
    return SERVER_OK;
}

char send_register_success(server_ctx_t *srv,server_conn_t *conn, const auth_success_t *success) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_REGISTER_OK;
    header.flags = 0;
    header.payload_size = sizeof(*success);
    header.seq_id = srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)success);
    return SERVER_OK;
}

char send_register_failure(server_ctx_t *srv,server_conn_t *conn, const char *reason) {
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_REGISTER_FAIL;
    header.flags = 0;
    header.payload_size = strlen(reason);
    header.seq_id = srv->seq_id++;
    
    server_send_packet(srv,conn, &header, (uint8_t*)reason);
    return SERVER_OK;
}

// Функция для генерации нового уникального ID
int generate_new_user_id(server_ctx_t *srv) {
    int max_id = 1000;  // Начальное значение
    
    pthread_mutex_lock(&srv->users_mutex);
    
    client_hash_entry_t *entry, *tmp;
    
    // Проходим по всем пользователям и находим максимальный ID
    HASH_ITER(hh, srv->users_by_username, entry, tmp) {
        if (entry->user->id > max_id) {
            max_id = entry->user->id;
        }
    }
    
    pthread_mutex_unlock(&srv->users_mutex);
    
    return max_id + 1;
}

// Переводим файловый дескриптор в неблокирующий режим
static int set_nonblocking(int fd) {
    // Получаем текущие флаги дескриптора
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;

    // Добавляем флаг неблокирующего режима
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);}

// Закрываем соединение клиента и удаляем его из хеш-таблицы
static void server_conn_close_and_remove(server_ctx_t *srv, int fd) {
    if (!srv) return;

    // Блокируем доступ к таблице соединений
    pthread_mutex_lock(&srv->conns_mutex);

    // Ищем соединение по fd
    conn_hash_entry_t *e = NULL;
    HASH_FIND_INT(srv->conns_by_fd, &fd, e);

    if (e) {
        // Получаем структуру соединения
        server_conn_t *c = e->conn;

        HASH_DEL(srv->conns_by_fd, e);
        free(e);

        if (c) {
            if (srv->epoll_fd >= 0) {
                epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            }
            close(c->fd);
            pthread_mutex_destroy(&c->write_mutex);
            free(c);
        }

        // Уменьшаем счётчик подключённых клиентов
        if (srv->connected_clients > 0)
            srv->connected_clients--;
    } 

    pthread_mutex_unlock(&srv->conns_mutex);
}

// Создаёт структуру server_conn_t для нового клиента
static server_conn_t *server_conn_create(int fd,
                                        struct sockaddr_in *addr,
                                        socklen_t addr_len) {
    // Выделяем и обнуляем память под соединение
    server_conn_t *c = calloc(1, sizeof(server_conn_t));
    if (!c)
        return NULL;

    // Сохраняем файловый дескриптор
    c->fd = fd;

    // Сохраняем адрес клиента
    if (addr) c->addr = *addr;
    c->addr_len = addr_len;

    // Изначально клиент не аутентифицирован
    c->authenticated = false;
    c->role = ROLE_STUDENT;
    c->username[0] = '\0';
    c->user_id = -1;

    // Сессионные данные пустые
    c->session_token[0] = '\0';
    c->session_created_at = 0;
    c->session_expires_at = 0;

    // Фиксируем время последней активности
    c->last_activity = time(NULL);

    // Начальное состояние соединения
    c->client_state = CONN_STATE_NEW;

    // Буферы чтения/записи пустые
    c->read_buffer_len = 0;
    c->write_buffer_len = 0;

    // Мьютекс для безопасной записи в сокет
    if (pthread_mutex_init(&c->write_mutex, NULL) != 0) {
        free(c);
        return NULL;
    }
    
    return c;
}

// Добавляет соединение в hash-таблицу сервера
static char server_conns_add(server_ctx_t *srv, server_conn_t *conn) {
    if (!srv || !conn)
        return (char)SERVER_ERR_INVALID_ARG;

    // Создаём элемент hash-таблицы
    conn_hash_entry_t *e =
        (conn_hash_entry_t*)calloc(1, sizeof(conn_hash_entry_t));
    if (!e)
        return (char)SERVER_ERR_NOMEM;

    // Ключ — файловый дескриптор
    e->fd = conn->fd;
    e->conn = conn;

    // Добавляем в hash-таблицу
    HASH_ADD_INT(srv->conns_by_fd, fd, e);

    // Увеличиваем счётчик клиентов
    srv->connected_clients++;

    return (char)SERVER_OK;
}

// Ищет соединение по файловому дескриптору
static server_conn_t *server_conns_find(server_ctx_t *srv, int fd) {
    conn_hash_entry_t *e = NULL;
    HASH_FIND_INT(srv->conns_by_fd, &fd, e);
    return e ? e->conn : NULL;
}

// Читает данные из сокета в буфер соединения
static ssize_t recv_into_buffer(server_conn_t *conn) {
    if (!conn) return -1;

    // Проверка на переполнение буфера
    if (conn->read_buffer_len >= sizeof(conn->read_buffer)) {
    SERVER_LOG_ERROR("Read buffer overflow: %zu", conn->read_buffer_len);
    return -2;
}
    // Читаем данные из TCP-сокета
    ssize_t r = recv(conn->fd,
                    conn->read_buffer + conn->read_buffer_len,
                    sizeof(conn->read_buffer) - conn->read_buffer_len, 0);

    if (r > 0) {
        // Увеличиваем длину буфера
        conn->read_buffer_len += (size_t)r;

        // Обновляем время активности клиента
        conn->last_activity = time(NULL);
    }

    return r;
}

// Пытаемся разобрать одно сообщение из TCP-буфера
static int try_parse_one_message(server_conn_t *conn,
                                protocol_header_t *out_hdr,
                                uint8_t *out_payload,
                                size_t out_payload_cap,
                                size_t *out_payload_len) {
    if (!conn || !out_hdr || !out_payload || !out_payload_len)
        return -1;

    if (conn->read_buffer_len < sizeof(protocol_header_t))
        return 0;    

    protocol_header_t hdr;
    memcpy(&hdr, conn->read_buffer, sizeof(protocol_header_t));

    // Проверяем магическое число протокола
    if (hdr.magic != PROTOCOL_MAGIC)
        return -2;

    // Проверяем размер payload'а
    if ((size_t)hdr.payload_size > MAX_PAYLOAD_LEN) {
    SERVER_LOG_ERROR("Payload too large: %u", MAX_PAYLOAD_LEN);
    return -3;
}

    // Полная длина пакета
    size_t full_len = sizeof(protocol_header_t) +
                        (size_t)hdr.payload_size;

    // Пакет ещё не полностью получен
    if (conn->read_buffer_len < full_len)
        return 0;

    // Проверяем размер выходного буфера
    if ((size_t)hdr.payload_size > out_payload_cap)
        return -4;

    // Копируем заголовок и payload
    memcpy(out_hdr, &hdr, sizeof(protocol_header_t));

    if (hdr.payload_size > 0) {
        memcpy(out_payload,
            conn->read_buffer + sizeof(protocol_header_t),
            (size_t)hdr.payload_size);
    }

    *out_payload_len = (size_t)hdr.payload_size;

    // Сдвигаем оставшиеся данные в буфере
    size_t remain = conn->read_buffer_len - full_len;
    if (remain > 0) {
        memmove(conn->read_buffer,
                conn->read_buffer + full_len,
                remain);
    }

    conn->read_buffer_len = remain;

    // Сообщение успешно разобрано
    return 1;
}

// Создаёт TCP-сокет, bind listen
static char server_listen_tcp(server_ctx_t *srv) {
    if (!srv)
        return (char)SERVER_ERR_INVALID_ARG;

    // Создаём TCP-сокет
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return (char)SERVER_ERR_NET;

    // Разрешаем повторное использование адреса
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    // Заполняем адрес сервера
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(srv->port);

    // Преобразуем IP
    if (inet_pton(AF_INET, srv->bind_ip, &a.sin_addr) != 1) {
        close(fd);
        return (char)SERVER_ERR_INVALID_ARG;
    }

    // Привязываем сокет
    if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
        close(fd);
        return (char)SERVER_ERR_NET;
    }

    // Начинаем слушать соединения
    if (listen(fd, SERVER_DEFAULT_BACKLOG) < 0) {
        close(fd);
        return (char)SERVER_ERR_NET;
    }

    // Делаем сокет неблокирующим
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return (char)SERVER_ERR_NET;
    }

    // Сохраняем fd и меняем состояние сервера
    srv->listen_fd = fd;
    srv->state = SERVER_STATE_LISTENING;

    return (char)SERVER_OK;
}

// Инициализация очередей 
char server_queues_init(server_work_queues_t *q,
                        size_t high_capacity,
                        size_t normal_capacity,
                        size_t low_capacity)
{
    if (!q) return (char)SERVER_ERR_INVALID_ARG;

    memset(q, 0, sizeof(*q));

    // Мьютекс/условная переменная
    if (pthread_mutex_init(&q->mutex, NULL) != 0)
        return (char)SERVER_ERR_NOMEM;

    if (pthread_cond_init(&q->cond, NULL) != 0) {
        pthread_mutex_destroy(&q->mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    // Буферы очередей
    q->high_items   = calloc(high_capacity,   sizeof(server_work_item_t));
    q->normal_items = calloc(normal_capacity, sizeof(server_work_item_t));
    q->low_items    = calloc(low_capacity,    sizeof(server_work_item_t));

    if (!q->high_items || !q->normal_items || !q->low_items) {
        free(q->high_items);
        free(q->normal_items);
        free(q->low_items);
        pthread_cond_destroy(&q->cond);
        pthread_mutex_destroy(&q->mutex);
        return (char)SERVER_ERR_NOMEM;
    }

    q->capacity[PRIORITY_HIGH]   = high_capacity;
    q->capacity[PRIORITY_NORMAL] = normal_capacity;
    q->capacity[PRIORITY_LOW]    = low_capacity;

    return (char)SERVER_OK;
}

void server_queues_destroy(server_work_queues_t *q)
{
    if (!q) return;

    free(q->high_items);
    free(q->normal_items);
    free(q->low_items);

    q->high_items = NULL;
    q->normal_items = NULL;
    q->low_items = NULL;

    pthread_cond_destroy(&q->cond);
    pthread_mutex_destroy(&q->mutex);

    memset(q, 0, sizeof(*q));
}

// Внутренняя функция: получить массив по приоритету
static server_work_item_t *queues_get_array(server_work_queues_t *q, work_priority_t pr)
{
    if (pr == PRIORITY_HIGH) return q->high_items;
    if (pr == PRIORITY_NORMAL) return q->normal_items;
    return q->low_items;
}

// Положить элемент в конкретную очередь
char server_queues_push(server_work_queues_t *q,
                        const server_work_item_t *item,
                        work_priority_t pr)
{
    if (!q || !item) return (char)SERVER_ERR_INVALID_ARG;

    pthread_mutex_lock(&q->mutex);

    // Проверяем переполнение
    if (q->count[pr] >= q->capacity[pr]) {
        pthread_mutex_unlock(&q->mutex);
        return (char)SERVER_ERR_GENERIC; // очередь переполнена
    }

    server_work_item_t *arr = queues_get_array(q, pr);

    size_t tail = q->tail[pr];
    arr[tail] = *item; // копируем структуру целиком

    q->tail[pr] = (tail + 1) % q->capacity[pr];
    q->count[pr]++;

    // Будим воркеров
    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
    return (char)SERVER_OK;
}

static bool queues_try_pop_locked(server_work_queues_t *q,
                                work_priority_t pr,
                                server_work_item_t *out)
{
    if (q->count[pr] == 0)
        return false;

    server_work_item_t *arr = queues_get_array(q, pr);

    size_t head = q->head[pr];
    *out = arr[head];

    q->head[pr] = (head + 1) % q->capacity[pr];
    q->count[pr]--;

    return true;
}

// Достаем задачу от HIGH до LOW
char server_queues_pop(server_work_queues_t *q, server_work_item_t *out_item)
{
    if (!q || !out_item) return (char)SERVER_ERR_INVALID_ARG;

    pthread_mutex_lock(&q->mutex);

    // Ждём работы
    while (q->count[PRIORITY_HIGH] == 0 &&
            q->count[PRIORITY_NORMAL] == 0 &&
            q->count[PRIORITY_LOW] == 0)
    {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    // Приоритетный выбор
    if (queues_try_pop_locked(q, PRIORITY_HIGH, out_item) ||
        queues_try_pop_locked(q, PRIORITY_NORMAL, out_item) ||
        queues_try_pop_locked(q, PRIORITY_LOW, out_item))
    {
        pthread_mutex_unlock(&q->mutex);
        return (char)SERVER_OK;
    }

    pthread_mutex_unlock(&q->mutex);
    return (char)SERVER_ERR_GENERIC;
}

// Достать задачу конкретного приоритета)
char server_queues_pop_priority(server_work_queues_t *q,
                                work_priority_t pr,
                                server_work_item_t *out_item)
{
    if (!q || !out_item) return (char)SERVER_ERR_INVALID_ARG;

    pthread_mutex_lock(&q->mutex);

    while (q->count[pr] == 0) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    if (queues_try_pop_locked(q, pr, out_item)) {
        pthread_mutex_unlock(&q->mutex);
        return (char)SERVER_OK;
    }

    pthread_mutex_unlock(&q->mutex);
    return (char)SERVER_ERR_GENERIC;
}

bool server_queues_has_items(const server_work_queues_t *q)
{
    if (!q) return false;
    return (q->count[PRIORITY_HIGH] +
            q->count[PRIORITY_NORMAL] +
            q->count[PRIORITY_LOW]) > 0;
}

bool server_queues_has_priority_items(const server_work_queues_t *q, work_priority_t pr)
{
    if (!q) return false;
    return q->count[pr] > 0;
}

// Диспетчеризация задач
// Выбор приоритета по типу сообщения
static work_priority_t choose_priority_by_msg(msg_type_t t)
{
    // HIGH: обслуживание соединения/сессии
    if (t == MSG_PING || t == MSG_AUTH_START || t == MSG_AUTH_VERIFY || t == MSG_REGISTER_START || t == MSG_REGISTER_VERIFY) {
        return PRIORITY_HIGH;
    }

    // LOW: тяжёлые операции (проверка/компиляция решений)
    if (t == MSG_SEND_SOLUTION) {
        return PRIORITY_LOW;
    }

    // NORMAL: всё остальное
    return PRIORITY_NORMAL;
}

char server_dispatch_work(server_ctx_t *srv,
                            server_conn_t *conn,
                            const protocol_header_t *hdr,
                            const void *payload,
                            size_t payload_len)
{
    if (!srv || !conn || !hdr) return (char)SERVER_ERR_INVALID_ARG;

    server_work_item_t item;
    memset(&item, 0, sizeof(item));

    item.type = WORK_ITEM_HANDLE_PACKET;
    item.priority = choose_priority_by_msg((msg_type_t)hdr->type);
    item.conn = conn;
    item.conn_fd = conn->fd;
    item.header = *hdr;

    if (payload_len > sizeof(item.payload))
        return (char)SERVER_ERR_INVALID_ARG;

    if (payload_len > 0 && payload) {
        memcpy(item.payload, payload, payload_len);
        item.payload_len = payload_len;
    }

    // Кладём в очередь нужного приоритета
    return server_queues_push(&srv->queues, &item, item.priority);
}

// Workers
static void* server_worker_main(void *arg)
{
    server_ctx_t *srv = (server_ctx_t*)arg;
    if (!srv) return NULL;

    while (!srv->stop_flag) {
        server_work_item_t item;

        // Блокируемся, пока не появится задача
        char rc = server_queues_pop(&srv->queues, &item);
        if (rc != (char)SERVER_OK)
            continue;

        // Если сервер уже останавливается — выходим
        if (srv->stop_flag)
            break;

        // Обработка пакета
        if (item.type == WORK_ITEM_HANDLE_PACKET) {
            
            pthread_mutex_lock(&srv->conns_mutex);
            server_conn_t *conn = server_conns_find(srv, item.conn_fd);
            pthread_mutex_unlock(&srv->conns_mutex);

            if (!conn) {
                // выбрасываем задачу
                continue;
            }

            char hrc = server_handle_message(srv,
                                            conn,
                                            &item.header,
                                            item.payload);

            // Если ошибка — можно закрыть соединение
            if (hrc != (char)SERVER_OK) {
                server_conn_close_and_remove(srv, item.conn_fd);
            }
        }
    }

    return NULL;
}

char server_start_workers(server_ctx_t *srv){
    if (!srv) return (char)SERVER_ERR_INVALID_ARG;

    if (srv->worker_count == 0)
        srv->worker_count = SERVER_WORKER_THREADS_DEFAULT;

    srv->workers = calloc(srv->worker_count, sizeof(pthread_t));
    if (!srv->workers)
        return (char)SERVER_ERR_NOMEM;

    for (size_t i = 0; i < srv->worker_count; i++) {
        if (pthread_create(&srv->workers[i], NULL, server_worker_main, srv) != 0) {
            // если не смогли создать поток — просим остановку и джойним то что создали
            srv->stop_flag = 1;
            pthread_cond_broadcast(&srv->queues.cond);

            for (size_t j = 0; j < i; j++) {
                pthread_join(srv->workers[j], NULL);
            }
            free(srv->workers);
            srv->workers = NULL;
            return (char)SERVER_ERR_GENERIC;
        }
    }

    return (char)SERVER_OK;
}

void server_stop_workers(server_ctx_t *srv){
    if (!srv || !srv->workers) return;

    // Просим остановку и будим всех воркеров
    srv->stop_flag = 1;
    pthread_cond_broadcast(&srv->queues.cond);

    for (size_t i = 0; i < srv->worker_count; i++) {
        pthread_join(srv->workers[i], NULL);
    }

    free(srv->workers);
    srv->workers = NULL;
    srv->worker_count = 0;
}


// Основной цикл TCP-сервера
char server_run(server_ctx_t *srv) {
    if (!srv)
        return (char)SERVER_ERR_INVALID_ARG;

    // Если сервер ещё не слушает — запускаем listen
    if (srv->listen_fd < 0) {
        char rc = server_listen_tcp(srv);
        if (rc != (char)SERVER_OK)
            return rc;
    }

    srv->state = SERVER_STATE_RUNNING;

    // Запускаем worker-потоки, которые будут обрабатывать очереди
    char wrc = server_start_workers(srv);
    if (wrc != (char)SERVER_OK) {
        srv->state = SERVER_STATE_ERROR;
        return wrc;
    }
   
    // epoll init
    srv->epoll_fd = epoll_create1(0);
    if (srv->epoll_fd < 0) {
        srv->state = SERVER_STATE_ERROR;
        return (char)SERVER_ERR_NET;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = srv->listen_fd;

    if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev) < 0) {
        close(srv->epoll_fd);
        srv->epoll_fd = -1;
        srv->state = SERVER_STATE_ERROR;
        return (char)SERVER_ERR_NET;
    }

    struct epoll_event events[SERVER_EPOLL_MAX_EVENTS];
    // Основной цикл сервера
    while (!srv->stop_flag) {

        // Ожидаем события
        int nfds = epoll_wait(srv->epoll_fd, events, SERVER_EPOLL_MAX_EVENTS, SERVER_EPOLL_TIMEOUT_MS);
        if (srv->listen_fd < 0 && srv->stop_flag) break;

        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            srv->state = SERVER_STATE_ERROR;
            return (char)SERVER_ERR_NET;
        }

        if (nfds == 0)
            continue;

        // Новые подключения
        int listen_ready = 0;
        for (int k = 0; k < nfds; k++) {
            if (events[k].data.fd == srv->listen_fd && (events[k].events & EPOLLIN)) {
                listen_ready = 1;
                break;
            }
        }

        if (listen_ready) {
            while (1) {
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);

                int cfd = accept(srv->listen_fd,
                                (struct sockaddr*)&caddr,
                                &clen);

                if (cfd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    break;
                }

				char client_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &caddr.sin_addr, client_ip, sizeof(client_ip));
                SERVER_LOG_INFO("Client connected fd=%d", cfd);

                set_nonblocking(cfd);

                server_conn_t *conn =
                    server_conn_create(cfd, &caddr, clen);

                if (!conn) {
					SERVER_LOG_ERROR("Failed to create connection struct for fd=%d", srv->listen_fd);
                    close(cfd);
                    continue;
                }

                pthread_mutex_lock(&srv->conns_mutex);
                server_conns_add(srv, conn);
                pthread_mutex_unlock(&srv->conns_mutex);
                
                struct epoll_event cev;
                memset(&cev, 0, sizeof(cev));
                cev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                cev.data.fd = cfd;

                if (epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
                    server_conn_close_and_remove(srv, cfd);
                    continue;
                }
            }
        }

        

        // Обработка клиентских сокетов
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == srv->listen_fd)
                continue;
                
            SERVER_LOG_INFO("Processing client fd=%d", fd);

            uint32_t re = events[i].events;

            // Ошибка или закрытие
            if (re & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                server_conn_close_and_remove(srv, fd);
                continue;
            }

            // Нет данных для чтения
            if (!(re & EPOLLIN))
                continue;

            pthread_mutex_lock(&srv->conns_mutex);
            server_conn_t *conn = server_conns_find(srv, fd);
            pthread_mutex_unlock(&srv->conns_mutex);

            if (!conn) {
                close(fd);
                continue;
            }

            ssize_t r = recv_into_buffer(conn);

            if (r == 0) {
                server_conn_close_and_remove(srv, fd);
                continue;
            }

            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                server_conn_close_and_remove(srv, fd);
                continue;
            }

            protocol_header_t hdr;
            uint8_t payload[SERVER_MAX_PAYLOAD_LEN];
            size_t payload_len = 0;

            // Разбираем все сообщения из буфера
            while (1) {
                int parsed =
                    try_parse_one_message(conn, &hdr,
                                            payload,
                                            sizeof(payload),
                                            &payload_len);

                if (parsed == 0)
                    break;

                if (parsed < 0) {
                    server_conn_close_and_remove(srv, fd);
                    break;
                }


                srv->processed_requests++;

                server_update_client_lifetime(srv, conn);
                char qrc = server_dispatch_work(srv, conn, &hdr, payload, payload_len);

                if (qrc != (char)SERVER_OK) {
					SERVER_LOG_ERROR("Failed to dispatch work: %d", qrc);
                    server_conn_close_and_remove(srv, fd);
                    break;
                }
            }
        }
    }

    // Завершение работы
    srv->state = SERVER_STATE_SHUTTING_DOWN;

    // Останавливаем worker'ы
    server_stop_workers(srv);
    
    // Закрываем соединения
    pthread_mutex_lock(&srv->conns_mutex);

    conn_hash_entry_t *e, *tmp;
    HASH_ITER(hh, srv->conns_by_fd, e, tmp) {
        int fd = e->fd;
        pthread_mutex_unlock(&srv->conns_mutex);
        server_conn_close_and_remove(srv, fd);
        pthread_mutex_lock(&srv->conns_mutex);
    }

    pthread_mutex_unlock(&srv->conns_mutex);

    // Закрываем listen сокет
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }

    if (srv->epoll_fd >= 0) {
        close(srv->epoll_fd);
        srv->epoll_fd = -1;
    }

    return (char)SERVER_OK;
}

void server_update_client_lifetime(server_ctx_t *srv, server_conn_t *conn) {
    if (!srv || !conn) return;

    time(&conn->last_activity);

    // Если клиент аутентифицирован, обновляем время жизни сессии
    if (conn->authenticated) {
        conn->session_expires_at = conn->last_activity + SERVER_SESSION_TIMEOUT_SEC;
    }
}

// Запрос на остановку сервера
void server_request_stop(server_ctx_t *srv) {
    if (!srv) return;
    srv->stop_flag = 1;
}

char server_send_packet(server_ctx_t *srv, server_conn_t *conn,
                       const protocol_header_t *header, 
                       const uint8_t *payload){
    if (!srv || !conn || !header) {
        return SERVER_ERR_INVALID_ARG;
    }
    
    // Проверяем размер payload
    if (header->payload_size > SERVER_MAX_PAYLOAD_LEN) {
		SERVER_LOG_WARN("Max payload len was exceeded %d",header->payload_size);
        return SERVER_ERR_INVALID_ARG;
    }
    
    pthread_mutex_lock(&conn->write_mutex);
    
    // Полный размер пакета: заголовок + payload
    size_t total_size = sizeof(protocol_header_t) + header->payload_size;
    uint8_t buffer[sizeof(protocol_header_t) + SERVER_MAX_PAYLOAD_LEN];
    
    // Копируем заголовок
    memcpy(buffer, header, sizeof(protocol_header_t));
    
    // Копируем payload если есть
    if (header->payload_size > 0 && payload) {
        memcpy(buffer + sizeof(protocol_header_t), payload, header->payload_size);
    }
    
    // Отправляем данные
    ssize_t sent = send(conn->fd, buffer, total_size, 0);
    
    pthread_mutex_unlock(&conn->write_mutex);
    
    if (sent < 0) {
        SERVER_LOG_ERROR("send failed for user=%s", conn->username);
        return SERVER_ERR_NET;
    }
    
    if ((size_t)sent != total_size) {
        SERVER_LOG_ERROR("Incomplete send to %s", conn->username);
        return SERVER_ERR_IO;
    }
    
    SERVER_LOG_INFO("Sent packet to %s",conn->username);
    
    return SERVER_OK;
}

int main(int argc, char *argv[]) {
    server_ctx_t srv = {0};

    char pidfile_path[MAX_PATH_LEN];
    
    if (argc > 1) {
        snprintf(pidfile_path, sizeof(pidfile_path), "%s", argv[1]);
    } else {
     char base_path[MAX_PATH_LEN];
	if (getcwd(base_path, sizeof(base_path)) == NULL) {
		SERVER_LOG_ERROR("Failed to get current directory: %s", strerror(errno));
		return SERVER_ERR_GENERIC;
	}

	char pidfile_path[MAX_PATH_LEN];
	int needed = snprintf(pidfile_path, sizeof(pidfile_path), 
                     "%s/leetcoded.pid", base_path);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format PID file path",NULL);
		return SERVER_ERR_INVALID_ARG;
	} else if ((size_t)needed >= sizeof(pidfile_path)) {
		SERVER_LOG_ERROR("PID file path too long",NULL);
		return SERVER_ERR_INVALID_ARG;
	}
    }  
	
	char rc = server_daemonize(&srv, pidfile_path);
    if (rc != SERVER_OK) {
        // сюда дойдёт только если демон не создался
        fprintf(stderr, "daemonize failed: %d\n", rc);
        return 1;
    }   

    
    // Дальше выполняется уже в демоне 
	rc = server_init(&srv, SERVER_BIND_ALL_INTERFACES, CLIENT_SERVER_PORT, true); 
    if (rc != SERVER_OK) {
        SERVER_LOG_ERROR("server_init failed: %d", rc);
        return 1;
    }
    
    // Вызов обработчика сигналов
    server_setup_signals(&srv);
    
    rc=server_db_init(&srv);
    if (rc != SERVER_OK) {
        SERVER_LOG_ERROR("server_db_init failed: %d", rc);
        return 1;
    }

    SERVER_LOG_INFO("Server listening on port 12345", NULL);
    server_run(&srv);

    server_db_close(&srv);
    server_log_close();
    return 0;
}
