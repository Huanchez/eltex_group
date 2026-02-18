#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/wait.h>

#include "common.h"
#include "uthash.h"  //Заголовочный файл для хэш-таблиц
#include "sha256.h" //Заголовочный файл для хэширования пароля

typedef message_type_t msg_type_t;

#define SERVER_MAX_LOGIN_LEN                 MAX_LOGIN_LEN
#define SERVER_MAX_PASS_LEN                  MAX_PASS_LEN
#define SERVER_MAX_PROBLEM_ID_LEN            MAX_PROBLEM_ID_LEN
#define SERVER_MAX_PATH_LEN                  MAX_PATH_LEN
#define SERVER_MAX_PAYLOAD_LEN               MAX_PAYLOAD_LEN
#define SERVER_MAX_SALT_LEN                  MAX_SALT_LEN

#define SERVER_DEFAULT_BACKLOG               128
#define SERVER_MAX_CLIENTS                   1024
#define SERVER_WORKER_THREADS_DEFAULT        4
#define SERVER_SESSION_TIMEOUT_SEC           300
#define SERVER_PIDFILE_MODE                  0644
#define SERVER_DAEMON_UMASK                  027
#define SERVER_FD_FALLBACK_MAX               1024
#define CLIENT_SERVER_PORT                   12345
#define SERVER_BIND_ALL_INTERFACES           "0.0.0.0"
#define EXIT_CODE_TIMEOUT                    124
#define MAX_OUTPUT_LEN 	                     8192
#define MAX_CMD_LEN 	                     512
#define MAX_DB_PATH_LEN 	                 1024

#define SERVER_RUNTIME_DIR_DEFAULT          "runtime"
#define DB_DIR_DEFAULT                      "database"
#define PROBLEMS_DIR_DEFAULT                "problems"
#define SOLUTIONS_DIR_DEFAULT               "solutions"
#define USERS_DIR_DEFAULT                   "users"

#define SERVER_EXEC_TIME_LIMIT_MS_DEFAULT        2000
#define SERVER_EXEC_MEM_LIMIT_KB_DEFAULT         262144
#define SERVER_COMPILATION_TIMEOUT_MS_DEFAULT    5000

#define DOCKER_IMAGE "sandbox:latest"

#define SERVER_LOG_FILE "server.log" 


typedef enum {
    SERVER_STATE_INIT = 0,
    SERVER_STATE_DAEMONIZING,
    SERVER_STATE_LISTENING,
    SERVER_STATE_RUNNING,
    SERVER_STATE_SHUTTING_DOWN,
    SERVER_STATE_ERROR
} server_state_t;


typedef enum {
    SERVER_OK = 0,
    SERVER_ERR_GENERIC = -1,
    SERVER_ERR_INVALID_ARG = -2,
    SERVER_ERR_NOMEM = -3,
    SERVER_ERR_NET = -4,
    SERVER_ERR_PROTOCOL = -5,
    SERVER_ERR_AUTH = -6,
    SERVER_ERR_NOT_FOUND = -7,
    SERVER_ERR_ACCESS = -8,
    SERVER_ERR_BUSY = -9,
    SERVER_ERR_IO = -10,
    SERVER_ERR_DB = -11,
    SERVER_ERR_EXEC = -12,
    SERVER_ERR_TIMEOUT = -13
} server_err_t;


typedef enum {
    PRIORITY_HIGH = 0,    // Для соединения
    PRIORITY_NORMAL = 1,  // Для других задач
    PRIORITY_LOW = 2      // Для компиляции
} work_priority_t;

typedef struct {
    int id;
    char username[MAX_LOGIN_LEN];
    uint8_t password_hash[SHA_LEN];  // SHA-256 хэш для пароля
    uint8_t salt[SERVER_MAX_SALT_LEN]; //Соль для пароля
    user_role_t role;
    bool online;
    problem_status_t active_status;
} server_client_info_t;

typedef struct {
    int exec_time_limit_ms;
    int exec_mem_limit_kb;
    int compilation_timeout_ms;
} server_exec_limits_t;


// Структура для хранения в хэш-таблице пользователей
typedef struct client_hash_entry {
    char username[MAX_LOGIN_LEN];                       // ключ
    server_client_info_t *user;                         // значение
    UT_hash_handle hh;                                  // специальное поле для uthash
} client_hash_entry_t;


// Хэш-запись для задач (ключ: problem_id)
typedef struct problem_hash_entry{
    int problem_id;                         // ключ
    problem_info_t *problem;        // значение
    UT_hash_handle hh;
} problem_hash_entry_t;

typedef struct server_conn {
    // Сетевая часть
    int fd;                          // файловый дескриптор сокета
    struct sockaddr_in addr;         // адрес клиента
    socklen_t addr_len;              // длина адреса
    
    // Буферы для чтения/записи
    char read_buffer[sizeof(protocol_header_t) + MAX_PAYLOAD_LEN];          // буфер для чтения
    size_t read_buffer_len;          // сколько данных в буфере
    
    char write_buffer[sizeof(protocol_header_t) + MAX_PAYLOAD_LEN];         // буфер для записи 
    size_t write_buffer_len;
    
    // Аутентификация
    bool authenticated;              // авторизован ли
    user_role_t role;              // роль (STUDENT/TEACHER)
    char username[MAX_LOGIN_LEN];               // логин пользователя 
    int user_id;                     // ID пользователя из БД
    uint8_t auth_salt[MAX_SALT_LEN];
    
    // Токен сессии 
    char session_token[MAX_TOKEN_LEN];          // 64-символьный токен + '\0'
    time_t session_created_at;       // когда создана сессия
    time_t session_expires_at;       // когда истекает
    time_t last_activity;            // последняя активность
    
    // Состояние клиента
    conn_state_t client_state;
    
    // Потокобезопасность
    pthread_mutex_t write_mutex;     // мьютекс для записи в сокет
    
} server_conn_t;

// Хэш-запись для соединений (ключ: fd)
typedef struct conn_hash_entry {
    int fd;                    // ключ
    server_conn_t *conn;       // значение
    UT_hash_handle hh;
} conn_hash_entry_t;

// Хэш-запись для сессий (ключ: session_token)
typedef struct session_hash_entry {
    char token[MAX_TOKEN_LEN];            // ключ
    server_conn_t *conn;       // ссылка на соединение
    time_t expires_at;
    UT_hash_handle hh;
} session_hash_entry_t;

typedef enum {
    WORK_ITEM_NONE = 0,
    WORK_ITEM_HANDLE_PACKET,
    WORK_ITEM_EVALUATE_SOLUTION,
    WORK_ITEM_LOAD_PROBLEM,
    WORK_ITEM_UPDATE_PROBLEM
} server_work_type_t;

typedef struct {
    server_work_type_t type;
    work_priority_t priority;
    server_conn_t *conn;
    int conn_fd; 
    protocol_header_t header;
    uint8_t payload[SERVER_MAX_PAYLOAD_LEN];
    size_t payload_len;
    char problem_id[SERVER_MAX_PROBLEM_ID_LEN];
    char path[SERVER_MAX_PATH_LEN];
} server_work_item_t;

typedef struct {
    // Очереди для разных приоритетов
    server_work_item_t *high_items;    // PRIORITY_HIGH
    server_work_item_t *normal_items;  // PRIORITY_NORMAL  
    server_work_item_t *low_items;     // PRIORITY_LOW
    
    size_t capacity[3];        // ёмкость для каждой очереди
    size_t head[3];           // голова для каждой очереди
    size_t tail[3];           // хвост для каждой очереди
    size_t count[3];          // количество элементов в каждой очереди
    
    pthread_mutex_t mutex;
    pthread_cond_t cond;      // условная переменная для ожидания работы
} server_work_queues_t;

typedef struct {
    int listen_fd;
    struct sockaddr_in listen_addr;
    uint16_t port;
    char bind_ip[64];
    server_state_t state;
    bool daemon_mode;
    char pidfile_path[SERVER_MAX_PATH_LEN];
    int epoll_fd;
    bool use_epoll;
    
    // Хэш-таблицы через uthash (указатели на первые элементы)
    conn_hash_entry_t *conns_by_fd;     // fd → server_conn_t*
    session_hash_entry_t *sessions;     // token → session_hash_entry_t
    client_hash_entry_t *users_by_username;     // client_username → server_client_info_t
    problem_hash_entry_t *problem_by_id;     // problem_id → problem_info_t

    // Мьютексы для потокобезопасности
    pthread_mutex_t conns_mutex;
    pthread_mutex_t sessions_mutex;
    pthread_mutex_t users_mutex;
    pthread_mutex_t problems_mutex;
    pthread_mutex_t solutions_mutex;
    
    // Пул потоков
    pthread_t *workers;
    size_t worker_count;
    
    // Три очереди с приоритетами
    server_work_queues_t queues;
    
    uint32_t seq_id;

    // Директории
    char database_dir[SERVER_MAX_PATH_LEN];     
    char problems_dir[SERVER_MAX_PATH_LEN];     
    char solutions_dir[SERVER_MAX_PATH_LEN];    
    char users_dir[SERVER_MAX_PATH_LEN];        
    char runtime_dir[SERVER_MAX_PATH_LEN];      
    server_exec_limits_t limits;
    
    // Флаг остановки
    volatile sig_atomic_t stop_flag;
    
    // Статистика
    int connected_clients;
    int processed_requests;
    int evaluated_solutions;
} server_ctx_t;

// Инициализация/очистка
char server_init(server_ctx_t *srv,
                const char *bind_ip,
                uint16_t port,
                bool daemon_mode);
void server_cleanup(server_ctx_t *srv);

char server_daemonize(server_ctx_t *srv,
                     const char *pidfile_path);
char server_run(server_ctx_t *srv);
void server_request_stop(server_ctx_t *srv);

// Работа с сетевыми соединениями
char server_send_packet(server_ctx_t *srv, server_conn_t *conn,
                                  const protocol_header_t *header, const uint8_t *payload);
char server_receive_packet(server_ctx_t *srv,server_conn_t *conn,
                            protocol_header_t *header,
                            void *payload_buffer,
                            size_t buffer_size);
char server_validate_header(const protocol_header_t *hdr);

// Хэш-таблицы (обертки над uthash)
char server_conn_register(server_ctx_t *srv, server_conn_t *conn);
server_conn_t* server_conn_find(server_ctx_t *srv, int fd);
char server_conn_unregister(server_ctx_t *srv, int fd);

char server_session_create(server_ctx_t *srv, 
                          server_conn_t *conn,
                          const char *token);
session_hash_entry_t* server_session_find(server_ctx_t *srv, const char *token);
char server_session_validate(server_ctx_t *srv, const char *token);
char server_session_destroy(server_ctx_t *srv, const char *token);
char server_session_cleanup_expired(server_ctx_t *srv);

char server_user_add(server_ctx_t *srv, const server_client_info_t *user);
server_client_info_t* server_user_find(server_ctx_t *srv, const char* user_username);
char server_user_remove(server_ctx_t *srv, int user_id);

char server_problem_add(server_ctx_t *srv, problem_info_t *problem);
problem_info_t* server_problem_find(server_ctx_t *srv,int problem_id);
char server_problem_remove(server_ctx_t *srv,int problem_id);

// Очереди
char server_queues_init(server_work_queues_t *queues, 
                        size_t high_capacity,
                        size_t normal_capacity, 
                        size_t low_capacity);

void server_queues_destroy(server_work_queues_t *queues);

char server_queues_push(server_work_queues_t *queues, 
                        const server_work_item_t *item,
                        work_priority_t priority);

char server_queues_pop(server_work_queues_t *queues, 
                      server_work_item_t *out_item);

char server_queues_pop_priority(server_work_queues_t *queues,
                                work_priority_t priority,
                                server_work_item_t *out_item);

bool server_queues_has_items(const server_work_queues_t *queues);

bool server_queues_has_priority_items(const server_work_queues_t *queues, 
                                        work_priority_t priority);

// Диспетчеризация задач
char server_dispatch_work(server_ctx_t *srv,
                            server_conn_t *conn,
                            const protocol_header_t *hdr,
                            const void *payload,
                            size_t payload_len);

// Обработчики сообщений
char server_handle_message(server_ctx_t *srv,
                            server_conn_t *conn,
                            const protocol_header_t *hdr,
                            const uint8_t *payload);
char send_auth_challenge(server_ctx_t *srv,server_conn_t *conn, const auth_challenge_t *challenge);

char send_auth_success(server_ctx_t *srv,server_conn_t *conn, const auth_success_t *success);

char send_auth_failure(server_ctx_t *srv,server_conn_t *conn, const char *reason);

char server_handle_packet(server_ctx_t *srv, server_conn_t *conn, //Смотрим какое msg туда и отправляем
                         const protocol_header_t *header, const uint8_t *payload);

char server_handle_auth_verify(server_ctx_t *srv, server_conn_t *conn,
                              const protocol_header_t *header, const uint8_t *payload);
                            
char server_handle_auth_start(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload);   
                            
char server_handle_problem_create(server_ctx_t *srv, server_conn_t *conn,
                                  const protocol_header_t *header, const uint8_t *payload);

char server_handle_problem_update(server_ctx_t *srv, server_conn_t *conn,
                                  const protocol_header_t *header, const uint8_t *payload);

char server_handle_get_solution_results_list(server_ctx_t *srv, server_conn_t *conn,
                                             const protocol_header_t *header, const uint8_t *payload);

char server_handle_get_solution_result(server_ctx_t *srv, server_conn_t *conn,
                                       const protocol_header_t *header, const uint8_t *payload);


char server_handle_get_problem_info(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload);

char server_handle_get_problem_list(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload);
                                                            
char server_handle_send_solution(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload);
                            
char server_handle_get_student_list(server_ctx_t *srv,
                                   server_conn_t *conn);
char server_handle_get_student_problems(server_ctx_t *srv,
                                    server_conn_t *conn,
                                    const void *payload,
                                    size_t payload_len);
                                    
char server_handle_get_student_solution(server_ctx_t *srv, server_conn_t *conn, 
                             const protocol_header_t *header, const uint8_t *payload);
                            
char server_handle_update_problem_status(server_ctx_t *srv,
                       server_conn_t *conn,const protocol_header_t *header, const uint8_t *payload);
                       
char server_handle_load_new_problem(server_ctx_t *srv,
                                server_conn_t *conn,
                                const void *payload,
                                size_t payload_len);
char server_handle_update_problem(server_ctx_t *srv,
                                server_conn_t *conn,
                                const void *payload,
                                size_t payload_len);
char server_handle_ping(server_ctx_t *srv,
                       server_conn_t *conn,const protocol_header_t *header, const uint8_t *payload);

// Worker потоки
void *server_worker_thread(void *arg);
char server_start_workers(server_ctx_t *srv);
void server_stop_workers(server_ctx_t *srv);

// Проверка решений
char server_store_solution_file(server_ctx_t *srv,
                                const char *student_login,
                                const char *problem_id,
                                const void *file_data,
                                size_t file_size,
                                char *out_path,
                                size_t out_path_size);

char server_evaluate_solution(server_ctx_t *srv,
                             server_conn_t *conn,
                             const char *student_login,
                             const char *problem_id,
                             const void *file_data,
                             size_t file_size,
                             common_solution_result_t *out_result);

// База данных
char server_db_init(server_ctx_t *srv);
void server_db_close(server_ctx_t *srv);
char server_db_get_problem_list(const char *problems_dir, //Загрузка всех задач
                            problem_info_t **out_problems,
                            size_t *out_count);
char server_db_get_problem_info(server_ctx_t *srv, //ПЕРЕДЕЛАЕТСЯ НА ФУНКЦИЮ ДЛЯ ХЭША!!!!
                            const char *problem_id,
                            char *out_text,
                            size_t out_text_size);
                            
char server_db_save_problem(//Сохранить задачу! Одну!!!
                            problem_info_t *out_problem);

char server_db_save_solution_result(server_ctx_t *srv,
                                   const char *student_login,
                                   const char *problem_id,
                                   const common_solution_result_t *result);

char server_db_set_solution_status(server_ctx_t *srv, //Изменить только статус выпонения 
                                const char *student_login,
                                const char *problem_id,
                                problem_status_t status);

char server_db_get_student_solution( //Загрузить конкертное решение
                                   const char *student_login,
                                   const char *problem_id,
                                   char **out_solution_code);

char server_db_get_users_list(const char *users_dir, //Загрузка пользователей
                               server_client_info_t **out_clients,
                               size_t *out_count);

static char load_problem_from_bin_file(const char *filename, problem_info_t *problem);

char save_problem_to_bin_file(const problem_info_t *problem, const char *filename);

static char load_user_from_bin_file(const char *filename, server_client_info_t *user);

char save_user_to_bin_file(const server_client_info_t *user, const char *filename);

int save_solution_to_temp_file(const char *code, const char *filename);

void free_problem(problem_info_t *problem);

//Хэш-паролей
// Генерация 32-байтной соли
void generate_salt(uint8_t salt[SERVER_MAX_SALT_LEN]);

int server_verify_proof(const uint8_t proof[SHA_LEN],
                        const uint8_t hashA_from_db[SHA_LEN]);


void generate_session_token(char *token, size_t size);

char server_handle_register_start(server_ctx_t *srv, server_conn_t *conn, 
                                    const protocol_header_t *header, const uint8_t *payload);

char server_handle_register_verify(server_ctx_t *srv, server_conn_t *conn,
                                    const protocol_header_t *header, const uint8_t *payload);

char send_register_challenge(server_ctx_t *srv,server_conn_t *conn, const auth_challenge_t *challenge);

char send_register_success(server_ctx_t *srv,server_conn_t *conn, const auth_success_t *success);

char send_register_failure(server_ctx_t *srv,server_conn_t *conn, const char *reason);                      

int generate_new_user_id(server_ctx_t *srv);

char server_problem_replace(server_ctx_t *srv, const problem_info_t *src, problem_info_t **old_problem_out);

char send_error_response(server_ctx_t *srv,server_conn_t *conn, const char *reason);

char save_result(server_ctx_t *srv, server_conn_t *conn,
                         common_solution_result_t *solution,
                         const char *user_dir, int problem_id,
                         int has_previous_solution,
                         common_solution_result_t *prev_solution,
                         int should_keep_previous);
                         
char* normalize_string(const char* str);

static void server_signal_handler(int sig);

void free_connection(server_conn_t *conn);

static void server_zero_queues_state(server_work_queues_t *q);

static void server_free_queues_buffers(server_work_queues_t *q);

static int write_text_file(const char *path, const char *data, size_t len);

static void normalize_output_inplace(char *s);

static int server_write_file(const char *path, const void *data, size_t len);

static int server_read_file(const char *path, void *buf, size_t cap, size_t *out_len);

static char *str_dup_range(const char *start, const char *end);

static int server_generate_problem_id(server_ctx_t *srv);

int copy_file(const char *src, const char *dst);

void extract_compile_error(const char *docker_output, char *error_msg, size_t max_len);

char* normalize_string(const char* str);

void cleanup_temp_dir(const char *temp_dir, const char *image_name);

int compare_with_previous(common_solution_result_t *new_solution, 
                          int has_previous_solution, 
                          common_solution_result_t *prev_solution);
                          
static int set_nonblocking(int fd);

static void server_conn_close_and_remove(server_ctx_t *srv, int fd);

static server_conn_t *server_conn_create(int fd,
                                         struct sockaddr_in *addr,
                                         socklen_t addr_len);                              

static ssize_t recv_into_buffer(server_conn_t *conn);

static int try_parse_one_message(server_conn_t *conn,
                                 protocol_header_t *out_hdr,
                                 uint8_t *out_payload,
                                 size_t out_payload_cap,
                                 size_t *out_payload_len);
                                 
static char server_listen_tcp(server_ctx_t *srv);

static server_work_item_t *queues_get_array(server_work_queues_t *q, work_priority_t pr);

char server_queues_push(server_work_queues_t *q,
                        const server_work_item_t *item,
                        work_priority_t pr);
                        

static bool queues_try_pop_locked(server_work_queues_t *q,
                                 work_priority_t pr,
                                 server_work_item_t *out);
                                 
char server_queues_pop(server_work_queues_t *q, server_work_item_t *out_item);

char server_queues_pop_priority(server_work_queues_t *q,
                               work_priority_t pr,
                               server_work_item_t *out_item);
                               
bool server_queues_has_items(const server_work_queues_t *q);

bool server_queues_has_priority_items(const server_work_queues_t *q, work_priority_t pr);

static work_priority_t choose_priority_by_msg(msg_type_t t);

static void* server_worker_main(void *arg);               

void server_request_stop(server_ctx_t *srv);      

static int safe_path_copy(char *dest, size_t dest_size, 
                          const char *base, const char *suffix);

//BD
problem_status_t get_problem_status_for_user(server_ctx_t *srv, 
                                            const char *username, 
                                            int problem_id);         
                                            
int save_solution_to_temp_file(const char *code, const char *filename);

char load_solution_from_file(const char *filename, common_solution_result_t *solution);

char save_user_to_bin_file(const server_client_info_t *user, const char *filename);

char load_solution_with_metrics(const char *filename, 
                               common_solution_result_t *solution,
                               int *exec_time_ms,
                               int *memory_used_kb);
                               
char save_solution_to_file(const common_solution_result_t *solution, const char *filename);                                                                                                                                                                      
                  
void server_update_client_lifetime(server_ctx_t *srv, server_conn_t *conn);

// Логирование
// void server_log_info(const char *fmt, ...);
// void server_log_warn(const char *fmt, ...);
// void server_log_error(const char *fmt, ...);
typedef enum {
    SERVER_LOG_LEVEL_INFO,
    SERVER_LOG_LEVEL_WARN,
    SERVER_LOG_LEVEL_ERROR
} server_log_level_t;

char server_log_init();
void server_log_msg(server_log_level_t level, const char *fmt, ...);
void server_log_close();


#define SERVER_LOG_INFO(x, y) server_log_msg(SERVER_LOG_LEVEL_INFO, x, y)
#define SERVER_LOG_WARN(x, y) server_log_msg(SERVER_LOG_LEVEL_WARN, x, y)
#define SERVER_LOG_ERROR(x, y) server_log_msg(SERVER_LOG_LEVEL_ERROR, x, y)

const char *server_err_to_str(int err);

#endif 
