#include "source/headers/client.h"

char client_init(client_ctx_t *ctx, const char *server_ip, uint16_t server_port)
{
    if (!ctx || !server_ip || server_port == 0) {
        return CLIENT_ERR_INVALID_ARGS;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->sockfd = -1;

    ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->sockfd < 0) {
        perror("socket");
        return CLIENT_ERR_SOCKET_CREATE;
    }

    ctx->server_addr.sin_family = AF_INET;
    ctx->server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &ctx->server_addr.sin_addr) != 1) {
        perror("inet_pton");
        close(ctx->sockfd);
        return CLIENT_ERR_INVALID_IP;
    }
    
	if (connect(ctx->sockfd, 
                (struct sockaddr*)&ctx->server_addr, 
                sizeof(ctx->server_addr)) < 0) {
        perror("connect");
        close(ctx->sockfd);
        return CLIENT_ERR_CONNECT;  
    }

    ctx->server_addr_len = sizeof(ctx->server_addr);

    if (pthread_mutex_init(&ctx->socket_mutex, NULL) != 0) {
        perror("pthread_mutex_init");
        close(ctx->sockfd);
        return CLIENT_ERR_MUTEX_INIT;
    }

    if (mkdir(CLIENT_WORK_DIRECTORY, WORKDIR_MODE) != 0) {
        if (errno != EEXIST) {
            perror("mkdir CLIENT_WORK_DIRECTORY");
            pthread_mutex_destroy(&ctx->socket_mutex);
            close(ctx->sockfd);
            return CLIENT_ERR_WORKDIR_CREATE;
        }
    }

    ctx->connected = true;
    ctx->state = CONN_STATE_NEW;
    ctx->seq_id = 1;

    strncpy(ctx->config.server_ip, server_ip,
            sizeof(ctx->config.server_ip) - 1);
    ctx->config.server_port = server_port;

    ctx->session.logged_in = false;
    ctx->session.session_token[0] = '\0';
    ctx->session.session_expires = 0;

    ctx->problems_cache = NULL;
    ctx->problems_count = 0;

    return CLIENT_OK;
}

void client_cleanup(client_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
    if (ctx->timer_pid > 0) {
        kill(ctx->timer_pid, SIGTERM);
        ctx->timer_pid = -1;
    }

    pthread_mutex_destroy(&ctx->socket_mutex);

    if (ctx->problems_cache) {
        free(ctx->problems_cache);
        ctx->problems_cache = NULL;
        ctx->problems_count = 0;
    }

    // remove_directory_recursive(CLIENT_WORK_DIRECTORY);

    ctx->connected = false;
    ctx->state = CONN_STATE_CLOSING;
    ctx->seq_id = 0;

    memset(&ctx->session, 0, sizeof(ctx->session));
    memset(&ctx->config, 0, sizeof(ctx->config));
}

// USER INTERACTION FUNCTIONS 
// Auth or registration menu
void client_greeting(client_ctx_t *ctx) {
    if (!ctx) return;

    char choice[ANSWER_CHOICE_ACTION];

    while (1) {
        printf("\nВыберите действие:\n1) Авторизация\n2) Регистрация\n3) Выход\nВыбор: ");
        if (!fgets(choice, sizeof(choice), stdin))
            return;
        strip_newline(choice);

        if (strcmp(choice, "1") == 0) {
            char login[MAX_LOGIN_LEN];
            char password[MAX_PASS_LEN];

            printf("Логин: ");
            if (!fgets(login, sizeof(login), stdin))
                return;
            strip_newline(login);

            printf("Пароль: ");
            if (!fgets(password, sizeof(password), stdin))
                return;
            strip_newline(password);

            char status = client_auth(ctx, login, password);
            if (status == CLIENT_OK) {
                printf("Вход выполнен успешно.\n");
            } else if (status == CLIENT_ERR_AUTH_FAILED) {
                printf("Ошибка входа: неверный логин или пароль.\n");
                continue;
            } else {
                printf("Ошибка входа (код %d).\n", status);
                continue;
            }
            return;
        } else if (strcmp(choice, "2") == 0) {
            client_register_user(ctx);
            return;
        } else if (strcmp(choice, "3") == 0) {
            printf("Выход из программы.\n");
            exit(0);
        } else {
            printf("Неверный выбор. Повторите.\n");
        }
    }
}

// Student menu
void client_student_menu(client_ctx_t *ctx) {
    if (!ctx) return;

    char choice[ANSWER_CHOICE_ACTION];

    while (1) {
        printf("\n=== МЕНЮ СТУДЕНТА ===\n");
        printf("1) Показать задачи\n");
        printf("2) Показать результаты проверок\n");
        printf("3) Выход\n");
        printf("Выбор: ");

        if (!fgets(choice, sizeof(choice), stdin)) return;
        strip_newline(choice);

        if (strcmp(choice, "1") == 0) {
            client_print_problems(ctx);
        } else if (strcmp(choice, "2") == 0) {
            client_student_solutions_list(ctx);
        } else if (strcmp(choice, "3") == 0) {
            exit(0);
        } else {
            printf("Неверный выбор. Повторите.\n");
        }
    }
}



// Print problems name
void client_print_problems(client_ctx_t *ctx) {
    if (!ctx) return;

    common_problem_t *problems = NULL;
    size_t problem_count = 0;

    char status = client_request_problem_list(ctx, &problems, &problem_count);
    if (status != CLIENT_OK) {
        printf("Ошибка при получении списка задач (код %d).\n", status);
        return;
    }

    if (problem_count == 0) {
        printf("Нет доступных задач.\n");
        if (problems) free(problems);
        return;
    }

    printf("\nДоступные задачи:\n");
    for (size_t i = 0; i < problem_count; i++) {
        printf("%zu) %s\n", i + 1, problems[i].title);
    }

    char choice[4];
    while (1) {
        printf("\nВыберите номер задачи (1-%zu): ", problem_count);
        if (!fgets(choice, sizeof(choice), stdin)) {
            break;
        }
        strip_newline(choice);

        char *endptr;
        size_t selected = strtoul(choice, &endptr, 10);

        if (*endptr != '\0' || selected < 1 || selected > problem_count) {
            printf("Неверный выбор. Повторите.\n");
            continue;
        }

        selected--; // в индекс массива

        if (ctx->session.role == ROLE_TEACHER) {
            client_edit_problem(ctx, 0, &problems[selected]);
        } else {
            client_solve_problem(ctx, &problems[selected], 0);
        }

        if (problems) free(problems);
        return;
    }

    if (problems) free(problems);
}

// Student solving problem
void client_solve_problem(client_ctx_t *ctx, const common_problem_t *problem, const char solution_exists) {
    if (!ctx || !problem) return;
    
    // printf("DEBUG: Статус задачи: %d, solution_exists: %d\n", problem->status, solution_exists);

    char problem_id_str[MAX_PROBLEM_ID_LEN];
    snprintf(problem_id_str, sizeof(problem_id_str), "%d", problem->problem_id);

    // Получаем заголовок задачи
    char *header_buffer = malloc(MAX_INPUT);
    if (!header_buffer) {
        perror("malloc header_buffer");
        return;
    }

    char status = client_request_problem_header(ctx, problem->problem_id,
                                                header_buffer, MAX_INPUT);
    if (status != CLIENT_OK) {
        printf("Ошибка при получении заголовка задачи (код %d).\n", status);
        free(header_buffer);
        return;
    }

   // Получаем решение, если оно есть
    char *solution_code = NULL;
    common_solution_result_t solution_result = {0}; 
    
    if (solution_exists) {
        solution_code = malloc(MAX_INPUT);
        if (!solution_code) {
            perror("malloc solution_code");
            free(header_buffer);
            return;
        }
        
        // Получаем КОД решения
        status = client_request_student_solution(ctx, ctx->session.username,
                                                 problem->problem_id, solution_code, MAX_INPUT);
        if (status != CLIENT_OK) {
            printf("Ошибка при получении решения (код %d).\n", status);
            free(header_buffer);
            free(solution_code);
            return;
        }
    }

    // Создаем директорию для задачи
    char problem_dir[CLIENT_MAX_PATH_LEN];
    snprintf(problem_dir, sizeof(problem_dir), "%s/%s", CLIENT_WORK_DIRECTORY, problem_id_str);

    if (mkdir(problem_dir, TASKDIR_MODE) != 0) {
        if (errno != EEXIST) {
            perror("mkdir problem_dir");
            free(header_buffer);
            if (solution_code) free(solution_code);
            return;
        }
    }

    // Создаем/перезаписываем файл
    size_t problem_dir_len = strlen(problem_dir);
    size_t required_len = problem_dir_len + strlen("/problem.c") + 1; // +1 для нуль-терминатора
    
    char file_path[CLIENT_MAX_PATH_LEN];
	strncpy(file_path, problem_dir, sizeof(file_path) - 1);
	file_path[sizeof(file_path) - 1] = '\0';
	strncat(file_path, "/problem.c", sizeof(file_path) - strlen(file_path) - 1);
    // printf("DEBUG: Путь к файлу: %s\n", file_path);
    
    FILE *fp = fopen(file_path, "w");
    if (!fp) {
        perror("fopen file_path");
        free(header_buffer);
        if (solution_code) free(solution_code);
        return;
    }
    
    // Если есть решение, записываем его, иначе - заголовок задачи
    const char *content_to_write = solution_code ? solution_code : header_buffer;
    size_t content_len = strlen(content_to_write);
    
    // printf("DEBUG: Записываем в файл: %s\n", solution_code ? "РЕШЕНИЕ" : "ЗАГОЛОВОК");
    // printf("DEBUG: Длина содержимого: %zu байт\n", content_len);
    
    size_t written = fwrite(content_to_write, 1, content_len, fp);
    if (written != content_len) {
        printf("Ошибка записи в файл: записано %zu из %zu байт\n", written, content_len);
        perror("fwrite");
    }
    
    fflush(fp);  // Принудительно сбрасываем буфер
    fclose(fp);
    
    // Проверяем, что файл записался
    FILE *check_fp = fopen(file_path, "r");
    if (check_fp) {
        fseek(check_fp, 0, SEEK_END);
        long file_size = ftell(check_fp);
        fseek(check_fp, 0, SEEK_SET);
        // printf("DEBUG: Размер файла на диске: %ld байт\n", file_size);
        fclose(check_fp);
    }

    // Очистка памяти
    free(header_buffer);
    if (solution_code) free(solution_code);

    printf("\n=== Задача: %s ===\n", problem->title);
    printf("%s\n", problem->description);

    char choice[ANSWER_CHOICE_ACTION];
    while (1) {
        printf("\nВыберите действие:\n");
        printf("1) Открыть редактор\n");
        printf("2) Отправить решение\n");
        printf("3) Отмена\n");
        printf("Выбор: ");

        if (!fgets(choice, sizeof(choice), stdin)) {
            return;
        }
        strip_newline(choice);

        if (strcmp(choice, "1") == 0) {
            // printf("DEBUG: Открываем редактор для файла: %s\n", file_path);
            open_external_editor(file_path);
            
            // После закрытия редактора проверим содержимое файла
            FILE *after_edit = fopen(file_path, "r");
            if (after_edit) {
                char buf[256];
                // printf("DEBUG: Содержимое файла после редактирования (первые 256 байт):\n");
                size_t read = fread(buf, 1, sizeof(buf) - 1, after_edit);
                buf[read] = '\0';
                printf("%s\n", buf);
                fclose(after_edit);
            }
        } else if (strcmp(choice, "2") == 0) {
            // printf("DEBUG: Отправляем файл: %s\n", file_path);
            
            // Читаем содержимое файла перед отправкой
            FILE *before_send = fopen(file_path, "r");
            if (before_send) {
                char file_content[4096];
                size_t read = fread(file_content, 1, sizeof(file_content) - 1, before_send);
                file_content[read] = '\0';
                // printf("DEBUG: Содержимое файла перед отправкой (%zu байт):\n%.200s\n", 
                    //    read, file_content);
                fclose(before_send);
            }
            
            status = client_send_solution_file(ctx, problem->problem_id, file_path);
            
            if (status == CLIENT_OK) {
                printf("Решение успешно отправлено.\n");
            } else {
                printf("Ошибка при отправке решения (код %d).\n", status);
            }
            return;
        } else if (strcmp(choice, "3") == 0){
            printf("Возврат в меню.\n");
            client_student_menu(ctx);
            return;
        } else {
            printf("Неверный выбор.\n");
        }
    }
}


void client_student_solutions_list(client_ctx_t *ctx) {
    if (!ctx) return;

    printf("\n=== МОИ РЕШЕНИЯ ===\n");
    
    // Запрашиваем список задач с решениями
    common_problem_t *solutions = NULL;
    size_t solution_count = 0;
    
    printf("Загрузка списка решений...\n");
    char status = client_request_student_problems(ctx, NULL, &solutions, &solution_count);
    
    if (status != CLIENT_OK) {
        printf("Ошибка получения списка решений (код %d)\n", status);
        return;
    }
    
    if (solution_count == 0) {
        printf("У вас нет отправленных решений.\n");
        if (solutions) free(solutions);
        return;
    }
    
    printf("\nНайдено решений: %zu\n", solution_count);
    
    // Выводим список решений - ИСПРАВЛЕНО форматирование
    for (size_t i = 0; i < solution_count; i++) {
        printf("%zu. Задача %d: %s [Статус: %s]\n",  // Убрали лишний printf
               i + 1, 
               solutions[i].problem_id,
               solutions[i].title,
               problem_status_to_string(solutions[i].status));
    }
    
    // Выбор решения для просмотра
    char choice_str[SCORE_CHOICE];
    while (1) {
        printf("\nВведите номер решения для просмотра (0 для выхода): ");
        if (!fgets(choice_str, sizeof(choice_str), stdin)) break;
        strip_newline(choice_str);
        
        int choice = atoi(choice_str);
        
        if (choice == 0) {
            break;
        }
        
        if (choice < 1 || choice > (int)solution_count) {
            printf("Неверный выбор. Введите число от 1 до %zu.\n", solution_count);
            continue;
        }
        
        int problem_id = solutions[choice - 1].problem_id;
        
        // Запрашиваем полную информацию о решении
        printf("\nЗагрузка решения задачи %d...\n", problem_id);
        
        common_solution_result_t result;
        status = client_get_solution_result(ctx, problem_id, &result);
        
        if (status == CLIENT_OK) {
            client_show_solution_result(&solutions[choice - 1], &result);
            
            printf("\nХотите приступить к решению? (y/n): ");
            char resp[ANSWER_CHOICE_ACTION];
            if (fgets(resp, sizeof(resp), stdin)) {
                strip_newline(resp);
                if (resp[0] == 'y' || resp[0] == 'Y') {
                    // Находим задачу для повторного решения
                    common_problem_t problem;
                    memset(&problem, 0, sizeof(problem));
                    problem.problem_id = problem_id;
                    strncpy(problem.title, solutions[choice - 1].title, 
                            sizeof(problem.title) - 1);
                    problem.time_limit_ms = solutions[choice - 1].time_limit_ms;
                    problem.memory_limit_kb = solutions[choice - 1].memory_limit_kb;
                        
                    client_solve_problem(ctx, &problem, 1); 
                }
            }
            
        } else {
            printf("Ошибка загрузки решения (код %d)\n", status);
        }
        
        break; // После просмотра одного решения выходим
    }
    
    if (solutions) free(solutions);
}

// Отображает результат решения, полученный с сервера
char client_show_solution_result(const common_problem_t *problem, const common_solution_result_t *result) {
    printf("\n========== РЕЗУЛЬТАТ РЕШЕНИЯ ==========\n");
    printf("Задача: %s (ID: %d)\n", problem->title, problem->problem_id);
    printf("\n");

    switch (result->status) {
        case PROBLEM_STATUS_COMPILATION_ERROR:
            printf("ОШИБКА КОМПИЛЯЦИИ\n");
            printf("Сообщение: %s\n", result->error_message);
            break;

        case PROBLEM_STATUS_RUNTIME_ERROR:
            printf("ОШИБКА ВРЕМЕНИ ВЫПОЛНЕНИЯ\n");
            printf("Сообщение: %s\n", result->error_message);
            break;

        case PROBLEM_STATUS_OUT_OF_TIME:
            printf("ПРЕВЫШЕН ЛИМИТ ВРЕМЕНИ\n");
            if (result->error_message[0] != '\0') {
                printf("Дополнительно: %s\n", result->error_message);
            }
            break;

        case PROBLEM_STATUS_OUT_OF_MEMORY:
            if (result->error_message[0] != '\0') {
                printf("Дополнительно: %s\n", result->error_message);
            }
            break;

        case PROBLEM_STATUS_WRONG:
            printf("НЕПРАВИЛЬНЫЙ ОТВЕТ\n");
            printf("Тесты: %d пройдено\n", result->auto_score);
            if (result->error_message[0] != '\0') {
                printf("Дополнительно: %s\n", result->error_message);
            }
            break;
        case PROBLEM_STATUS_COMPLETED:
            printf("УСПЕШНО!\n");
            printf("Все тесты пройдены!\n");
            break;
        case PROBLEM_STATUS_REVIEW:
            printf("ПРЕПОДАВАТЕЛЬ ОСТАВИЛ КОММЕНТАРИЙ\n");
            if (result->error_message[0] != '\0') {
                printf("Комментарий преподавателя: %s\n", result->teacher_comment);
            }
            break;
        case PROBLEM_STATUS_ACCEPTED:
            printf("РАБОТА ПРИНЯТА ПРЕПОДАВАТЕЛЕМ\n");
            break;
        default:
            printf("НЕИЗВЕСТНЫЙ СТАТУС: %d\n", result->status);
            if (result->error_message[0] != '\0') {
                printf("Сообщение: %s\n", result->error_message);
            }
            break;
    }

    printf("\n========================================\n");
    return result->status;
}

// Показывает решение с подробной информацией
void client_show_full_solution(const common_problem_t *problem, 
                               const common_solution_result_t *solution,
                               int is_teacher_view) {
    
    printf("\n========================================================================\n");
    printf("ЗАДАЧА: %s (ID: %d)\n", problem->title, problem->problem_id);
    printf("========================================================================\n");
    
    // 1. ОПИСАНИЕ ЗАДАЧИ
    printf("\nОПИСАНИЕ ЗАДАЧИ:\n");
    printf("  Ограничение по времени: %d мс\n", problem->time_limit_ms);
    printf("  Ограничение по памяти: %d КБ\n", problem->memory_limit_kb);
    
    // 2. СТАТУС РЕШЕНИЯ
    printf("\nСТАТУС РЕШЕНИЯ:\n");
    printf("  Статус: %s\n", problem_status_to_string(solution->status));
    printf("  Автоматическая оценка: %d/100\n", solution->auto_score);
    if (solution->final_score > 0) {
        printf("  Финальная оценка преподавателя: %d/100\n", solution->final_score);
    }
    
    // 3. КОММЕНТАРИИ ПРЕПОДАВАТЕЛЯ
    if (solution->teacher_comment[0] != '\0') {
        printf("\nКОММЕНТАРИЙ ПРЕПОДАВАТЕЛЯ:\n");
        printf("  %s\n", solution->teacher_comment);
    }
    
    // 4. ОШИБКИ (если есть)
    if (solution->error_message[0] != '\0') {
        printf("\nОШИБКА:\n");
        printf("  %s\n", solution->error_message);
    }
    
    // 6. КОД РЕШЕНИЯ
    printf("\nКОД РЕШЕНИЯ:\n");
    printf("========================================================================\n");
    
    if (strlen(solution->code) > 0) {
        // Сохраняем код во временный файл
        char temp_file[256];
        snprintf(temp_file, sizeof(temp_file), "/tmp/solution_%d.c", problem->problem_id);
        
        FILE *f = fopen(temp_file, "w");
        if (f) {
            fprintf(f, "// Задача: %s\n", problem->title);
            fprintf(f, "// Автор: %s\n", solution->username);
            fprintf(f, "// Статус: %s\n", problem_status_to_string(solution->status));
            if (solution->teacher_comment[0] != '\0') {
                fprintf(f, "// Комментарий преподавателя: %s\n", solution->teacher_comment);
            }
            fprintf(f, "\n%s\n", solution->code);
            fclose(f);
            
            // Показываем первые 20 строк кода в консоли
            printf("Первые 20 строк кода:\n");
            printf("------------------------------------------------------------------------\n");
            
            FILE *code_fp = fopen(temp_file, "r");
            if (code_fp) {
                char line[256];
                int line_count = 0;
                while (fgets(line, sizeof(line), code_fp) && line_count < 20) {
                    printf("%s", line);
                    line_count++;
                }
                fclose(code_fp);
                
                if (line_count >= 20) {
                    printf("... (код продолжается)\n");
                }
            }
            printf("------------------------------------------------------------------------\n");
            
            // Предлагаем открыть в редакторе
            printf("\n");
            if (is_teacher_view) {
                printf("1. Открыть код в редакторе\n");
                printf("2. Вернуться к проверке\n");
                printf("Выбор: ");
                
                char choice[ANSWER_CHOICE_ACTION];
                if (fgets(choice, sizeof(choice), stdin)) {
                    strip_newline(choice);
                    if (choice[0] == '1') {
                        open_external_editor(temp_file);
                    }
                }
            } else {
                // Для студента
                printf("Хотите открыть код в редакторе? (y/n): ");
                char answer[ANSWER_CHOICE_ACTION];
                if (fgets(answer, sizeof(answer), stdin)) {
                    strip_newline(answer);
                    if (answer[0] == 'y' || answer[0] == 'Y') {
                        open_external_editor(temp_file);
                    }
                }
            }
            
            // Удаляем временный файл
            unlink(temp_file);
        }
    } else {
        printf("  Код решения отсутствует\n");
    }
    
    printf("\n========================================================================\n");
}

const char* problem_status_to_string(problem_status_t status) {
    switch (status) {
        case PROBLEM_STATUS_NEW: return "Новая";
        case PROBLEM_STATUS_IN_PROGRESS: return "В процессе";
        case PROBLEM_STATUS_SENT: return "Отправлена";
        case PROBLEM_STATUS_COMPILATION_ERROR: return "Ошибка компиляции";
        case PROBLEM_STATUS_RUNTIME_ERROR: return "Ошибка выполнения";
        case PROBLEM_STATUS_OUT_OF_TIME: return "Превышено время";
        case PROBLEM_STATUS_OUT_OF_MEMORY: return "Превышена память";
        case PROBLEM_STATUS_WRONG: return "Неверный ответ";
        case PROBLEM_STATUS_ACCEPTED: return "Принято";
        case PROBLEM_STATUS_REVIEW: return "Отправлен на доработку";
        case PROBLEM_STATUS_COMPLETED: return "Завершена";
        default: return "Неизвестно";
    }
}

// Функция для ПРЕПОДАВАТЕЛЯ - просмотр решений выбранного студента
void client_teacher_view_student_solutions(client_ctx_t *ctx, const char *student_login) {
    if (!ctx || !student_login) {
        printf("Ошибка: неверные параметры\n");
        return;
    }
    
    printf("\n========================================================================\n");
    printf("ПРОВЕРКА РЕШЕНИЙ СТУДЕНТА: %s\n", student_login);
    printf("========================================================================\n");
    
    // Запрашиваем список задач студента
    common_problem_t *problems = NULL;
    size_t problem_count = 0;
    
    printf("Загрузка списка решений студента...\n");
    
    protocol_header_t hdr = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_GET_SOLUTION_RESULTS_LIST,
        .flags = 0,
        .payload_size = strlen(student_login) + 1,
        .seq_id = ctx->seq_id++
    };
    
    char rc = client_send_packet(ctx, &hdr, student_login, strlen(student_login) + 1);
    if (rc != CLIENT_OK) {
        printf("Ошибка отправки запроса (код %d)\n", rc);
        return;
    }
    
    // Получаем ответ
    protocol_header_t resp_hdr;
    uint8_t buffer[8192];
    
    rc = client_receive_packet(ctx, &resp_hdr, buffer, sizeof(buffer));
    if (rc != CLIENT_OK) {
        printf("Ошибка получения ответа (код %d)\n", rc);
        return;
    }
    
    if (resp_hdr.type == MSG_ERROR) {
        printf("Сервер вернул ошибку: %s\n", (char*)buffer);
        return;
    }
    
    if (resp_hdr.type != MSG_SOLUTION_RESULTS_LIST) {
        printf("Неверный тип ответа\n");
        return;
    }
    
    size_t count = resp_hdr.payload_size / sizeof(common_problem_t);
    if (count == 0) {
        printf("У студента нет отправленных решений.\n");
        return;
    }
    
    problems = malloc(resp_hdr.payload_size);
    if (!problems) {
        printf("Ошибка выделения памяти\n");
        return;
    }
    
    memcpy(problems, buffer, resp_hdr.payload_size);
    problem_count = count;
    
    printf("Найдено решений: %zu\n", problem_count);
    printf("------------------------------------------------------------------------\n");
    
    // Выводим список решений
    for (size_t i = 0; i < problem_count; i++) {
        printf("%zu. %s (ID: %d) [%s]\n", 
               i + 1, 
               problems[i].title, 
               problems[i].problem_id,
               problem_status_to_string(problems[i].status));
    }
    
    // Цикл проверки решений
    while (1) {
        printf("\n------------------------------------------------------------------------\n");
        printf("Выберите действие:\n");
        printf("1. Проверить решение\n");
        printf("0. Назад\n");
        printf("Выбор: ");
        
        char action[ANSWER_CHOICE_ACTION];
        if (!fgets(action, sizeof(action), stdin)) break;
        strip_newline(action);
        
        if (strcmp(action, "0") == 0) {
            break;
        } else if (strcmp(action, "1") != 0) {
            printf("Неверный выбор\n");
            continue;
        }
        
        // Выбор задачи для проверки
        printf("\nВведите номер задачи для проверки (1-%zu, 0 для отмены): ", problem_count);
        char choice_str[SCORE_CHOICE];
        if (!fgets(choice_str, sizeof(choice_str), stdin)) break;
        strip_newline(choice_str);
        
        int choice = atoi(choice_str);
        if (choice == 0) continue;
        
        if (choice < 1 || choice > (int)problem_count) {
            printf("Неверный номер\n");
            continue;
        }
        
        int problem_id = problems[choice - 1].problem_id;
        
        // Загружаем полное решение
        printf("\nЗагрузка решения...\n");
        
        solution_request_t request;
        strncpy(request.student_login, student_login, sizeof(request.student_login) - 1);
        request.student_login[sizeof(request.student_login) - 1] = '\0';
        request.problem_id = problem_id;
        
        protocol_header_t req_hdr = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_GET_STUDENT_SOLUTION,
            .flags = 0,
            .payload_size = sizeof(request),
            .seq_id = ctx->seq_id++
        };
        
        rc = client_send_packet(ctx, &req_hdr, &request, sizeof(request));
        if (rc != CLIENT_OK) {
            printf("Ошибка отправки запроса\n");
            continue;
        }
        
        // Получаем решение
        protocol_header_t sol_hdr;
        common_solution_result_t solution;
        memset(&solution, 0, sizeof(solution));
        
        rc = client_receive_packet(ctx, &sol_hdr, &solution, sizeof(solution));
        if (rc != CLIENT_OK) {
            printf("Ошибка получения решения\n");
            continue;
        }
        
        if (sol_hdr.type == MSG_ERROR) {
            printf("Сервер вернул ошибку\n");
            continue;
        }
        
        if (sol_hdr.type != MSG_STUDENT_SOLUTION) {
            printf("Неверный тип ответа\n");
            continue;
        }
        
        // Показываем полную информацию о решении
        client_show_full_solution(&problems[choice - 1], &solution,1);
        
        // В client_teacher_view_student_solutions после показа решения:

		// Действия преподавателя
		printf("\n------------------------------------------------------------------------\n");
		printf("ДЕЙСТВИЯ ПРЕПОДАВАТЕЛЯ:\n");
		printf("1. Принять решение (поставить оценку)\n");
		printf("2. Отправить на доработку\n");
		printf("3. Вернуться к списку\n");
		printf("Выбор: ");

		char teacher_action[ANSWER_CHOICE_ACTION];
		if (!fgets(teacher_action, sizeof(teacher_action), stdin)) continue;
		strip_newline(teacher_action);

		if (strcmp(teacher_action, "3") == 0) {
			continue; // Вернуться к списку
		}

		if (strcmp(teacher_action, "1") == 0) {
			// Принять решение
			printf("\nВведите финальную оценку (0-100): ");
			char score_str[SCORE_CHOICE];
			if (fgets(score_str, sizeof(score_str), stdin)) {
				strip_newline(score_str);
				int final_score = atoi(score_str);
        
				if (final_score < 0 || final_score > 100) {
					printf("Некорректная оценка\n");
					continue;
				}
        
				printf("Введите комментарий для студента: ");
				char comment[MAX_COMMENT];
				if (fgets(comment, sizeof(comment), stdin)) {
					strip_newline(comment);
            
					// Используем единую структуру
					solution_update_stat_t update_request;
					memset(&update_request, 0, sizeof(update_request));
            
					strncpy(update_request.student_login, student_login, 
							sizeof(update_request.student_login) - 1);
					update_request.student_login[sizeof(update_request.student_login) - 1] = '\0';
					update_request.problem_id = problem_id;
					update_request.status = PROBLEM_STATUS_ACCEPTED;
					update_request.final_score = final_score;
					strncpy(update_request.teacher_comment, comment, 
							sizeof(update_request.teacher_comment) - 1);
					update_request.teacher_comment[sizeof(update_request.teacher_comment) - 1] = '\0';
            
					protocol_header_t update_hdr = {
						.magic = PROTOCOL_MAGIC,
						.type = MSG_UPDATE_PROBLEM_STATUS,
						.flags = 0,
						.payload_size = sizeof(update_request),
						.seq_id = ctx->seq_id++
					};
            
					printf("Отправка обновления статуса (размер: %zu)...\n", sizeof(update_request));
            
					rc = client_send_packet(ctx, &update_hdr, &update_request, 
											sizeof(update_request));
					if (rc == CLIENT_OK) {
						printf("Оценка %d/100 отправлена студенту %s\n", 
							final_score, student_login);
						problems[choice - 1].status = PROBLEM_STATUS_ACCEPTED;
                
						// Ждем подтверждение
						protocol_header_t ack_hdr;
						rc = client_receive_packet(ctx, &ack_hdr, NULL, 0);
						if (rc == CLIENT_OK && ack_hdr.type == MSG_ACK) {
							printf("Статус обновлен успешно\n");
						}
					} else {
						printf("Ошибка отправки оценки\n");
					}
				}
			}
    
		} else if (strcmp(teacher_action, "2") == 0) {
			// Отправить на доработку
			printf("\nВведите комментарий с замечаниями: ");
			char comment[MAX_COMMENT];
			if (fgets(comment, sizeof(comment), stdin)) {
				strip_newline(comment);
        
				// Используем единую структуру
				solution_update_stat_t update_request;
				memset(&update_request, 0, sizeof(update_request));
        
				strncpy(update_request.student_login, student_login, 
						sizeof(update_request.student_login) - 1);
				update_request.student_login[sizeof(update_request.student_login) - 1] = '\0';
				update_request.problem_id = problem_id;
				update_request.status = PROBLEM_STATUS_REVIEW;
				update_request.final_score = 0; // Оценка 0 при доработке
				strncpy(update_request.teacher_comment, comment, 
						sizeof(update_request.teacher_comment) - 1);
				update_request.teacher_comment[sizeof(update_request.teacher_comment) - 1] = '\0';
        
				protocol_header_t update_hdr = {
					.magic = PROTOCOL_MAGIC,
					.type = MSG_UPDATE_PROBLEM_STATUS,
					.flags = 0,
					.payload_size = sizeof(update_request),
					.seq_id = ctx->seq_id++
				};
        
				printf("Отправка запроса на доработку (размер: %zu)...\n", sizeof(update_request));
        
				rc = client_send_packet(ctx, &update_hdr, &update_request, 
										sizeof(update_request));
				if (rc == CLIENT_OK) {
					printf("Запрос на доработку отправлен\n");
					problems[choice - 1].status = PROBLEM_STATUS_REVIEW;
            
					// Ждем подтверждение
					protocol_header_t ack_hdr;
					rc = client_receive_packet(ctx, &ack_hdr, NULL, 0);
					if (rc == CLIENT_OK && ack_hdr.type == MSG_ACK) {
						printf("Запрос на доработку принят\n");
					}
				} else {
					printf("Ошибка отправки\n");
				}
			}
	}	}
    if (problems) free(problems);
    printf("\n========================================================================\n");
}

// Меню преподавателя
void client_teacher_menu(client_ctx_t *ctx) {
    if (!ctx) return;

    char choice[ANSWER_CHOICE_ACTION];

    while (1) {
        printf("\n=== МЕНЮ УЧИТЕЛЯ ===\n");
        printf("1) Посмотреть решения студентов\n");
        printf("2) Обновить задачи\n");
        printf("3) Создать ученика\n");
        printf("4) Выход\n");
        printf("Выбор: ");

        if (!fgets(choice, sizeof(choice), stdin)) {
            return;
        }
        strip_newline(choice);

        if (strcmp(choice, "1") == 0) {
            client_student_list(ctx);
        } else if (strcmp(choice, "2") == 0) {
            client_teacher_menu_problems(ctx);
        } else if (strcmp(choice, "3") == 0) {
            client_register_user(ctx);
        } else if (strcmp(choice, "4") == 0) {
            printf("Досвидос!\n");
            return;
        } else {
            printf("Неверный выбор. Повторите.\n");
        }
    }
}

// Список студентов
void client_student_list(client_ctx_t *ctx) {
    if (!ctx) return;

    char **student_logins = malloc(CLIENT_MAX_STUDENTS * sizeof(char*)); // Заглушка для 100 студентов
    size_t student_count = 0;

    char status = client_request_student_list(ctx, student_logins, &student_count);
    if (status != CLIENT_OK) {
        printf("Ошибка при получении списка студентов (код %d).\n", status);
        free(student_logins);
        return;
    }

    if (student_count == 0) {
        printf("Нет студентов.\n");
        free(student_logins);
        return;
    }

    printf("\nСписок студентов:\n");
    for (size_t i = 0; i < student_count; i++) {
        printf("%zu) %s\n", i + 1, student_logins[i]);
    }

    char choice[SCORE_CHOICE];
    size_t selected_idx = 0;  // Объявляем здесь, вне while
    bool valid_choice = false;
    
    while (!valid_choice) {
        printf("\nВыберите номер студента (1-%zu) или 0 для выхода: ", student_count);
        if (!fgets(choice, sizeof(choice), stdin)) {
            break;
        }
        strip_newline(choice);

        char *endptr;
        long selected = strtol(choice, &endptr, 10);

        if (*endptr != '\0') {
            printf("Неверный ввод. Повторите.\n");
            continue;
        }

        if (selected == 0) {
            valid_choice = true;
            break;
        }

        if (selected < 1 || (size_t)selected > student_count) {
            printf("Неверный выбор. Повторите.\n");
            continue;
        }

        selected_idx = (size_t)selected - 1; // В индекс массива (0-based)
        valid_choice = true;
    }

    if (valid_choice && selected_idx < student_count) {
        client_teacher_view_student_solutions(ctx, student_logins[selected_idx]);
    }

    // Освобождаем память
    for (size_t i = 0; i < student_count; i++) {
        free(student_logins[i]);
    }
    free(student_logins);
}


// Меню управления задачами для преподавателя: создать новую / редактировать существующую
void client_teacher_menu_problems(client_ctx_t *ctx) {
    if (!ctx) return;

    char choice[ANSWER_CHOICE_ACTION];

    while (1) {
        printf("\n=== УПРАВЛЕНИЕ ЗАДАЧАМИ (Учитель) ===\n");
        printf("1) Создать новую задачу\n");
        printf("2) Обновить существующую задачу\n");
        printf("3) Вернуться\n");
        printf("Выбор: ");

        if (!fgets(choice, sizeof(choice), stdin)) return;
        strip_newline(choice);

        if (strcmp(choice, "1") == 0) {
            client_edit_problem(ctx, 1, NULL);
        } else if (strcmp(choice, "2") == 0) {
            client_print_problems(ctx);
        } else if (strcmp(choice, "3") == 0) {
            return;
        } else {
            printf("Неверный выбор. Повторите.\n");
        }
    }
}

char client_request_full_problem(client_ctx_t *ctx, int problem_id, problem_info_t *problem) {
    if (!ctx || !problem) return CLIENT_ERR_INVALID_ARGS;
    
    // printf("[DEBUG] Запрос полной задачи id=%d\n", problem_id);
    
    // Формируем заголовок запроса
    protocol_header_t header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_PROBLEM_INFO,  // новый тип сообщения
        .flags = 0,
        .payload_size = sizeof(problem_id),
        .seq_id = ctx->seq_id++
    };
    
    // Отправляем запрос
    char result = client_send_packet(ctx, &header, &problem_id, sizeof(problem_id));
    if (result != CLIENT_OK) {
        printf("[ERROR] Ошибка отправки запроса полной задачи: %d\n", result);
        return result;
    }
    
    // Получаем ответ
    protocol_header_t response_header;
    memset(problem, 0, sizeof(problem_info_t));
    
    result = client_receive_packet(ctx, &response_header, problem, sizeof(problem_info_t));
    if (result != CLIENT_OK) {
        printf("[ERROR] Ошибка получения полной задачи: %d\n", result);
        return result;
    }
    
    // Проверяем тип ответа
    if (response_header.type == MSG_ERROR) {
        printf("[ERROR] Сервер вернул ошибку для задачи %d\n", problem_id);
        return CLIENT_ERR_PROTOCOL;
    }
    
    if (response_header.type != MSG_PROBLEM_INFO) {
        printf("[ERROR] Неожиданный тип ответа: %u (ожидался %u)\n", 
               response_header.type, MSG_PROBLEM_INFO);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размер
    if (response_header.payload_size != sizeof(problem_info_t)) {
        printf("[WARNING] Размер ответа не совпадает: %u (ожидался %zu)\n", 
               response_header.payload_size, sizeof(problem_info_t));
        // Все равно продолжаем, копируем что есть
    }
    
    // Гарантируем нулевое завершение строк
    problem->title[sizeof(problem->title) - 1] = '\0';
    problem->description[sizeof(problem->description) - 1] = '\0';
    
    if (problem->header_size < MAX_CODE) {
        problem->problem_header[problem->header_size] = '\0';
    } else {
        problem->problem_header[MAX_CODE - 1] = '\0';
    }
    
    // Гарантируем нулевое завершение строк в тестах
    for (size_t i = 0; i < problem->test_count && i < MAX_TEST_COUNT; i++) {
        problem->test_cases[i].input[MAX_TEST_INPUT_LEN - 1] = '\0';
        problem->test_cases[i].expected[MAX_TEST_OUTPUT_LEN - 1] = '\0';
    }
    
    // printf("[DEBUG] Получена полная задача: %s (id=%d)\n", problem->title, problem->problem_id);
    // printf("[DEBUG]   Описание: %.*s\n", 50, problem->description);
    // printf("[DEBUG]   Код: %zu байт\n", problem->header_size);
    // printf("[DEBUG]   Тестов: %zu\n", problem->test_count);
    
    return CLIENT_OK;
}

// Edit or create new problem
void client_edit_problem(client_ctx_t *ctx, int is_new, common_problem_t *common_problem) {
    if (!ctx) return;
    if (!is_new && !common_problem) return;

    // Храним полную задачу
    problem_info_t problem;
    memset(&problem, 0, sizeof(problem));
    
    if (is_new) {
        // Новая задача
        client_edit_problem_metadata(&problem);
    } else {
        // Загружаем полную задачу с сервера
        printf("\nЗагрузка задачи %d с сервера...\n", common_problem->problem_id);
        
        char status = client_request_full_problem(ctx, common_problem->problem_id, &problem);
        if (status != CLIENT_OK) {
            printf("Ошибка загрузки (код %d)\n", status);
            return;
        }
        
        printf("✓ Загружено: '%s', %zu тестов\n", problem.title, problem.test_count);
    }

    char choice[ANSWER_CHOICE_ACTION];
    while (1) {
        printf("\n=== РЕДАКТОР ЗАДАЧИ ===\n");
        printf("Название: %s\n", problem.title);
        printf("ID: %d | Тестов: %zu | Код: %zu байт\n", 
               problem.problem_id, problem.test_count, problem.header_size);
        printf("\n1. Редактировать метаданные\n");
        printf("2. Редактировать код задачи\n");
        printf("3. Редактировать тесты\n");
        printf("4. Просмотреть тесты\n");
        printf("5. Отправить на сервер\n");
        printf("0. Отмена\n");
        printf("Выбор: ");
        
        if (!fgets(choice, sizeof(choice), stdin)) break;
        strip_newline(choice);
        
        if (strcmp(choice, "1") == 0) {
            // Редактирование метаданных
            printf("\n--- Редактирование метаданных ---\n");
            client_edit_problem_metadata(&problem);
            
        } else if (strcmp(choice, "2") == 0) {
            // Редактирование кода
            printf("\n--- Редактирование кода ---\n");
            
            // Создаем временный файл с кодом
            char tmp_file[256];
            snprintf(tmp_file, sizeof(tmp_file), "/tmp/problem_%d_%d.c", 
                    problem.problem_id, (int)time(NULL));
            
            FILE *fp = fopen(tmp_file, "w");
            if (!fp) {
                perror("Не удалось создать временный файл");
                continue;
            }
            
            if (problem.header_size > 0) {
                fwrite(problem.problem_header, 1, problem.header_size, fp);
            } else {
                fprintf(fp, "/* Введите код задачи здесь */\n\nint main() {\n    return 0;\n}\n");
            }
            fclose(fp);
            
            printf("Открываю редактор... (файл: %s)\n", tmp_file);
            open_external_editor(tmp_file);
            
            // Читаем обновленный код
            char *new_code = NULL;
            size_t new_len = 0;
            if (read_whole_file(tmp_file, &new_code, &new_len) == 0) {
                if (new_len < MAX_CODE) {
                    memcpy(problem.problem_header, new_code, new_len);
                    problem.header_size = new_len;
                    printf("Код обновлен (%zu байт)\n", new_len);
                } else {
                    printf("Ошибка: код слишком большой (%zu > %d)\n", new_len, MAX_CODE);
                }
                free(new_code);
            }
            
            // Удаляем временный файл
            remove(tmp_file);
            
        } else if (strcmp(choice, "3") == 0) {
            // Редактирование тестов
            printf("\n--- Редактирование тестов ---\n");
            
            // Создаем временный файл с тестами
            char tmp_file[256];
            snprintf(tmp_file, sizeof(tmp_file), "/tmp/tests_%d_%d.txt", 
                    problem.problem_id, (int)time(NULL));
            
            FILE *fp = fopen(tmp_file, "w");
            if (!fp) {
                perror("Не удалось создать временный файл");
                continue;
            }
            
            if (problem.test_count > 0) {
                for (size_t i = 0; i < problem.test_count; i++) {
                    fprintf(fp, "# test %zu\n", i + 1);
                    fprintf(fp, "INPUT:\n%s\n\n", problem.test_cases[i].input);
                    fprintf(fp, "EXPECTED:\n%s\n\n\n", problem.test_cases[i].expected);
                }
            } else {
                fprintf(fp, "# test 1\nINPUT:\n\nEXPECTED:\n\n\n");
            }
            fclose(fp);
            
            printf("Открываю редактор тестов... (файл: %s)\n", tmp_file);
            open_external_editor(tmp_file);
            
            // Читаем обновленные тесты
            char *tests_txt = NULL;
            size_t tests_len = 0;
            if (read_whole_file(tmp_file, &tests_txt, &tests_len) == 0) {
                memset(problem.test_cases, 0, sizeof(problem.test_cases));
                problem.test_count = 0;
                
                if (parse_tests_txt_to_array(tests_txt, tests_len, 
                                            problem.test_cases, MAX_TEST_COUNT, 
                                            &problem.test_count) == 0) {
                    printf("Загружено %zu тестов\n", problem.test_count);
                }
                free(tests_txt);
            }
            
            // Удаляем временный файл
            remove(tmp_file);
            
        } else if (strcmp(choice, "4") == 0) {
            // Просмотр тестов
            printf("\n=== ТЕСТЫ (%zu) ===\n", problem.test_count);
            if (problem.test_count == 0) {
                printf("Нет тестов\n");
            } else {
                for (size_t i = 0; i < problem.test_count; i++) {
                    printf("\n--- Тест %zu ---\n", i + 1);
                    printf("INPUT:\n%s\n", problem.test_cases[i].input);
                    printf("EXPECTED:\n%s\n", problem.test_cases[i].expected);
                }
            }
            printf("===================\n");
            
        } else if (strcmp(choice, "5") == 0) {
            // Отправка на сервер
            printf("\n--- Отправка задачи ---\n");
            printf("Название: %s\n", problem.title);
            printf("Описание: %s\n", problem.description);
            printf("ID: %d\n", problem.problem_id);
            printf("Лимит времени: %d мс\n", problem.time_limit_ms);
            printf("Лимит памяти: %d КБ\n", problem.memory_limit_kb);
            printf("Размер кода: %zu байт\n", problem.header_size);
            printf("Количество тестов: %zu\n", problem.test_count);
            
            printf("\nОтправить? (y/n): ");
            char confirm[ANSWER_CHOICE_ACTION];
            if (!fgets(confirm, sizeof(confirm), stdin)) continue;
            strip_newline(confirm);
            if (confirm[0] != 'y' && confirm[0] != 'Y') {
                printf("Отправка отменена\n");
                continue;
            }
            
            // Создаем временный файл для отправки (требуется по интерфейсу client_load_problem)
            char tmp_file[MAX_FILE_LEN];
            snprintf(tmp_file, sizeof(tmp_file), "/tmp/send_%d.c", (int)time(NULL));
            
            FILE *fp = fopen(tmp_file, "w");
            if (!fp) {
                perror("Не удалось создать временный файл");
                continue;
            }
            
            if (problem.header_size > 0) {
                fwrite(problem.problem_header, 1, problem.header_size, fp);
            }
            fclose(fp);
            
            // Отправляем
            char status = client_load_problem(ctx, &problem, tmp_file);
            
            // Удаляем временный файл
            remove(tmp_file);
            
            if (status == CLIENT_OK) {
                printf("\n✓ ЗАДАЧА УСПЕШНО ОТПРАВЛЕНА\n");
                printf("ID: %d\n", problem.problem_id);
                if (is_new && problem.problem_id > 0) {
                    printf("Присвоен новый ID: %d\n", problem.problem_id);
                }
            } else {
                printf("\n✗ ОШИБКА ОТПРАВКИ (код %d)\n", status);
            }
            
            return;
            
        } else if (strcmp(choice, "0") == 0) {
            printf("Редактирование отменено\n");
            return;
        } else {
            printf("Неверный выбор\n");
        }
    }
}
// Edit problem metadata (name, description, time and memory limit)
void client_edit_problem_metadata(problem_info_t *problem) {
    if (!problem) return;
    
    char input[MAX_METADATA_INPUT];
    
    // Название
    printf("Название задачи [%s]: ", problem->title);
    if (fgets(input, sizeof(input), stdin)) {
        strip_newline(input);
        if (strlen(input) > 0) {
            strncpy(problem->title, input, sizeof(problem->title) - 1);
            problem->title[sizeof(problem->title) - 1] = '\0';
        }
    }
    
    // Описание
    printf("Описание [%s]: ", problem->description);
    if (fgets(input, sizeof(input), stdin)) {
        strip_newline(input);
        if (strlen(input) > 0) {
            strncpy(problem->description, input, sizeof(problem->description) - 1);
            problem->description[sizeof(problem->description) - 1] = '\0';
        }
    }
    
    // Лимит времени
    printf("Лимит времени (мс) [%d]: ", problem->time_limit_ms);
    if (fgets(input, sizeof(input), stdin)) {
        strip_newline(input);
        if (strlen(input) > 0) {
            problem->time_limit_ms = atoi(input);
        }
    }
    
    // Лимит памяти
    printf("Лимит памяти (КБ) [%d]: ", problem->memory_limit_kb);
    if (fgets(input, sizeof(input), stdin)) {
        strip_newline(input);
        if (strlen(input) > 0) {
            problem->memory_limit_kb = atoi(input);
        }
    }
}

// Test editor
void client_open_tests_editor(const char *tests_path) {
    FILE *f = fopen(tests_path, "r");
    if (!f) {
        f = fopen(tests_path, "w");
        if (f) {
            fprintf(f,
                "# Формат тестов\n"
                "# ------------\n"
                "# Каждый тест состоит из двух секций: INPUT и EXPECTED\n"
                "# Обязательно оставляйте пустую строку между тестами\n"
                "# Комментарии начинаются с #\n"
                "#\n"
                "# Пример теста:\n"
                "# test 1\n"
                "INPUT:\n"
                "5\n"
                "1 2 3 4 5\n"
                "\n"
                "EXPECTED:\n"
                "15\n"
                "\n"
                "\n"
                "# test 2\n"
                "INPUT:\n"
                "3\n"
                "10 20 30\n"
                "\n"
                "EXPECTED:\n"
                "60\n"
                "\n"
                "\n"
            );
            fclose(f);
            printf("Создан шаблон тестов в файле: %s\n", tests_path);
        } else {
            perror("Не удалось создать файл тестов");
            return;
        }
    } else {
        fclose(f);
    }

    printf("Открываю редактор тестов...\n");
    open_external_editor(tests_path);
}

// Регистрация студента
char client_register_user(client_ctx_t *ctx) {
    char login[MAX_LOGIN_LEN];
    char password[MAX_PASS_LEN];
    char password_confirm[MAX_PASS_LEN];
    uint8_t password_salt[SHA_LEN];

    while (1) {
        printf("Введите логин: ");
        if (!fgets(login, sizeof(login), stdin))
            return CLIENT_ERR_UNKNOWN;
        strip_newline(login);

        printf("Введите пароль: ");
        if (!fgets(password, sizeof(password), stdin))
            return CLIENT_ERR_UNKNOWN;
        strip_newline(password);

        printf("Подтвердите пароль: ");
        if (!fgets(password_confirm, sizeof(password_confirm), stdin))
            return CLIENT_ERR_UNKNOWN;
        strip_newline(password_confirm);

        if (strcmp(password, password_confirm) != 0) {
            printf("Ошибка: пароли не совпадают. Попробуйте снова.\n\n");
            continue;
        }

        auth_start_request_t start_req;
        memset(&start_req, 0, sizeof(start_req));
        strncpy(start_req.username, login, sizeof(start_req.username) - 1);
        start_req.username[sizeof(start_req.username) - 1] = '\0';
        
        protocol_header_t header;
        header.magic = PROTOCOL_MAGIC;
        header.type = MSG_REGISTER_START; 
        header.flags = 0;
        header.payload_size = sizeof(start_req);
        header.seq_id = ctx->seq_id++;
        
        // Отправляем запрос
        char result = client_send_packet(ctx, &header, (uint8_t*)&start_req, sizeof(start_req));
        if (result != CLIENT_OK) {
            printf("Ошибка сети: %d\n", result);
            continue;
        }
        
        
        // Получаем соль от сервера
        protocol_header_t challenge_header;
        auth_challenge_t challenge;
        size_t challenge_len = sizeof(challenge);
        
        result = client_receive_packet(ctx, &challenge_header, (uint8_t*)&challenge, challenge_len);
        if (result != CLIENT_OK) {
            printf("Ошибка при получении соли: %d\n", result);
            continue;
        }


        if (challenge_header.type != MSG_REGISTER_START) {
            if (challenge_header.type == MSG_ERROR) {
				
                // Пользователь уже существует
                printf("Пользователь с таким логином уже существует.\n");
                printf("Пожалуйста, выберите другой логин.\n\n");
                continue;
            }
            printf("Неверный ответ от сервера\n");
            continue;
        }
        
        // Вычисляем хэш пароля

		auth_verify_request_t *verify_req = calloc(1, sizeof(auth_verify_request_t));


		if (!verify_req) {
			printf("malloc failed!\n");
			return CLIENT_ERR_NOMEM;
		}

        password_create(password, challenge.salt, password_salt);

		// Копируем вычисленный хэш
		memcpy(verify_req->password_hash, password_salt, sizeof(verify_req->password_hash));


		// Теперь отправляем
		header.type = MSG_REGISTER_VERIFY;
		header.flags = 0;
		header.payload_size = sizeof(*verify_req);
		header.seq_id = ctx->seq_id++;

		result = client_send_packet(ctx, &header, verify_req, sizeof(*verify_req));
        free(verify_req);
        verify_req = NULL;

        if (result != CLIENT_OK) {
            printf("Ошибка отправки данных регистрации: %d\n", result);
            continue;
        }
        
        // Получаем результат регистрации
        protocol_header_t final_header;
        auth_success_t reg_success;
        size_t success_len = sizeof(reg_success);
        
        result = client_receive_packet(ctx, &final_header, (uint8_t*)&reg_success, success_len);
        if (result != CLIENT_OK) {
            printf("Ошибка при получении ответа: %d\n", result);
            continue;
        }
        
        // Обрабатываем результат
        if (final_header.type == MSG_REGISTER_OK) {
            // Регистрация успешна
            strncpy(ctx->session.username, login, sizeof(ctx->session.username) - 1);
            ctx->session.role = ROLE_TEACHER;
            ctx->session.logged_in = true;
            
            // Если сервер вернул токен сессии
            if (reg_success.session_token[0] != '\0') {
                strncpy(ctx->session.session_token, reg_success.session_token,
                        sizeof(ctx->session.session_token) - 1);
                ctx->session.session_expires = time(NULL) + reg_success.expires_in;
            }
            
            ctx->state = CONN_STATE_AUTHENTICATED;
            printf("Пользователь успешно создан.\n");
            return CLIENT_OK;
        } else if (final_header.type == MSG_REGISTER_FAIL) {
            // Ошибка регистрации
            printf("Ошибка регистрации: пользователь уже существует или серверная ошибка.\n");
            continue;
        } else {
            printf("Неизвестный ответ от сервера: %d\n", final_header.type);
            continue;
        }
    }
}

/* 
SERVER-CLIENT COMMUNICATION FUNCTIONS
*/

// Send protocol-headed packet
char client_send_packet(client_ctx_t *ctx,
                       const protocol_header_t *header,
                       const void *payload,
                       size_t payload_size){				   
						   				   
    if (!ctx || !header) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    if (payload_size > CLIENT_MAX_PAYLOAD_LEN) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    pthread_mutex_lock(&ctx->socket_mutex);
    
    // Формируем пакет
    size_t total_size = sizeof(protocol_header_t) + payload_size;
    uint8_t buffer[sizeof(protocol_header_t) + CLIENT_MAX_PAYLOAD_LEN];
    
    memcpy(buffer, header, sizeof(protocol_header_t));
    if (payload_size > 0 && payload) {
        memcpy(buffer + sizeof(protocol_header_t), payload, payload_size);
    }
    
    ssize_t sent = send(ctx->sockfd, buffer, total_size, 0);
    
    pthread_mutex_unlock(&ctx->socket_mutex);
    
    if (sent < 0) {
        perror("client_send_packet: send");
        return CLIENT_ERR_NETWORK;
    }
    
    if ((size_t)sent != total_size) {
        fprintf(stderr, "client_send_packet: incomplete send (%zd of %zu bytes)\n", 
                sent, total_size);
        return CLIENT_ERR_NETWORK;
    }
    
    // printf("Sent TCP packet: type=%u, size=%zu, seq=%u\n",
    //        header->type, payload_size, header->seq_id);
    
    return CLIENT_OK;
}

char client_receive_packet(client_ctx_t *ctx,
                                 protocol_header_t *header,
                                 void *payload_buffer,
                                 size_t buffer_size){
    // Читаем заголовок
    ssize_t received = recv(ctx->sockfd, header, sizeof(protocol_header_t), 0);
    if (received != sizeof(protocol_header_t)) {
        printf("[ERROR] Failed to read header: %zd (expected %zu), errno=%d\n", 
               received, sizeof(protocol_header_t), errno);
        return CLIENT_ERR_NETWORK;
    }
    
    // printf("[DEBUG] Received header: magic=0x%x, type=%u, size=%u, seq=%u\n",
    //        header->magic, header->type, header->payload_size, header->seq_id);
    
    // Проверяем магию
    if (header->magic != PROTOCOL_MAGIC) {
        printf("[ERROR] Bad magic: 0x%x (expected 0x%x)\n", 
               header->magic, PROTOCOL_MAGIC);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размер
    /*if (header->payload_size > buffer_size) {
        printf("[ERROR] Payload too large: %u > %zu\n", 
               header->payload_size, buffer_size);
        return CLIENT_ERR_INVALID_ARGS;
    }*/
    
    // Читаем payload
    if (header->payload_size > 0) {
        received = recv(ctx->sockfd, payload_buffer, header->payload_size, 0);
        if ((size_t)received != header->payload_size) {
            printf("[ERROR] Failed to read payload: %zd (expected %u), errno=%d\n", 
                   received, header->payload_size, errno);
            return CLIENT_ERR_IO;
        }
    }
    
    // printf("Received packet: type=%u, size=%u, seq=%u\n",
    //        header->type, header->payload_size, header->seq_id);
    
    return CLIENT_OK;
}

/* REQUESTs*/

char client_request_problem_list(client_ctx_t *ctx, common_problem_t **problems, size_t *problem_count){
    if (!ctx || !problems || !problem_count) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    // Отправляем запрос на список задач
    protocol_header_t request = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_GET_PROBLEM_LIST,
        .flags = 0,
        .payload_size = 0,
        .seq_id = ctx->seq_id++
    };
    
    char result = client_send_packet(ctx, &request, NULL, 0);
    if (result != CLIENT_OK) {
        printf("Failed to send request: %d\n", result);
        return result;
    }
    
    // Cоздаем буфер для получения ответа
    size_t buffer_size = MAX_PROBLEMS_COUNT * sizeof(common_problem_t);
    common_problem_t *buffer = malloc(buffer_size);
    
    if (!buffer) {
        return CLIENT_ERR_NOMEM;
    }
    
    // Получаем ответ
    protocol_header_t response_header;
    
    result = client_receive_packet(ctx, &response_header, buffer, buffer_size);
    
    // Проверяем результат
    if (result != CLIENT_OK) {
        free(buffer);
        printf("Failed to receive response: %d\n", result);
        return result;
    }
    
    // Проверяем тип ответа
    if (response_header.type == MSG_ERROR) {
        free(buffer);
        printf("Server error\n");
        return CLIENT_ERR_PROTOCOL;
    }
    
    if (response_header.type != MSG_PROBLEM_LIST) {
        free(buffer);
        printf("Wrong response type: %u (expected %u)\n", 
                response_header.type, MSG_PROBLEM_LIST);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размер данных
    if (response_header.payload_size == 0) {
        *problems = NULL;
        *problem_count = 0;
        free(buffer);
        return CLIENT_OK;
    }
    
    // Проверяем, что размер кратен размеру структуры
    if (response_header.payload_size % sizeof(common_problem_t) != 0) {
        free(buffer);
        printf("Invalid data size: %u (not multiple of %zu)\n",
                response_header.payload_size, sizeof(common_problem_t));
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Рассчитываем количество задач
    *problem_count = response_header.payload_size / sizeof(common_problem_t);
    
    printf("Received %zu problems\n", *problem_count);
    
    // Выделяем точный размер под задачи
    *problems = malloc(response_header.payload_size);
    if (!*problems) {
        free(buffer);
        return CLIENT_ERR_NOMEM;
    }
    
    // Копируем данные из буфера
    memcpy(*problems, buffer, response_header.payload_size);
    free(buffer);
    
    return CLIENT_OK;
}

char client_request_student_list(client_ctx_t *ctx, char **student_logins, size_t *student_count) {
    if (!ctx) { 
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    *student_logins = NULL;
    *student_count = 0;
    
    // Отправляем запрос списка студентов
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_GET_STUDENT_LIST;
    header.flags = 0;
    header.payload_size = 0;
    header.seq_id = ctx->seq_id++;
    
    char result = client_send_packet(ctx, &header, NULL, 0);
    if (result != CLIENT_OK) {
        return result;
    }
    
    // Получаем размер списка
    protocol_header_t size_header;
    size_t count = 0;
    
    result = client_receive_packet(ctx, &size_header, (uint8_t*)&count, sizeof(count));
    if (result != CLIENT_OK) {
        return result;
    }
    
    if (size_header.type != MSG_STUDENT_LIST_SIZE) {
        return CLIENT_ERR_PROTOCOL;
    }

    *student_count = count;
    if (count == 0) {
        return CLIENT_OK;
    }
    
    // Получаем список логинов
    size_t logins_buffer_size = count * MAX_LOGIN_LEN;
    char *logins_buffer = malloc(logins_buffer_size);
    if (!logins_buffer) {
        return CLIENT_ERR_NOMEM;
    }
    
    protocol_header_t list_header;
    result = client_receive_packet(ctx, &list_header, (uint8_t*)logins_buffer, logins_buffer_size);
    if (result != CLIENT_OK) {
        free(logins_buffer);
        return result;
    }
    
    if (list_header.type != MSG_STUDENT_LIST) {
        free(logins_buffer);
        return CLIENT_ERR_PROTOCOL;
    }
    
    for (size_t i = 0; i < count; i++) {
        student_logins[i] = strdup(logins_buffer + i * MAX_LOGIN_LEN);
    }
    
    return CLIENT_OK;
}

char client_request_problem_header(client_ctx_t *ctx, const int problem_id, char *buffer, size_t buffer_size){
    if (!ctx || !buffer || buffer_size == 0) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    // Формируем заголовок пакета для запроса заголовка задачи
    protocol_header_t header = {
        .magic = PROTOCOL_MAGIC,  
        .type = MSG_GET_PROBLEM,
        .flags = 0,
        .payload_size = sizeof(problem_id),
        .seq_id = ctx->seq_id++
    };
    
    // Отправляем запрос
    char result = client_send_packet(ctx, &header, &problem_id, sizeof(problem_id));
    if (result != CLIENT_OK) {
        return result;
    }
    
    // Получаем ответ от сервера
    protocol_header_t response_header;
    common_problem_header_t problem_header;
    
    result = client_receive_packet(ctx, &response_header, &problem_header, 
                                sizeof(common_problem_header_t));
    if (result != CLIENT_OK) {
        return result;
    }
    
    // Проверяем тип ответа
    if (response_header.type != MSG_PROBLEM_INFO) {
        fprintf(stderr, "Unexpected response type: %u\n", response_header.type);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размер данных
    if (response_header.payload_size < sizeof(common_problem_header_t)) {
        fprintf(stderr, "Invalid response size\n");
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Копируем заголовок задачи в буфер клиента
    size_t copy_size = problem_header.header_size;
    if (copy_size > buffer_size - 1) { // -1 для нуль-терминатора
        copy_size = buffer_size - 1;
    }
    
    memcpy(buffer, problem_header.problem_header, copy_size);
    buffer[copy_size] = '\0'; // Гарантируем нуль-терминированную строку
    
    printf("Received problem header\n");
    
    return CLIENT_OK;
}

char client_get_solution_result(client_ctx_t *ctx, int problem_id, common_solution_result_t *result) {
    if (!ctx || !result) return CLIENT_ERR_INVALID_ARGS;

    protocol_header_t hdr = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_GET_SOLUTION_RESULT,
        .flags = 0,
        .payload_size = sizeof(int),
        .seq_id = ctx->seq_id++
    };

    char rc = client_send_packet(ctx, &hdr, &problem_id, sizeof(int));
    if (rc != CLIENT_OK) return rc;

    protocol_header_t rh;
    common_solution_result_t tmp;
    size_t tmp_len = sizeof(tmp);

    rc = client_receive_packet(ctx, &rh, &tmp, tmp_len);
    if (rc != CLIENT_OK) return rc;

    if (rh.type == MSG_SOLUTION_RESULT_FULL && rh.payload_size == sizeof(tmp)) {
        *result = tmp;
        return CLIENT_OK;
    }

    return CLIENT_ERR_PROTOCOL;
}

char client_request_student_problems(client_ctx_t *ctx, const char *student_login,
                                     common_problem_t **problems, size_t *problem_count) {
    if (!ctx || !problems || !problem_count) return CLIENT_ERR_INVALID_ARGS;

    *problems = NULL;
    *problem_count = 0;

    // Определяем тип запроса
    uint32_t payload_size = 0;
    const void *payload_data = NULL;
    
    if (student_login != NULL && student_login[0] != '\0' && 
        ctx->session.role == ROLE_TEACHER) {
        // Преподаватель запрашивает студента - отправляем логин
        payload_size = strlen(student_login) + 1;
        payload_data = student_login;
    } else {
        // Студент запрашивает свои решения - НЕ отправляем логин
        payload_size = 0;
        payload_data = NULL;
    }

    protocol_header_t hdr = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_GET_SOLUTION_RESULTS_LIST,
        .flags = 0,
        .payload_size = payload_size,
        .seq_id = ctx->seq_id++
    };

    // printf("[DEBUG] Sending request: type=%d, size=%u\n", hdr.type, hdr.payload_size);
    
    char rc = client_send_packet(ctx, &hdr, payload_data, payload_size);
    if (rc != CLIENT_OK) return rc;

     protocol_header_t rh;
    uint8_t buf[CLIENT_MAX_PAYLOAD_LEN];

    rc = client_receive_packet(ctx, &rh, buf, sizeof(buf));
    if (rc != CLIENT_OK) return rc;

    if (rh.type == MSG_SOLUTION_RESULTS_LIST) {
        if (rh.payload_size == 0) {
            return CLIENT_OK;
        }

        if (rh.payload_size % sizeof(common_problem_t) != 0) {
            return CLIENT_ERR_PROTOCOL;
        }

        size_t cnt = rh.payload_size / sizeof(common_problem_t);
        common_problem_t *arr = (common_problem_t*)malloc(cnt * sizeof(common_problem_t));
        if (!arr) return CLIENT_ERR_NOMEM;

        memcpy(arr, buf, rh.payload_size);

        *problems = arr;
        *problem_count = cnt;
        return CLIENT_OK;
    }

    if (rh.type == MSG_ERROR) return CLIENT_ERR_PROTOCOL;
    return CLIENT_ERR_PROTOCOL;
}

char client_request_student_solution(client_ctx_t *ctx, const char *student_login, const int problem_id,char *solution_code, size_t buffer_size){
	if (!ctx || !student_login || !problem_id || !solution_code || buffer_size == 0) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    // Подготавливаем структуру запроса
    solution_request_t request;
    
    // Копируем логин студента
    strcpy(request.student_login, student_login);
    
    // Копируем ID задачи
    request.problem_id = problem_id;
    
    // Размер запроса - размер всей структуры
    size_t request_size = sizeof(solution_request_t);
    
    // Формируем заголовок пакета
    protocol_header_t header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_GET_STUDENT_SOLUTION,
        .flags = 0,
        .payload_size = request_size,
        .seq_id = ctx->seq_id++
    };   
    
    // Отправляем запрос
    char result = client_send_packet(ctx, &header, &request, request_size);
    if (result != CLIENT_OK) {
        fprintf(stderr, "Не удалось отправить запрос на получение файла решения\n");
        return result;
    }
    
    // Получаем ответ от сервера
    protocol_header_t response_header;
    common_solution_result_t solution_result;
    
    // Получаем полную структуру с решением
    result = client_receive_packet(ctx, &response_header, &solution_result, 
                                    sizeof(common_solution_result_t));
    if (result != CLIENT_OK) {
        fprintf(stderr, "Не удалось получить файл решения\n");
        return result;
    }
    
    // Проверяем тип ответа
    if (response_header.type == MSG_ERROR) {
        // Сервер вернул ошибку
        if (response_header.payload_size > 0) {
            char error_msg[MAX_ERROR_MSG_LEN];
            ssize_t received = recv(ctx->sockfd, error_msg, 
                                response_header.payload_size, 0);
            if (received > 0) {
                error_msg[received] = '\0';
                fprintf(stderr, "Server error: %s\n", error_msg);
            }
        }
        return CLIENT_OK;
    }
    
    if (response_header.type != MSG_STUDENT_SOLUTION) {
        fprintf(stderr, "Unexpected response type: %u\n", response_header.type);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размер данных
    if (response_header.payload_size < sizeof(common_solution_result_t)) {
        fprintf(stderr, "Invalid response size\n");
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Копируем код решения в буфер клиента
    size_t code_len = strlen(solution_result.code);
    if (code_len >= buffer_size) {
        code_len = buffer_size - 1;  // Оставляем место для нуль-терминатора
        fprintf(stderr, "Warning: Solution code truncated\n");
    }
    
    memcpy(solution_code, solution_result.code, code_len);
    solution_code[code_len] = '\0';  // Гарантируем нуль-терминированную строку
    
    if (solution_result.teacher_comment[0] != '\0') {
        printf("  Комментарий преподавателя: %s\n", solution_result.teacher_comment);
    }
    
    if (solution_result.error_message[0] != '\0') {
        printf("  Ошибка: %s\n", solution_result.error_message);
    }
    
    return CLIENT_OK;
}						   					   						   

// Отправки
char client_auth(client_ctx_t *ctx, const char *login, const char *password) {
    if (!ctx || !login || !password) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    if (!ctx->connected) {
        return CLIENT_ERR_NOT_CONNECTED;
    }
    
    // Запрашиваем соль 
    auth_start_request_t start_req;
    memset(&start_req, 0, sizeof(start_req));
    strncpy(start_req.username, login, sizeof(start_req.username) - 1);
    start_req.username[sizeof(start_req.username) - 1] = '\0';
    
    protocol_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.type = MSG_AUTH_START;
    header.flags = 0;
    header.payload_size = sizeof(start_req);
    header.seq_id = ctx->seq_id++;
    
    // Отправляем запрос на начало аутентификации
    char result = client_send_packet(ctx, &header, (uint8_t*)&start_req, sizeof(start_req));
    if (result != CLIENT_OK) {
        return result;
    }
    // Получаем соль от сервера
    protocol_header_t challenge_header;
    auth_challenge_t challenge;

    result = client_receive_packet(ctx, &challenge_header, &challenge, sizeof(challenge));
    if (result != CLIENT_OK) {
        return result;
    }
    
    if (challenge_header.type != MSG_AUTH_START) {
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Вычисляем хэш и отправляем его
    auth_verify_request_t verify_req;
    
    // Вычисляем хэш: SHA256(соль + пароль)
    uint8_t salt_pass[SHA_LEN];
    
    password_create(password,challenge.salt,salt_pass);

    memcpy(verify_req.password_hash, salt_pass, sizeof(verify_req.password_hash));

    // Отправляем верификацию
    header.type = MSG_AUTH_VERIFY;
    header.payload_size = sizeof(verify_req);
    header.seq_id = ctx->seq_id++;
    
    result = client_send_packet(ctx, &header, (uint8_t*)&verify_req, sizeof(verify_req));
    if (result != CLIENT_OK) {
        return result;
    }

    // Получаем финальный ответ
    protocol_header_t final_header;
    auth_success_t auth_success;
    
    result = client_receive_packet(ctx, &final_header, (uint8_t*)&auth_success, sizeof(auth_success));
    if (result != CLIENT_OK) {
        return result;
    }
    
    // Обрабатываем результат
    if (final_header.type == MSG_AUTH_OK) {
        // Сохраняем сессию
        strncpy(ctx->session.session_token, auth_success.session_token, 
                sizeof(ctx->session.session_token) - 1);
        ctx->session.session_expires = time(NULL) + auth_success.expires_in;
        ctx->session.role = auth_success.role;
        ctx->session.logged_in = true;
        strncpy(ctx->session.username, login, sizeof(ctx->session.username) - 1);
        
        return CLIENT_OK;
    } else if (final_header.type == MSG_AUTH_FAIL) {
        return CLIENT_ERR_AUTH_FAILED;
    } else {
        return CLIENT_ERR_PROTOCOL;
    }
}

static char client_send_solution(client_ctx_t *ctx, int problem_id, const char *code)
{
    if (!ctx || !code)
        return 1;

    // Используем solution_code_t
    solution_code_t req;
    memset(&req, 0, sizeof(req));
    req.problem_id = problem_id;
    
    // Копируем код с проверкой длины
    size_t code_len = strlen(code);
    if (code_len >= MAX_CODE) {
        code_len = MAX_CODE - 1;
        printf("[WARNING] Code truncated to %zu characters\n", code_len);
    }
    
    memcpy(req.code, code, code_len);
    req.code[code_len] = '\0';
    
    // printf("[DEBUG] Sending solution: problem_id=%d, code_len=%zu\n", 
        //    problem_id, code_len);

    protocol_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PROTOCOL_MAGIC;
    hdr.type = MSG_SEND_SOLUTION;
    hdr.flags = 0;
    hdr.payload_size = sizeof(req);
    hdr.seq_id = ctx->seq_id++;

    // отправить
    char rc = client_send_packet(ctx, &hdr, (const uint8_t *)&req, sizeof(req));
    if (rc != 0) {
        printf("[ERROR] Failed to send solution: %d\n", rc);
        return rc;
    }

    // printf("[DEBUG] Solution sent, waiting for result...\n");

//    printf("[DEBUG] Solution sent, waiting for result...\n");
    // printf("[DEBUG] sizeof(common_solution_result_t) on CLIENT = %zu\n", 
        //    sizeof(common_solution_result_t));

    protocol_header_t rhdr;
    
    // СПОСОБ 1: Используйте отдельный большой буфер
    uint8_t large_buffer[16384];  // 16KB буфер
    
    rc = client_receive_packet(ctx, &rhdr, large_buffer, sizeof(large_buffer));
    if (rc != 0) {
        printf("[ERROR] Failed to receive result: %d\n", rc);
        return rc;
    }

    // printf("[DEBUG] Response received: type=%u, size=%u\n", 
    //        rhdr.type, rhdr.payload_size);

    if (rhdr.type != MSG_SOLUTION_RESULT) {
        printf("[ERROR] Unexpected server response type=%u (expected %u)\n", 
               rhdr.type, MSG_SOLUTION_RESULT);
        return 1;
    }

    // Копируем данные из буфера в структуру
    common_solution_result_t res;
    memset(&res, 0, sizeof(common_solution_result_t));
    
    // Копируем сколько можем
    size_t copy_size = rhdr.payload_size;
    if (copy_size > sizeof(res)) {
        copy_size = sizeof(res);
        printf("[WARNING] Truncating from %u to %zu bytes\n", 
               rhdr.payload_size, copy_size);
    }
    
    memcpy(&res, large_buffer, copy_size);
    
    // Теперь проверяем данные
    // printf("[DEBUG] Received solution: problem_id=%d, status=%d, score=%d\n",
    //        res.problem_id, res.status, res.auto_score);

    // Проверяем размер (может быть меньше из-за выравнивания)
    if (rhdr.payload_size < sizeof(common_solution_result_t) - MAX_CODE) {
        printf("[ERROR] Invalid response size: %u (min expected %zu)\n", 
               rhdr.payload_size, sizeof(common_solution_result_t) - MAX_CODE);
        return 1;
    }

    // печать результата
    printf("\n=== РЕЗУЛЬТАТ РЕШЕНИЯ ===\n");
    printf("Задача: %d\n", res.problem_id);
    printf("Статус: %s\n", problem_status_to_string(res.status));
    printf("Автоматическая оценка: %d/100\n", res.auto_score);
    
    if (res.final_score > 0) {
        printf("Финальная оценка: %d/100\n", res.final_score);
    }
    
    if (res.error_message[0] != '\0') {
        printf("Ошибка: %s\n", res.error_message);
    }
    
    if (res.teacher_comment[0] != '\0') {
        printf("Комментарий преподавателя: %s\n", res.teacher_comment);
    }
    
    printf("Время выполнения: %d мс\n", res.exec_time_ms);
    printf("Использовано памяти: %d КБ\n", res.memory_used_kb);
    
    if (res.code[0] != '\0') {
        printf("\nОтправленный код (%zu символов):\n", strlen(res.code));
        // Показываем первые 200 символов
        char preview[CODE_PREVIEW + 1];
        strncpy(preview, res.code, CODE_PREVIEW);
        preview[CODE_PREVIEW] = '\0';
        printf("%s\n", preview);
        if (strlen(res.code) > CODE_PREVIEW) {
            printf("... (ещё %zu символов)\n", strlen(res.code) - CODE_PREVIEW);
        }
    }
    
    printf("===========================\n");

    return 0;
}

char client_update_problem_status(client_ctx_t *ctx, const char *student_login, const char *problem_id, const common_solution_result_t new_result){
							return CLIENT_OK;
                        }

char client_load_problem(client_ctx_t *ctx, problem_info_t *info, const char *problem_file_path) {
    // printf("[DEBUG] client_load_problem: start\n");
    // printf("[DEBUG] ctx=%p, info=%p, path=%s\n", (void*)ctx, (void*)info, problem_file_path);
    
    if (!ctx || !info || !problem_file_path) {
        printf("[ERROR] Invalid arguments\n");
        return CLIENT_ERR_INVALID_ARGS;
    }

    // Читаем problem.c (заголовок) - это обязательно
    // printf("[DEBUG] Reading problem.c...\n");
    char *code = NULL;
    size_t code_len = 0;
    if (read_whole_file(problem_file_path, &code, &code_len) != 0) {
        printf("[ERROR] Failed to read problem.c\n");
        perror("read problem.c");
        return CLIENT_ERR_IO;
    }

    // printf("[DEBUG] Code length: %zu bytes\n", code_len);

    // Проверяем, не превышает ли код максимальный размер
    if (code_len > MAX_PAYLOAD_LEN) {
        printf("[ERROR] Code too large: %zu > %d\n", code_len, MAX_PAYLOAD_LEN);
        free(code);
        return CLIENT_ERR_INVALID_ARGS;
    }

    // Копируем код в структуру
    // printf("[DEBUG] Copying code to structure...\n");
    memset(info->problem_header, 0, sizeof(info->problem_header));
    memcpy(info->problem_header, code, code_len);
    info->header_size = code_len;
    free(code);
    
    // printf("[DEBUG] Header size: %zu\n", info->header_size);

    // ВАЖНО: НЕ перезаписываем тесты, если они уже есть!
    // Тесты уже были установлены в client_edit_problem
    
    // printf("[DEBUG] Keeping existing tests: %zu\n", info->test_count);
    
    // Выводим отладочную информацию о тестах
    // for (size_t i = 0; i < info->test_count; i++) {
    //     printf("[DEBUG] Test %zu:\n", i + 1);
    //     printf("  Input: '%.100s' (len=%zu)\n", 
    //            info->test_cases[i].input, 
    //            strlen(info->test_cases[i].input));
    //     printf("  Expected: '%.100s' (len=%zu)\n", 
    //            info->test_cases[i].expected, 
    //            strlen(info->test_cases[i].expected));
    // }

    // Отправляем всю структуру
    protocol_header_t hdr;
    hdr.magic = PROTOCOL_MAGIC;

    if (info->problem_id == 0) {
        hdr.type = MSG_PROBLEM_CREATE;
    } else {
        hdr.type = MSG_PROBLEM_UPDATE;
        // printf("[DEBUG] UPDATING existing problem id=%d\n", info->problem_id);
    }

    hdr.flags = 0;
    hdr.payload_size = sizeof(problem_info_t);
    hdr.seq_id = ctx->seq_id++;

    // printf("[DEBUG] Sending packet:\n");
    // printf("  type: %u\n", hdr.type);
    // printf("  payload_size: %u (struct size: %zu)\n", hdr.payload_size, sizeof(problem_info_t));
    // printf("  seq_id: %u\n", hdr.seq_id);
    // printf("  test_count being sent: %zu\n", info->test_count);
    
    char rc = client_send_packet(ctx, &hdr, info, sizeof(problem_info_t));
    if (rc != CLIENT_OK) {
        printf("[ERROR] client_send_packet failed: %d\n", rc);
        return rc;
    }

    // printf("[DEBUG] Packet sent successfully\n");

    // Ждём ответ
    protocol_header_t rh;
    problem_info_t saved;
    memset(&saved, 0, sizeof(saved));

    // printf("[DEBUG] Waiting for response...\n");
    rc = client_receive_packet(ctx, &rh, &saved, sizeof(problem_info_t));
    if (rc != CLIENT_OK) {
        printf("[ERROR] client_receive_packet failed: %d\n", rc);
        return rc;
    }

    // printf("[DEBUG] Response received:\n");
    // printf("  type: %u\n", rh.type);
    // printf("  payload_size: %u\n", rh.payload_size);
    // printf("  seq_id: %u\n", rh.seq_id);

    if (rh.type == MSG_ERROR) {
        printf("[ERROR] Server returned error\n");
        return CLIENT_ERR_PROTOCOL;
    }

    if (rh.type != MSG_PROBLEM_SAVED) {
        printf("[ERROR] Unexpected response type: %u (expected %u)\n", 
               rh.type, MSG_PROBLEM_SAVED);
        return CLIENT_ERR_PROTOCOL;
    }

    if (rh.payload_size != sizeof(saved)) {
        printf("[ERROR] Invalid response size: %u (expected %zu)\n", 
               rh.payload_size, sizeof(saved));
        return CLIENT_ERR_PROTOCOL;
    }

    // Обновляем информацию
    *info = saved;

    printf("[SUCCESS] Problem saved on server. ID=%d, Tests=%zu\n", 
           info->problem_id, info->test_count);
    // printf("[DEBUG] client_load_problem: end\n");
    return CLIENT_OK;
}
				   
char client_send_solution_file(client_ctx_t *ctx, const int problem_id, const char *solution_path) {
    if (!ctx || !solution_path) {
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    // printf("[DEBUG] Sending solution for problem %d from file: %s\n", problem_id, solution_path);
    
    // Открываем файл с решением
    FILE *file = fopen(solution_path, "r");
    if (!file) {
        fprintf(stderr, "Cannot open solution file: %s\n", solution_path);
        return CLIENT_ERR_IO;
    }
    
    // Определяем размер файла
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Проверяем размер файла
    if (file_size > MAX_CODE - 1) { // -1 для нуль-терминатора
        fprintf(stderr, "Solution file too large: %ld bytes (max %d)\n", file_size, MAX_CODE - 1);
        fclose(file);
        return CLIENT_ERR_IO;
    }
    
    if (file_size == 0) {
        fprintf(stderr, "Solution file is empty: %s\n", solution_path);
        fclose(file);
        return CLIENT_ERR_INVALID_ARGS;
    }
    
    // Подготавливаем структуру
    solution_code_t submission;
    memset(&submission, 0, sizeof(solution_code_t));
    submission.problem_id = problem_id;
    
    // Читаем содержимое файла
    size_t bytes_read = fread(submission.code, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Failed to read solution file: read %zu of %ld bytes\n", bytes_read, file_size);
        return CLIENT_ERR_IO;
    }
    
    // Гарантируем нуль-терминацию
    submission.code[bytes_read] = '\0';
    
    // printf("[DEBUG] Solution loaded: problem_id=%d, code_length=%zu\n", 
    //        submission.problem_id, bytes_read);
    
    // Формируем заголовок пакета
    protocol_header_t header = {
        .magic = PROTOCOL_MAGIC,
        .type = MSG_SEND_SOLUTION,
        .flags = 0,
        .payload_size = sizeof(submission),
        .seq_id = ctx->seq_id++
    };
    
    // printf("[DEBUG] Sending packet: type=%d, size=%u, seq=%d\n", 
    //        header.type, header.payload_size, header.seq_id);
    
    // Отправляем решение на сервер
    char result = client_send_packet(ctx, &header, &submission, sizeof(submission));
    if (result != CLIENT_OK) {
        fprintf(stderr, "Failed to send solution for problem %d: error %d\n", problem_id, result);
        return result;
    }
    
    // printf("[DEBUG] Solution sent, waiting for response...\n");
    
    // === ИСПРАВЛЕННАЯ ЧАСТЬ: Принимаем common_solution_result_t ===
    protocol_header_t resp_header;
    
    // Большой буфер для приема данных
    #define RECV_BUFFER_SIZE 32768
    uint8_t recv_buffer[RECV_BUFFER_SIZE];
    
    result = client_receive_packet(ctx, &resp_header, recv_buffer, sizeof(recv_buffer));
    if (result != CLIENT_OK) {
        fprintf(stderr, "Failed to receive solution result: error %d\n", result);
        return result;
    }
    
    // printf("[DEBUG] Response received: type=%d, size=%u\n", 
    //        resp_header.type, resp_header.payload_size);
    
    if (resp_header.type == MSG_ERROR) {
        fprintf(stderr, "Server returned error\n");
        return CLIENT_ERR_PROTOCOL;
    }
    
    if (resp_header.type != MSG_SOLUTION_RESULT) {
        fprintf(stderr, "Unexpected response type: %d (expected %d)\n", 
                resp_header.type, MSG_SOLUTION_RESULT);
        return CLIENT_ERR_PROTOCOL;
    }
    
    // Проверяем размеры
    // printf("[DEBUG] Server payload: %u bytes\n", resp_header.payload_size);
    // printf("[DEBUG] sizeof(common_solution_result_t): %zu bytes\n", sizeof(common_solution_result_t));
    
    // Создаем структуру для результата
    common_solution_result_t full_result;
    memset(&full_result, 0, sizeof(common_solution_result_t));
    
    // Безопасное копирование
    size_t copy_size = resp_header.payload_size;
    if (copy_size > sizeof(full_result)) {
        copy_size = sizeof(full_result);
        printf("[WARNING] Truncating from %u to %zu bytes\n", resp_header.payload_size, copy_size);
    }
    
    memcpy(&full_result, recv_buffer, copy_size);
    
    // Гарантируем нулевое завершение строк
    full_result.username[MAX_LOGIN_LEN - 1] = '\0';
    full_result.code[MAX_CODE - 1] = '\0';
    full_result.teacher_comment[MAX_COMMENT - 1] = '\0';
    full_result.error_message[255] = '\0';
    
    // === ВЫВОД РЕЗУЛЬТАТА ===
    printf("\n=== РЕЗУЛЬТАТ ПРОВЕРКИ ===\n");
    
    // Статус задачи
    printf("Статус: %s\n", problem_status_to_string(full_result.status));
    
    // Оценки
    printf("Автоматическая оценка: %d/100\n", full_result.auto_score);
    if (full_result.final_score > 0) {
        printf("Финальная оценка: %d/100\n", full_result.final_score);
    }
    
    // Сообщения об ошибках
    if (full_result.error_message[0] != '\0') {
        printf("Ошибка: %s\n", full_result.error_message);
    }
    
    if (full_result.teacher_comment[0] != '\0') {
        printf("Комментарий преподавателя: %s\n", full_result.teacher_comment);
    }
    
    // Производительность
    if (full_result.exec_time_ms > 0) {
        printf("Время выполнения: %d мс\n", full_result.exec_time_ms);
    }
    
    if (full_result.memory_used_kb > 0) {
        printf("Использовано памяти: %d КБ\n", full_result.memory_used_kb);
    }
    
    // Отправленный код (первые строки)
    if (full_result.code[0] != '\0') {
        printf("\n--- Отправленный код (первые 10 строк) ---\n");
        const char *code_ptr = full_result.code;
        int line_count = 0;
        while (*code_ptr && line_count < 10) {
            const char *line_end = strchr(code_ptr, '\n');
            if (line_end) {
                printf("%.*s\n", (int)(line_end - code_ptr), code_ptr);
                code_ptr = line_end + 1;
                line_count++;
            } else {
                printf("%s\n", code_ptr);
                break;
            }
        }
        if (strlen(full_result.code) > 0 && line_count == 10) {
            printf("... (полный код: %zu символов)\n", strlen(full_result.code));
        }
        printf("----------------------------------------\n");
    }
    
    printf("==========================================\n");
    
    return CLIENT_OK;

}	
        
void client_timer(client_ctx_t *ctx) {
    if (!ctx) return;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    } else if (pid == 0) {
        ping_pong(ctx);
        _exit(0);
    } else {
        ctx->timer_pid = pid;
    }
    return;
}


// Функции утилиты
static char read_whole_file(const char *path, char **out_buf, size_t *out_len) {
    if (!out_buf || !out_len) return -1;
    *out_buf = NULL;
    *out_len = 0;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    buf[n] = '\0';
    *out_buf = buf;
    *out_len = n;
    return CLIENT_OK;
}

static void strip_newline(char *s) {
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n') {
        s[len - 1] = '\0';
    }
}

static void remove_directory_recursive(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) {
        return;
    }

    struct dirent *entry;
    char full_path[CLIENT_FS_PATH_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path),
                "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                remove_directory_recursive(full_path);
                rmdir(full_path);
            } else {
                unlink(full_path);
            }
        }
    }

    closedir(dir);
    rmdir(path);
}

void open_external_editor(const char *file_path) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return;
    }

    if (pid == 0) {
		setenv("LANG", "ru_RU.UTF-8", 1);
        setenv("LC_ALL", "ru_RU.UTF-8", 1);
		
        // Пробуем vim
        execlp("vim", "vim", file_path, NULL);
        // Если vim не найден, пробуем nano
        execlp("nano", "nano", file_path, NULL);
        // Если nano не найден, пробуем vi
        execlp("vi", "vi", file_path, NULL);
        
        // Если ничего не сработало
        fprintf(stderr, "Ошибка: не найден ни один редактор (vim, nano, vi)\n");
        fprintf(stderr, "Установите редактор или отредактируйте файл вручную: %s\n", file_path);
        _exit(1);
    }

    waitpid(pid, NULL, 0);
}

void password_create(const char *password, uint8_t salt[MAX_SALT_LEN], uint8_t hashA[SHA_LEN]) {  
    
    struct sha256_buff ctx;
    sha256_init(&ctx);
    
    // Входные данные: пароль (переменная длина) + соль (MAX_SALT_LEN байт)
    sha256_update(&ctx, salt, MAX_SALT_LEN);
    sha256_update(&ctx, (uint8_t*)password, strlen(password));
    
    sha256_finalize(&ctx);  
    sha256_read(&ctx, hashA);  
}

int parse_tests_txt_to_array(const char *txt, size_t len,
                             test_case_t *out_array, size_t array_capacity,
                             size_t *out_count) {
    if (!txt || !out_array || !out_count) return -1;

    *out_count = 0;

    const char *p = txt;
    const char *end = txt + len;

    while (p < end && *out_count < array_capacity) {
        // Ищем "INPUT:"
        const char *in_tag = strstr(p, "INPUT:");
        if (!in_tag || in_tag >= end) break;

        const char *in_start = in_tag + strlen("INPUT:");
        // Пропускаем перевод строки после INPUT:
        while (in_start < end && (*in_start == '\n' || *in_start == '\r' || *in_start == ' ' || *in_start == '\t')) 
            in_start++;

        const char *exp_tag = strstr(in_start, "EXPECTED:");
        if (!exp_tag || exp_tag >= end) break;

        const char *in_end = exp_tag;
        // Убираем переводы строк и пробелы в конце input
        while (in_end > in_start && 
               (in_end[-1] == '\n' || in_end[-1] == '\r' || 
                in_end[-1] == ' ' || in_end[-1] == '\t'))
            in_end--;

        const char *exp_start = exp_tag + strlen("EXPECTED:");
        // Пропускаем перевод строки после EXPECTED:
        while (exp_start < end && (*exp_start == '\n' || *exp_start == '\r' || *exp_start == ' ' || *exp_start == '\t')) 
            exp_start++;

        const char *next_in = strstr(exp_start, "INPUT:");
        const char *exp_end = next_in ? next_in : end;
        // Убираем переводы строк и пробелы в конце expected
        while (exp_end > exp_start && 
               (exp_end[-1] == '\n' || exp_end[-1] == '\r' || 
                exp_end[-1] == ' ' || exp_end[-1] == '\t'))
            exp_end--;

        // Получаем текущий тест
        test_case_t *tc = &out_array[*out_count];
        tc->id = (int)(*out_count + 1);
        tc->problem_id = 0; // будет заполнено позже

        // Копируем input
        size_t input_len = (size_t)(in_end - in_start);
        if (input_len >= MAX_TEST_INPUT_LEN - 1) 
            input_len = MAX_TEST_INPUT_LEN - 1; // оставляем место для '\0'
        
        if (input_len > 0) {
            // Используем memcpy вместо strncpy для гарантированного копирования
            memcpy(tc->input, in_start, input_len);
        }
        tc->input[input_len] = '\0'; // Гарантируем нулевое завершение

        // Копируем expected
        size_t expected_len = (size_t)(exp_end - exp_start);
        if (expected_len >= MAX_TEST_OUTPUT_LEN - 1) 
            expected_len = MAX_TEST_OUTPUT_LEN - 1; // оставляем место для '\0'
        
        if (expected_len > 0) {
            // Используем memcpy вместо strncpy для гарантированного копирования
            memcpy(tc->expected, exp_start, expected_len);
        }
        tc->expected[expected_len] = '\0'; // Гарантируем нулевое завершение

        // Дополнительная очистка от начальных пробелов/табуляций
        // Убираем пробелы в начале input
        char *ptr = tc->input;
        while (*ptr == ' ' || *ptr == '\t') {
            memmove(ptr, ptr + 1, strlen(ptr));
        }
        
        // Убираем пробелы в начале expected
        ptr = tc->expected;
        while (*ptr == ' ' || *ptr == '\t') {
            memmove(ptr, ptr + 1, strlen(ptr));
        }

        (*out_count)++;
        p = exp_end;
    }

    return 0;
}

void debug_print_tests(const problem_info_t *problem) {
    printf("\n=== DEBUG: TESTS IN PROBLEM ===\n");
    printf("Total tests: %zu\n", problem->test_count);
    
    for (size_t i = 0; i < problem->test_count; i++) {
        printf("\n--- Test %zu ---\n", i + 1);
        printf("ID: %d, Problem ID: %d\n", 
               problem->test_cases[i].id, 
               problem->test_cases[i].problem_id);
        
        printf("Input (length by strlen: %zu):\n", 
               strlen(problem->test_cases[i].input));
        printf("'%s'\n", problem->test_cases[i].input);
        
        printf("\nExpected (length by strlen: %zu):\n", 
               strlen(problem->test_cases[i].expected));
        printf("'%s'\n", problem->test_cases[i].expected);
        
        // Вывод сырых байтов (первые 50)
        printf("\nRaw input bytes (hex, first 50): ");
        for (int j = 0; j < 50 && j < strlen(problem->test_cases[i].input) + 1; j++) {
            printf("%02X ", (unsigned char)problem->test_cases[i].input[j]);
        }
        printf("\n");
    }
    printf("=== END DEBUG ===\n\n");
}
			   	   	

static void ping_pong(client_ctx_t *ctx) {
    while (ctx->connected) {
        sleep(30); // Пинг каждые 30 секунд

        pthread_mutex_lock(&ctx->socket_mutex);
        protocol_header_t header = {
            .magic = PROTOCOL_MAGIC,
            .type = MSG_PING,
            .flags = 0,
            .payload_size = 0,
            .seq_id = ctx->seq_id++
        };

        char result = client_send_packet(ctx, &header, NULL, 0);
        if (result != CLIENT_OK) {
            fprintf(stderr, "Failed to send ping: %d\n", result);
            return;
        }

        protocol_header_t response;
        result = client_receive_packet(ctx, &response, NULL, 0);
        if (result != CLIENT_OK || response.type != MSG_PONG) {
            fprintf(stderr, "Failed to receive pong: %d\n", result);
            return;
        }
        pthread_mutex_unlock(&ctx->socket_mutex);
    }
}
						   	   	

int main() {
    client_ctx_t client;

    char err = client_init(&client, CLIENT_SERVER_IP, CLIENT_SERVER_PORT);
    if (err != CLIENT_OK) {
        fprintf(stderr, "client_init failed: %d\n", err);
        return EXIT_FAILURE;
    }
    client_timer(&client);

    client_greeting(&client);

    if (client.session.role == ROLE_STUDENT) {
        client_student_menu(&client);
    } else if (client.session.role == ROLE_TEACHER) {
        client_teacher_menu(&client);
    }

    client_cleanup(&client);
    return EXIT_SUCCESS;
}
