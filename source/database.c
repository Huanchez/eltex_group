#include "headers/server.h"

char server_db_get_problem_list(const char *problems_dir,
                            problem_info_t **out_problems,
                            size_t *out_count) {
    SERVER_LOG_INFO("server_db_get_problem_list: start", NULL);
    *out_problems = NULL;
    *out_count = 0;

	if (!problems_dir || !out_problems || !out_count) {
        SERVER_LOG_ERROR("Invalid arguments to server_db_get_problem_list",NULL);
        return SERVER_ERR_INVALID_ARG;
    }

    DIR *dir;
    struct dirent *entry;
    char path[MAX_DB_PATH_LEN];

    SERVER_LOG_INFO("Opening problems directory: %s", problems_dir);
    dir = opendir(problems_dir);
    if(!dir) {
        SERVER_LOG_ERROR("Failed to open problems directory: %s", problems_dir);
        return SERVER_ERR_DB;
    }
    
    size_t problem_count = 0;
    
    // Первый проход: подсчет файлов .bin
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        const char *ext = strrchr(entry->d_name, '.');
        if (ext && (strcmp(ext, ".bin") == 0)) {
            problem_count++;
        }
        SERVER_LOG_INFO("Found task file: %s", entry->d_name);
    }

    SERVER_LOG_INFO("Total problem files found: %zu", problem_count);

    if (problem_count == 0) {
        SERVER_LOG_WARN("No problems found in directory: %s", problems_dir);
        closedir(dir);
        return SERVER_OK;  // Нет задач - не ошибка
    }

    problem_info_t *problems = malloc(problem_count * sizeof(problem_info_t));
    if (!problems) {
        closedir(dir);
        SERVER_LOG_ERROR("Memory allocation failed for %zu problems", problem_count);
        return SERVER_ERR_NOMEM;  
    }

    rewinddir(dir);

    size_t idx = 0;

    // Второй проход: загрузка задач
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        const char *ext = strrchr(entry->d_name, '.');
        if (ext && (strcmp(ext, ".bin") == 0)) {
            snprintf(path, sizeof(path), "%s/%s", problems_dir, entry->d_name);
            
            if (load_problem_from_bin_file(path, &problems[idx]) != SERVER_OK) {
				// Ошибка загрузки одной задачи
				free(problems);
				closedir(dir);
				SERVER_LOG_ERROR("Failed to load task file: %s", path);
				return SERVER_ERR_DB;
			}
            idx++;
        }
    }

    closedir(dir);

    *out_problems = problems;
    *out_count = problem_count;

    SERVER_LOG_INFO("server_db_get_problem_list: loaded %zu problems", problem_count);
    return SERVER_OK;
}
                        
char save_problem_to_bin_file(const problem_info_t *problem, const char *filename) {
    SERVER_LOG_INFO("Saving problem to file: %s", filename);
    FILE *f = fopen(filename, "wb");
    if (!f) return SERVER_ERR_DB;
    
    // Пишем фиксированные поля
    if (fwrite(problem->title, sizeof(problem->title), 1, f) != 1 ||
        fwrite(&problem->problem_id, sizeof(problem->problem_id), 1, f) != 1 ||
        fwrite(&problem->description, sizeof(problem->description), 1, f) != 1 ||
        fwrite(&problem->time_limit_ms, sizeof(problem->time_limit_ms), 1, f) != 1 ||
        fwrite(&problem->memory_limit_kb, sizeof(problem->memory_limit_kb), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to write fixed fields", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    // Пишем заголовок
    size_t header_size = problem->header_size;
    if (fwrite(&header_size, sizeof(header_size), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to write header size", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    if (header_size > 0) {
        if (fwrite(problem->problem_header, 1, header_size, f) != header_size) {
            SERVER_LOG_ERROR("Failed to write problem header", NULL);
            fclose(f);
            return SERVER_ERR_DB;
        }
    }
    
    // Пишем test_count
    size_t test_count = problem->test_count;
    if (fwrite(&test_count, sizeof(test_count), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to write test count", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    // Пишем тесты
    for (size_t i = 0; i < test_count; i++) {
        const test_case_t *test = &problem->test_cases[i];
        
        // Пишем фиксированные поля теста
        if (fwrite(&test->id, sizeof(test->id), 1, f) != 1 ||
            fwrite(&test->problem_id, sizeof(test->problem_id), 1, f) != 1) {
            SERVER_LOG_ERROR("Failed to write test metadata for test %zu", i);
            fclose(f);
            return SERVER_ERR_DB;
        }
        
        // Пишем input (включая нулевой байт)
        size_t input_len = strlen(test->input) + 1;
        if (fwrite(test->input, 1, input_len, f) != input_len) {
            SERVER_LOG_ERROR("Failed to write input for test %zu", i);
            fclose(f);
            return SERVER_ERR_DB;
        }
        
        // Пишем expected (включая нулевой байт)
        size_t expected_len = strlen(test->expected) + 1;
        if (fwrite(test->expected, 1, expected_len, f) != expected_len) {
            SERVER_LOG_ERROR("Failed to write expected for test %zu", i);
            fclose(f);
            return SERVER_ERR_DB;
        }
    }
    
    fclose(f);
    SERVER_LOG_INFO("Task successfully saved: %s", filename);
    return SERVER_OK;
}

static char load_problem_from_bin_file(const char *filename, problem_info_t *problem) {
    SERVER_LOG_INFO("Loading problem binary file: %s", filename);
    FILE *f = fopen(filename, "rb");
    if (!f) {
        SERVER_LOG_ERROR("Failed to open problem file: %s", filename);
        return SERVER_ERR_DB;
    }

    // Инициализируем нулями
    memset(problem, 0, sizeof(problem_info_t));
    
    // Читаем фиксированные поля
    if (fread(problem->title, sizeof(problem->title), 1, f) != 1 ||
        fread(&problem->problem_id, sizeof(problem->problem_id), 1, f) != 1 ||
        fread(&problem->description, sizeof(problem->description), 1, f) != 1 ||
        fread(&problem->time_limit_ms, sizeof(problem->time_limit_ms), 1, f) != 1 ||
        fread(&problem->memory_limit_kb, sizeof(problem->memory_limit_kb), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to read fixed fields", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    // Читаем заголовок
    size_t header_size;
    if (fread(&header_size, sizeof(header_size), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to read header size", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    if (header_size > MAX_CODE) {
        SERVER_LOG_ERROR("Header too large: %zu", header_size);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    problem->header_size = header_size;
    
    // Читаем заголовок задачи
    if (header_size > 0) {
        if (fread(problem->problem_header, 1, header_size, f) != header_size) {
            SERVER_LOG_ERROR("Failed to read problem header", NULL);
            fclose(f);
            return SERVER_ERR_DB;
        }
    }
    
    // Гарантируем нулевое завершение
    if (header_size < MAX_CODE) {
        problem->problem_header[header_size] = '\0';
    } else if (header_size > 0) {
        problem->problem_header[MAX_CODE - 1] = '\0';
    }
    
    // Читаем test_count
    size_t test_count;
    if (fread(&test_count, sizeof(test_count), 1, f) != 1) {
        SERVER_LOG_ERROR("Failed to read test count", NULL);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    if (test_count > MAX_TEST_COUNT) {
        SERVER_LOG_ERROR("Too many tests: %zu", test_count);
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    problem->test_count = test_count;
    
    // Читаем тесты
    for (size_t i = 0; i < test_count; i++) {
        test_case_t *test = &problem->test_cases[i];
        
        // Инициализируем тест нулями
        memset(test, 0, sizeof(test_case_t));
        
        // Читаем фиксированные поля теста
        if (fread(&test->id, sizeof(test->id), 1, f) != 1 ||
            fread(&test->problem_id, sizeof(test->problem_id), 1, f) != 1) {
            SERVER_LOG_ERROR("Failed to read test metadata for test %zu", i);
            fclose(f);
            return SERVER_ERR_DB;
        }
        
        // Читаем input (строку до нулевого байта)
        int ch;
        size_t pos = 0;
        while (pos < MAX_TEST_INPUT_LEN - 1) {
            ch = fgetc(f);
            if (ch == EOF) {
                SERVER_LOG_ERROR("Unexpected EOF while reading input for test %zu", i);
                fclose(f);
                return SERVER_ERR_DB;
            }
            
            test->input[pos] = (char)ch;
            
            if (ch == '\0') {
                break;
            }
            
            pos++;
        }
        
        // Если строка слишком длинная
        if (pos >= MAX_TEST_INPUT_LEN - 1) {
            test->input[MAX_TEST_INPUT_LEN - 1] = '\0';
            
            // Пропускаем остаток строки до нулевого байта
            while (1) {
                ch = fgetc(f);
                if (ch == EOF) {
                    SERVER_LOG_ERROR("Unexpected EOF while skipping long input for test %zu", i);
                    fclose(f);
                    return SERVER_ERR_DB;
                }
                if (ch == '\0') {
                    break;
                }
            }
            
            SERVER_LOG_WARN("Test %zu input truncated", i);
        }
        
        // Читаем expected (строку до нулевого байта)
        pos = 0;
        while (pos < MAX_TEST_OUTPUT_LEN - 1) {
            ch = fgetc(f);
            if (ch == EOF) {
                SERVER_LOG_ERROR("Unexpected EOF while reading expected for test %zu", i);
                fclose(f);
                return SERVER_ERR_DB;
            }
            
            test->expected[pos] = (char)ch;
            
            if (ch == '\0') {
                break;
            }
            
            pos++;
        }
        
        // Если строка слишком длинная
        if (pos >= MAX_TEST_OUTPUT_LEN - 1) {
            test->expected[MAX_TEST_OUTPUT_LEN - 1] = '\0';
            
            // Пропускаем остаток строки до нулевого байта
            while (1) {
                ch = fgetc(f);
                if (ch == EOF) {
                    SERVER_LOG_ERROR("Unexpected EOF while skipping long expected for test %zu", i);
                    fclose(f);
                    return SERVER_ERR_DB;
                }
                if (ch == '\0') {
                    break;
                }
            }
            
            SERVER_LOG_WARN("Test %zu output truncated", i);
        }
    }
    
    fclose(f);
    SERVER_LOG_INFO("Successfully loaded problem: %d", problem->problem_id);
    return SERVER_OK;
}

char server_db_get_problem_info(server_ctx_t *srv, 
                            const char *problem_id,
                            char *out_text,
                            size_t out_text_size);
char server_db_set_solution_status(server_ctx_t *srv, //
                              const char *student_login,
                              const char *problem_id,
                              problem_status_t status);
char server_db_get_solution_status(server_ctx_t *srv, //
                              const char *student_login,
                              const char *problem_id,
                              problem_status_t status);                              
char server_db_save_solution_result(server_ctx_t *srv,
                                   const char *student_login,
                                   const char *problem_id,
                                   const common_solution_result_t *result);
char server_db_get_users_list(const char *users_dir,
                               server_client_info_t **out_clients,
                               size_t *out_count){
    *out_clients = NULL;
    *out_count = 0;

	if (!users_dir || !out_clients || !out_count) {
        SERVER_LOG_ERROR("Invalid arguments to server_db_get_users_list",NULL);
        return SERVER_ERR_INVALID_ARG;
    }

    DIR *dir;
    struct dirent *entry;
    char path[MAX_DB_PATH_LEN];


    dir = opendir(users_dir);
    if(!dir) {
        return SERVER_ERR_DB;
    }
    
    size_t clients_count = 0;
    
    // Первый проход: подсчет файлов .bin
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        const char *ext = strrchr(entry->d_name, '.');
        if (ext && (strcmp(ext, ".bin") == 0)) {
            clients_count++;
        }
    }

    if (clients_count == 0) {
        closedir(dir);
        return SERVER_OK;  // Нет пользователей - не ошибка
    }

    server_client_info_t *users = malloc(clients_count * sizeof(server_client_info_t));
    if (!users) {
        closedir(dir);
        return SERVER_ERR_NOMEM;  
    }

    rewinddir(dir);

    size_t idx = 0;

    // Второй проход: загрузка пользователей
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        const char *ext = strrchr(entry->d_name, '.');
        if (ext && (strcmp(ext, ".bin") == 0)) {
            snprintf(path, sizeof(path), "%s/%s", users_dir, entry->d_name);
            
            if (load_user_from_bin_file(path, &users[idx]) != SERVER_OK) {
                // Ошибка загрузки одной задачи
                free(users); //Нет динамических полей в структуре
                closedir(dir);
                return SERVER_ERR_DB;
            }
            idx++;
        }
    }

    closedir(dir);

    *out_clients = users;
    *out_count = clients_count;

    return SERVER_OK;

}

static char load_user_from_bin_file(const char *filename, server_client_info_t *user) {
    FILE *f = fopen(filename, "rb");
    if (!f) return SERVER_ERR_DB;

    // Инициализируем нулями
    memset(user, 0, sizeof(server_client_info_t));
    
    // Читаем каждое поле отдельно
    if (fread(&user->id, sizeof(int), 1, f) != 1 ||
        fread(user->username, sizeof(char), MAX_USERNAME_LEN, f) != MAX_USERNAME_LEN ||
        fread(user->password_hash, sizeof(char), MAX_PASS_LEN, f) != MAX_PASS_LEN ||
        fread(user->salt, sizeof(char), MAX_SALT_LEN, f) != MAX_SALT_LEN ||
        fread(&user->role, sizeof(user_role_t), 1, f) != 1 ||
        fread(&user->online, sizeof(bool), 1, f) != 1 ||
        fread(&user->active_status, sizeof(problem_status_t), 1, f) != 1) {
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    fclose(f);
    return SERVER_OK;
}

char save_user_to_bin_file(const server_client_info_t *user, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) return SERVER_ERR_DB;
    
    // Пишем фиксированную часть
    if (fwrite(&user->id, sizeof(int), 1, f) != 1 ||
        fwrite(user->username, sizeof(char), MAX_USERNAME_LEN, f) != MAX_USERNAME_LEN ||
        fwrite(user->password_hash, sizeof(char), MAX_PASS_LEN, f) != MAX_PASS_LEN ||
        fwrite(user->salt, sizeof(char), MAX_SALT_LEN, f) != MAX_SALT_LEN ||
        fwrite(&user->role, sizeof(user_role_t), 1, f) != 1 ||
        fwrite(&user->online, sizeof(bool), 1, f) != 1 ||
        fwrite(&user->active_status, sizeof(problem_status_t), 1, f) != 1) {
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    fclose(f);
    return SERVER_OK;
}
                               
char load_solution_from_file(const char *filename, common_solution_result_t *solution) {
    if (!filename || !solution) return SERVER_ERR_INVALID_ARG;
    
    SERVER_LOG_INFO("Loading solution from: %s", filename);
    
    FILE *f = fopen(filename, "rb");
    if (!f) {
        SERVER_LOG_ERROR("Failed to open solution file: %s", filename);
        return SERVER_ERR_DB;
    }
    
    // Читаем всю структуру
    size_t n = fread(solution, 1, sizeof(common_solution_result_t), f);
    fclose(f);
    
    if (n != sizeof(common_solution_result_t)) {
        SERVER_LOG_ERROR("Corrupted solution file: %s ", filename);
        return SERVER_ERR_DB;
    }
    
    // Гарантируем нулевое завершение строк
    solution->username[sizeof(solution->username) - 1] = '\0';
    solution->code[sizeof(solution->code) - 1] = '\0';
    solution->teacher_comment[sizeof(solution->teacher_comment) - 1] = '\0';
    solution->error_message[sizeof(solution->error_message) - 1] = '\0';
    
    SERVER_LOG_INFO("Solution loaded: user=%s", solution->username);
    
    return SERVER_OK;
}
                 
problem_status_t get_problem_status_for_user(server_ctx_t *srv, 
                                            const char *username, 
                                            int problem_id) {
    if (!srv || !username) return PROBLEM_STATUS_NEW;
    
    char solution_file[MAX_PATH_LEN];
	int needed = snprintf(solution_file, sizeof(solution_file), 
						"%s/%s/%d.bin", srv->solutions_dir, username, problem_id);

	if (needed < 0) {
		SERVER_LOG_ERROR("Failed to format solution file path",NULL);
		return SERVER_ERR_DB; // или другой код ошибки
	} else if ((size_t)needed >= sizeof(solution_file)) {
		SERVER_LOG_ERROR("Solution file path too long", NULL);
		return SERVER_ERR_DB;
	}
    
    SERVER_LOG_INFO("Checking solution status: file=%s", solution_file);
    
    // Создаем директорию пользователя, если не существует
    char user_dir[MAX_PATH_LEN];
    
    needed = snprintf(user_dir, sizeof(user_dir), "%s/%s", srv->solutions_dir, username);

	if (needed < 0 || (size_t)needed >= sizeof(user_dir)) {
		return SERVER_ERR_DB;
	}
    mkdir(user_dir, TASKDIR_MODE);
    
    // Проверяем существование файла
    if (access(solution_file, F_OK) != 0) {
        SERVER_LOG_INFO("Solution file not found: %s", solution_file);
        return PROBLEM_STATUS_NEW;
    }
    
    // Загружаем решение
    common_solution_result_t solution;
    if (load_solution_from_file(solution_file, &solution) != SERVER_OK) {
        SERVER_LOG_WARN("Failed to load solution from %s", solution_file);
        return PROBLEM_STATUS_NEW;
    }
    
    return solution.status;
}

int save_solution_to_temp_file(const char *code, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        return 0;
    }
    
    size_t code_len = strlen(code);
    if (fwrite(code, 1, code_len, f) != code_len) {
        fclose(f);
        unlink(filename);
        return 0;
    }
    
    fclose(f);
    return 1;
}

char save_solution_to_file(const common_solution_result_t *solution, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) return SERVER_ERR_DB;
    
    // Пишем всю структуру за раз
    if (fwrite(solution, 1, sizeof(common_solution_result_t), f) != 
        sizeof(common_solution_result_t)) {
        fclose(f);
        return SERVER_ERR_DB;
    }
    
    fclose(f);
    return SERVER_OK;
}              

char load_solution_with_metrics(const char *filename, 
                               common_solution_result_t *solution,
                               int *exec_time_ms,
                               int *memory_used_kb) {
    
    if (load_solution_from_file(filename, solution) != SERVER_OK) {
        return SERVER_ERR_DB;
    }
    
    if (exec_time_ms) *exec_time_ms = solution->exec_time_ms;
    if (memory_used_kb) *memory_used_kb = solution->memory_used_kb;

    
    return SERVER_OK;
}                             
