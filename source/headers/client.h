#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "common.h"
#include "sha256.h" //Заголовочный файл для хэширования пароля

typedef message_type_t client_msg_type_t;

#define CLIENT_MAX_PATH_LEN         256
#define CLIENT_MAX_PAYLOAD_LEN      MAX_PAYLOAD_LEN
#define CLIENT_PING_INT_SEC         60
#define CLIENT_SERVER_IP            "127.0.0.1"
#define CLIENT_SERVER_PORT          12345
#define CLIENT_WORK_DIRECTORY       "src"
#define CLIENT_SOLUTIONS_DIRECTORY  "solutions"
#define CLIENT_PROBLEMS_DIRECTORY   "problems"
#define CLIENT_MENU_CHOICE_LEN      16
#define CLIENT_COMMENT_LEN          256
#define CLIENT_MAX_STUDENTS         100
#define CLIENT_FS_PATH_LEN          512
#define MAX_INPUT                   255
#define MAX_METADATA_INPUT          1024
#define CODE_PREVIEW                200
#define ANSWER_CHOICE_ACTION        8
#define SCORE_CHOICE                16


typedef enum {
    CLIENT_OK = 0,

    CLIENT_ERR_INVALID_ARGS,
    CLIENT_ERR_SOCKET_CREATE,
    CLIENT_ERR_INVALID_IP,
    CLIENT_ERR_MUTEX_INIT,
    CLIENT_ERR_WORKDIR_CREATE,
    CLIENT_ERR_LOGIN_ALREADY_EXISTS,
    CLIENT_ERR_NOT_CONNECTED,
    CLIENT_ERR_PROTOCOL,
    CLIENT_ERR_AUTH_FAILED,
    CLIENT_ERR_CONNECT,
    CLIENT_ERR_NETWORK,
    CLIENT_ERR_IO,
    CLIENT_ERR_TIMEOUT,
    CLIENT_ERR_NOMEM,

    CLIENT_ERR_UNKNOWN
} client_error_t;

/* Пользователь */
typedef struct {
    char server_ip[16];
    uint16_t server_port;
} client_config_t;

typedef struct {
    char username[MAX_LOGIN_LEN];
    user_role_t role;          // STUDENT/TEACHER
    bool logged_in;
    char session_token[MAX_TOKEN_LEN];      // Получен от сервера после успешного входа
    time_t session_expires;      // Когда истекает токен
} client_session_t;

/* Контекст клиента */
typedef struct {
    // Сеть
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t server_addr_len;
    bool connected;
    
    // Состояние
    conn_state_t state;
    client_session_t session;    // Текущая сессия
    
    // Настройки 
    client_config_t config;
    
    // Служебное
    uint32_t seq_id;
    pthread_mutex_t socket_mutex;
    
    // Буферы/кэш
    common_problem_t *problems_cache;     // Загруженные задачи
    size_t problems_count;

    pid_t timer_pid;
} client_ctx_t;

char client_init(client_ctx_t *ctx,
                const char *server_ip,
                uint16_t server_port);

void client_cleanup(client_ctx_t *ctx);

char client_send_packet(client_ctx_t *ctx,
                        const protocol_header_t *header,
                        const void *payload,
                        size_t payload_size);

char client_receive_packet(client_ctx_t *ctx,
                            protocol_header_t *header,
                            void *payload_buffer,
                            size_t buffer_size);

char client_auth(client_ctx_t *ctx,
                const char *login,
                const char *password);

char client_request_problem_list(client_ctx_t *ctx,
                             common_problem_t **problems,
                             size_t *problem_count);

char client_request_problem_header(client_ctx_t *ctx,
                                const int problem_id,
                                char *buffer,
                                size_t buffer_size);

// УДАЛИТЬ? 
void open_external_editor(const char *file_path);

char client_send_solution_file(client_ctx_t *ctx,
                                const int problem_id,
                                const char *solution_path);

char client_request_student_list(client_ctx_t *ctx,
                                char **student_logins,
                                size_t *student_count);

char client_request_student_problems(client_ctx_t *ctx,
                                 const char *student_login,
                                 common_problem_t **problems,
                                 size_t *problem_count);

char client_request_student_solution(client_ctx_t *ctx,
                                    const char *student_login,
                                    const int problem_id,
                                    char *solution_code, size_t buffer_size);

char client_update_problem_status(client_ctx_t *ctx,
                              const char *student_login,
                              const char *problem_id,
                              common_solution_result_t new_result);
                              
int parse_tests_txt_to_array(const char *txt, size_t len,
                             test_case_t *out_array, size_t array_capacity,
                             size_t *out_count);

char client_load_problem(client_ctx_t *ctx, problem_info_t *info, const char *problem_file_path);


char client_send_ping(client_ctx_t *ctx);

// УДАЛИТЬ? 

char client_register_user(client_ctx_t *ctx);

void client_greeting(client_ctx_t *ctx);

void client_print_problems(client_ctx_t *ctx);

void client_solve_problem(client_ctx_t *ctx, 
                          const common_problem_t *problem,
                          const char solution_exists);

char client_get_solution_result(client_ctx_t *ctx,  
                                    int problem_id, 
                                    common_solution_result_t *result);

char client_get_solution_result_list(client_ctx_t *ctx,
                                     common_problem_t **problems,
                                     size_t *problem_count);

char client_show_solution_result(const common_problem_t *problem, 
                                 const common_solution_result_t *result);

void client_teacher_menu(client_ctx_t *ctx);

void client_teacher_menu_problems(client_ctx_t *ctx);

void client_edit_problem(client_ctx_t *ctx, int is_new, 
                         common_problem_t *problem);

void client_edit_problem_metadata(problem_info_t *info);

void client_student_list(client_ctx_t *ctx);

void client_student_solutions_list(client_ctx_t *ctx);

void client_student_solution_checking(client_ctx_t *ctx, 
                                      const char *student_login, 
                                      const common_problem_t *problem);

void client_student_menu(client_ctx_t *ctx);

char client_send_teacher_create(client_ctx_t *ctx,
                                const char *username,
                                const char *password);

void password_create(const char *password, uint8_t salt[MAX_SALT_LEN], uint8_t hashA[SHA_LEN]);
                     
                     
char send_all(int fd, const void *buf, size_t len);

char recv_all(int fd, void *buf, size_t len);

static char read_whole_file(const char *path, char **out_buf, size_t *out_len);

const char* problem_status_to_string(problem_status_t status);

static void strip_newline(char *s);

static void ping_pong(client_ctx_t *ctx);

#endif /* CLIENT_H */
