#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PROTOCOL_MAGIC       0xABCD1234

// Общие лимиты 
#define MAX_LOGIN_LEN     	64
#define MAX_PASS_LEN      	64
#define MAX_PROBLEM_ID_LEN  64
#define MAX_PATH_LEN      	256
#define MAX_PAYLOAD_LEN   	52048
#define MAX_SALT_LEN    	32
#define SHA_LEN    			32
#define MAX_TEST_COUNT		10
#define MAX_PROBLEMS_COUNT  100
#define MAX_CODE			12288
#define MAX_COMMENT			2048
#define MAX_RESULT_MESSAGE	256
#define MAX_TEST_INPUT_LEN	1024
#define MAX_TEST_OUTPUT_LEN	1024
#define MAX_ERROR_MSG_LEN	256
#define MAX_TOKEN_LEN	    65
#define MAX_USERNAME_LEN	50
#define MAX_FILE_LEN	    256
#define WORKDIR_MODE        0700
#define TASKDIR_MODE        0755
#define MAX_COMMAND_LEN 	4096
#define MAX_OUTPUT_LEN 	    8192



// Типы сообщений 
typedef enum {
    MSG_AUTH_START,
    MSG_AUTH_VERIFY,
    MSG_AUTH_OK,
    MSG_AUTH_FAIL,
    MSG_GET_PROBLEM_LIST,
    MSG_PROBLEM_LIST,
    MSG_GET_PROBLEM,
    MSG_PROBLEM_INFO,
    MSG_SEND_SOLUTION,
    MSG_SOLUTION_RESULT,
    MSG_GET_STUDENT_LIST,
    MSG_STUDENT_LIST_SIZE,
    MSG_STUDENT_LIST,
    MSG_GET_STUDENT_PROBLEMS,
    MSG_STUDENT_PROBLEMS,
    MSG_GET_STUDENT_SOLUTION,
    MSG_STUDENT_SOLUTION,
    MSG_UPDATE_PROBLEM_STATUS,
    MSG_LOAD_NEW_PROBLEM,
    MSG_UPDATE_PROBLEM,
    MSG_PING,
    MSG_PONG,
    MSG_ACK,
    MSG_ERROR,
    MSG_REGISTER_START,
    MSG_REGISTER_VERIFY,
    MSG_REGISTER_OK,
    MSG_REGISTER_FAIL,
    MSG_PROBLEM_CREATE,       
    MSG_PROBLEM_UPDATE,        
    MSG_PROBLEM_SAVED, 
    MSG_GET_SOLUTION_RESULTS_LIST, 
    MSG_SOLUTION_RESULTS_LIST,
    MSG_GET_SOLUTION_RESULT, 
    MSG_SOLUTION_RESULT_FULL
} message_type_t;

// Роль пользователя 
typedef enum {
    ROLE_STUDENT = 0,
    ROLE_TEACHER = 1
} user_role_t;

// Заголовок пакета
typedef struct {
    uint32_t magic;
    uint16_t type;           // message_type_t
    uint16_t flags;
    uint32_t payload_size;
    uint32_t seq_id;
} protocol_header_t;

// Состояние соединения 
typedef enum {
    CONN_STATE_NEW = 0,
    CONN_STATE_AUTHENTICATING,
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_EDITING,
    CONN_STATE_WAITING_RESULT,
    CONN_STATE_CLOSING
} conn_state_t;

// Статус задачи/решения 
typedef enum {
    PROBLEM_STATUS_NEW = 0,
    PROBLEM_STATUS_IN_PROGRESS,
    PROBLEM_STATUS_SENT,
    PROBLEM_STATUS_COMPILATION_ERROR,
    PROBLEM_STATUS_RUNTIME_ERROR,
    PROBLEM_STATUS_OUT_OF_TIME,
    PROBLEM_STATUS_OUT_OF_MEMORY,
    PROBLEM_STATUS_WRONG,
    PROBLEM_STATUS_ACCEPTED,
    PROBLEM_STATUS_REVIEW,
    PROBLEM_STATUS_COMPLETED,
    PROBLEM_STATUS_UNKNOWN
} problem_status_t;

// Универсальное описание задачи  
typedef struct {
    int problem_id;
    char title[256];
    char description[1024];
    int time_limit_ms;
    int memory_limit_kb;   
    problem_status_t status;
} common_problem_t;

typedef struct {
    int id;
    int problem_id;
    char input[1024];      
    char expected[1024];
} test_case_t;

typedef struct { //Передача всей задачи
    char title[100];
    char description[1024];
    int problem_id;
    char problem_header[MAX_CODE];      // текст заголовка (.h файл)
    size_t header_size;        // размер заголовка в байтах
    int time_limit_ms;
    int memory_limit_kb;
    test_case_t test_cases[MAX_TEST_COUNT];   // массив структур тестов
    size_t test_count;         // количество тестов
} problem_info_t;

typedef struct {
	char problem_header[MAX_CODE];      
    size_t header_size;        
} common_problem_header_t;

typedef struct {
    char student_login[MAX_LOGIN_LEN];  
    int problem_id;     
} solution_request_t;

 typedef struct {
     char student_login[MAX_LOGIN_LEN];  
     int problem_id;     
     problem_status_t status;
     char teacher_comment[MAX_COMMENT];
     int final_score;
} solution_update_stat_t;


typedef struct {
	int problem_id;
	char code[MAX_CODE];           // исходный код
}solution_code_t;

#pragma pack(push, 1)  // Убираем ВСЁ выравнивание
typedef struct {
    char username[MAX_LOGIN_LEN];
    int problem_id;
    char code[MAX_CODE];
    problem_status_t status;
    
    int auto_score;       // автоматическая оценка
    int final_score;      // финальная оценка (после проверки учителем)
    char teacher_comment[MAX_COMMENT];
    
    char error_message[MAX_ERROR_MSG_LEN];
    int exec_time_ms;     // время выполнения
    int memory_used_kb;   // использовано памяти

} common_solution_result_t;
#pragma pack(pop)

// Запрос на начало аутентификации 
typedef struct {
    char username[MAX_LOGIN_LEN];
} auth_start_request_t;

// Ответ с солью 
typedef struct {
    uint8_t salt[MAX_SALT_LEN];
} auth_challenge_t;

// Запрос с хэшем
typedef struct {
    uint8_t password_hash[SHA_LEN];  // Хэш(соль + пароль)
} auth_verify_request_t;

// Успешный ответ 
typedef struct {
    char session_token[MAX_TOKEN_LEN];
    uint32_t expires_in;  // секунды
    user_role_t role;
} auth_success_t;

typedef enum
{
    SOL_RES_ACCEPTED = 0,
    SOL_RES_COMPILE_ERROR,
    SOL_RES_RUNTIME_ERROR,
    SOL_RES_TIME_LIMIT,
    SOL_RES_WRONG_ANSWER
} solution_status_t;

typedef struct
{
    int32_t problem_id;           // какую задачу решаем
    uint32_t code_size;           // фактический размер кода
    char code[MAX_CODE]; // сам код 
} send_solution_request_t;

typedef struct
{
    solution_status_t status;         // OK / WRONG_ANSWER / RUNTIME_ERROR / COMPILE_ERROR
    uint32_t passed;
    uint32_t total;
    int32_t failed_test_index;        // -1 если нет
    char message[MAX_RESULT_MESSAGE]; // лог, ошибка компиляции, пояснение

} solution_result_t;

// Запрос на создание/обновление задачи
typedef struct {
    common_problem_t meta;     // title/desc/limits/problem_id
    uint32_t code_size;        // размер problem.c
    uint32_t tests_size;       // размер tests.txt
    uint8_t data[];
} problem_upload_request_t;

#endif /* COMMON_H */
