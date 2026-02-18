#define _GNU_SOURCE

#include "headers/server.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

// держим открытым и залоченным до конца жизни демона
static int g_pidfile_fd = -1;

// Закрытие и удаление
void server_pidfile_close_and_remove(server_ctx_t *srv) {
    if (!srv) return;

    if (g_pidfile_fd >= 0) {                            // если реально открыт
        flock(g_pidfile_fd, LOCK_UN);                   // снимаем блокировку
        close(g_pidfile_fd);                            // закрываем дескриптор
        g_pidfile_fd = -1;                              // сбрасываем состояние
    }

    if (srv->pidfile_path[0] != '\0') {                 // если путь сохранён
        unlink(srv->pidfile_path);                      // удаляем
    }
    SERVER_LOG_INFO("PID file removed", NULL);
}

// Открытие pidfile, lock и запись PID текущего процесса
static char pidfile_open_lock_write(const char *pidfile_path) {
    if (!pidfile_path || pidfile_path[0] == '\0') {
        SERVER_LOG_ERROR("Invalid pidfile path", NULL);
        return (char)SERVER_ERR_INVALID_ARG;
    }

    int fd = open(pidfile_path, O_RDWR | O_CREAT, SERVER_PIDFILE_MODE); // открываем
    if (fd < 0) {
        SERVER_LOG_ERROR("Failed to open pidfile: %s", strerror(errno));                                       
        return (char)SERVER_ERR_IO;                    
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {             // пытаемся залочить
        SERVER_LOG_ERROR("Failed to lock pidfile (is another instance running?)", NULL);
        close(fd);                                      
        return (char)SERVER_ERR_BUSY;                   
    }

    if (ftruncate(fd, 0) < 0) {                         // очищаем файл
        SERVER_LOG_INFO("Failed to truncate pidfile", NULL);
        flock(fd, LOCK_UN);                             
        close(fd);                                    
        return (char)SERVER_ERR_IO;           
    }

    char buf[64];                                       // буфер под PID строкой
    int len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (len <= 0 || write(fd, buf, (size_t)len) != len) {
        SERVER_LOG_ERROR("Failed to write to pidfile", NULL);
        flock(fd, LOCK_UN);                           
        close(fd);                                     
        return (char)SERVER_ERR_IO;                    
    }

    g_pidfile_fd = fd;                                  // сохраняем fd
    SERVER_LOG_INFO("PID file created at %s", pidfile_path);
    return (char)SERVER_OK;                            
}

// Закрыть все fd кроме pidfile
static void close_all_fds_except(int keep_fd) {
    struct rlimit rl;                                   // лимиты на количество fd
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {           
        for (int fd = 3; fd < SERVER_FD_FALLBACK_MAX; fd++) {            
            if (fd != keep_fd) close(fd);               // закрываем все кроме keep_fd
        }
        return;                                         
    }

    for (int fd = 3; fd < (int)rl.rlim_max; fd++) {     // закрываем всё, что выше stdio
        if (fd != keep_fd) close(fd);                   // оставляем только pidfile fd
    }
}

// Собственно демонизация: double-fork setsid pidfile редирект stdio
char server_daemonize(server_ctx_t *srv, const char *pidfile_path) {
    if (!srv || !pidfile_path) {                        // валидация
        SERVER_LOG_ERROR("Invalid arguments to server_daemonize", NULL);
        return (char)SERVER_ERR_INVALID_ARG;            // неверный аргумент
    }

    memset(srv->pidfile_path, 0, sizeof(srv->pidfile_path));      // чистим путь
    snprintf(srv->pidfile_path, sizeof(srv->pidfile_path), "%s", pidfile_path); // и сохраняем

    pid_t pid = fork();                                 // первый fork
    if (pid < 0) {                                      // если fork не удался
        SERVER_LOG_ERROR("First fork failed in daemonize", NULL);
        return (char)SERVER_ERR_GENERIC;
    }
    if (pid > 0) {                                      // родитель
        SERVER_LOG_INFO("First parent closing...", NULL);
        _exit(0);
    }

    if (setsid() < 0) {                                 // создаём новую сессию
        SERVER_LOG_ERROR("setsid failed in daemonize", NULL);
        return (char)SERVER_ERR_GENERIC;
    }

    pid = fork();                                       // второй fork
    if (pid < 0) {
        SERVER_LOG_ERROR("Second fork failed in daemonize", NULL);   
        return (char)SERVER_ERR_GENERIC;                
    }
    if (pid > 0) {                                      // промежуточный родитель
        SERVER_LOG_INFO("Second parent closing...", NULL);
        _exit(0);
    }

    // Остаётся финальный демон
    umask(SERVER_DAEMON_UMASK);
    
    char rc = pidfile_open_lock_write(pidfile_path);    // создаём лочим pidfile 
    if (rc != (char)SERVER_OK) {
        SERVER_LOG_ERROR("Failed to create and lock pidfile", NULL);
        return rc;
    }

    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) {                                   // если не открылся
        SERVER_LOG_ERROR("Failed to open /dev/null", NULL);
        server_pidfile_close_and_remove(srv);           // чистим pidfile
        return (char)SERVER_ERR_IO;
    }

    if (dup2(nullfd, STDIN_FILENO) < 0) {               // stdin -> /dev/null
        SERVER_LOG_ERROR("Failed to redirect stdin to /dev/null", NULL);
        close(nullfd);                                  // закрываем /dev/null
        server_pidfile_close_and_remove(srv);
        return (char)SERVER_ERR_IO;
    }
    if (dup2(nullfd, STDOUT_FILENO) < 0) {              // stdout -> /dev/null
        SERVER_LOG_ERROR("Failed to redirect stdout to /dev/null", NULL);
        close(nullfd);
        server_pidfile_close_and_remove(srv);
        return (char)SERVER_ERR_IO;
    }
    if (dup2(nullfd, STDERR_FILENO) < 0) {              // stderr -> /dev/null
        SERVER_LOG_ERROR("Failed to redirect stderr to /dev/null", NULL);
        close(nullfd);
        server_pidfile_close_and_remove(srv);
        return (char)SERVER_ERR_IO;
    }

    if (nullfd > STDERR_FILENO) {                       // если это не 0/1/2
        close(nullfd);
    }

    close_all_fds_except(g_pidfile_fd);                 // закрываем всё прочее
    srv->daemon_mode = true;                            // помечаем режим демона в контексте

    SERVER_LOG_INFO("Daemonization complete", NULL);
    return (char)SERVER_OK;                             
}
