CC = gcc

SOURCE_DIR = ./source
EXEC_DIR = ./bin

CFLAGS_SERVER = -g
CFLAGS_CLIENT = -g
# CFLAGS += -pthread

SERVER_SOURCES = server_daemon.c sha256.c database.c
CLIENT_SOURCES = sha256.c

SERVER_SOURCES_PATH = $(SERVER_SOURCES:%.c=$(SOURCE_DIR)/%.c)
CLIENT_SOURCES_PATH = $(CLIENT_SOURCES:%.c=$(SOURCE_DIR)/%.c)

SERVER_EXEC = server
CLIENT_EXEC = client

PID_FILE = leetcoded.pid
LOG_FILE = server.log


all: $(EXEC_DIR)/$(SERVER_EXEC) $(EXEC_DIR)/$(CLIENT_EXEC)


$(EXEC_DIR)/$(SERVER_EXEC): $(SERVER_EXEC).c $(SERVER_SOURCES_PATH)
	mkdir -p $(EXEC_DIR)
	$(CC) $(CFLAGS_SERVER) -o $@ $^


$(EXEC_DIR)/$(CLIENT_EXEC): $(CLIENT_EXEC).c $(CLIENT_SOURCES_PATH)
	mkdir -p $(EXEC_DIR)
	$(CC) $(CFLAGS_CLIENT) -o $@ $^


run_server: $(EXEC_DIR)/$(SERVER_EXEC)
	./$<


run_client: $(EXEC_DIR)/$(CLIENT_EXEC)
	./$<

kill_server:
	@if [ -f "$(PID_FILE)" ]; then \
		PID=$$(cat "$(PID_FILE)" 2>/dev/null); \
		if [ -n "$$PID" ] && ps -p "$$PID" > /dev/null 2>&1; then \
			echo "Stopping server with PID $$PID"; \
			kill $$PID; \
			sleep 1; \
		fi; \
	fi
	@rm -f $(PID_FILE)
	@echo "PID file removed"

clean_log:
	@rm -f $(LOG_FILE)
	@echo "Log file removed"

clean_bin:
	@rm -rf $(EXEC_DIR) runtime src 
	@echo "Folders removed"

clean_database:
	@rm -rf database
	@echo "Database folder removed"

clean: kill_server clean_log clean_bin
clean_all: clean clean_database
rebuild: clean all

.PHONY: all run_server run_client kill_server clean_log clean_bin clean_database clean clean_all rebuild
