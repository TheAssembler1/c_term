#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/stat.h>

#define LINE_BUFFER_SIZE 512
#define MAX_PATH_SIZE 512
#define MAX_CMD_PART_SIZE 64
#define MAX_CMD_PARTS 32
#define MAX_HOSTNAME_SIZE 512

#undef DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG_PRINT(message, ...) \
    fprintf(stderr, message, ##__VA_ARGS__)
#else 
#define DEBUG_PRINT(message, ...)
#endif
#define PRINT(message, ...) \
    fprintf(stdout, message, ##__VA_ARGS__); \
    fflush(stdout);
char hostname[MAX_HOSTNAME_SIZE];


#define PRINT_PROMPT() do {                                            \
    int get_hostname_stat = gethostname(hostname, MAX_HOSTNAME_SIZE); \
    char *cwd = get_current_dir_name();                             \
    if (get_hostname_stat == -1) {                                    \
        PRINT("[%s]$ ", cwd);                                         \
    } else {                                                            \
        PRINT("[%s]:[%s]$ ", hostname, cwd);                            \
    } \
    free(cwd); \
} while(0)


// return must be freed
char** parse_cmd(char* cmd) {
    char** cmd_parts = malloc(MAX_CMD_PARTS * sizeof(char*));
    uint32_t cur_part = 0;

    uint32_t i = 0;
    while (cmd[i] != '\0') {
        // Skip any spaces
        while (cmd[i] == ' ') i++;
        if (cmd[i] == '\0') break;

        // Start of token
        uint32_t start = i;

        // Find end of token
        while (cmd[i] != ' ' && cmd[i] != '\0') i++;

        uint32_t len = i - start;
        if (len >= MAX_CMD_PART_SIZE) len = MAX_CMD_PART_SIZE - 1;

        char* part = malloc(len + 1);
        memcpy(part, &cmd[start], len);
        part[len] = '\0';

        cmd_parts[cur_part++] = part;

        if (cur_part >= MAX_CMD_PARTS - 1) break;
    }

    cmd_parts[cur_part] = NULL;
    return cmd_parts;
}


// corresponding call to parse_cmd
void free_cmd_parts(char** cmd_parts) {
    uint32_t cur_part = 0;
    while(cmd_parts[cur_part] != NULL) {
        free(cmd_parts[cur_part]);
        cur_part++;
    }
    if(cmd_parts != NULL)
        free(cmd_parts);
}

// true if command was found and executed
static bool exec_path_command(char** cmd_parts, char* path, uint32_t start_loc, uint32_t end_loc) {
    DEBUG_PRINT("Attempting to execute cmd %s in path: \n", cmd_parts[0]);
    for(int i = start_loc; i <= end_loc; i++)
        DEBUG_PRINT("%c", path[i]);
    DEBUG_PRINT("\n");

    // NULL and / must be added
    uint32_t path_len = strlen(cmd_parts[0]) + end_loc - start_loc + 2;
    if(path_len > MAX_PATH_SIZE - 1) {
        DEBUG_PRINT("Path exceeds max size: %d\n", MAX_PATH_SIZE - 1);
        return false;
    }
    // folder + cmd_parts[0] + NULL
    char abs_path[MAX_PATH_SIZE];
    // folder
    memcpy(abs_path, &path[start_loc], end_loc - start_loc + 1);
    // / 
    abs_path[end_loc - start_loc + 1] = '/';
    // cmd_parts[0]
    memcpy(&abs_path[end_loc - start_loc + 2], cmd_parts[0], strlen(cmd_parts[0]));
    // NULl
    abs_path[path_len] = 0;

    DEBUG_PRINT("Actual absolute path: %s, length: %ld\n", abs_path, strlen(abs_path));

    // make sure we can execute file
    if (access(abs_path, X_OK) != 0) {
        DEBUG_PRINT("File was not executable by user\n");
        return false;
    }

    pid_t pid;
    // we are the child
    if((pid = fork()) == 0) {
        int cur_part = 0;
        DEBUG_PRINT("Logging cmd parts:\n");
        while(cmd_parts[cur_part] != NULL) {
            DEBUG_PRINT("\tPart %d, str length: %ld, name: %s\n", cur_part, strlen(cmd_parts[cur_part]), cmd_parts[cur_part]);
            cur_part++;
        }
        int exit_stat = execv(abs_path, cmd_parts);
        free_cmd_parts(cmd_parts);
        exit(exit_stat);
    } else { // we are the parent
        int exit_stat;
        wait(&exit_stat);
        DEBUG_PRINT("Child process returned: %d\n", exit_stat);
        return true;
    }

    return false;
}

static void exec_command(char* line_buffer) {
    DEBUG_PRINT("Executing Command: %s\n", line_buffer);

    char* env_path = getenv("PATH");
    if(env_path == NULL) {
        PRINT("Command not found\n");
        return;
    }

    DEBUG_PRINT("%s\n", env_path);

    // get cmd parts
    char** cmd_parts = parse_cmd(line_buffer);

    if (cmd_parts[0] == NULL) {
        free_cmd_parts(cmd_parts);
        return;
    }

    // iterate through paths
    uint32_t start_path_loc = 0;
    uint32_t end_path_loc = 0;
    bool executed_cmd = false;
    while(env_path[end_path_loc] != 0) {
        if(env_path[end_path_loc] == ':' || env_path[end_path_loc + 1] == 0) {
            if(env_path[end_path_loc + 1] == 0)
                end_path_loc++;

            // end_loc - 1 due to it pointing to ':'
            executed_cmd = exec_path_command(cmd_parts, env_path, start_path_loc, end_path_loc - 1);
            if(executed_cmd)
                break;
            // move past ':'
            end_path_loc++;
            start_path_loc = end_path_loc;
        } else 
            end_path_loc++;
    }

    if(!executed_cmd)
        PRINT("Command not found\n");
    
    free_cmd_parts(cmd_parts);
}

int main() {
    char line_buffer[LINE_BUFFER_SIZE];
    uint32_t cur_char_loc = 0;

    for(;;) {
        if(cur_char_loc == 0)
            PRINT_PROMPT();

        char c = getchar();

        if(c == EOF)
            break;

        // check if user hits enter
        if(c == '\n') {
            // user didn't input any string
            if(cur_char_loc == 0)
                continue;

            line_buffer[cur_char_loc] = 0;
            exec_command(line_buffer);
            // reset line buffer
            cur_char_loc = 0;
        } else { // check that we can fit next char in line buffer
            line_buffer[cur_char_loc] = c;
            cur_char_loc++;

            // we need to fit a NULL terminator and next char as well (hince... - 1)
            if(cur_char_loc + 1 >= LINE_BUFFER_SIZE - 1) {
                PRINT("Command exceeds max length of %d\n", LINE_BUFFER_SIZE - 1);
                cur_char_loc = 0;
                // get rest of chars from input buffer to reset
                while((char)getchar() != '\n') {};
            }
        }
    }

    return 0;
}
