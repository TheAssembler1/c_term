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

#define PRINT_PROMPT() do {                                             \
    int get_hostname_stat = gethostname(hostname, MAX_HOSTNAME_SIZE);   \
    char *cwd = get_current_dir_name();                                 \
    if (get_hostname_stat == -1) {                                      \
        PRINT("[%s]$ ", cwd);                                           \
    } else {                                                            \
        PRINT("[%s]:[%s]$ ", hostname, cwd);                            \
    } \
    free(cwd); \
} while(0)

// return value must be freed with free_parsed_string
char** parse_string(char* str, const char* delim) {
    uint32_t cur_parts_max_size = 1;
    uint32_t idx = 0;
    char** parts = malloc((cur_parts_max_size + 1) * sizeof(char*));
    char* cur_part = strtok(str, delim);

    while(cur_part != NULL) {
        idx++;

        if(cur_parts_max_size <= idx) {
            cur_parts_max_size *= 2;
            parts = realloc(parts, (cur_parts_max_size + 1) * sizeof(char*));
        }

        parts[idx - 1] = strdup(cur_part);
        cur_part = strtok(NULL, delim);
    }

    parts[idx] = NULL;

    return parts;
}

// corresponding call to parse_string
void free_parsed_string(char** parts) {
    char* cur_part = NULL;
    int idx = 0;

    if(parts == NULL)
        return;

    while((cur_part = parts[idx]) != NULL) {
        free(cur_part);
        idx++;
    }
    free(parts);
}

// true if command was found and executed
static bool exec_path_command(char** cmd_parts, char* path) {
    DEBUG_PRINT("Attempting to execute cmd %s in path: %s\n", cmd_parts[0], path);

    // NULL and / must be added
    uint32_t path_len = strlen(cmd_parts[0]) + strlen(path) + 1;
    if(path_len > MAX_PATH_SIZE - 1) {
        DEBUG_PRINT("Path exceeds max size: %d\n", MAX_PATH_SIZE - 1);
        return false;
    }

    // folder + cmd_parts[0] + NULL
    char abs_path[MAX_PATH_SIZE];
    strcpy(abs_path, path);
    strcat(abs_path, "/");
    strcat(abs_path, cmd_parts[0]);

    DEBUG_PRINT("Actual absolute path: %s, length: %ld\n", abs_path, strlen(abs_path));

    // make sure we can execute file
    if (access(abs_path, X_OK) != 0) {
        DEBUG_PRINT("File was not executable by user\n");
        return false;
    } else
        DEBUG_PRINT("Able to access file\n");

    pid_t pid;
    // we are the child
    if((pid = fork()) == 0) {
        int cur_part = 0;
        DEBUG_PRINT("Logging cmd parts:\n");
        while(cmd_parts[cur_part] != NULL) {
            DEBUG_PRINT("\tPart %d, str length: %ld, name: %s\n", 
                cur_part, strlen(cmd_parts[cur_part]), cmd_parts[cur_part]);
            cur_part++;
        }
        int exit_stat = execv(abs_path, cmd_parts);
        free_parsed_string(cmd_parts);
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
    char** paths = NULL;
    char* env_path = NULL;
    char** cmd_parts = NULL

    DEBUG_PRINT("Executing Command: %s\n", line_buffer);

    env_path = strdup(getenv("PATH"));
    if(env_path == NULL) {
        PRINT("Command not found\n");
        free(env_path);
        return;
    }
    DEBUG_PRINT("Current env path: %s\n", env_path);

    // get cmd parts
    cmd_parts = parse_string(line_buffer, " ");
    if (cmd_parts[0] == NULL) {
        goto done;
    }

    // check if it is a builtin cmd
    if(strcmp(cmd_parts[0], "cd") == 0) {
        char resolved_path[MAX_PATH_SIZE];
        if(cmd_parts[1] == NULL)
            strcpy(resolved_path, getenv("HOME"));
        else if (realpath(cmd_parts[1], resolved_path) != NULL)
            DEBUG_PRINT("Full path: %s\n", resolved_path);
        if(chdir(resolved_path) == -1)
            PRINT("%s: No such file or directory\n", cmd_parts[0]);
        goto done;
    }
    if(strcmp(cmd_parts[0], "exit") == 0) {
        exit(0);
    }
    if(strcmp(cmd_parts[0], "pwd") == 0) {
        char *cwd = get_current_dir_name();
        PRINT("%s\n", cwd);
        goto done;
    }
    if(strcmp(cmd_parts[0], "help") == 0) {
        PRINT("Git gud\n");
        goto done;
    }
    if(strcmp(cmd_parts[0], "echo") == 0) {
        if(cmd_parts[1] != NULL)
            PRINT("%s\n", cmd_parts[1]);
        goto done;
    }


    // iterate through paths
    paths = parse_string(env_path, ":");
    bool executed_cmd = false;
    uint32_t idx = 0;
    while(paths[idx] != NULL) {
        if(executed_cmd = exec_path_command(cmd_parts, paths[idx]))
            break;
        idx++;
    }

    if(!executed_cmd)
        DEBUG_PRINT("Command not found\n");
    else 
        DEBUG_PRINT("Command executed successfully\n");
    
done:
    if(env_path != NULL)
        free(env_path);
    if(paths != NULL)
        free_parsed_string(paths);
    if(cmd_parts != NULL)
        free_parsed_string(cmd_parts);
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
