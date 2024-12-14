#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 256
#define MAX_KEY_LENGTH 128
#define MAX_VALUE_LENGTH 128

// Structure to store key-value pairs
typedef struct {
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
} ConfigEntry;

// Function to trim whitespace from a string
void trim_whitespace(char *str) {
    char *start = str;
    char *end;

    // Trim leading spaces
    while (isspace((unsigned char)*start)) start++;

    // Shift the trimmed string to the beginning
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }

    // Trim trailing spaces
    end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) end--;

    // Write the null terminator
    *(end + 1) = '\0';
}

// Function to find an existing key in the entries
int find_key(ConfigEntry *entries, int entry_count, const char *key) {
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].key, key) == 0) {
            return i; // Return the index of the matching key
        }
    }
    return -1; // Key not found
}

// Function to parse a configuration file
int parse_config_file(const char *filename, ConfigEntry *entries, int max_entries) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int entry_count = 0;

    while (fgets(line, sizeof(line), file)) {
        // Ignore comments and empty lines
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        trim_whitespace(line);
        if (*line == '\0') continue;

        // Split line into key and value
        char *delimiter = strchr(line, '=');
        if (!delimiter) {
            fprintf(stderr, "Invalid line (missing '='): %s\n", line);
            continue;
        }

        *delimiter = '\0';
        char *key = line;
        char *value = delimiter + 1;

        trim_whitespace(key);
        trim_whitespace(value);

        if (*key == '\0' || *value == '\0') {
            fprintf(stderr, "Invalid line (empty key or value): %s\n", line);
            continue;
        }

        // Check for duplicate keys
        int existing_index = find_key(entries, entry_count, key);
        if (existing_index != -1) {
            // Update the value of the existing key
            strncpy(entries[existing_index].value, value, MAX_VALUE_LENGTH - 1);
            entries[existing_index].value[MAX_VALUE_LENGTH - 1] = '\0';
        } else {
            if (entry_count >= max_entries) {
                fprintf(stderr, "Maximum entries reached, skipping remaining lines\n");
                break;
            }

            // Store the new key-value pair
            strncpy(entries[entry_count].key, key, MAX_KEY_LENGTH - 1);
            entries[entry_count].key[MAX_KEY_LENGTH - 1] = '\0';

            strncpy(entries[entry_count].value, value, MAX_VALUE_LENGTH - 1);
            entries[entry_count].value[MAX_VALUE_LENGTH - 1] = '\0';

            entry_count++;
        }
    }

    fclose(file);
    return entry_count;
}

// Test the configuration file parser
int main() {
    const char *filename = "config.conf";
    ConfigEntry entries[100];

    int entry_count = parse_config_file(filename, entries, 100);
    if (entry_count < 0) {
        fprintf(stderr, "Failed to parse configuration file\n");
        return 1;
    }

    printf("Parsed %d entries:\n", entry_count);
    for (int i = 0; i < entry_count; i++) {
        printf("%s = %s\n", entries[i].key, entries[i].value);
    }

    return 0;
}
