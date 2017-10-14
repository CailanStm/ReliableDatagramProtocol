#ifndef helpers_h
#define helpers_h

#include <stddef.h>
#include <netinet/in.h>

// Prints an address in a human readable way. For debugging
void printAddress(const struct sockaddr_in* sockAddress, const socklen_t length);

// Converts a string in-place to all upper case
void stringToUpper(char* string, size_t length);

// Prints an error message for the given function that caused the error
void print_error(const char* error_function);

// Converts a string to a int, including error checking
int string_to_int(const char* input_string);

int get_full_path(char* full_path, size_t full_path_size, const char* relative_path);

long get_curr_time_ms();

#endif // helpers_h
