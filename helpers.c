#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "helpers.h"

void printAddress(const struct sockaddr_in* sockAddress, const socklen_t length)
{
	printf("sock address: %d\n", sockAddress->sin_addr.s_addr);
	printf("sock address length: %d\n", length);
	printf("sock address family: %d\n", sockAddress->sin_family);
	printf("sock address port: %d\n", sockAddress->sin_port);
}

void stringToUpper(char* string, size_t length)
{
	int i;
	for (i = 0; i < length; i++)
	{
		string[i] = toupper(string[i]);
	}
}

void print_error(const char* error_function)
{
	fprintf(stderr, "ERROR: %s failed: %s\n", error_function, strerror(errno));
}

int string_to_int(const char* input_string)
{
	char* endptr;
	int result = strtol(input_string, &endptr, 10);
	if (endptr > input_string)
	{
		return result;
	}
	else
	{
		// Conversion failed
		return -1;
	}
}

int get_full_path(char* full_path, size_t full_path_size, const char* relative_path)
{
	if (getcwd(full_path, full_path_size) == NULL)
	{
		print_error("getcwd");
		return -1;
	}
	strcat(full_path, "/");
	strcat(full_path, relative_path);
}

long get_curr_time_ms()
{
	struct timespec curr_time;
	memset(&curr_time, 0, sizeof curr_time);
	clock_gettime(CLOCK_REALTIME, &curr_time);
	return curr_time.tv_sec * 1000 + curr_time.tv_nsec / 1000000;
}
	

