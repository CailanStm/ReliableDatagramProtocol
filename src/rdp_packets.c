#include <math.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "helpers.h"
#include "rdp_packets.h"

int set_type(char* rdp_packet, const char* type)
{
	if (strlen(type) != TYPE_FIELD_LENGTH)
	{
		return -1;
	}
	else
	{
		char* field_ptr = rdp_packet + TYPE_FIELD_INDEX;
		memcpy(field_ptr, type, TYPE_FIELD_LENGTH);
		return 1;
	}
}

void extract_type(const char* rdp_packet, char* type)
{
	const char* field_ptr = rdp_packet + TYPE_FIELD_INDEX;
	memcpy(type, field_ptr, TYPE_FIELD_LENGTH);
	type[TYPE_FIELD_LENGTH] = '\0';
}

int set_seq_ack_num(char* rdp_packet, int number)
{	
	if (number < 0)
	{
		return -1;
	}
	else
	{
		number %= get_max_seq_ack_num();
		
		// don't want to copy trailing \0
		char temp[SEQ_ACK_FIELD_LENGTH + 1];
		sprintf(temp, "%0*d", SEQ_ACK_FIELD_LENGTH, number);
		
		char* field_ptr = rdp_packet + SEQ_ACK_FIELD_INDEX;
		memcpy(field_ptr, temp, SEQ_ACK_FIELD_LENGTH);
		
		return 1;
	}
}

int extract_seq_ack_num(const char* rdp_packet)
{
	const char* field_ptr = rdp_packet + SEQ_ACK_FIELD_INDEX;
	char temp[SEQ_ACK_FIELD_LENGTH + 1];
	memset(temp, '\0', sizeof(temp));
	memcpy(temp, field_ptr, SEQ_ACK_FIELD_LENGTH);
	
	return string_to_int(temp);
}

int set_payload_window_size(char* rdp_packet, int size)
{	
	if (size < 0 || size > get_max_payload_window_size())
	{
		return -1;
	}
	else
	{
		char temp[PAYLOAD_WINDOW_FIELD_LENGTH + 1];
		sprintf(temp, "%0*d", PAYLOAD_WINDOW_FIELD_LENGTH, size);
		
		char* field_ptr = rdp_packet + PAYLOAD_WINDOW_FIELD_INDEX;
		memcpy(field_ptr, temp, PAYLOAD_WINDOW_FIELD_LENGTH);
		return 1;
	}
}

int extract_payload_window_size(const char* rdp_packet)
{
	const char* field_ptr = rdp_packet + PAYLOAD_WINDOW_FIELD_INDEX;
	char temp[PAYLOAD_WINDOW_FIELD_LENGTH + 1];
	memset(temp, '\0', sizeof(temp));
	memcpy(temp, field_ptr, PAYLOAD_WINDOW_FIELD_LENGTH);
	
	return string_to_int(temp);
}

int set_blank_line(char* rdp_packet)
{
	char* field_ptr = rdp_packet + BLANK_LINE_FIELD_INDEX;
	memcpy(field_ptr, "\r\n\r\n", BLANK_LINE_FIELD_LENGTH);
}

void set_packet_default_header(char* rdp_packet)
{
	memset(rdp_packet, '0', RDP_HEADER_LENGTH);
	memcpy(rdp_packet, "CSC361", 6);
	memcpy(rdp_packet + BLANK_LINE_FIELD_INDEX, "\r\n\r\n", BLANK_LINE_FIELD_LENGTH);
}

int get_max_seq_ack_num()
{
	return pow(10, SEQ_ACK_FIELD_LENGTH) - 1;
}

int get_max_payload_window_size()
{
	return pow(10, PAYLOAD_WINDOW_FIELD_LENGTH) - 1;
}

// returns -1 if seq_num is before ack_num, 0 if they are equal, 1
// if seq_num is after ack_num (handles rollover)
int compare_seq_num(int seq_num, int ack_num)
{
	if (seq_num == ack_num)
	{
		return 0;
	}
	
	int large_difference_threshold = get_max_seq_ack_num() *  4/5;
	
	int ack_difference = seq_num - ack_num;
		
	if (abs(ack_difference) > large_difference_threshold)
	{
		// sequence number rollover has occured
		if (ack_difference < 0)
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		if (ack_difference < 0)
		{
			return -1;
		}
		else
		{
			return 1;
		}
	}
}

void print_packet(const char* rdp_packet, int size)
{
	//printf("packet size: %d\n", size);
	printf("packet contents: ");
	int i;
	for (i = 0; i < size; i++)
	{
		char c = rdp_packet[i];
		if(c == '\0')
		{
			printf("\\0");
		}
		else if(c == '\n')
		{
			printf("\\n");
		}
		else if(c == '\r')
		{
			printf("\\r");
		}
		else
		{
			printf("%c", rdp_packet[i]);
		}
	}
	printf("\n");
}

void print_log(char event_type, char* sender_ip, int sender_port, char* dest_ip, 
			int dest_port, char* packet_type, int seq_ack_num, int payload_window_size)
{
	struct timespec curr_time;
	clock_gettime(CLOCK_REALTIME, &curr_time);
	
	int hours = ( curr_time.tv_sec / 3600 ) % 24;
	int minutes = ( curr_time.tv_sec % 3600 ) / 60;
	int seconds = (curr_time.tv_sec % 3600) % 60;
	long microseconds = curr_time.tv_nsec / 1000;
	
	hours -= 7; // UTC is 7 hours ahead
	if (hours < 0)
	{
		hours += 24;
	}
	
	printf("%02d:%02d:%02d.%06ld ", hours, minutes, seconds, microseconds);
									
	printf("%c %s:%d %s:%d %s %d %d\n", event_type, sender_ip, sender_port, dest_ip, 
										dest_port, packet_type, seq_ack_num, payload_window_size);
}

void print_final_stats(int total_data_bytes, int unique_data_bytes, int total_data_packets,
						int unique_data_packets, int num_syn, int num_fin, int num_rst_1,
						int num_ack, int num_rst_2, long total_time_msec, int sender)
{
	char suffix_one[10] = "";
	char suffix_two[10] = "";
	
	if (sender == 1)
	{
		strcpy(suffix_one, "sent");
		strcpy(suffix_two, "received");
	}
	else
	{
		strcpy(suffix_one, "received");
		strcpy(suffix_two, "sent");
	}
	
	printf("\n");
	printf("total data bytes %s: %d\n", suffix_one, total_data_bytes);
	printf("unique data bytes %s: %d\n", suffix_one, unique_data_bytes);
	printf("total data packets %s: %d\n", suffix_one, total_data_packets);
	printf("unique data packets %s: %d\n", suffix_one, unique_data_packets);
	printf("SYN packets %s: %d\n", suffix_one, num_syn);
	printf("FIN packets %s: %d\n", suffix_one, num_fin);
	printf("RST packets %s: %d\n", suffix_one, num_rst_1);
	printf("ACK packets %s: %d\n", suffix_two, num_ack);
	printf("RST packets %s: %d\n", suffix_two, num_rst_2);
	printf("total time duration (second): %.3f\n", total_time_msec / 1000.0);
}

