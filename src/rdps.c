#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include "helpers.h"
#include "rdp_packets.h"

typedef enum sent_type { SEND_ERR, DAT, FIN } sent_type;
typedef enum recv_type { RCV_ERR, ACK, RST, TIMEOUT } recv_type;
int TIMEOUT_VALUE_MS = 30;

typedef struct connection_info 
{
	int next_sequence_num;
	int largest_seq_sent;
	int last_ack_received;
	int curr_window_size;
	int last_window_size_received;
	int bytes_sent_not_acked;
	long last_time_received;
	
	int total_dat_packets_sent;
	int total_dat_bytes_sent;
	int unique_dat_packets_sent;
	int unique_dat_bytes_sent;
	
	int syn_sent;
	int fin_sent;
	int rst_sent;
	int ack_received;
	int rst_received;
	
	long start_time_msec;
	
	struct sockaddr_in* dest_address;
	char* sender_ip;
	size_t sender_port;
} connection_info;

typedef struct timer_info 
{
	long* timestamps;
	int* expected_acks;
	int max_num_timestamps;
	int earliest_index;
	int num_timestamps;
} timer_info;

int start_timer(timer_info* timers, int expected_ack)
{
	if (timers->num_timestamps > timers->max_num_timestamps)
	{
		printf("ERROR: Too many timers: %d\n", timers->num_timestamps);
		return -1;
	}
	
	int next_index = timers->earliest_index + timers->num_timestamps;
	if (next_index >= timers->max_num_timestamps)
	{
		next_index = next_index - timers->max_num_timestamps;
	}
	
	timers->timestamps[next_index] = get_curr_time_ms();
	timers->expected_acks[next_index] = expected_ack;
	timers->num_timestamps++;
	
	if (timers->num_timestamps == 1)
	{
		timers->earliest_index = next_index;
	}
	
	return 1;
}

void reset_timers(timer_info* timers)
{
	memset(timers->timestamps, 0, sizeof(long) * timers->max_num_timestamps);
	memset(timers->expected_acks, 0, sizeof(int) * timers->max_num_timestamps);
	timers->earliest_index = 0;
	timers->num_timestamps = 0;
}

void clear_old_timers(timer_info* timers, int ack_received)
{
	int i;
	int index = timers->earliest_index;
	int original_num_timestamps = timers->num_timestamps;
	
	for (i = 0; i < original_num_timestamps; i++)
	{
		if (index == timers->max_num_timestamps)
		{
			index = 0;
		}
		
		if (compare_seq_num(timers->expected_acks[index], ack_received) <= 0)
		{
			timers->num_timestamps--;
		}
		else
		{
			timers->earliest_index = index;
			break;
		}
		
		index++;
	}
}

void initialize_timers(timer_info* timers, int MAX_NUM_TIMERS)
{
	timers->timestamps = malloc(sizeof(long) * MAX_NUM_TIMERS);
	memset(timers->timestamps, 0, sizeof(long) * MAX_NUM_TIMERS);
	timers->expected_acks = malloc(sizeof(int) * MAX_NUM_TIMERS);
	memset(timers->expected_acks, 0, sizeof(int) * MAX_NUM_TIMERS);
	timers->earliest_index = 0;
	timers->num_timestamps = 0;
	timers->max_num_timestamps = MAX_NUM_TIMERS;
}

void check_timers(timer_info* timers, connection_info* curr_connection, FILE** file_data)
{
	if (timers->num_timestamps > 0 && get_curr_time_ms() - timers->timestamps[timers->earliest_index] > TIMEOUT_VALUE_MS)
	{
		// timer expired - resend data
		size_t num_unacked_bytes = curr_connection->bytes_sent_not_acked;
		
		// move file pointer back in the file
		fseek(*file_data, -num_unacked_bytes, SEEK_CUR);
		
		// move sequence number back
		curr_connection->next_sequence_num -= num_unacked_bytes;
		if (curr_connection->next_sequence_num < 0)
		{
			curr_connection->next_sequence_num += get_max_seq_ack_num();
		}
		
		// reset the timers
		reset_timers(timers);

		curr_connection->bytes_sent_not_acked = 0;
	}
}

void print_log_sender(connection_info* curr_connection, const char* packet)
{
	int seq_ack_num = extract_seq_ack_num(packet);
	char event_type = '\0';
	
	char packet_type[4];
	memset(packet_type, 0, 4);
	extract_type(packet, packet_type);
	
	char sending_ip[20] = "";
	int sending_port;
	char receiving_ip[20] = "";
	int receiving_port;
	
	if (strncmp(packet_type, "ACK", 3) == 0)
	{
		// we received this packet
		curr_connection->ack_received++;		
		event_type = 'r';
		if (compare_seq_num(seq_ack_num, curr_connection->last_ack_received) <= 0)
		{
			event_type = 'R';
		}
		
		strcpy(sending_ip, inet_ntoa(curr_connection->dest_address->sin_addr));
		sending_port = ntohs(curr_connection->dest_address->sin_port);
		strcpy(receiving_ip, curr_connection->sender_ip);
		receiving_port = curr_connection->sender_port;
	}
	else
	{
		// we sent this packet		
		int payload_size = extract_payload_window_size(packet);
		
		if (strncmp(packet_type, "SYN", 3) == 0)
		{
			curr_connection->syn_sent++;
		}
		else if (strncmp(packet_type, "FIN", 3) == 0)
		{
			curr_connection->fin_sent++;
		}
		else if (strncmp(packet_type, "DAT", 3) == 0)
		{
			curr_connection->total_dat_packets_sent++;
			curr_connection->total_dat_bytes_sent += payload_size;
		}
		
		event_type = 's';
		if (compare_seq_num(seq_ack_num, curr_connection->largest_seq_sent) <= 0)
		{
			// we are resending this packet
			event_type = 'S';
		}
		else if (strncmp(packet_type, "DAT", 3) == 0)
		{
			curr_connection->unique_dat_packets_sent++;
			curr_connection->unique_dat_bytes_sent += payload_size;
		}
		
		strcpy(receiving_ip, inet_ntoa(curr_connection->dest_address->sin_addr));
		receiving_port = ntohs(curr_connection->dest_address->sin_port);
		strcpy(sending_ip, curr_connection->sender_ip);
		sending_port = curr_connection->sender_port;
	}
	
	int payload_window_size = extract_payload_window_size(packet);
	
	print_log(event_type, sending_ip, sending_port, receiving_ip, receiving_port,
				packet_type, seq_ack_num, payload_window_size);
}


void print_rst_log(connection_info* curr_connection, int sent)
{
	char packet_type[4] = "RST";
	char event_type = '\0';
	
	char sending_ip[20] = "";
	int sending_port;
	char receiving_ip[20] = "";
	int receiving_port;
	
	if (sent == 1)
	{
		event_type = 's';
		curr_connection->rst_sent++;
		
		strcpy(sending_ip, curr_connection->sender_ip);
		sending_port = curr_connection->sender_port;
		strcpy(receiving_ip, inet_ntoa(curr_connection->dest_address->sin_addr));
		receiving_port = ntohs(curr_connection->dest_address->sin_port);
	}
	else
	{
		event_type = 'r';
		curr_connection->rst_received++;
		
		strcpy(sending_ip, inet_ntoa(curr_connection->dest_address->sin_addr));
		sending_port = ntohs(curr_connection->dest_address->sin_port);
		strcpy(receiving_ip, curr_connection->sender_ip);
		receiving_port = curr_connection->sender_port;
	}
	
	print_log(event_type, sending_ip, sending_port, receiving_ip, receiving_port,
				packet_type, 0, 0);
}

void print_final_stats_sender(const connection_info* curr_connection)
{
	long curr_time = get_curr_time_ms();
	long time_elapsed = curr_time - curr_connection->start_time_msec;
	
	print_final_stats(curr_connection->total_dat_bytes_sent, curr_connection->unique_dat_bytes_sent,
					curr_connection->total_dat_packets_sent, curr_connection->unique_dat_packets_sent,
					curr_connection->syn_sent, curr_connection->fin_sent,
					curr_connection->rst_sent, curr_connection->ack_received,
					curr_connection->rst_received, time_elapsed, 1);
}

void handle_arguments(int argc, char* argv[], int* sender_port, char* sender_ip, int* receiver_port, char* receiver_ip, char* sender_file_name)
{	
	int valid_num_arguments = 6;
	
	if (argc != valid_num_arguments)
	{
		printf("Incorrect syntax for running sender.\nPlease use: ./rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\nExiting.\n");
		exit(EXIT_FAILURE);
	}
	
	int sender_ip_index = 1;
	int sender_port_index = 2;
	int receiver_ip_index = 3;
	int receiver_port_index = 4;
	int sender_file_name_index = 5;
	
	*sender_port = string_to_int(argv[sender_port_index]);
	if (*sender_port <= 0)
	{
		printf("Invalid sender port number specified.\nEnsure that syntax is correct: ./rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\nExiting.\n");
		exit(EXIT_FAILURE);
	}
	*receiver_port = string_to_int(argv[receiver_port_index]);
	if (*receiver_port <= 0)
	{
		printf("Invalid receiver port number specified.\nEnsure that syntax is correct: ./rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\nExiting.\n");
		exit(EXIT_FAILURE);
	}
	
	strcpy(sender_ip, argv[sender_ip_index]);
	strcpy(receiver_ip, argv[receiver_ip_index]);
	strcpy(sender_file_name, argv[sender_file_name_index]);
}

int setup_socket(int sender_port, const char* sender_ip)
{
	int sock = 0;
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	struct sockaddr_in sender_address;
	memset(&sender_address, 0, sizeof(sender_address));
	sender_address.sin_family = AF_INET;
	inet_pton(AF_INET, sender_ip, &(sender_address.sin_addr));
	sender_address.sin_port = htons(sender_port);
	
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
	{
		print_error("setsockopt");
	}
	
	if (bind(sock, (struct sockaddr*)&sender_address, sizeof sender_address) == -1)
	{
		print_error("bind");
		close(sock);
		exit(EXIT_FAILURE);
	}
	
	return sock;
}

int open_rdp_connection(int socket, connection_info* curr_connection)
{
	char packet[RDP_HEADER_LENGTH];
	set_packet_default_header(packet);
	
	set_type(packet, "SYN");
	
	int start_seq_num = rand() % get_max_seq_ack_num();
	set_seq_ack_num(packet, start_seq_num);
	curr_connection->next_sequence_num = start_seq_num;
	
	set_blank_line(packet);
	
	set_payload_window_size(packet, 0);
	
	if ( sendto(socket, packet, sizeof(packet),
		0, (struct sockaddr*)(curr_connection->dest_address), 
		sizeof(*(curr_connection->dest_address))) < 0 )
	{
		print_error("sendto");
	}
	
	print_log_sender(curr_connection, packet);
	curr_connection->largest_seq_sent = start_seq_num;	
	
	int num_tries_until_fail = 5;
	while (num_tries_until_fail > 0)
	{
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(socket, &read_fds);
		
		int num_fds = socket + 1;
		
		struct timeval timeout = {0, 2 * TIMEOUT_VALUE_MS * 1000};

		int select_result = select(num_fds, &read_fds, NULL, NULL, &timeout);

		if (select_result == 0)
		{
			// timeout occurred
			printf("SYN attempt timed out, trying again...\n");
			if (sendto(socket, packet, sizeof(packet),
				0, (struct sockaddr*)curr_connection->dest_address, sizeof(*(curr_connection->dest_address))) < 0)
			{
				print_error("sendto");
			}
			print_log_sender(curr_connection, packet);
			num_tries_until_fail--;
		}
		else if (select_result == -1)
		{
			print_error("select");
			close(socket);
			exit(EXIT_FAILURE);
		} 
		else if (FD_ISSET(socket, &read_fds))
		{
			char response[RDP_MAX_PACKET_SIZE];
			socklen_t destination_address_len = sizeof(*(curr_connection->dest_address));
			ssize_t receive_size = recvfrom(socket, (void*)response, sizeof(response), 0, 
					(struct sockaddr*)curr_connection->dest_address, &destination_address_len);
			char response_type[4];
			extract_type(response, response_type);
				
			if (receive_size < 0)
			{
				print_error("recvfrom");
				close(socket);
				exit(EXIT_FAILURE);
			}
			else if (strncmp(response_type, "ACK", 3) == 0 &&
						extract_seq_ack_num(response) == start_seq_num + 1)
			{
				print_log_sender(curr_connection, response);				
				curr_connection->last_window_size_received = extract_payload_window_size(response);
				curr_connection->curr_window_size = curr_connection->last_window_size_received;
				curr_connection->last_ack_received = extract_seq_ack_num(response);
				curr_connection->next_sequence_num = curr_connection->last_ack_received;
				curr_connection->start_time_msec = get_curr_time_ms();
				return 1;				
			}
			else
			{
				printf("Unexpected packet received during handshake: ");
				print_log_sender(curr_connection, response);
			}
		}
	}
	
	return -1;
}

// Points the FILE pointer to the actual file data
// Returns the file length, or -1 if an error occurred
long get_file_data(FILE** file_to_send_ptr, const char* filename)
{
	char filename_full[256];
	get_full_path(filename_full, sizeof(filename_full), filename);
	
	*file_to_send_ptr = fopen(filename_full, "r");
	long file_length = -1;
	
	if (*file_to_send_ptr)
	{
		fseek(*file_to_send_ptr, 0, SEEK_END);
		file_length = ftell(*file_to_send_ptr);
		fseek(*file_to_send_ptr, 0, SEEK_SET);
	}
	else
	{
		print_error("fopen");
		return -1;
	}
	
	return file_length;
}

recv_type listen_for_response(int socket, timer_info* timers, connection_info* curr_connection)
{
	char response[RDP_MAX_PACKET_SIZE];
	int peek_size = recvfrom(socket, response, RDP_MAX_PACKET_SIZE, MSG_PEEK | MSG_DONTWAIT, NULL, 0);
	while (peek_size > 0)
	{
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(socket, &read_fds);
		
		int num_fds = socket + 1;	
		struct timeval timeout = {0, TIMEOUT_VALUE_MS * 1000};
		int select_result = select(num_fds, &read_fds, NULL, NULL, &timeout);

		if (select_result == 0)
		{
			// timeout occurred - this will be handled automatically in main loop
			printf("timeout occurred in listen\n");
			return TIMEOUT;
		}
		else if (select_result == -1)
		{
			// actual failure with select (should not happen)
			print_error("select");
			close(socket);
			exit(EXIT_FAILURE);
		} 
		else if (FD_ISSET(socket, &read_fds))
		{
			char response[RDP_MAX_PACKET_SIZE];
			socklen_t destination_address_len = sizeof(*(curr_connection->dest_address));
			ssize_t receive_size = recvfrom(socket, (void*)response, sizeof(response), 0, 
					(struct sockaddr*)curr_connection->dest_address, &destination_address_len);
			char response_type[4];
			extract_type(response, response_type);
			
			curr_connection->last_time_received = get_curr_time_ms();
						
			if (receive_size < 0)
			{
				print_error("recvfrom");
				close(socket);
				exit(EXIT_FAILURE);
			}
			else if (strncmp(response_type, "ACK", 3) == 0)
			{
				print_log_sender(curr_connection, response);
				
				curr_connection->last_ack_received = extract_seq_ack_num(response);
				curr_connection->last_window_size_received = extract_payload_window_size(response);
				
				clear_old_timers(timers, curr_connection->last_ack_received);
			}
			else if (strncmp(response_type, "RST", 3) == 0)
			{
				return RST;
			}
			else
			{
				printf("Unexpected packet received.\n");
				return RCV_ERR;
			}
		}
		
		peek_size = recvfrom(socket, response, RDP_MAX_PACKET_SIZE, MSG_PEEK | MSG_DONTWAIT, NULL, 0);
	}
	
	return ACK;
}

sent_type send_data_window(int socket, FILE** file_data, long file_length, const char* filename, timer_info* timers, connection_info* curr_connection)
{	
	if (file_length == -1)
	{
		printf("Failed to read data from specified file. Exiting.\n");
		close(socket);
		exit(EXIT_FAILURE);
	}
	int remaining_window_space = curr_connection->curr_window_size;
	
	int end_of_file = 0;
	
	while (remaining_window_space >= RDP_MAX_PAYLOAD_SIZE)
	{
		int file_position_from_end = file_length - ftell(*file_data);
		if (file_position_from_end == 0)
		{
			return FIN;
		}
		
		size_t payload_size = RDP_MAX_PAYLOAD_SIZE;
		
		if (file_position_from_end < RDP_MAX_PAYLOAD_SIZE)
		{
			if (remaining_window_space >= file_position_from_end)
			{
				payload_size = file_position_from_end;
			}
			else
			{
				// need to wait until window size is large enough
				return DAT; 
			}
		}
		
		char packet[payload_size + RDP_HEADER_LENGTH];
		set_packet_default_header(packet);
		set_seq_ack_num(packet, curr_connection->next_sequence_num);
		set_type(packet, "DAT");
		
		char payload[payload_size];
		memset(payload, '\0', sizeof(payload));	
		set_payload_window_size(packet, sizeof(payload));
		
		int read_result = fread(payload, sizeof(payload), 1, *file_data);
		if (read_result != 1)
		{
			// reached end of file. send the data and then FIN
			end_of_file = 1;
		}
		memcpy(packet + RDP_HEADER_LENGTH, payload, sizeof(payload));
		
		
		int send_result = sendto(socket, packet, sizeof(packet), 0, 
							(struct sockaddr*)curr_connection->dest_address,
							sizeof(*(curr_connection->dest_address)));
		
		if (send_result < 0)
		{
			print_error("sendto");
			return SEND_ERR;
		}

		print_log_sender(curr_connection, packet); 
		
		// for determining if packets are duplicates
		if (compare_seq_num(curr_connection->next_sequence_num, curr_connection->largest_seq_sent) > 0)
		{
			curr_connection->largest_seq_sent = curr_connection->next_sequence_num;
		}
		
		curr_connection->next_sequence_num += sizeof(payload);
		curr_connection->next_sequence_num %= get_max_seq_ack_num(); //in case overflow has occurred
		
		start_timer(timers, curr_connection->next_sequence_num);
		
		remaining_window_space -= sizeof(payload);
	}

	if (end_of_file == 1)
	{
		return FIN;
	}
	else
	{
		return DAT;
	}
}

void send_rst(int sock, connection_info* curr_connection)
{
	char rst_packet[RDP_HEADER_LENGTH];
	set_packet_default_header(rst_packet);
	set_type(rst_packet, "RST");
	
	print_rst_log(curr_connection, 1);
	
	int bytes_sent = sendto(sock, rst_packet, sizeof(rst_packet), 0, 
								(struct sockaddr*)curr_connection->dest_address, 
								sizeof(*(curr_connection->dest_address)));
	if (bytes_sent < 0)
	{
		print_error("sendto");
		close(sock);
		exit(EXIT_FAILURE);
	}
}

void close_connection(int sock, timer_info* timers, connection_info* curr_connection)
{
	char fin_packet[RDP_HEADER_LENGTH];
	memset(fin_packet, '\0', sizeof(fin_packet));
	set_packet_default_header(fin_packet);
	set_type(fin_packet, "FIN");
	set_seq_ack_num(fin_packet, curr_connection->next_sequence_num);
	
	int connection_closed = 0;
	while (connection_closed == 0)
	{
		int send_result = sendto(sock, fin_packet, sizeof(fin_packet), 0, 
							(struct sockaddr*)curr_connection->dest_address,
							sizeof(*(curr_connection->dest_address)));
		if (send_result < 0)
		{
			print_error("fin sendto");
		}
		else
		{
			print_log_sender(curr_connection, fin_packet);
			long curr_time = get_curr_time_ms();
			long time_diff = 0;
			curr_connection->largest_seq_sent = curr_connection->next_sequence_num;
			
			while (time_diff < TIMEOUT_VALUE_MS)
			{
				listen_for_response(sock, timers, curr_connection);
				if (curr_connection->last_ack_received == curr_connection->next_sequence_num + 1)
				{
					connection_closed = 1;
					break;
				}
				time_diff = get_curr_time_ms() - curr_time;
			}
		}
	}
}

int main(int argc, char* argv[])
{
	srand(time(NULL));
	int sender_port = 0;
	char sender_ip[32];
	int receiver_port = 0;
	char receiver_ip[32];
	char sender_file_name[128];
	int MAX_NUM_TIMERS = 256;
	
	handle_arguments(argc, argv, &sender_port, sender_ip, &receiver_port, receiver_ip, sender_file_name);
	int sock = setup_socket(sender_port, sender_ip);
		
	struct sockaddr_in destination_address;
	memset(&destination_address, 0, sizeof(destination_address));
	destination_address.sin_family = AF_INET;
	inet_pton(AF_INET, receiver_ip, &(destination_address.sin_addr));
	destination_address.sin_port = htons(receiver_port);
	
	timer_info timers;
	memset(&timers, 0, sizeof(timers));
	
	connection_info curr_connection;
	memset(&curr_connection, 0, sizeof(curr_connection));
	curr_connection.sender_port = sender_port;
	
	curr_connection.sender_ip = malloc(sizeof sender_ip);
	memcpy(curr_connection.sender_ip, sender_ip, sizeof sender_ip);
	
	curr_connection.dest_address = malloc(sizeof destination_address);
	memcpy(curr_connection.dest_address, &destination_address, sizeof destination_address);
	
	int is_active = 1;
	
	while (is_active == 1)
	{		
		FILE* file_data = NULL;
		long file_length = get_file_data(&file_data, sender_file_name);
		
		// these values will ensure that the first packets are considered
		// to have come after these initial values
		curr_connection.last_ack_received = 2 * get_max_seq_ack_num(); 
		curr_connection.largest_seq_sent = 2 * get_max_seq_ack_num();
		curr_connection.last_time_received = get_curr_time_ms();
		
		int result = open_rdp_connection(sock, &curr_connection);
										
		if (result == -1)
		{
			printf("Too many SYN retries, give up.\n");
			close(sock); 
			exit(EXIT_FAILURE);
		}
		else
		{
			// Connection successfully opened
			initialize_timers(&timers, MAX_NUM_TIMERS);
			
			for (;;)
			{			
				if (get_curr_time_ms() - curr_connection.last_time_received > 5000)
				{
					printf("Connection timed out.\n");
					is_active = 0;
					print_final_stats_sender(&curr_connection);
					break;
				}
		
				check_timers(&timers, &curr_connection, &file_data);
		
				sent_type send_result = send_data_window(sock, &file_data, file_length, sender_file_name, &timers, &curr_connection);
				
				if (listen_for_response(sock, &timers, &curr_connection) == RST)
				{
					print_rst_log(&curr_connection, 0);	
					break;
				}
				
				if (send_result == FIN)
				{
					if (curr_connection.last_ack_received == curr_connection.next_sequence_num)
					{
						close_connection(sock, &timers, &curr_connection);
						is_active = 0;
						print_final_stats_sender(&curr_connection);
						break;
					}
				}
				else if (send_result == SEND_ERR)
				{
					send_rst(sock, &curr_connection);
					break;
				}
				
				curr_connection.bytes_sent_not_acked = curr_connection.next_sequence_num - curr_connection.last_ack_received;
				if (curr_connection.bytes_sent_not_acked < 0)
				{
					curr_connection.bytes_sent_not_acked = curr_connection.next_sequence_num + (get_max_seq_ack_num() - curr_connection.last_ack_received);
				}
				
				curr_connection.curr_window_size = curr_connection.last_window_size_received - curr_connection.bytes_sent_not_acked;
			}
			
			reset_timers(&timers);
		}
		
		fclose(file_data);	
	}
	
	free(timers.timestamps);
	free(timers.expected_acks);
	free(curr_connection.sender_ip);
	free(curr_connection.dest_address);
	close(sock); 
	return 0;
}

