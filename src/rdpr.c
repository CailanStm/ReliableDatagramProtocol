#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include "helpers.h"
#include "rdp_packets.h"

int MAX_WINDOW_SIZE = 10240;
enum accepted_type {ERR, DAT, FIN};

typedef struct connection_info 
{	
	int window_size;
	int next_expected_byte;
	struct sockaddr_in* source_address;
	char* receiver_ip;
	size_t receiver_port;
	int connection_established;

	int last_ack_sent;
	int total_dat_packets_received;
	int total_dat_bytes_received;
	int unique_dat_packets_received;
	int unique_dat_bytes_received; 
	
	int syn_received;
	int fin_received;
	int rst_received;
	int ack_sent;
	int rst_sent;
	
	int out_of_order_seq_nums[50]; // window size ensures that this many should never occur at one time
	int num_out_of_order_seq_nums;
	
	long start_time_msec;
	long finish_time_msec;
} connection_info;

void print_log_receiver(connection_info* curr_connection, const char* packet)
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
		// we sent this packet
		curr_connection->ack_sent++;
		event_type = 's';
		if (compare_seq_num(seq_ack_num, curr_connection->last_ack_sent) <= 0)
		{
			// we are resending this packet
			event_type = 'S';
		}
		
		strcpy(sending_ip, curr_connection->receiver_ip);
		sending_port = curr_connection->receiver_port;
		strcpy(receiving_ip, inet_ntoa(curr_connection->source_address->sin_addr));
		receiving_port = ntohs(curr_connection->source_address->sin_port);
	}
	else
	{
		// we received this packet		
		int payload_size = extract_payload_window_size(packet);
		int unique_receive = 1;
		
		if (strncmp(packet_type, "SYN", 3) == 0)
		{
			if (curr_connection->syn_received > 0)
			{
				unique_receive = 0;
			}
			curr_connection->syn_received++;
		}
		else if (strncmp(packet_type, "FIN", 3) == 0)
		{
			if (curr_connection->fin_received > 0)
			{
				unique_receive = 0;
			}
			curr_connection->fin_received++;
		}
		else if (strncmp(packet_type, "DAT", 3) == 0)
		{
			curr_connection->total_dat_packets_received++;
			curr_connection->total_dat_bytes_received += payload_size;
			
			int i;
			for (i = 0; i < curr_connection->num_out_of_order_seq_nums; i++)
			{
				if (seq_ack_num == curr_connection->out_of_order_seq_nums[i])
				{
					unique_receive = 0;
					break;
				}
			}
		}
		
		event_type = unique_receive == 0 ? 'R' : 'r';
		
		strcpy(sending_ip, inet_ntoa(curr_connection->source_address->sin_addr));
		sending_port = ntohs(curr_connection->source_address->sin_port);
		strcpy(receiving_ip, curr_connection->receiver_ip);
		receiving_port = curr_connection->receiver_port;
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
		
		strcpy(sending_ip, curr_connection->receiver_ip);
		sending_port = curr_connection->receiver_port;
		strcpy(receiving_ip, inet_ntoa(curr_connection->source_address->sin_addr));
		receiving_port = ntohs(curr_connection->source_address->sin_port);
	}
	else
	{
		event_type = 'r';
		curr_connection->rst_received++;
		
		strcpy(sending_ip, inet_ntoa(curr_connection->source_address->sin_addr));
		sending_port = ntohs(curr_connection->source_address->sin_port);
		strcpy(receiving_ip, curr_connection->receiver_ip);
		receiving_port = curr_connection->receiver_port;
	}
	
	print_log(event_type, sending_ip, sending_port, receiving_ip, receiving_port,
				packet_type, 0, 0);
}

void print_final_stats_receiver(const connection_info* curr_connection)
{
	long curr_time = get_curr_time_ms();
	long time_elapsed = curr_connection->finish_time_msec - curr_connection->start_time_msec;
	
	print_final_stats(curr_connection->total_dat_bytes_received, curr_connection->unique_dat_bytes_received,
					curr_connection->total_dat_packets_received, curr_connection->unique_dat_packets_received,
					curr_connection->syn_received, curr_connection->fin_received,
					curr_connection->rst_received, curr_connection->ack_sent,
					curr_connection->rst_sent, time_elapsed, 0);
}

// See documentation for format of the RDP header
int parse_header(const char* packet_data, size_t packet_length, char* message_type, size_t* seq_ack_num, size_t* payload_window_size)
{
	const char* blank_line = "\r\n\r\n";
	size_t blank_line_len = strlen(blank_line);
	
	if (strncmp(packet_data, "CSC361", MAGIC_FIELD_LENGTH) != 0)
	{
		printf("Invalid magic field.\n");
		return -1;
	}
	
	extract_type(packet_data, message_type);
	int seq_ack_temp = extract_seq_ack_num(packet_data);
	int payload_window_temp = extract_payload_window_size(packet_data);
	
	if (strncmp(packet_data + BLANK_LINE_FIELD_INDEX, blank_line, blank_line_len) != 0)
	{
		printf("Invalid packet: no blank line at end of header.\n");
		return -1;
	}
	
	if (seq_ack_temp < 0)
	{
		printf("Invalid sequence/ack number.\n");
		return -1;		
	}
	else if (payload_window_temp < 0)
	{
		printf("Invalid payload/window size.\n");
		return -1;
	}
	else
	{
		*seq_ack_num = seq_ack_temp;
		*payload_window_size = payload_window_temp;
	}
	
	// insert checksum handler here
	
	if (strcmp(message_type, "DAT") != 0 &&
		strcmp(message_type, "SYN") != 0 &&
		strcmp(message_type, "FIN") != 0 &&
		strcmp(message_type, "RST") != 0)
	{
		printf("Invalid message type.\n");
		return -1;
	}
	
	return 1;
}

// store an out of order seq num we received, so we can check for duplicates
void add_out_of_order_seq_num(connection_info* curr_connection, int seq_num)
{
	int i;
	for (i = 0; i < curr_connection->num_out_of_order_seq_nums; i++)
	{
		if (seq_num == curr_connection->out_of_order_seq_nums[i])
		{
			// no need to add it
			return;
		}
	}
	curr_connection->out_of_order_seq_nums[curr_connection->num_out_of_order_seq_nums] = seq_num;
	curr_connection->num_out_of_order_seq_nums++;
}

void clear_surpassed_seq_nums(connection_info* curr_connection)
{
	int initial_num = curr_connection->num_out_of_order_seq_nums;
	int i;
	int non_cleared_indices[initial_num];
	int k = 0;
	for (i = 0; i < initial_num; i++)
	{
		if (compare_seq_num(curr_connection->out_of_order_seq_nums[i], curr_connection->next_expected_byte) >= 0)
		{
			non_cleared_indices[k] = i;
			k++;
		}
		else
		{
			curr_connection->num_out_of_order_seq_nums--;
		}
	}
	
	int index = 0;
	for (i = 0; i < k; i++)
	{
		int next_non_cleared = non_cleared_indices[index];		
		curr_connection->out_of_order_seq_nums[i] = curr_connection->out_of_order_seq_nums[next_non_cleared];
		index++;
	}
}

void handle_arguments(int argc, char* argv[], int* receiver_port, char* receiver_ip, char* receiver_file_name)
{	
	int valid_num_arguments = 4;
	
	if (argc != valid_num_arguments)
	{
		printf("Incorrect syntax for starting receiver.\nPlease use: ./rdpr <receiver_ip> <receiver_port> <receiver_file_name>\nExiting.\n");
		exit(EXIT_FAILURE);
	}
	
	int receiver_ip_index = 1;
	int receiver_port_index = 2;
	int receiver_file_name_index = 3;
	
	*receiver_port = string_to_int(argv[receiver_port_index]);
	if (*receiver_port <= 0)
	{
		printf("Invalid port number specified.\nEnsure that syntax is correct: ./rdpr <receiver_ip> <receiver_port> <receiver_file_name>\nExiting.\n");
		exit(EXIT_FAILURE);
	}
	
	strcpy(receiver_ip, argv[receiver_ip_index]);
	strcpy(receiver_file_name, argv[receiver_file_name_index]);
}

int setup_socket(int receiver_port, const char* receiver_ip)
{
	int sock = 0;
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	struct sockaddr_in receiver_address;
	memset(&receiver_address, 0, sizeof(receiver_address));
	receiver_address.sin_family = AF_INET;
	inet_pton(AF_INET, receiver_ip, &(receiver_address.sin_addr));
	receiver_address.sin_port = htons(receiver_port);
	
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
	{
		print_error("setsockopt");
	}
	
	if (bind(sock, (struct sockaddr*)&receiver_address, sizeof receiver_address) == -1)
	{
		print_error("bind");
		close(sock);
		exit(EXIT_FAILURE);
	}
	
	return sock;
}

int open_file_for_write(FILE** file_ptr_out, const char* filename)
{
	char filename_full[256];
	if (get_full_path(filename_full, sizeof(filename_full), filename) == -1)
	{
		printf("Get full path failed.\n");
		return -1;
	}
	
	*file_ptr_out = fopen(filename_full, "w");
	if (*file_ptr_out == NULL)
	{
		print_error("fopen");
		return -1;
	}
}

// If -1 is returned, then connection was not successfully accepted
int accept_connection(int sock, const char* received_packet, size_t received_size, connection_info* curr_connection)
{
	if (received_size > RDP_MAX_PACKET_SIZE)
	{
		printf("Received a packet that is too large.\n");
		return -1;
	}
	
	char message_type[TYPE_FIELD_LENGTH + 1];
	memset(message_type, '\0', TYPE_FIELD_LENGTH);
	size_t seq_num = 0;
	size_t payload_size = 0;
	
	if (parse_header(received_packet, received_size, message_type, &seq_num, &payload_size) == -1)
	{
		printf("Parsing failed.\n");
		return -1;
	}
	
	char response_packet[RDP_HEADER_LENGTH];
	
	if (strcmp(message_type, "SYN") == 0)
	{
		curr_connection->next_expected_byte = (seq_num + 1) % get_max_seq_ack_num();
		curr_connection->window_size = MAX_WINDOW_SIZE;
		
		set_packet_default_header(response_packet);
		set_type(response_packet, "ACK");
		set_seq_ack_num(response_packet, curr_connection->next_expected_byte);
		set_payload_window_size(response_packet, curr_connection->window_size);
	}
	else
	{
		printf("Received unexpected packet type.\n");
		return -1;
	}
	
	int bytes_sent = sendto(sock, response_packet, sizeof(response_packet), 0, (struct sockaddr*)(curr_connection->source_address), sizeof(*(curr_connection->source_address)));
	if (bytes_sent < 0)
	{
		print_error("initial sendto");
		return -1;
	}
	
	print_log_receiver(curr_connection, response_packet);
	curr_connection->last_ack_sent = curr_connection->next_expected_byte;
	curr_connection->start_time_msec = get_curr_time_ms();
	curr_connection->connection_established = 1;
	
	return 1;
}

int write_data_to_file(FILE** output_file, const char* data, size_t data_length)
{
	if (data_length == 0)
	{
		return 1;
	}
	if (fwrite(data, data_length, 1, *output_file) != 1)
	{
		print_error("fwrite");
		fclose(*output_file);
		exit(EXIT_FAILURE);
	}
	
	return 1;
}

enum accepted_type accept_data(int sock, const char* received_packet, size_t received_size, connection_info* curr_connection, FILE** output_file)
{
	if (received_size > RDP_MAX_PACKET_SIZE)
	{
		printf("Received a packet that is too large.\n");
		return -1;
	}
	
	char message_type[TYPE_FIELD_LENGTH + 1];
	memset(message_type, '\0', TYPE_FIELD_LENGTH);
	size_t seq_num = 0;
	size_t payload_size = 0;
	
	if (parse_header(received_packet, received_size, message_type, &seq_num, &payload_size) == -1)
	{
		printf("Parsing failed.\n");
		// send reset???
		return ERR;
	}
	
	if (seq_num == curr_connection->next_expected_byte)
	{
		if (strncmp(message_type, "DAT", 3) == 0)
		{
			// send response before reading/writing the data
			char response_packet[RDP_HEADER_LENGTH];
			curr_connection->next_expected_byte = seq_num + payload_size;
			
			set_packet_default_header(response_packet);
			set_type(response_packet, "ACK");
			set_seq_ack_num(response_packet, curr_connection->next_expected_byte);
			
			curr_connection->window_size -= payload_size;
			set_payload_window_size(response_packet, curr_connection->window_size);
			
			// ensure that next_expected_byte is up to date, in case overflow occurred
			curr_connection->next_expected_byte = extract_seq_ack_num(response_packet);
			
			int bytes_sent = sendto(sock, response_packet, sizeof(response_packet), 0, 
									(struct sockaddr*)curr_connection->source_address, 
									sizeof(*(curr_connection->source_address)));
			if (bytes_sent < 0)
			{
				print_error("sendto");
				return ERR;
			}
			
			print_log_receiver(curr_connection, response_packet);
			curr_connection->last_ack_sent = curr_connection->next_expected_byte;
			
			curr_connection->unique_dat_packets_received++;
			curr_connection->unique_dat_bytes_received += payload_size;
			
			clear_surpassed_seq_nums(curr_connection);
			
			write_data_to_file(output_file, received_packet + RDP_HEADER_LENGTH, received_size - RDP_HEADER_LENGTH);
		}
		else if (strncmp(message_type, "FIN", 3) == 0)
		{
			char response_packet[RDP_HEADER_LENGTH];	
			set_packet_default_header(response_packet);
			set_type(response_packet, "ACK");
			set_seq_ack_num(response_packet, seq_num + 1);
			
			curr_connection->window_size -= payload_size;
			set_payload_window_size(response_packet, curr_connection->window_size);
			
			// ensure that next_expected_byte is up to date, in case overflow occurred
			curr_connection->next_expected_byte = extract_seq_ack_num(response_packet);
			
			int bytes_sent = sendto(sock, response_packet, sizeof(response_packet), 0, 
									(struct sockaddr*)curr_connection->source_address, 
									sizeof(*(curr_connection->source_address)));
			if (bytes_sent < 0)
			{
				print_error("sendto");
				return -1;
			}
			
			print_log_receiver(curr_connection, response_packet);
			curr_connection->last_ack_sent = curr_connection->next_expected_byte;
			
			return FIN;
		}
	}
	else if (strncmp(message_type, "DAT", 3) == 0 || strncmp(message_type, "FIN", 3) == 0)
	{
		char response_packet[RDP_HEADER_LENGTH];
		set_packet_default_header(response_packet);
		set_type(response_packet, "ACK");
		set_seq_ack_num(response_packet, curr_connection->next_expected_byte);
		set_payload_window_size(response_packet, curr_connection->window_size);
		
		int bytes_sent = sendto(sock, response_packet, sizeof(response_packet), 0, 
								(struct sockaddr*)curr_connection->source_address, 
								sizeof(*(curr_connection->source_address)));
		if (bytes_sent < 0)
		{
			print_error("sendto");
			return ERR;
		}
		
		print_log_receiver(curr_connection, response_packet);
		
		add_out_of_order_seq_num(curr_connection, seq_num);
		
		curr_connection->last_ack_sent = curr_connection->next_expected_byte;
	}
	
	curr_connection->window_size += payload_size;
	if (curr_connection->window_size > MAX_WINDOW_SIZE)
	{
		curr_connection->window_size = MAX_WINDOW_SIZE;
	}
	
	return DAT;
}

void send_rst(int sock, connection_info* curr_connection)
{
	char rst_packet[RDP_HEADER_LENGTH];
	set_packet_default_header(rst_packet);
	set_type(rst_packet, "RST");
	
	print_rst_log(curr_connection, 1);
	
	int bytes_sent = sendto(sock, rst_packet, sizeof(rst_packet), 0, 
								(struct sockaddr*)curr_connection->source_address, 
								sizeof(*(curr_connection->source_address)));
	if (bytes_sent < 0)
	{
		print_error("sendto");
		close(sock);
		exit(EXIT_FAILURE);
	}
}

void send_final_ack(int sock, connection_info* curr_connection)
{
	char response_packet[RDP_HEADER_LENGTH];
	set_packet_default_header(response_packet);
	set_type(response_packet, "ACK");
	set_seq_ack_num(response_packet, curr_connection->next_expected_byte);
	set_payload_window_size(response_packet, curr_connection->window_size);
	
	for (;;)
	{
		int bytes_sent = sendto(sock, response_packet, sizeof(response_packet), 0, 
									(struct sockaddr*)curr_connection->source_address, 
									sizeof(*(curr_connection->source_address)));
		if (bytes_sent < 0)
		{
			print_error("sendto");
			close(sock);
			exit(EXIT_FAILURE);
		}
		
		print_log_receiver(curr_connection, response_packet);
		curr_connection->last_ack_sent = curr_connection->next_expected_byte;
		curr_connection->finish_time_msec = get_curr_time_ms();
		
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);
		
		int num_fds = sock + 1;
		
		struct timeval timeout = {1, 0};
		int select_result = select(num_fds, &read_fds, NULL, NULL, &timeout);
		
		if (select_result == 0)
		{
			// timeout occurred - connection is finished
			return;
		}
		else if (select_result == -1)
		{
			print_error("select");
			close(sock);
			exit(EXIT_FAILURE);
		} 
		else if (FD_ISSET(sock, &read_fds))
		{
			// received something from sender - final ack must not have sent successfully
			printf("Resending final ack\n");
		}
	}
}

int main(int argc, char* argv[])
{	
	int receiver_port = 0;
	char receiver_ip[32];
	char receiver_file_name[128];
	handle_arguments(argc, argv, &receiver_port, receiver_ip, receiver_file_name);	
	int sock = setup_socket(receiver_port, receiver_ip);
	
	connection_info curr_connection;
	memset(&curr_connection, 0, sizeof(curr_connection));
	curr_connection.receiver_port = receiver_port;
	curr_connection.receiver_ip = malloc(sizeof receiver_ip);
	memcpy(curr_connection.receiver_ip, receiver_ip, sizeof receiver_ip);
	curr_connection.start_time_msec = get_curr_time_ms(); // will be overwritten on the receipt of a SYN
	curr_connection.finish_time_msec = get_curr_time_ms(); // will be overwritten during FIN
	
	struct sockaddr_in source_address_tmp;
	socklen_t source_addr_len = sizeof(source_address_tmp);
	curr_connection.source_address = malloc(source_addr_len);
	memcpy(curr_connection.source_address, &source_address_tmp, source_addr_len);
	
	int is_active = 1;

	while (is_active == 1)
	{
		// these values will ensure that the first packets are considered
		// to have come after these initial values
		curr_connection.last_ack_sent = 2 * get_max_seq_ack_num(); 
		memset(&(curr_connection.out_of_order_seq_nums), 0, 50);
		curr_connection.num_out_of_order_seq_nums = 0;
		curr_connection.connection_established = 0;
		
		FILE* output_file = NULL;
		if (open_file_for_write(&output_file, receiver_file_name) == -1)
		{
			printf("Could not open the specified file for writing.\n");
			exit(EXIT_FAILURE);
		}
		
		for(;;)
		{
			char packet_buffer[RDP_MAX_PACKET_SIZE] = "";
			
			ssize_t receive_size;
			
			fd_set read_fds;
			FD_ZERO(&read_fds);
			FD_SET(sock, &read_fds);			
			int num_fds = sock + 1;			
			struct timeval timeout = {5, 0};
			int select_result = select(num_fds, &read_fds, NULL, NULL, &timeout);
			
			if (select_result == 0)
			{
				// timeout occurred
				printf("Connection timed out.\n");
				is_active = 0;
				curr_connection.finish_time_msec = get_curr_time_ms();
				print_final_stats_receiver(&curr_connection);
				break;
			}
			else if (select_result == -1)
			{
				print_error("select");
				close(sock);
				exit(EXIT_FAILURE);
			} 
			else if (FD_ISSET(sock, &read_fds))
			{
				receive_size = recvfrom(sock, (void*)packet_buffer, sizeof(packet_buffer), 0, 
										(struct sockaddr*)(curr_connection.source_address), &source_addr_len);
				
				if (receive_size == -1)
				{
					print_error("recvfrom");
					send_rst(sock, &curr_connection);
					break;
				}
				
				print_log_receiver(&curr_connection, packet_buffer);
				
				char message_type[4];
				memset(message_type, '\0', 4);
				extract_type(packet_buffer, message_type);
				
				if (strncmp(message_type, "SYN", 3) == 0)
				{
					accept_connection(sock, packet_buffer, receive_size, &curr_connection);
				}
				else if (strncmp(message_type, "RST", 3) == 0)
				{
					print_rst_log(&curr_connection, 0);
					break;
				}
				else if (curr_connection.connection_established == 1)
				{
					enum accepted_type return_value;
					return_value = accept_data(sock, packet_buffer, receive_size, &curr_connection, &output_file);

					if (return_value == FIN)
					{
						send_final_ack(sock, &curr_connection);
						print_final_stats_receiver(&curr_connection);
						is_active = 0;
						break;
					}
					else if (return_value == ERR)
					{
						send_rst(sock, &curr_connection);
						break;
					}
				}
			}
		}
		
		fclose(output_file);
	}
	
	free(curr_connection.receiver_ip);
	free(curr_connection.source_address);
	close(sock);
	return 0;
}
