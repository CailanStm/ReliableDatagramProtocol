#ifndef rdp_constants_h
#define rdp_constants_h

enum { RDP_MAX_PACKET_SIZE = 1024 };

enum { MAGIC_FIELD_LENGTH = 6 };

enum { TYPE_FIELD_INDEX = MAGIC_FIELD_LENGTH };
enum { TYPE_FIELD_LENGTH = 3 };

enum { SEQ_ACK_FIELD_INDEX = TYPE_FIELD_INDEX + TYPE_FIELD_LENGTH };
enum { SEQ_ACK_FIELD_LENGTH = 5 };

enum { PAYLOAD_WINDOW_FIELD_INDEX = SEQ_ACK_FIELD_INDEX + SEQ_ACK_FIELD_LENGTH };
enum { PAYLOAD_WINDOW_FIELD_LENGTH = 6 };

enum { BLANK_LINE_FIELD_INDEX = PAYLOAD_WINDOW_FIELD_INDEX + PAYLOAD_WINDOW_FIELD_LENGTH };
enum { BLANK_LINE_FIELD_LENGTH = 4 };

enum { RDP_HEADER_LENGTH = BLANK_LINE_FIELD_INDEX + BLANK_LINE_FIELD_LENGTH };

enum { RDP_MAX_PAYLOAD_SIZE = RDP_MAX_PACKET_SIZE - RDP_HEADER_LENGTH};
		
int set_type(char* rdp_packet, const char* type);
void extract_type(const char* rdp_packet, char* output_type);

int set_seq_ack_num(char* rdp_packet, int number);
int extract_seq_ack_num(const char* rdp_packet);

int set_payload_window_size(char* rdp_packet, int size);
int extract_payload_window_size(const char* rdp_packet);

int set_blank_line(char* rdp_packet);
void set_packet_default_header(char* rdp_packet);

int get_max_seq_ack_num();
int get_max_payload_window_size();

// returns -1 if seq_num is before ack_num, 0 if they are equal, 1
// if seq_num is after ack_num (handles rollover)
int compare_seq_num(int seq_num, int ack_num);

void print_packet(const char* rdp_packet, int size);

void print_log(char event_type, char* sender_ip, int sender_port, char* dest_ip, 
			int dest_port, char* packet_type, int seq_ack_num, int payload_window_size);
			
void print_final_stats(int total_data_bytes, int unique_data_bytes, int total_data_packets,
						int unique_data_packets, int num_syn, int num_fin, int num_rst_1,
						int num_ack, int num_rst_2, long total_time_msec, int sender);

#endif // rdp_constants_h