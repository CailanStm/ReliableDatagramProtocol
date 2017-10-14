#include <stdio.h>
#include <string.h>
#include "rdp_packets.h"

typedef struct connection_info 
{
	int next_expected_byte;
	int out_of_order_seq_nums[50];
	int num_out_of_order_seq_nums;
} connection_info;

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

int main()
{
	connection_info curr_connection;
	memset(&curr_connection, 0, sizeof curr_connection);
	
	curr_connection.out_of_order_seq_nums[0] = 80348;
	curr_connection.out_of_order_seq_nums[1] = 81348;
	curr_connection.out_of_order_seq_nums[2] = 82348;
	curr_connection.out_of_order_seq_nums[3] = 83348;
	curr_connection.out_of_order_seq_nums[4] = 84348;
	curr_connection.out_of_order_seq_nums[5] = 86348;
	curr_connection.out_of_order_seq_nums[6] = 87348;
	curr_connection.out_of_order_seq_nums[7] = 88348;
	curr_connection.out_of_order_seq_nums[8] = 85348;
	curr_connection.num_out_of_order_seq_nums = 9;
	
	curr_connection.next_expected_byte = 81348;
	// expected result: [81348 82348 83348 84348 86348 87348 88348 85348]
	clear_surpassed_seq_nums(&curr_connection);
	printf("num out of order remaining: %d\n", curr_connection.num_out_of_order_seq_nums);
	int i;
	printf("they are: [");
	for (i = 0; i < curr_connection.num_out_of_order_seq_nums; i++)
	{
		printf("%d ", curr_connection.out_of_order_seq_nums[i]);
	}
	printf("]\n");
	
	/*curr_connection.out_of_order_seq_nums[0] = 1356;
	curr_connection.out_of_order_seq_nums[1] = 1396;
	curr_connection.out_of_order_seq_nums[2] = 1756;
	curr_connection.out_of_order_seq_nums[3] = 93056;
	curr_connection.out_of_order_seq_nums[4] = 92342;
	curr_connection.out_of_order_seq_nums[5] = 92643;
	curr_connection.out_of_order_seq_nums[6] = 93252;
	curr_connection.out_of_order_seq_nums[7] = 94564;
	curr_connection.out_of_order_seq_nums[8] = 95676;
	curr_connection.out_of_order_seq_nums[9] = 92344;	
	curr_connection.num_out_of_order_seq_nums = 10;
	
	curr_connection.next_expected_byte = 95676;
	// expected result: [1356, 1396, 1756, 95676]
	clear_surpassed_seq_nums(&curr_connection);
	printf("num out of order remaining: %d\n", curr_connection.num_out_of_order_seq_nums);
	int i;
	printf("they are: [");
	for (i = 0; i < curr_connection.num_out_of_order_seq_nums; i++)
	{
		printf("%d ", curr_connection.out_of_order_seq_nums[i]);
	}
	printf("]\n");*/
}