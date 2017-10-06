Reliable Datagram Protocol
Developed for CSC 361 at UVic by:
Cailan St Martin
V00826057
Lab section B03
March 2017

Overview:
	This is an implementation of an application-layer reliable data transfer protocol.
	It implements both a sender and a receiver, and is capable of transferring files
	of any size and filetype over a lossy network.

Building the code:
	- run "make" to build the executables (rdpr and rdps)
	- run "make clean" to clear the executables

Running the code:
	Make sure to have the receiver running before the sender
	- to run the receiver: "./rdpr [receiver_ip] [receiver_port] [receiver_filename]"
	- to run the sender: "./rdps [sender_ip] [sender_port] [receiver_ip] [receiver_port] [receiver_filename]"
	
Basic Packet Structure
	The RDP header is a fixed-length string of ASCII characters, ending in a blank line
	(represented by the characters \r\n\r\n). The general format is as follows:
	
		CSC361***#####@@@@@@\r\n\r\n
	
	CSC361: indicates that this is indeed valid packet
	***: the type of the packet (SYN, ACK, FIN, DAT, RST)
	#####: the sequence number or acknowledgement number of the packet (5 ASCII numbers)
	@@@@@@: the window size or payload length of the packet (6 ASCII numbers)
	\r\n\r\n: a blank line, indicating the boundary between the header fields and the payload
	
	The header is followed by the payload of the packet. The maximum size of a payload is 1000 bytes
	(maximum packet size is 1024 bytes, header size is 24 bytes)
	
	The numerical fields (sequence/acknowledgement and window/payload size) are encoded into ASCII,
	and are specified in base 10 (ie, each digit is between 0 and 9 inclusive). Since it is ASCII
	encoded, there is no reason to use a binary representation; base 10 allows for a much larger
	range of numbers in as many characters as base 2 would. I chose base 10 rather than a larger base,
	such as 16, for simplicity.
	
	The meaning of each of these fields is as described in the P2 assignment specification. The receiver
	interprets ##### as a sequence number, while the sender interprets it as an acknowledgement number.
	Sequence and acknowledgement numbers are byte-oriented.
	The receiver interprets @@@@@@ as a payload length (in bytes), while the sender interprets it as
	the receiver's available window size (in bytes). I use no additional header fields.
	I have a module, rdp_packets, which defines the header field lengths, and provides 
	functions for the interpretation and creation of packets.
	
Functionality/Implementation
	The protocol implements the following data transfer mechanisms:
	
	Connection Management
		Connection opening and closing is handled using 2-way handshakes.
	
		The sender opens a connection with a SYN packet, which is acknowledged by the
		receiver with an ACK packet. The sender will resend the SYN packet a fixed number
		of times if it does not receive a response, before timing out.
		
		The sender closes a connection with a FIN packet, which is acknowledged by the
		receiver with an ACK packet. As soon as the ACK is received, the sender considers
		the connection closed; if it is not received, the FIN is resent. The receiver waits 
		for a fixed period time after sending the ACK; if it receives another FIN, it retransmits
		the ACK. Otherwise, if it does not receive any more packets during this time, the receiver 
		considers the connection closed.
		
		If either side does not hear from the other for 5 seconds, the connection is considered
		to have timed out, and is closed.
		
	Data Transfer
		The sender specifies data packets using the DAT packet type. Each packet is given a
		sequence number, which the receiver uses to ensure that packets are being received
		in the correct order. Packets are acknowledged by the receiver via ACK packets, which
		contain a cumulative acknowledgement number specifying the next expected sequence number.
		The data is written to a file on the receiver side.
		
	Flow Control
		The receiver specifies a fixed maximum window size of 10240 bytes. When the receiver gets
		an inorder data packet, it decrements the window size by the size of the received payload, and 
		sends an acknowledgement. If an out of order packet is received, the receiver simply drops
		the packet and sends an acknowledgement, without decrementing the window size. Once the data
		has been read from the socket and handled, the receiver increments the window size by the 
		size of the data payload.
		
		Whenever the sender sends data, it fills the window size with 1000 byte packets (unless there
		are less than 1000 bytes left in the file, in which case a smaller packet is sent), and sends
		them all. It then waits until it receives an acknowledgement indicating more space has been 
		freed in the receiver's window.
		
	Error Control
		The receiver always acknowledges cumulatively, meaning that the acknowledgement number it sends
		is always the next expected inorder byte. If it receives an out of order packet, this packet is
		simply dropped. 
		
		The sender keeps an array of timestamps, each one mapped to a particular sequence number 
		that has been sent but not yet acknowledged by the sender. The timeout value is fixed at 
		30ms. (This was updated since the original design document, to reflect a more accurate 
		representation of the average round trip time between sender and receiver). After each 
		iteration of (send data, listen for response), the sender checks the status of the timestamps. 
		Any that have since been acknowledged by the receiver are cleared. If any timestamp is older
		than the timeout value, that packet is assumed to have been lost. The sender reverts back to
		that sequence number and that position in the file, and starts sending the data again.
		
		This method ensures that the data will be completely delivered to the receiver in the correct order, even
		in a lossy network.
	
	Connection Reset
		If the sender or the receiver receives an unexpected packet, or a send or receive fails
		unexpectedly, a RST packet is sent. This triggers the connection to be restarted; the sender 
		will assume all data to have been lost and will attempt to start a new connection. The receiver 
		will close and reopen the output file, and wait for the sender to open a new connection.
		
	Logging
		Both the sender and receiver keep track of whether each packet they are sending or receiving
		is new or is being retransmitted. They also keep track of the total number of packets/bytes, 
		and total number of unique packets/bytes, that have been sent. The total time (between initial
		SYN-ACK and final FIN-ACK) that has elapsed is also stored. All of this information, as well
		as statistics about the types of packets transferred, are logged when the connection is successfully
		closed.
		
Code Structure
	The architecture of this code was broken into modules, to reduce code duplication
	and improve the general organization and testability
	- The module rdp_packets contains shared functionality and information (used by 
	both rdps and rdpr) that is specific to the RDP implementation.
	- The module helpers contains generic shared functionality.
	
	Both the sender and receiver are written to be modular, and use various functions
	to handle distinct functionalities. They also use data structures to make passing
	data between functions easier, and to improve the readability and maintainability 
	of the code. These functions and structures can be observed via an inspection of 
	the code.

	Sender:
	A connection_info struct is used to hold all connection-specific information. Once the input 
	arguments are handled, the connection info has been initialized, and the file has been opened 
	for reading, a connection is established (as specified under Connection Management). Assuming 
	this was successful, the following flow is executed in a loop:
		- Check for a connection timeout
		- Check the timers (held in a timer_info struct) for a single packet timeout, which would
		trigger retransmission
		- Send data
		- Listen for response
		
	Once the data has all been sent and acknowledged successfully, the connection is closed via 
	the FIN-ACK handshake.
	
	If an RST packet is received, the process (starting with establishing a new connection) is restarted.
	
	Each of these steps is logically described in more detail in the Functionality/Implementation section.
	
	Since the sequence number is a fixed size in the RDP header specification, the sender must be prepared
	to deal with rollover, if the sequence number exceeds the maximum value. To handle this, the function 
	compare_seq_num in rdp_packets uses a threshold value to determine if a small sequence number is actually
	appearing after a larger sequence number. (Simply, if the difference is very large, we assume rollover has
	occurred). Both the sender and the receiver use this function to deal with sequence number rollover. This
	means that there is no limit on the filesize that can be transferred.
	
	The data that is read from the file is read directly into a char array, and is treated as arbitrary data types.
	No string operations are used, which means that even random binary files (which could contain null terminators)
	can be transferred without problems.
	
	Receiver:
	As with the sender, a connection_info struct is used to keep track of all connection-specific 
	information. Once the input arguments are handled, the connection info initialized, and the
	file opened for writing, the following flow is executed in a loop:
		- Check for a connection timeout
		- Listen for incoming packet
		- Write data (if applicable)
		- Send acknowledgement
	
	If a FIN is received, the receiver sends an ACK to close the connection. The file is 
	then saved and closed.
	
	If an RST packet is received, the file is closed and reopened (clearing the previous data),
	and the process starts again.
	
	Each of these steps is logically described in more detail in the Functionality/Implementation section.
	
		