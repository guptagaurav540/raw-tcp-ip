//hi mandeep
struct tcp_header
{
 uint16_t source_port;  //source port(16)
 uint16_t dest_port;  //Destination port(16)
 uint32_t sequ_number;  //sequence number(32)
 uint32_t ack_number; //acknowledgement number(32)
 uint8_t header_len;  //(4)header length-(4)reserved bit
 uint8_t bit_urg:1,bit_ack:1,bit_psh:1,
         bit_rsh:1,bit_sin:1,bit_fin:1 ;//2 bit reserved URG,ACK,PSH,RSH,SYN,FIN each are of 1 bit
 uint16_t window_size; //receiver advertise window size(16)
 uint16_t checksum;  //checksum(16) to be computed
 uint16_t urgent_pointer;//points to urgent data byte(16) if URG flag_bit set to 1

/*it may be possible option file be required */

// uint32_t options;    //option field may not be 32 so to compromise the remaining
                   //bits we can use padding
};


// we have to find what is data length
#define TCP_DATA_LEN 1  
//hi mandeep
struct udp_header
{
 uint16_t source_port;  //source port(16)
 uint16_t dest_port;  //Destination port(16)
 uint16_t length;
 uint16_t checksum;  //checksum(16) to be computed
 
/*it may be possible option file be required */

// uint32_t options;    //option field may not be 32 so to compromise the remaining
                   //bits we can use padding
};
