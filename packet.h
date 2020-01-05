#define SYN_PACKET 1
#define FIN_PACKET 2
#define ACK_PACKET 3
#define PSH_PACKET 4
#define TCP 6
#define UDP 17

int socket_create()
{
    int tcp_socket=socket(PF_INET,SOCK_RAW,IPPROTO_TCP);
    if(tcp_socket<0)
    {
        perror("Error in TCP creating socket......");
        exit(-1);
        return(-1);
    }
    else
    {
        printf("Raw TCP Socket created...%d.......\n",tcp_socket);
        return(tcp_socket);
    }
    
}

int socket_create_udp()
{
    int udp_socket=socket(PF_INET,SOCK_RAW,IPPROTO_UDP);
    if(udp_socket<0)
    {
        perror("Error in UDP creating socket......");
        exit(-1);
        return(-1);
    }
    else
    {
        printf("Raw UDP Socket created...%d.......\n",udp_socket);
        return(udp_socket);
    }
} 


void conf_address(struct sockaddr_in *addr,char *ip,char *port)
{
    addr->sin_family=AF_INET;
    addr->sin_port=htons(atoi(port)); 
    addr->sin_addr.s_addr =inet_addr(ip);
    if(inet_pton(AF_INET,ip,&addr->sin_addr)!=1){
        perror("Error in ip address");
        exit(-1);
       }else{ printf("address ok:\n"); }
}
void set_up_ip_header(struct ip_header *ipheader,struct sockaddr_in *source_addr,
struct sockaddr_in *dest_addr,int protocol)
{
    ipheader->header_ver=4;
    ipheader->header_len = 5;
    ipheader->service_esn=16;         
    ipheader->total_length=sizeof(struct ip_header)+sizeof(struct tcp_header);
    ipheader->ident=htons(54321);          
    ipheader->flag_offset=0;                 
    ipheader->ttl=64;                 
    ipheader->protocol=protocol;            
    ipheader->checksum=0; 
    ipheader->src_addr=source_addr->sin_addr.s_addr;
    ipheader->dest_addr=dest_addr->sin_addr.s_addr;

}
void set_up_tcp_header(struct tcp_header *tcpheader,struct sockaddr_in *source_addr,
struct sockaddr_in *dest_addr)
{

    tcpheader->source_port=source_addr->sin_port;
    tcpheader->dest_port=dest_addr->sin_port;
    tcpheader->sequ_number=htonl(1);               
    tcpheader->ack_number=0;           
    tcpheader->header_len=5;
    tcpheader->bit_urg=0;
    tcpheader->bit_ack=0;
    tcpheader->bit_psh=0;
    tcpheader->bit_rsh=0;

    tcpheader->bit_sin=0;
    tcpheader->bit_fin=0;
    tcpheader->window_size=htons(1024);
    tcpheader->checksum=0;      //  tcp checksum Done by kernel
    tcpheader->urgent_pointer=0;

}
void create_raw_packet(char *buffer,int *buffer_length,int type,struct sockaddr_in *source_addr,
struct sockaddr_in *dest_addr,char *data,int len)
{
    char *dgram;
    char *payload;
    int dgram_len;
    dgram=calloc(DATA_LEN,sizeof(char));
    struct ip_header *ipheader=(struct ip_header *)dgram;                   
    struct tcp_header *tcpheader=(struct tcp_header *)(dgram+sizeof(struct ip_header));
    set_up_ip_header(ipheader,source_addr,dest_addr,TCP);
    set_up_tcp_header(tcpheader,source_addr,dest_addr);

    switch(type)
    {
        case(SYN_PACKET):
            tcpheader->bit_sin=1;
            tcpheader->bit_fin=0;
            tcpheader->bit_ack=1;
            tcpheader->bit_psh=1;
            

            break;
        case(FIN_PACKET):
            tcpheader->bit_fin=1;
            break;
        case(ACK_PACKET):
            tcpheader->bit_ack=1;
            break;
        case(PSH_PACKET):
            tcpheader->bit_ack=1;
            tcpheader->bit_psh=1;
            payload=dgram+sizeof(struct ip_header)+sizeof(struct tcp_header);
            memcpy(payload,data+8,len-8);
            /* set ack no and seq no*/


            /**************************/
            break;
    }

    ipheader->checksum=ip_check_sum((uint16_t *)dgram,(sizeof(struct ip_header)+sizeof(struct tcp_header)));
    memcpy(buffer,dgram,DATA_LEN);
    *buffer_length=ipheader->total_length;

}
void drop_packet(char *buffer)
{
    if(strlen(buffer)<1)
    {
        printf("wtf: data in Packet is error\n");
        exit(-1);
    }
    else{
        printf("packet is look good :\n");
    }
}




void set_up_udp_header(struct udp_header *udpheader,struct sockaddr_in *source_addr,
struct sockaddr_in *dest_addr)
{

    udpheader->source_port=source_addr->sin_port;
    udpheader->dest_port=dest_addr->sin_port;
    udpheader->checksum=0;      

}


void create_raw_packet_udp(char *buffer,int *buffer_length,int type,struct sockaddr_in *source_addr,
struct sockaddr_in *dest_addr,char *data,int len)
{
    char *dgram;
    char *payload;
    int dgram_len;
    dgram=calloc(DATA_LEN,sizeof(char));
    struct ip_header *ipheader=(struct ip_header *)dgram;                   
    struct udp_header *udpheader=(struct udp_header *)(dgram+sizeof(struct ip_header));
    set_up_ip_header(ipheader,source_addr,dest_addr,UDP);
    set_up_udp_header(udpheader,source_addr,dest_addr);

    ipheader->checksum=ip_check_sum((uint16_t *)dgram,(sizeof(struct ip_header)+sizeof(struct udp_header)));
    memcpy(buffer,dgram,DATA_LEN);
    *buffer_length=ipheader->total_length;

}

