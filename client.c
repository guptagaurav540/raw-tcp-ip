#include<netinet/tcp.h>
#include<netinet/ip.h>
#include"ip_header.h"
#include"check_sum.h"
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<error.h>
#include"packet.h"
#include <net/ethernet.h>

#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include<sys/ioctl.h>
#include<net/if.h>

#include<netpacket/packet.h>
#include<getopt.h>

#include<time.h>

#define PACK_LEN 8192
#define DATA_LEN 1024
int main(int argc,char *argv[])
{
    if(argc !=5)
    {
        printf("less argument ");
        exit(-1);
    }
    //Create socket 
    int tcp_socket=socket_create();
    //configure source address,destination address;
    struct sockaddr_in source_addr,dest_addr;
    conf_address(&source_addr,argv[1],argv[2]);
    conf_address(&dest_addr,argv[3],argv[4]);

    int one=1;
    char *buffer;
    buffer=calloc(PACK_LEN,sizeof(char));
    int buffer_length;
    memset(buffer,0,PACK_LEN);
    char *data;
    data=calloc(DATA_LEN,sizeof(char));
    int data_len=0;
    printf("configure socket\n");
    int setsock_no=setsockopt(tcp_socket,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one));
    if(setsock_no<0)
    {
        perror("Error..........in setsockopt()\n");
        exit(-1);
    }
    else
    {
        printf("setsockopt() is OK......:\n");
    }
    
    
    
//    ************************SYN PACKET SENDING***************************************
    create_raw_packet(buffer,&buffer_length,SYN_PACKET,&source_addr,&dest_addr,data,data_len);
    drop_packet(buffer);            //if packet is not created;means size is less then 0
    while(1){
    int send_no=sendto(tcp_socket,buffer,buffer_length,0,(struct sockaddr *)&source_addr,sizeof(source_addr));
    if(send_no<0)
    {
        perror("errro in sending........:\n");
        exit(-1);
    }
    else
    {
        printf("message sending succes.....:\n");
        sleep(2);
    }
    }
    close(tcp_socket);
    return 0;
}