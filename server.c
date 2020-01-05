#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
 #include <unistd.h>
#include"ip_header.h"
#include"check_sum.h"

#include<string.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void PrintData (unsigned char* , int);
 
int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
 
int check_packet(unsigned char* Buffer,char *ip)
{
    struct iphdr *iph = (struct iphdr *)Buffer; 
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    char *str;
    int len=strlen(ip);
    str=calloc(len+1,sizeof(char));
    
    inet_ntop(AF_INET, &(source.sin_addr), str, INET_ADDRSTRLEN);
  //  printf("%s %s\n",ip,str);
    if(strcmp(str,ip)==0)
    {
        return(1);
    }else{
        return(0);
    }
}


int main(int argc,char *argv[])
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
    if(argc<3)
    {
        perror("argc error :");
        exit(-1);
    }
    char *ip;
    int len=strlen(argv[1]);
    ip=calloc(len+1,sizeof(char));
    strcpy(ip,argv[1]);
    int port=atoi(argv[2]);
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    logfile=fopen("log.txt","w");
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        if(check_packet(buffer,ip)){
        ProcessPacket(buffer , data_size);
        }
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct ip_header *iph = (struct ip_header*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   Others : %d   Total : %d\r",tcp,others,total);
}




void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct ip_header *iph = (struct ip_header *)Buffer;
    iphdrlen =5*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->src_addr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->dest_addr;
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->header_ver);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->header_len,((unsigned int)(iph->header_len))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->service_esn);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->total_length));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->ident));
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->checksum));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct ip_header *iph = (struct ip_header *)Buffer;
    iphdrlen = 5*4;
     
    struct tcp_header *tcph=(struct tcp_header*)(Buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");    
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile,"\n");
    fprintf(logfile,"TCP Header\n");
    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source_port));
    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest_port));
    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->sequ_number));
    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_number));
    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->bit_urg);
    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->bit_ack);
    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->bit_psh);
    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->bit_rsh);
    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->bit_sin);
    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->bit_fin);
    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window_size));
    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->checksum));
    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urgent_pointer);
    fprintf(logfile,"\n");
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");
         
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile,"TCP Header\n");
 /*   PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    fprintf(logfile,"\n###########################################################");
*/
}
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
             
            fprintf(logfile,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}