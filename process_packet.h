#pragma once
#include "common.h"
#include "logger.h"

#define port(A) ntohs(hdr->source) == A || ntohs(hdr->dest) == A
#define txt(A, B)                                                              \
  printf("<><><><><>Total number of packets that used the %s protocol: %d\n", A, B);

struct stats {
  int num_of_packets;
  int tcp_packets;
  int udp_packets;
  int dns_packets;
  int http_packets;
  int smtp_packets;
  int ssh_packets;
  int ftp_packets;
  int https_packets;
  int ipv4_packets;
  int ipv6_packets;
  int arp_packets;
  int gopher_packets;
};

struct tls_header {
    uint8_t  content_type;
    uint16_t version;
    uint16_t length; 
};

struct arp_header {
  u_int16_t htype;
  u_int16_t ptype;
  u_int8_t hlen;
  u_int8_t plen;
  u_int16_t oper;
  u_int8_t sha[6];
  u_int8_t spa[4];
  u_int8_t tha[6];
  u_int8_t tpa[4];
};

struct ipv6_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t traffic_class_1 : 4, ip_version : 4;
  u_int8_t flow_label_1 : 4, traffic_class_2 : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  u_int8_t ip_version : 4, traffic_class_1 : 4;
  u_int8_t traffic_class_2 : 4, flow_label : 4;
#else
#error "Please fix <bits/endian.h>"
#endif
  u_int16_t flow_label_2;
  u_int16_t payload_length;
  u_int8_t next_header;
  u_int8_t hop_limit;

  unsigned char src_ipv6[16];
  unsigned char dst_ipv6[16];
};

struct dnshdr {
  unsigned short id; // identification number

  unsigned char rd : 1;     // recursion desired
  unsigned char tc : 1;     // truncated message
  unsigned char aa : 1;     // authoritive answer
  unsigned char opcode : 4; // purpose of message
  unsigned char qr : 1;     // query/response flag

  unsigned char rcode : 4; // response code
  unsigned char cd : 1;    // checking disabled
  unsigned char ad : 1;    // authenticated data
  unsigned char z : 1;     // its z! reserved
  unsigned char ra : 1;    // recursion available

  unsigned short q_count;    // number of question entries
  unsigned short ans_count;  // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count;  // number of resource entries
};

void init_processing_stats();
void process_packet(void *data, size_t data_size);
void display_processing_stats();
