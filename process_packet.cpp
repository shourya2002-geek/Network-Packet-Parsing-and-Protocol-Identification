#include "process_packet.h"

static void *glbl_data;
static size_t glbl_data_size;
static struct stats curr_stats;

void init_processing_stats() { memset(&curr_stats, 0, sizeof(curr_stats)); }

void display_processing_stats() {
  printf("<><><><>....Total number of packets analysed: %d\n",
         curr_stats.num_of_packets);
  txt("IPv4", curr_stats.ipv4_packets);
  txt("IPv6", curr_stats.ipv6_packets);
  txt("TCP", curr_stats.tcp_packets);
  txt("UDP", curr_stats.udp_packets);
  txt("ARP", curr_stats.arp_packets);
  txt("DNS", curr_stats.dns_packets);
  txt("HTTP", curr_stats.http_packets);
  txt("HTTPS", curr_stats.https_packets);
  txt("FTP", curr_stats.ftp_packets);
  txt("SMTP", curr_stats.smtp_packets);
}

void print_UDP_header(struct udphdr *udph) {
  write_lg("\n");
  write_lg(">>UDP Header<<");
  write_lg("<>>>>-Source Port  : %d", ntohs(udph->source));
  write_lg("<>>>>-Destination Port : %d", ntohs(udph->dest));
  write_lg("<>>>>-UDP Length  : %d", ntohs(udph->len));
  write_lg("<>>>>-UDP Checksum : %d", ntohs(udph->check));
  write_lg("\n");
}

void print_TCP_header(struct tcphdr *tcph) {
  write_lg("\n");
  write_lg(">>TCP Header<<");
  write_lg("<>>>>-Source Port      : %u", ntohs(tcph->source));
  write_lg("<>>>>-Destination Port : %u", ntohs(tcph->dest));
  write_lg("<>>>>-Sequence Number    : %u", ntohl(tcph->seq));
  write_lg("<>>>>-Acknowledge Number : %u", ntohl(tcph->ack_seq));
  write_lg("<>>>>-Header Length      : %d DWORDS or %d BYTES",
           (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
  write_lg("<>>>>-Urgent Flag          : %d", (unsigned int)tcph->urg);
  write_lg("<>>>>-Acknowledgement Flag : %d", (unsigned int)tcph->ack);
  write_lg("<>>>>-Push Flag            : %d", (unsigned int)tcph->psh);
  write_lg("<>>>>-Reset Flag           : %d", (unsigned int)tcph->rst);
  write_lg("<>>>>-Synchronise Flag     : %d", (unsigned int)tcph->syn);
  write_lg("<>>>>-Finish Flag          : %d", (unsigned int)tcph->fin);
  write_lg("<>>>>-Window         : %d", ntohs(tcph->window));
  write_lg("<>>>>-Checksum       : %d", ntohs(tcph->check));
  write_lg("<>>>>-Urgent Pointer : %d", tcph->urg_ptr);
  write_lg("\n");

  return;
}

void print_DNS_header(struct dnshdr *dnsh) {
write_lg("\n");
  write_lg(">>DNS HEADER<<");
  write_lg("<>>>>-Identification Number      : %u", dnsh->id);
  write_lg("<>>>>-Recursion Desired          : %u", dnsh->rd);
  write_lg("<>>>>-Truncated Message          : %u", (dnsh->tc));
  write_lg("<>>>>-Authoritative Answer       : %u", (dnsh->aa));
  write_lg("<>>>>-Purpose of message         : %d", (unsigned int)dnsh->opcode);
  write_lg("<>>>>-Query/Response Flag        : %d", (unsigned int)dnsh->qr);
  write_lg("<>>>>-Response code              : %d", (unsigned int)dnsh->rcode);
  write_lg("<>>>>-Checking Disabled          : %d", (unsigned int)dnsh->cd);
  write_lg("<>>>>-Authenticated data         : %d", (unsigned int)dnsh->ad);
  write_lg("<>>>>-Recursion available        : %d", (unsigned int)dnsh->ra);
  write_lg("<>>>>-Number of question entries : %d", (dnsh->q_count));
  write_lg("<>>>>-Number of answer entries   : %d", (dnsh->ans_count));
  write_lg("<>>>>-Number of authority entries: %d", dnsh->auth_count);
  write_lg("<>>>>-Number of resource entries : %d", dnsh->add_count);
  write_lg("\n");
  return;
}

void process_DNS_header(bool ipv4_type) {
  struct dnshdr *shdr;
  if (ipv4_type) {
    shdr =
        (struct dnshdr *)(glbl_data + sizeof(struct tcphdr) +
                          sizeof(struct ether_header) + sizeof(struct iphdr));
  } else {
    shdr =
        (struct dnshdr *)(glbl_data + sizeof(struct tcphdr) +
                          sizeof(struct ether_header) + sizeof(struct ip6_hdr));
  }
  print_DNS_header(shdr);
}

void process_tls() {
    
}

void process_TCP(bool ipv4_type) {
  curr_stats.tcp_packets++;
  struct tcphdr *hdr;
  if (ipv4_type) {
    hdr = (struct tcphdr *)(glbl_data + sizeof(struct ether_header) +
                            sizeof(struct iphdr));
  } else {
    hdr = (struct tcphdr *)(glbl_data + sizeof(struct ether_header) +
                            sizeof(struct ip6_hdr));
  }
  print_TCP_header(hdr);
  if (port(80)) {
    write_lg(">>>HTTP Protocol<<<");
    curr_stats.http_packets++;
  } else if (port(443)) {
    write_lg(">>>HTTP/TLS Protocol<<<");
    process_tls();
    curr_stats.https_packets++;
  } else if (port(25) || port(587)) {
    write_lg(">>>SMTP Protocol<<<");
    curr_stats.smtp_packets++;
  } else if (port(20) || port(21)) {
    write_lg(">>>FTP Protocol<<<");
    curr_stats.ftp_packets++;
  } 
}

void process_UDP(bool ipv4_type) {
  curr_stats.udp_packets++;
  struct udphdr *hdr;
  if (ipv4_type) {
    hdr = (struct udphdr *)(glbl_data + sizeof(struct ether_header) +
                            sizeof(struct iphdr));
  } else {
    hdr = (struct udphdr *)(glbl_data + sizeof(struct ether_header) +
                            sizeof(struct ip6_hdr));
  }
  print_UDP_header(hdr);
  if (port(53)) {
    curr_stats.dns_packets++;
    process_DNS_header(ipv4_type);
  }
}

void print_IPv4_header(struct iphdr *iph) {
 write_lg("\n");
  write_lg(">>IP HEADER<<");
  write_lg("<>>>>-IP Version   : %d", (unsigned int)iph->version);
  write_lg("<>>>>-Type Of Service : %d", (unsigned int)iph->tos);
  write_lg("<>>>>-IP Total Length : %d  Bytes(Size of Packet)",
           ntohs(iph->tot_len));
  write_lg("<>>>>-Identification    : %d", ntohs(iph->id));
  write_lg("<>>>>-TTL : %d", (unsigned int)iph->ttl);
  write_lg("<>>>>-Protocol : %d", (unsigned int)iph->protocol);
  write_lg("<>>>>-Checksum : %d", ntohs(iph->check));
  write_lg("\n");
}

void print_IPV6_header(struct ipv6_header *hdr) {
  char src[50], dst[50], stemp[5], dtemp[5];
  int i;

  memset(src, 0, sizeof(src));
  memset(dst, 0, sizeof(dst));
  for (i = 1; i <= 16; i++) {
    if (i % 2 == 0 && i < 16) {
      sprintf(stemp, "%02x:", hdr->src_ipv6[i - 1]);
      sprintf(dtemp, "%02x:", hdr->dst_ipv6[i - 1]);
    } else {
      sprintf(stemp, "%02x", hdr->src_ipv6[i - 1]);
      sprintf(dtemp, "%02x", hdr->dst_ipv6[i - 1]);
    }
    strcat(src, stemp);
    strcat(dst, dtemp);
  }
  write_lg("\n");
  write_lg(">>IPV6 HEADER<<");
  write_lg("<>>>>>-Source       : %s", src);
  write_lg("<>>>>>-Destination  : %s", dst);
  write_lg("\n"); 
}

void process_IPv4() {
  curr_stats.ipv4_packets++;
  struct iphdr *iph = (struct iphdr *)(glbl_data + sizeof(struct ether_header));
  print_IPv4_header(iph);
  switch (iph->protocol) {
  case 6:
    process_TCP(true);
    break;
  case 17:
    process_UDP(true);
    break;
  default:
    break;
  }
}

void process_ARP() {
  curr_stats.arp_packets++;
  struct arp_header *hdr =
      (struct arp_header *)(glbl_data + sizeof(struct ether_header));
 write_lg("\n");
  write_lg(">>ARP HEADER<<");
  write_lg("<>>>>>-Hardware type : %d", ntohs(hdr->htype));
  write_lg("<>>>>>-Protocol Type : %d", ntohs(hdr->ptype));
  write_lg("<>>>>>-Hardware addr len: %d", ntohs(hdr->hlen));
  write_lg("<>>>>>-Protocol addr len: %d", ntohs(hdr->plen));
  write_lg("<>>>>>--Operation : %d", ntohs(hdr->plen));
  write_lg("\n");
}

void process_IPv6() {
  curr_stats.ipv6_packets++;
  struct ipv6_header *ip6h =
      (struct ipv6_header *)(glbl_data + sizeof(struct ether_header));

  switch (ntohs(ip6h->next_header)) {
  case 6:
    process_TCP(false);
    break;
  case 17:
    process_UDP(false);
    break;
  default:
    print_IPV6_header(ip6h);
    break;
  }
}

void printEther(struct ether_header *eth) {
 write_lg("\n");
  write_lg(">>ETHERNET HEADER<<");
  write_lg("<>>>>>-Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  write_lg("<>>>>>-Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  write_lg("<>>>>>>>-Protocol: %u", (unsigned short)eth->ether_type);
  write_lg("\n");
}

void process_ethernet() {
  struct ether_header *eth = (struct ether_header *)glbl_data;
  printEther(eth);
  switch (ntohs(eth->ether_type)) {
  case 0x0800: // IPv4 Protocol
    process_IPv4();
    break;
  case 0x0806: // ARP Protocol
    process_ARP();
    break;
  case 0x86dd: // IPv6 Protocol
    process_IPv6();
    break;
  default: // Some Other Protocol
    break;
  }
}

void process_packet(void *data, size_t data_size) {
  glbl_data = NULL;
  glbl_data_size = 0;
  curr_stats.num_of_packets++;
  printf("-----------------------------------------------------------------\n");
  printf("<><>--Packet %d recieved, processing has started ...\n", curr_stats.num_of_packets);
  write_lg("<><>------------------------------------------------------------<><>\n");
  write_lg("Packet Detials:\npacket NO.: %d\npacket Size %zu", curr_stats.num_of_packets,
           data_size);
  write_lg("<><>------------------------------------------------------------<><>\n");
  glbl_data = data;
  glbl_data_size = data_size;
  process_ethernet();
  printf("<><>--Packet %d  has been processed\n", curr_stats.num_of_packets);
  printf("-----------------------------------------------------------------\n");
}
