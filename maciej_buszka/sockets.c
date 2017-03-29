/* 
  Maciej Buszka
  279129
*/

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "sockets.h"

#define time_diff(_start, _end) ((_end.tv_sec - _end.tv_sec) * 1000000000L \
  + _end.tv_nsec - _start.tv_nsec)

int open_socket(socket_t *s) {
  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd < 0) return fd;
  s->s_fd = fd;
  return 0;
}

void print_message(const message_t *msg) {
  printf("{ id : %d, seq : %d, type : %d }\n",
    msg->m_icmp_id,
    msg->m_icmp_seq,
    msg->m_type);
}

int check_replies(result_t *res, const socket_t *s, int16_t id, int ttl) {
  message_t msg;
  fd_set descriptors;
  struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
  struct timespec start;
  struct timespec snap;
  unsigned long nsecs;
  int ready = 0;
  int count = 0;
  int resp  = 0;

  FD_ZERO(&descriptors);
  FD_SET(s->s_fd, &descriptors);
  clock_gettime(CLOCK_MONOTONIC, &start);
  bzero(res, sizeof(result_t));

  do {
    ready = select(s->s_fd + 1, &descriptors, NULL, NULL, &tv);
    if (ready <  0) fail(-ready);
    if (ready == 0) break;

    clock_gettime(CLOCK_MONOTONIC, &snap);
    nsecs = time_diff(start, snap);
    tv.tv_sec = 0;
    tv.tv_usec = 1000000L - ((nsecs / 1000L) % 1000000L);

    while ((resp = read_icmp_message(&msg, s)) != -EWOULDBLOCK) {
      if (resp < 0) fail(-resp);
      if (resp == 1) continue;
      if (msg.m_icmp_seq / 3 == ttl - 1 && msg.m_icmp_id == id) {
        count ++;
        if (msg.m_type == M_ECHO_REPLY) res->r_found = 1;
        res->r_avg_time += nsecs / 1000000;

        for (int i=0; i<3; i++) {
          if (strlen(res->r_addresses[i]) == 0) {
            strcpy(res->r_addresses[i], msg.m_ip_str);
            break;
          }
          if (strcmp(msg.m_ip_str, res->r_addresses[i]) == 0) break;
        }
      }
    }
  } while (count < 3);

  if (count == 0) return 2;
  res->r_avg_time /= count;
  return count == 3 ? 0 : 1;
}

int send_echo_request(const socket_t *s, const char* ip_str, int ttl,
                      int16_t id, int16_t seq_nr) {
  struct icmphdr     icmp_header;
  struct sockaddr_in target;

  icmp_header.type = ICMP_ECHO;
  icmp_header.code = 0;
  icmp_header.un.echo.id = htons(id);
  icmp_header.un.echo.sequence = htons(seq_nr);
  icmp_header.checksum = 0;
  icmp_header.checksum = compute_icmp_checksum(
    (u_int16_t*) &icmp_header, sizeof(struct icmphdr));

  bzero(&target, sizeof(target));
  target.sin_family = AF_INET;
  inet_pton(AF_INET, ip_str, &target.sin_addr);
  setsockopt(s->s_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));

  ssize_t bytes_sent = sendto(s->s_fd,
                              &icmp_header,
                              sizeof(icmp_header),
                              MSG_DONTWAIT,
                              (struct sockaddr*) &target,
                              sizeof(target));
  return bytes_sent;
}

int read_icmp_message(message_t *m, const socket_t *s) {
  u_int8_t 			      buffer[IP_MAXPACKET];
  struct sockaddr_in  sender;
  struct icmphdr     *icmp_header;
  ssize_t				      ip_header_len;
  struct iphdr       *ip_header = (struct iphdr*) buffer;
  socklen_t 			    sender_len = sizeof(sender);

  ssize_t packet_len = recvfrom (s->s_fd, buffer, IP_MAXPACKET, MSG_DONTWAIT,
                                 (struct sockaddr*)&sender, &sender_len);

  if (packet_len < 0) {
    return -errno;
  }

  if (ip_header->protocol != IPPROTO_ICMP) {
    return 1;
  }

  inet_ntop(AF_INET, &(sender.sin_addr), m->m_ip_str, sizeof(m->m_ip_str));
  ip_header_len = ip_header->ihl * 4;
  icmp_header   = (struct icmphdr *) (buffer + ip_header_len);

  if (icmp_header->type == ICMP_TIME_EXCEEDED) {
    struct iphdr* inner = (struct iphdr*) (icmp_header + 1);
    ssize_t       inner_len = inner->ihl * 4;
    icmp_header = (struct icmphdr *) (((char*) inner) + inner_len);
    m->m_type = M_TTL_EXCEEDED;
    m->m_icmp_id = ntohs(icmp_header->un.echo.id);
    m->m_icmp_seq = ntohs(icmp_header->un.echo.sequence);
  } else if (icmp_header->type == ICMP_ECHOREPLY) {
    m->m_type = M_ECHO_REPLY;
    m->m_icmp_id  = ntohs(icmp_header->un.echo.id);
    m->m_icmp_seq = ntohs(icmp_header->un.echo.sequence);
  }
  return 0;
}

u_int16_t compute_icmp_checksum (const void *buff, int length) {
	u_int32_t sum;
	const u_int16_t* ptr = buff;
	assert (length % 2 == 0);
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (u_int16_t)(~(sum + (sum >> 16)));
}
