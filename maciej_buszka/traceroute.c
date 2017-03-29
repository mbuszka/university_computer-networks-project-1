/*
  Maciej Buszka
  279129
*/

#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sockets.h"

void print_usage(const char *prog_name) {
  printf("Usage :\n%s <ip addr>\n where ip addr is in format xxx.xxx.xxx.xxx\n",
         prog_name);
}

int check_user_input(char *ip_str) {
  struct in_addr dummy;
  return inet_pton(AF_INET, ip_str, &dummy);
}

int main(int argc, char *argv[]) {
  int       result;
  socket_t  socket;
  char      ip_str[20];
  int16_t   id = getpid();

  if (argc != 2) {
    print_usage(argv[0]);
    exit(0);
  }

  strncpy(ip_str, argv[1], sizeof(ip_str));
  if (!check_user_input(ip_str)) {
    print_usage(argv[0]);
    exit(0);
  }

  if ((result = open_socket(&socket)) < 0)
    fail(-result);

  result_t res;

  for (int ttl=1; ttl<=30; ttl++) {
    for (int j=0; j<3; j++)
      send_echo_request(&socket, ip_str, ttl, id, 3 * (ttl-1) + j);
    result = check_replies(&res, &socket, id, ttl);
    if (result < 0)
      fail(-result);

    printf("%d. ", ttl);

    if (result == 2) {
      printf("*\n");
      continue;
    }

    for (int k=0; k<3; k++) {
      if (res.r_addresses[k][0]) printf("%s ", res.r_addresses[k]);
    }

    if (result == 0) printf("%lums\n", res.r_avg_time);
    if (result == 1) printf("???\n");
    if (res.r_found) break;
  }

  return 0;
}
