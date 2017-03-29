/*
  Maciej Buszka
  279129
*/

#define panic(msg) do { \
  fprintf(stderr, "%s : %s/n", __func__, msg); \
  exit(1); \
} while(0)

#define fail(err_number) do {\
  fprintf(stderr, "%s : %s\n", __func__, strerror(err_number));\
  exit(1);\
} while (0)

#define M_TTL_EXCEEDED 0
#define M_ECHO_REPLY   1

typedef struct socket {
  int s_fd;
} socket_t;

typedef struct message {
  char    m_ip_str[20];
  int16_t m_icmp_id;
  int16_t m_icmp_seq;
  int     m_type;
} message_t;

typedef struct result {
  char          r_addresses[3][20];
  unsigned long r_avg_time;
  int           r_found;
} result_t;

int check_replies(result_t *res, const socket_t *s, int16_t id, int ttl);
int open_socket(socket_t *s);
int read_icmp_message(message_t *m, const socket_t *s);
int send_echo_request(const socket_t *s, const char* ip_str, int ttl,
                      int16_t id, int16_t seq_nr);
u_int16_t compute_icmp_checksum (const void *buff, int length);
