#include "common.h"
#include "logger.h"
#include "process_packet.h"

static unsigned char *data;
static fd_t socket_fd;

void sig_handler() {
  display_processing_stats();
  close(socket_fd);
  free(data);
  exit(EXIT_SUCCESS);
}

int main() {
  size_t data_size = -1, sock_len = sa_size;
  struct sockaddr saddr;

  signal(SIGINT, sig_handler);
  signal(SIGABRT, sig_handler);

  data = (unsigned char *)malloc(65536);

  socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  int num_of_packets = 0;

  init_logger("LOG.txt");
  init_processing_stats();

  if ((signed int)socket_fd < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  while (true) {
    data_size =
        recvfrom(socket_fd, data, 65536, 0, &saddr, (socklen_t *)&sock_len);
    if ((signed long)data_size < 0) {
      perror("recvfrom");
      exit(EXIT_FAILURE);
    }

    process_packet(data, data_size);
  }

  display_processing_stats();
  destroy_logger();
  close(socket_fd);
  free(data);
}
