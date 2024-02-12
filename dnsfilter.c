#include "ksyscall.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo) { stop = 1; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
  // struct socket_info *e = data;
  // printf("socket fd: %d", e->fd);
  // char ss[200]=;
  // read(e->fd, *ss, sizeof(ss));

  struct dns_info {
    int pid;
    int sockFd;
    char message[32];
  };

  struct dns_info *e = data;
  printf("socket fd: %d", e->sockFd);
  printf("message: %s", e->message);

  return 0;
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct ksyscall_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Open load and verify BPF application */
  skel = ksyscall_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Attach tracepoint handler */
  err = ksyscall_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  // Setup ringbuffer polling
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

  printf("Successfully started! Please run `sudo cat "
         "/sys/kernel/debug/tracing/trace_pipe` "
         "to see output of the BPF programs.\n");

  while (!stop) {
    err = ring_buffer__poll(rb, 100);
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  ksyscall_bpf__destroy(skel);
  return -err;
}
