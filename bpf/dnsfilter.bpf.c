#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define SOCK_DGRAM 2
#define SOCK_STREAM 1

volatile int pid_dns;
volatile int sockfd;

SEC("ksyscall/socket")
int BPF_KSYSCALL(dnssock, int domain, int type, int protocol) {
  char command[16];
  if (type == SOCK_DGRAM) {
    bpf_get_current_comm(&command, sizeof(command));

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    pid_dns = pid;
  }

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;

  if (pid != pid_dns) {
    return 0;
  }

  int ret_fd = (int)BPF_CORE_READ(ctx, ret);
  if (ret_fd <= 0) {
    return 0;
  }
  sockfd = ret_fd;
  // bpf_printk("got sockfd %d from process %d", sockfd, pid_dns);
  return 0;
}

struct accept_args_t {
  struct sockaddr_in *addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);

} rb SEC(".maps");

struct dns_info {
  int pid;
  int sockFd;
  char *message;
};

SEC("ksyscall/connect")
int BPF_KSYSCALL(dnsconn, int socket, const struct sockaddr *address,
                 int address_len) {
  u64 id = bpf_get_current_pid_tgid();

  u32 pid = id >> 32;

  struct sockaddr_in ads;
  bpf_probe_read_user(&ads, sizeof(ads), address);

  // bpf_printk("%d", __bpf_ntohs(ads.sin_port));
  int port = __bpf_ntohs(ads.sin_port);
  if (pid == pid_dns && socket == sockfd && port == 53) {
    char command[16];
    bpf_get_current_comm(&command, sizeof(command));
    bpf_printk("we got a dns packet from process %d with command %s", pid,
               command);
    // reserve ringbuf
    // struct socket_info *e;
  } else {
    pid_dns = 0;
    sockfd = 0;
  }

  return 0;
}

SEC("ksyscall/sendmmsg")
int BPF_KSYSCALL(dnssmsg, int sockfdn, struct mmsghdr *msgvec,
                 unsigned int vlen, int flags) {
  int pid = bpf_get_current_pid_tgid() >> 32;
  if (sockfdn == sockfd && pid == pid_dns) {
    if (vlen > 0) {
      struct mmsghdr msg;
      bpf_probe_read_user(&msg, sizeof(msg), msgvec);
      int msg_iovlen = msg.msg_hdr.msg_iovlen;
      bpf_printk("msglen %d", msg_iovlen);

      struct iovec message;
      bpf_probe_read_user(&message, sizeof(message), msg.msg_hdr.msg_iov);
      char message_data[7];
      if (message.iov_len > 0) {
        bpf_probe_read_user_str(message_data, sizeof(message.iov_base),
                                message.iov_base);
        // #pragma unroll
        // 				for (int i = 0; i < message.iov_len;
        // i++) { 					bpf_printk("query: %s",
        // message_data[i]);
        // 				}

        // #pragma unroll
        // 				while (message_data[offset] != '\0') {
        // 					offset++;
        // 				}
        char *domain_name;
        bpf_probe_read_user_str(domain_name, sizeof(message.iov_base),
                                message.iov_base);
        bpf_printk("Domain name: %s  \n", domain_name);
      }
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
