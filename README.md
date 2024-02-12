# eBPF program to capture the dns queries

This ebpf program captures the dns quries by tracing the syscalls using kprobes and tracepoints.
This can be achieved by using socketfilters as well which will be added in future.
