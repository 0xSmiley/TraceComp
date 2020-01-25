#define TRACE_ENT_SYSCALL(name)                                         \
int syscall__##name(struct pt_regs *ctx)                                \
{                                                                       \
    bpf_trace_printk("Hello, Clone!\n");                                \
    return 0                                                            \
}