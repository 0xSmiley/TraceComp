int clone(struct pt_regs *ctx) {
    bpf_trace_printk("Hello, Clone!\n");
    return 0;
}