int clone( struct pt_regs *ctx) {
    bpf_trace_printk("Clone test!\\n");
    return 0;
}
