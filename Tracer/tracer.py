from bcc import BPF

path="modules.c"

def load_bpf():
    with open(path, "r") as f:
        bpf = f.read()
    return bpf

def main():
    prog=load_bpf()
    print(prog)
    b = BPF(text=prog)
    b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="syscall__clone")
    b.trace_print()

    # header
    print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

    # format output
    while 1:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

#!/usr/bin/python
#from bcc import BPF

#BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()

if __name__== "__main__":
    main()

