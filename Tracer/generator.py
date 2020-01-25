Syscalllpath="parsed.txt"

moduleEx="""
int syscall_%(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->%");
    return 0;
}
"""


def main():
    fd=open("modules.c", "a+")
    with open(Syscalllpath, "r") as f:
        syscalls=f.readlines()
        for syscall in syscalls:
            syscall=syscall.strip()
            module=moduleEx.replace('%',syscall)
            fd.write(module)


if __name__== "__main__":
    main()
