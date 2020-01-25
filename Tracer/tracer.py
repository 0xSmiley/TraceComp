from bcc import BPF

path="modules.c"

def load_modules():
    with open(path, "r") as f:
        modules = f.read()
    return modules

def main():
    prog=load_modules()
    b = BPF(text=prog)
    syscall="clone"
    b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall__"+syscall)

    print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
    while 1:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

if __name__== "__main__":
    main()

