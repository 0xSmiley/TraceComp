from bcc import BPF

pathModules="modules.c"
pathSyscalls="parsed.txt"

def load_modules():
    with open(pathModules, "r") as f:
        modules = f.read()
    return modules

def load_syscalls():
    with open(pathSyscalls, "r") as f:
        syscalls = f.readlines()
    return syscalls

def main():
    prog=load_modules()
    b = BPF(text=prog)
    syscalls=load_syscalls()
    for syscall in syscalls:
        syscall=syscall.strip()
        b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall_"+syscall)

    print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
    while 1:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

if __name__== "__main__":
    main()

