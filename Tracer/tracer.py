from bcc import BPF
import socket
import os

pathModules="modules.c" 
#pathModules="sampleMod.c"
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
    logf = open("logTracer.log", "w")
    cap = open("captures.log", "w")
    prog=load_modules()
    b = BPF(text=prog)
    syscalls=load_syscalls()
    for syscall in syscalls:
        syscall=syscall.strip()
	try: 
            b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall_"+syscall)
            #b.attach_kretprobe(event=b.get_syscall_fnname(syscall), fn_name="hello")
            logf.write("Tracing "+syscall+'\n')
        except:
            logf.write("Failed to trace "+syscall+'\n')    

    logf.close()
    hostnameContainer = socket.gethostname()
    hostnameHost= os.environ['HOST_HOSTNAME']

    cap.write("%-18s %-16s %-12s %s" % ("TIME(s)", "COMM", "Namespace", "Syscall\n"))
    print("Tracing")
    while 1:
        
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            
        except Exception:
            continue
        msg=msg.split(':')
        uts=msg[0]
        syscall=msg[1]
        if (uts!=hostnameHost and uts!=hostnameContainer):
            cap.write("%-18.9f %-16s %-12s %s\n" % (ts, task, uts, syscall))
            #print("%-18.9f %-16s %-12s %s" % (ts, task, uts, syscall))
        
    cap.close()
        

if __name__== "__main__":
    main()
