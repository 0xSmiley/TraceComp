from bcc import BPF
import socket
import os
import seccompAllGenerator

pathModules="modules.c" 
pathSyscalls="newListSyscalls.txt"

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
    i=0
    for syscall in syscalls:
        syscall=syscall.strip()
        try: 
            b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall_"+syscall)
            logf.write("Tracing "+syscall+'\n')
        except Exception:
            print("Error at ",syscall)
            continue
            #logf.write("Failed to trace "+syscall+'\n')
        
  

    logf.close()
    hostnameContainer = socket.gethostname()
    hostnameHost= os.environ['HOST_HOSTNAME']

    cap.write("%s;%s;%s;%s" % ("TIME(s)", "COMM", "Namespace", "Syscall\n"))
    print("Tracing")
    while 1:
        
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        
        except KeyboardInterrupt:
            cap.close()
            seccompAllGenerator.EbpfMode()
        
        except Exception:
            continue
        
        msg=msg.split(':')
        uts=msg[0]
        syscall=msg[1]
        if (uts!=hostnameHost and uts!=hostnameContainer):
            cap.write("%f;%s;%s;%s\n" % (ts, task, uts, syscall))
            #print("%f;%s;%s;%s" % (ts, task, uts, syscall))
        
    cap.close()
        

if __name__== "__main__":
    main()
