from bcc import BPF
import socket
import os


pathModules="sampleMod.c"

def load_modules():
    with open(pathModules, "r") as f:
        modules = f.read()
    return modules



def main():
    logf = open("logTracer.log", "w")
    cap = open("captures.log", "w")
    prog=load_modules()
    b = BPF(text=prog)
    syscalls=["exit_group"]
    for syscall in syscalls:
        syscall=syscall.strip()
        try: 
            if BPF.ksymname( b.get_syscall_fnname(syscall)) == -1:
                print(syscall)
            #print(b.get_syscall_fnname(syscall))
            b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="hello")
            #b.attach_kretprobe(event=b.get_syscall_fnname(syscall), fn_name="hello2")
            logf.write("Tracing "+syscall+'\n')
        except:
            logf.write("Failed to trace "+syscall+'\n')    

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
            exit(0)
        
        except Exception:
            continue
        
        msg=msg.split(':')
        uts=msg[0]
        syscall=msg[1]
        if (uts!=hostnameHost and uts!=hostnameContainer):
            cap.write("%f;%s;%s;%s\n" % (ts, task, uts, syscall))
            print("%f;%s;%s;%s" % (ts, task, uts, syscall))
        
    cap.close()
        

if __name__== "__main__":
    main()
