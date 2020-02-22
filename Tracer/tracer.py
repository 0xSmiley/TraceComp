from bcc import BPF
import socket
import os
import seccompGenerator
import time

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
    logf = open("logTracer.log", "w")
    prog=load_modules()
    b = BPF(text=prog)
    syscalls=load_syscalls()
    for syscall in syscalls:
        syscall=syscall.strip()
        try: 
            b.attach_kprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall_"+syscall)
            #b.attach_kretprobe(event=b.get_syscall_fnname(syscall), fn_name="syscall_"+syscall)
            logf.write("Tracing "+syscall+'\n')
        except:
            logf.write("Failed to trace "+syscall+'\n')    

    logf.close()
    hostnameContainer = socket.gethostname()
    hostnameHost= os.environ['HOST_HOSTNAME']
    
    fileDesc={}
    print("Tracing")
    while 1:
        
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        
        except KeyboardInterrupt:
            exit()
        
        except Exception:
            continue
        msg=msg.decode("utf-8") 
        msg=msg.split(':')
        uts=msg[0]
        syscall=msg[1]
        
        if (uts!=hostnameHost and uts!=hostnameContainer):
            if uts not in fileDesc:
                fd = open(uts+".cap", "w")
                fd.write("%s;%s;%s;%s" % ("TIME(s)", "COMM", "Namespace", "Syscall\n"))
                fileDesc[uts] = fd
            else:
                fd=fileDesc[uts]

            fd.write("%f;%s;%s;%s\n" % (ts, task, uts, syscall))
            #print("%f;%s;%s;%s" % (ts, task, uts, syscall))
            if syscall=="exit_group":
                time.sleep(1)
                stream=os.popen('docker inspect -f {{.State.Running}} '+uts)
                containerCheck = stream.read().strip()
                if containerCheck =='false':
                    fd.close()
                    seccompGenerator.EbpfMode(uts)
                    print("Container: "+uts+" traced")
                print(containerCheck)
        

if __name__== "__main__":
    main()
