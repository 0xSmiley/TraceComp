from bcc import BPF
import socket
import os
import seccompGenerator
import time
import docker
from threading import Timer


pathModules="modules.c" 
pathSyscalls="parsed.txt"
fileDesc={}

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
    
    
    client = docker.from_env()
    containerList=client.containers.list()
    print("Tracing")
    
    while 1:
        
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        
        except KeyboardInterrupt:
            exit()
        
        
        msg=msg.decode("utf-8") 
        task=task.decode("utf-8")
        msg=msg.split(':')
        uts=msg[0]
        syscall=msg[1]
        
        if (uts!=hostnameHost and uts!=hostnameContainer):
            if uts not in fileDesc:
                fd = open("Captures/"+uts+".cap", "w")
                fd.write("%s;%s;%s;%s" % ("TIME(s)", "COMM", "NAMESPACE", "SYSCALL\n"))
                fileDesc[uts] = fd
            else:
                fd=fileDesc[uts]
            try:
                fd.write("%f;%s;%s;%s\n" % (ts, task, uts, syscall))
                #print("%f;%s;%s;%s" % (ts, task, uts, syscall))
            except Exception:
                print("Error on "+uts+ " "+ task+ " "+syscall)

            currentContainerList=client.containers.list()
            if len(containerList)<len(currentContainerList):
                containerList=currentContainerList
                #print(containerList)
            elif len(containerList)>len(currentContainerList):
                #print(containerList,currentContainerList)
                t=Timer(10,stopTraceInit,[containerList,currentContainerList])
                #t = threading.Thread(target=stopTraceInit, args=[containerList,currentContainerList])
                t.start()
                containerList=currentContainerList

def stopTraceInit(containerList,currentContainerList):
    currentContainerList=set(currentContainerList)
    diff = [x for x in containerList if x not in currentContainerList]

    for container in diff:
        fullUts=container.id
        uts=fullUts[:12]
        fd=fileDesc[uts]
        seccompGenerator.EbpfMode(uts)
        fd.close()
        print("Traced "+uts)

        

if __name__== "__main__":
    main()
