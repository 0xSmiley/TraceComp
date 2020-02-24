from bcc import BPF
import socket
import os
import seccompGenerator
import time
import docker
from threading import Timer
import ctypes as ct


pathModules="modules.c" 
pathSyscalls="parsed.txt"
fileDesc={}
hostnameContainer = socket.gethostname()
hostnameHost= os.environ['HOST_HOSTNAME']
client = docker.from_env()

def load_modules():
    with open(pathModules, "r") as f:
        modules = f.read()
    return modules

def load_syscalls():
    with open(pathSyscalls, "r") as f:
        syscalls = f.readlines()
    return syscalls

class Data(ct.Structure):
    _fields_ = [
      ('uts', ct.c_char * 50), 
      ('syscall', ct.c_char * 30), 
    ]



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
    
    b['data_event'].open_perf_buffer(traceEvent)
    print("Tracing")
    while True:
        try:
            # Poll the data structure till Ctrl+C
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print('Bye !')
            exit()


def traceEvent(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    uts=data.uts.decode("utf-8")
    syscall=data.syscall.decode("utf-8")
    
    
    if (uts!=hostnameHost and uts!=hostnameContainer):
        
        if uts not in fileDesc:
            fd = open("Captures/"+uts+".cap", "w")
            fd.write("%s;%s" % ("NAMESPACE", "SYSCALL\n"))
            fileDesc[uts] = fd
        else:
            fd=fileDesc[uts]
        try:
            fd.write("%s;%s\n" % (uts, syscall))
            #print("%s;%s\n" % (uts, syscall))
        except Exception:
            seccompGenerator.EbpfMode(uts)
            fd.close()
            print("Error on "+uts + "  " + syscall)
    
        """container = client.containers.get(uts)
        containerCheck=container.status.strip()
        if containerCheck=="exited":
            t=Timer(10,stopTrace,[uts,fd])
            t.start()"""

def stopTrace(uts,fd):
    seccompGenerator.EbpfMode(uts)
    fd.close()
    print("Traced "+uts)


if __name__== "__main__":
    main()
