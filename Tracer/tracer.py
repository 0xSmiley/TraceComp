from bcc import BPF
import socket
import os
import seccompGenerator
import time
import threading
import grpc
from concurrent import futures

import service_pb2
import service_pb2_grpc


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

def sendMessage(channel,utsMessage):
    stub = service_pb2_grpc.ComunicationStub(channel)
    message = service_pb2.Uts(uts=utsMessage)
    response=""
    try:
        response = stub.AddUuts(message)
        #print(response)
        if response.confirm == 1:
            fdTmp=fileDesc[utsMessage]
            fdTmp.close()
            seccompGenerator.EbpfMode(utsMessage)
            print("Traced "+utsMessage)
        else:
            print("Error on gRPC ")
    
    except:
        print("ERROR " + response+" done")



def main():
    channel = grpc.insecure_channel('localhost:50051')

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
    
    print("Tracing")
    
    while 1:
        
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        
        except KeyboardInterrupt:
            print("Exit")
            exit(0)
        
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
                x = threading.Thread(target=sendMessage, args=([channel,uts]))
                x.start()
            else:
                fd=fileDesc[uts]
            try:
                fd.write("%f;%s;%s;%s\n" % (ts, task, uts, syscall))
                #print("%f;%s;%s;%s" % (ts, task, uts, syscall))
            except Exception:
                print("Error on "+uts+ " "+ task+ " "+syscall)
        

if __name__== "__main__":
    main()
