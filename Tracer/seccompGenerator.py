import sys

firstPart="""
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {
            "names": [
"""
secondPart="""              "$" """
thirdPart="""
    ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}

"""
syscalls={}
fileDesc={}

def EbpfMode():
    
    with open('captures.log') as log:
        line=log.readline()
        line=log.readline()
        while line:
            parts=line.split(';')
            syscall=parts[3].strip()
            namespace=parts[2].strip()
            values=syscalls.get(namespace, [])
            
            if namespace not in fileDesc:
                fd=open(namespace+".json", "w")
                fd.write(firstPart)
                fileDesc[namespace]=fd

            if syscall not in values:
                fd=fileDesc[namespace]
                if len(values) != 0:
                    fd.write(',\n')
                module=secondPart.replace('$',syscall)

                fd.write(module)
                syscalls.setdefault(namespace, []).append(syscall)
            line=log.readline()
    
    for key in fileDesc:
        fd=fileDesc[key]
        fd.write(thirdPart)
        fd.close()
    
    log.close()
    exit(0)

def standardMode(path):
    syscallList=[]
    with open(path) as log:
        line=log.readline()
        fd=open("outputSeccomp.json", "w")
        fd.write(firstPart)

        while line:
            syscall=line.strip()
            if syscall not in syscallList:
                if len(syscallList) != 0:
                    fd.write(',\n')
                module=secondPart.replace('$',syscall)
                fd.write(module)
                syscallList.append(syscall)
            line=log.readline()
        fd.write(thirdPart)
        fd.close()
        log.close()

if len(sys.argv) > 1:
    path = sys.argv[1]
    if path != "":
        standardMode(path)


