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
syscalls=[]

def EbpfMode(uts):

    fd=open("Captures/"+uts+".json", "w")
    fd.write(firstPart)
    
    with open("Captures/"+uts+'.cap') as log:
        line=log.readline()
        line=log.readline()
        while line:
            parts=line.split(';')
            syscall=parts[3].strip()
            
            if syscall not in syscalls:
                if len(syscalls) != 0:
                    fd.write(',\n')
                if syscall == "newuname":
                    newModule=secondPart.replace('$',"uname")
                    fd.write(newModule)
                    fd.write(',\n')
                elif syscall == "newstat":
                    newModule=secondPart.replace('$',"stat")
                    fd.write(newModule)
                    fd.write(',\n')
                elif syscall == "newfstatat":
                    newModule=secondPart.replace('$',"fstatat")
                    fd.write(newModule)
                    fd.write(',\n')
                elif syscall == "newfstat":
                    newModule=secondPart.replace('$',"fstat")
                    fd.write(newModule)
                    fd.write(',\n')
                elif syscall == "newlstat":
                    newModule=secondPart.replace('$',"lstat")
                    fd.write(newModule)
                    fd.write(',\n')

                module=secondPart.replace('$',syscall)
                fd.write(module)
                syscalls.append(syscall)

            line=log.readline()

    fd.write(thirdPart)
    fd.close()
    log.close()


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


