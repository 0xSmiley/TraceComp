firstPart="""
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
"""
secondPart="""
        {
            "name": "$",
            "action": "SCMP_ACT_ALLOW"
        }"""
thirdPart="""
    ]
}
"""
def EbpfMode():
    print("Test1")
    fd=open("CustomSeccomp.json", "w")
    fd.write(firstPart)
    i=0
    with open('captures.log') as log:
        print("Test2")
        line=log.readline()
        line=log.readline()
        while line:
            print("Test3")
            if i != 0:
                fd.write(',\n')
            parts=line.split(';')
            syscall=parts[3].strip()
            module=secondPart.replace('$',syscall)
            print(syscall)
            fd.write(module)
            line=log.readline()
            i=i+1
    
    fd.write(thirdPart)
    
    fd.close()
    log.close()
    exit(0)

#EbpfMode()