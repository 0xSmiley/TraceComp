

def syscalls(path):
    parsed = open("parsed.txt", "w")
    with open(path, "r") as f:
        for line in f:
            result=line.find('(')
            if result==-1:
                continue
            else:
                parsed.write(line[:result]+"\n")
    parsed.close()


path = "ListSyscall.txt"
syscalls(path)