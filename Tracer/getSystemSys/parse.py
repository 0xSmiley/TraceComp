fd = open("syscalls.txt", "w")
with open("./kallsyms", "r") as f:
    syscalls=f.readlines()
    for syscall in syscalls:
        tmp=syscall.split(" ")
        if tmp[1]=="T":
            sys=tmp[2]
            if "." not in sys:
                if "[" in sys:
                    index=sys.index("[")
                    sys=sys[:index].strip()
                if "x64" in sys:
                    fd.write(sys)
fd.close
        