
Syscalllpath="newListSyscalls.txt"

header="""
#include <uapi/linux/utsname.h>
#include <linux/pid_namespace.h>

struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
};

static __always_inline char * get_task_uts_name(struct task_struct *task){
    return task->nsproxy->uts_ns->name.nodename;
}

"""

moduleEx="""
int syscall_$(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:$\\n", get_task_uts_name(task));
    }
    return 0;
}
"""


def main():
    fd=open("modules.c", "w")
    fd.write(header)
    with open(Syscalllpath, "r") as f:
        syscalls=f.readlines()
        for syscall in syscalls:
            syscall=syscall.strip()
            module=moduleEx.replace('$',syscall)
            fd.write(module)


if __name__== "__main__":
    main()
