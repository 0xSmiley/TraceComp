#include <uapi/linux/utsname.h>
#include <linux/pid_namespace.h>

struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
};

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    return task->nsproxy->uts_ns->name.nodename;
}

int hello(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:OHH ENTRY!\n", get_task_uts_name(task));
    }
    return 0;
}
int hello2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:OHH RETURN!\n", get_task_uts_name(task));
    }
    return 0;
}