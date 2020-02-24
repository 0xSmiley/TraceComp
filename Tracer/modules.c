

#include <uapi/linux/utsname.h>
#include <linux/pid_namespace.h>


struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
};

struct data_t {
    char uts[50];

    char syscall[30];
    
};
BPF_PERF_OUTPUT(data_event);

static __always_inline char * get_task_uts_name(struct task_struct *task){
    return task->nsproxy->uts_ns->name.nodename;
}

int syscall_arch_prctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name =get_task_uts_name(task);

    if (strcmp(uts_name,"ubuntu-VirtualBox")==0)
        return 0;
    else if (strcmp(uts_name,"cd1746c4b31d")==0)
        return 0;
    else{    
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "arch_prctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigreturn(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigreturn");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_iopl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "iopl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ioperm(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ioperm");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_modify_ldt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "modify_ldt");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mmap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mmap");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_set_thread_area(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "set_thread_area");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_get_thread_area(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "get_thread_area");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_set_tid_address(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "set_tid_address");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fork(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fork");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_vfork(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "vfork");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clone(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clone");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clone3(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clone3");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_unshare(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "unshare");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_personality(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "personality");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_waitid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "waitid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_exit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "exit");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_exit_group(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "exit_group");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_wait4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "wait4");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_waitpid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "waitpid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sysctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sysctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_capget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "capget");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_capset(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "capset");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ptrace(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ptrace");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_restart_syscall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "restart_syscall");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sgetmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sgetmask");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pause(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pause");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sigaltstack(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sigaltstack");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sigpending(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sigpending");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigpending(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigpending");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ssetmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ssetmask");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sigsuspend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sigsuspend");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigsuspend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigsuspend");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigprocmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigprocmask");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sigprocmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sigprocmask");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigqueueinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigqueueinfo");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_kill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "kill");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_tgkill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "tgkill");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_tkill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "tkill");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_tgsigqueueinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_tgsigqueueinfo");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigtimedwait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigtimedwait");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigtimedwait_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigtimedwait_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pidfd_send_signal(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pidfd_send_signal");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_signal(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "signal");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rt_sigaction(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rt_sigaction");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_umask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "umask");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getpriority(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getpriority");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_gettid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "gettid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getpid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getpid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getppid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getppid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_geteuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "geteuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getcpu(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getcpu");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getegid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getegid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setpgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setpgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getpgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getpgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getpgrp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getpgrp");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sysinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sysinfo");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_times(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "times");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getresgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getresgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getresuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getresuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getsid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getsid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_old_getrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "old_getrlimit");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_gethostname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "gethostname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_newuname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "newuname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_uname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "uname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setdomainname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setdomainname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sethostname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sethostname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_olduname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "olduname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setpriority(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setpriority");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setregid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setregid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setreuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setreuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setresuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setresuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setresgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setresgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setfsuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setfsuid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setfsgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setfsgid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setsid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setsid");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setrlimit");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getrlimit");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_prlimit64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "prlimit64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getrusage(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getrusage");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_prctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "prctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pidfd_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pidfd_open");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setns(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setns");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_reboot(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "reboot");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getgroups(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getgroups");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setgroups(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setgroups");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_get_priority_max(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_get_priority_max");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_get_priority_min(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_get_priority_min");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_getscheduler(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_getscheduler");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_getparam(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_getparam");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_getattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_getattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_rr_get_interval(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_rr_get_interval");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_rr_get_interval_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_rr_get_interval_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_setscheduler(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_setscheduler");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_setparam(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_setparam");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_setattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_setattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_nice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "nice");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_yield(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_yield");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_setaffinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_setaffinity");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sched_getaffinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sched_getaffinity");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_membarrier(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "membarrier");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_syslog(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "syslog");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_kcmp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "kcmp");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_time(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "time");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_adjtimex(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "adjtimex");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_stime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "stime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_stime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "stime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_gettimeofday(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "gettimeofday");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_settimeofday(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "settimeofday");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_adjtimex_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "adjtimex_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_nanosleep(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "nanosleep");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_nanosleep_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "nanosleep_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_delete(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_delete");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_gettime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_gettime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_gettime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_getoverrun(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_getoverrun");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_settime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_settime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_settime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_gettime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_gettime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_gettime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_settime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_settime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_settime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_getres_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_getres_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_getres(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_getres");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_nanosleep(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_nanosleep");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_nanosleep_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_nanosleep_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timer_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timer_create");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_adjtime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_adjtime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_clock_adjtime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "clock_adjtime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getitimer(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getitimer");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_alarm(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "alarm");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setitimer(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setitimer");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_set_robust_list(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "set_robust_list");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_get_robust_list(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "get_robust_list");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_futex(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "futex");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_futex_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "futex_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_chown16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "chown16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lchown16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lchown16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchown16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchown16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setregid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setregid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setgid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setgid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setreuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setreuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setresuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setresuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setresgid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setresgid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setfsuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setfsuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setfsgid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setfsgid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_geteuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "geteuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getgid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getgid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getegid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getegid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getgroups16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getgroups16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setgroups16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setgroups16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getresuid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getresuid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getresgid16(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getresgid16");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_delete_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "delete_module");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_init_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "init_module");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_finit_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "finit_module");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_acct(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "acct");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_kexec_load(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "kexec_load");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_kexec_file_load(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "kexec_file_load");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_seccomp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "seccomp");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_bpf(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "bpf");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rseq(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rseq");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fadvise64_64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fadvise64_64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fadvise64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fadvise64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_readahead(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "readahead");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mincore(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mincore");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mlock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mlock");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mlock2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mlock2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_munlock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "munlock");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_munlockall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "munlockall");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mlockall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mlockall");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mmap_pgoff(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mmap_pgoff");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_munmap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "munmap");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_brk(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "brk");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_remap_file_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "remap_file_pages");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pkey_free(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pkey_free");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pkey_alloc(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pkey_alloc");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mprotect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mprotect");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pkey_mprotect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pkey_mprotect");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mremap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mremap");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_msync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "msync");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_process_vm_readv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "process_vm_readv");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_process_vm_writev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "process_vm_writev");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_madvise(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "madvise");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_swapoff(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "swapoff");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_swapon(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "swapon");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_migrate_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "migrate_pages");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_set_mempolicy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "set_mempolicy");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_get_mempolicy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "get_mempolicy");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mbind(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mbind");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_move_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "move_pages");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_memfd_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "memfd_create");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_vhangup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "vhangup");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_close(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "close");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchdir");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_truncate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "truncate");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ftruncate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ftruncate");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fallocate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fallocate");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_faccessat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "faccessat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_access(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "access");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_chdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "chdir");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_chroot(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "chroot");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchmod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchmod");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchmodat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchmodat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_chmod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "chmod");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchownat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchownat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_chown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "chown");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lchown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lchown");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fchown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fchown");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "open");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_openat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "openat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_creat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "creat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_llseek(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "llseek");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lseek(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lseek");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_writev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "writev");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pwritev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pwritev");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pwritev2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pwritev2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sendfile(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sendfile");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sendfile64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sendfile64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_copy_file_range(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "copy_file_range");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_read(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "read");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_write(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "write");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pread64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pread64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pwrite64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pwrite64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_readv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "readv");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_preadv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "preadv");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_preadv2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "preadv2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_stat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "stat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lstat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fstat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_newstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "newstat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_newlstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "newlstat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_newfstatat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "newfstatat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_newfstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "newfstat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_statx(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "statx");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_readlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "readlinkat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_readlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "readlink");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_execve(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "execve");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_execveat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "execveat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_uselib(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "uselib");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pipe2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pipe2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pipe(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pipe");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_renameat2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "renameat2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_renameat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "renameat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rename(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rename");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mknodat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mknodat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mknod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mknod");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mkdirat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mkdirat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mkdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mkdir");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_rmdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "rmdir");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_unlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "unlink");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_unlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "unlinkat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_symlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "symlinkat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_symlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "symlink");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_linkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "linkat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_link(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "link");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fcntl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fcntl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ioctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ioctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_old_readdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "old_readdir");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getdents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getdents");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getdents64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getdents64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_poll(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "poll");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ppoll(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ppoll");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_select(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "select");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pselect6(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pselect6");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_dup3(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "dup3");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_dup2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "dup2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_dup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "dup");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sysfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sysfs");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_umount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "umount");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_oldumount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "oldumount");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_open_tree(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "open_tree");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fsmount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fsmount");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_move_mount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "move_mount");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mount");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_pivot_root(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "pivot_root");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_listxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "listxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_llistxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "llistxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lgetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lgetxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_flistxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "flistxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fgetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fgetxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_removexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "removexattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lremovexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lremovexattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fremovexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fremovexattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lsetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lsetxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fsetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fsetxattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_vmsplice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "vmsplice");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_splice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "splice");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_tee(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "tee");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fsync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fsync");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fdatasync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fdatasync");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_syncfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "syncfs");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sync");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sync_file_range(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sync_file_range");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sync_file_range2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sync_file_range2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_futimesat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "futimesat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utimes(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utimes");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_futimesat_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "futimesat_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utimes_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utimes_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utimensat_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utimensat_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_utimensat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "utimensat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getcwd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getcwd");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ustat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ustat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_statfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "statfs");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_statfs64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "statfs64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fstatfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fstatfs");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fstatfs64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fstatfs64");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fsopen(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fsopen");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fspick(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fspick");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fsconfig(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fsconfig");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_bdflush(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "bdflush");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_inotify_init1(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "inotify_init1");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_inotify_init(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "inotify_init");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_inotify_rm_watch(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "inotify_rm_watch");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_inotify_add_watch(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "inotify_add_watch");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fanotify_init(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fanotify_init");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_fanotify_mark(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "fanotify_mark");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_epoll_create1(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "epoll_create1");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_epoll_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "epoll_create");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_epoll_wait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "epoll_wait");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_epoll_pwait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "epoll_pwait");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_epoll_ctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "epoll_ctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_signalfd4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "signalfd4");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_signalfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "signalfd");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timerfd_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timerfd_create");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timerfd_gettime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timerfd_gettime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timerfd_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timerfd_gettime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timerfd_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timerfd_settime");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_timerfd_settime32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "timerfd_settime32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_eventfd2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "eventfd2");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_eventfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "eventfd");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_userfaultfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "userfaultfd");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_destroy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_destroy");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_cancel(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_cancel");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_getevents_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_getevents_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_getevents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_getevents");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_pgetevents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_pgetevents");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_submit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_submit");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_setup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_setup");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_uring_enter(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_uring_enter");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_uring_setup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_uring_setup");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_io_uring_register(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "io_uring_register");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_flock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "flock");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_name_to_handle_at(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "name_to_handle_at");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_open_by_handle_at(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "open_by_handle_at");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_quotactl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "quotactl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_lookup_dcookie(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "lookup_dcookie");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_msgget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "msgget");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_msgctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "msgctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_msgrcv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "msgrcv");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_msgsnd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "msgsnd");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_semop(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "semop");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_semctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "semctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_semget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "semget");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_semtimedop(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "semtimedop");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_semtimedop_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "semtimedop_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_shmget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "shmget");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_shmctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "shmctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_shmat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "shmat");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_shmdt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "shmdt");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_getsetattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_getsetattr");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_open");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_timedsend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_timedsend");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_timedsend_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_timedsend_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_timedreceive_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_timedreceive_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_timedreceive(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_timedreceive");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_notify(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_notify");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_mq_unlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "mq_unlink");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_request_key(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "request_key");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_add_key(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "add_key");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_keyctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "keyctl");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ioprio_get(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ioprio_get");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_ioprio_set(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "ioprio_set");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getrandom(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getrandom");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getsockopt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getsockopt");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_setsockopt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "setsockopt");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_socket(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "socket");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_socketpair(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "socketpair");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_bind(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "bind");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_listen(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "listen");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_accept4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "accept4");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_accept(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "accept");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_connect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "connect");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getsockname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getsockname");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_getpeername(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "getpeername");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sendto(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sendto");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_send(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "send");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_recvfrom(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "recvfrom");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_recv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "recv");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_shutdown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "shutdown");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sendmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sendmsg");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_sendmmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "sendmmsg");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_recvmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "recvmsg");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_recvmmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "recvmmsg");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_recvmmsg_time32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "recvmmsg_time32");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int syscall_socketcall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);
    //bpf_trace_printk("Aqui %s",uts_name);
    if(uts_name){
        bpf_trace_printk("Aqui %s",uts_name);
        struct data_t data = {};
        bpf_probe_read_str(&data.uts, 50, get_task_uts_name(task));
        strcpy(data.syscall, "socketcall");
        data_event.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
