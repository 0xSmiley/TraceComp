
#include <uapi/linux/utsname.h>
#include <linux/pid_namespace.h>

struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
};

static __always_inline char * get_task_uts_name(struct task_struct *task){
    return task->nsproxy->uts_ns->name.nodename;
}


int syscall__llseek(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:_llseek\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall__newselect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:_newselect\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall__sysctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:_sysctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_accept(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:accept\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_accept4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:accept4\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_access(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:access\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_acct(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:acct\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_add_key(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:add_key\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_adjtimex(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:adjtimex\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_alarm(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:alarm\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_alloc_hugepages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:alloc_hugepages\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_arc_gettls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:arc_gettls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_arc_settls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:arc_settls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_arc_usr_cmpxchg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:arc_usr_cmpxchg\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_arch_prctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:arch_prctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_atomic_barrier(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:atomic_barrier\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_atomic_cmpxchg_32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:atomic_cmpxchg_32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_bdflush(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:bdflush\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_bfin_spinlock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:bfin_spinlock\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_bind(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:bind\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_bpf(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:bpf\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_brk(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:brk\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_breakpoint(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:breakpoint\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_cacheflush(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:cacheflush\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_capget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:capget\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_capset(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:capset\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_chdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:chdir\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_chmod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:chmod\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_chown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:chown\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_chown32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:chown32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_chroot(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:chroot\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clock_adjtime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clock_adjtime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clock_getres(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clock_getres\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clock_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clock_gettime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clock_nanosleep(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clock_nanosleep\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clock_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clock_settime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clone2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clone2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clone(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clone\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_clone3(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:clone3\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_close(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:close\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_cmpxchg_badaddr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:cmpxchg_badaddr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_connect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:connect\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_copy_file_range(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:copy_file_range\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_creat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:creat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_create_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:create_module\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_delete_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:delete_module\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_dma_memcpy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:dma_memcpy\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_dup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:dup\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_dup2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:dup2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_dup3(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:dup3\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_epoll_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:epoll_create\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_epoll_create1(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:epoll_create1\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_epoll_ctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:epoll_ctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_epoll_pwait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:epoll_pwait\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_epoll_wait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:epoll_wait\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_eventfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:eventfd\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_eventfd2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:eventfd2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_execv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:execv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_execve(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:execve\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_execveat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:execveat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_exit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:exit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_exit_group(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:exit_group\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_faccessat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:faccessat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fadvise64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fadvise64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fadvise64_64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fadvise64_64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fallocate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fallocate\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fanotify_init(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fanotify_init\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fanotify_mark(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fanotify_mark\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchdir\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchmod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchmod\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchmodat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchmodat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchown\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchown32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchown32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fchownat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fchownat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fcntl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fcntl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fcntl64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fcntl64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fdatasync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fdatasync\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fgetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fgetxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_finit_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:finit_module\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_flistxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:flistxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_flock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:flock\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fork(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fork\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_free_hugepages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:free_hugepages\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fremovexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fremovexattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fsconfig(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fsconfig\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fsetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fsetxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fsmount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fsmount\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fsopen(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fsopen\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fspick(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fspick\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fstat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fstat64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fstat64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fstatat64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fstatat64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fstatfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fstatfs\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fstatfs64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fstatfs64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_fsync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:fsync\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ftruncate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ftruncate\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ftruncate64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ftruncate64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_futex(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:futex\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_futimesat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:futimesat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_get_kernel_syms(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:get_kernel_syms\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_get_mempolicy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:get_mempolicy\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_get_robust_list(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:get_robust_list\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_get_thread_area(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:get_thread_area\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_get_tls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:get_tls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getcpu(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getcpu\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getcwd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getcwd\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getdents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getdents\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getdents64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getdents64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getdomainname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getdomainname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getdtablesize(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getdtablesize\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getegid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getegid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getegid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getegid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_geteuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:geteuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_geteuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:geteuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getgid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getgid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getgroups(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getgroups\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getgroups32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getgroups32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_gethostname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:gethostname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getitimer(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getitimer\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpeername(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpeername\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpagesize(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpagesize\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpgrp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpgrp\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getppid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getppid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getpriority(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getpriority\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getrandom(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getrandom\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getresgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getresgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getresgid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getresgid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getresuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getresuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getresuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getresuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getrlimit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getrusage(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getrusage\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getsid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getsid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getsockname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getsockname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getsockopt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getsockopt\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_gettid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:gettid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_gettimeofday(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:gettimeofday\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getunwind(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getunwind\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getxgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getxgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getxpid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getxpid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_getxuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:getxuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_init_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:init_module\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_inotify_add_watch(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:inotify_add_watch\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_inotify_init(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:inotify_init\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_inotify_init1(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:inotify_init1\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_inotify_rm_watch(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:inotify_rm_watch\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_cancel(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_cancel\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_destroy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_destroy\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_getevents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_getevents\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_pgetevents(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_pgetevents\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_setup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_setup\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_submit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_submit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_uring_enter(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_uring_enter\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_uring_register(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_uring_register\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_io_uring_setup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:io_uring_setup\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ioctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ioctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ioperm(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ioperm\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_iopl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:iopl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ioprio_get(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ioprio_get\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ioprio_set(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ioprio_set\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ipc(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ipc\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_kcmp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:kcmp\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_kern_features(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:kern_features\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_kexec_file_load(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:kexec_file_load\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_kexec_load(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:kexec_load\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_keyctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:keyctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_kill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:kill\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lchown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lchown\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lchown32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lchown32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lgetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lgetxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_link(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:link\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_linkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:linkat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_listen(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:listen\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_listxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:listxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_llistxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:llistxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lookup_dcookie(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lookup_dcookie\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lremovexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lremovexattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lseek(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lseek\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lsetxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lsetxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lstat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_lstat64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:lstat64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_madvise(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:madvise\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mbind(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mbind\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_memory_ordering(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:memory_ordering\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_metag_get_tls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:metag_get_tls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_metag_set_fpu_flags(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:metag_set_fpu_flags\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_metag_set_tls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:metag_set_tls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_metag_setglobalbit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:metag_setglobalbit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_membarrier(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:membarrier\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_memfd_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:memfd_create\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_migrate_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:migrate_pages\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mincore(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mincore\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mkdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mkdir\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mkdirat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mkdirat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mknod(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mknod\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mknodat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mknodat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mlock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mlock\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mlock2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mlock2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mlockall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mlockall\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mmap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mmap\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mmap2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mmap2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_modify_ldt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:modify_ldt\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mount\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_move_mount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:move_mount\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_move_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:move_pages\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mprotect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mprotect\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_getsetattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_getsetattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_notify(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_notify\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_open\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_timedreceive(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_timedreceive\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_timedsend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_timedsend\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mq_unlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mq_unlink\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_mremap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:mremap\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_msgctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:msgctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_msgget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:msgget\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_msgrcv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:msgrcv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_msgsnd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:msgsnd\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_msync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:msync\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_munlock(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:munlock\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_munlockall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:munlockall\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_munmap(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:munmap\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_name_to_handle_at(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:name_to_handle_at\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_nanosleep(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:nanosleep\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_newfstatat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:newfstatat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_nfsservctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:nfsservctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_nice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:nice\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_old_adjtimex(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:old_adjtimex\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_old_getrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:old_getrlimit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_oldfstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:oldfstat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_oldlstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:oldlstat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_oldolduname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:oldolduname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_oldstat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:oldstat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_oldumount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:oldumount\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_olduname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:olduname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:open\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_open_by_handle_at(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:open_by_handle_at\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_open_tree(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:open_tree\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_openat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:openat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_or1k_atomic(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:or1k_atomic\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pause(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pause\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pciconfig_iobase(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pciconfig_iobase\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pciconfig_read(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pciconfig_read\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pciconfig_write(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pciconfig_write\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_perf_event_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:perf_event_open\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_personality(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:personality\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_perfctr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:perfctr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_perfmonctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:perfmonctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pidfd_send_signal(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pidfd_send_signal\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pidfd_open(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pidfd_open\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pipe(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pipe\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pipe2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pipe2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pivot_root(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pivot_root\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pkey_alloc(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pkey_alloc\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pkey_free(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pkey_free\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pkey_mprotect(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pkey_mprotect\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_poll(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:poll\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ppoll(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ppoll\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_prctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:prctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pread(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pread\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pread64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pread64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_preadv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:preadv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_preadv2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:preadv2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_prlimit64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:prlimit64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_process_vm_readv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:process_vm_readv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_process_vm_writev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:process_vm_writev\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pselect6(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pselect6\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ptrace(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ptrace\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pwrite(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pwrite\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pwrite64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pwrite64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pwritev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pwritev\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_pwritev2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:pwritev2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_query_module(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:query_module\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_quotactl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:quotactl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_read(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:read\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_readahead(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:readahead\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_readdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:readdir\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_readlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:readlink\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_readlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:readlinkat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_readv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:readv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_reboot(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:reboot\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_recv(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:recv\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_recvfrom(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:recvfrom\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_recvmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:recvmsg\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_recvmmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:recvmmsg\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_remap_file_pages(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:remap_file_pages\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_removexattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:removexattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rename(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rename\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_renameat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:renameat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_renameat2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:renameat2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_request_key(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:request_key\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_restart_syscall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:restart_syscall\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_riscv_flush_icache(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:riscv_flush_icache\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rmdir(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rmdir\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rseq(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rseq\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigaction(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigaction\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigpending(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigpending\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigprocmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigprocmask\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigqueueinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigqueueinfo\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigreturn(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigreturn\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigsuspend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigsuspend\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_sigtimedwait(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_sigtimedwait\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rt_tgsigqueueinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rt_tgsigqueueinfo\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_rtas(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:rtas\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_s390_runtime_instr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:s390_runtime_instr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_s390_pci_mmio_read(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:s390_pci_mmio_read\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_s390_pci_mmio_write(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:s390_pci_mmio_write\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_s390_sthyi(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:s390_sthyi\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_s390_guarded_storage(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:s390_guarded_storage\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_get_affinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_get_affinity\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_get_priority_max(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_get_priority_max\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_get_priority_min(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_get_priority_min\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_getaffinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_getaffinity\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_getattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_getattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_getparam(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_getparam\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_getscheduler(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_getscheduler\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_rr_get_interval(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_rr_get_interval\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_set_affinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_set_affinity\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_setaffinity(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_setaffinity\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_setattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_setattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_setparam(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_setparam\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_setscheduler(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_setscheduler\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sched_yield(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sched_yield\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_seccomp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:seccomp\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_select(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:select\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_semctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:semctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_semget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:semget\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_semop(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:semop\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_semtimedop(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:semtimedop\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_send(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:send\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sendfile(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sendfile\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sendfile64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sendfile64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sendmmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sendmmsg\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sendmsg(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sendmsg\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sendto(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sendto\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_set_mempolicy(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:set_mempolicy\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_set_robust_list(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:set_robust_list\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_set_thread_area(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:set_thread_area\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_set_tid_address(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:set_tid_address\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_set_tls(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:set_tls\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setdomainname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setdomainname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setfsgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setfsgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setfsgid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setfsgid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setfsuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setfsuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setfsuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setfsuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setgid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setgid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setgroups(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setgroups\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setgroups32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setgroups32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sethae(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sethae\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sethostname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sethostname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setitimer(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setitimer\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setns(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setns\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setpgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setpgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setpgrp(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setpgrp\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setpriority(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setpriority\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setregid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setregid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setregid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setregid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setresgid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setresgid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setresgid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setresgid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setresuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setresuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setresuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setresuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setreuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setreuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setreuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setreuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setrlimit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setsid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setsid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setsockopt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setsockopt\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_settimeofday(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:settimeofday\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setuid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setuid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setuid32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setuid32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setup\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_setxattr(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:setxattr\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sgetmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sgetmask\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_shmat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:shmat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_shmctl(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:shmctl\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_shmdt(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:shmdt\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_shmget(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:shmget\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_shutdown(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:shutdown\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigaction(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigaction\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigaltstack(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigaltstack\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_signal(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:signal\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_signalfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:signalfd\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_signalfd4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:signalfd4\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigpending(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigpending\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigprocmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigprocmask\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigreturn(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigreturn\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sigsuspend(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sigsuspend\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_socket(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:socket\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_socketcall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:socketcall\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_socketpair(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:socketpair\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_spill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:spill\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_splice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:splice\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_spu_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:spu_create\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_spu_run(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:spu_run\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sram_alloc(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sram_alloc\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sram_free(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sram_free\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ssetmask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ssetmask\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_stat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:stat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_stat64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:stat64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_statfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:statfs\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_statfs64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:statfs64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_statx(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:statx\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_stime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:stime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_subpage_prot(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:subpage_prot\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_switch_endian(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:switch_endian\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_swapcontext(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:swapcontext\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_swapoff(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:swapoff\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_swapon(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:swapon\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_symlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:symlink\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_symlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:symlinkat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sync(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sync\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sync_file_range(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sync_file_range\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sync_file_range2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sync_file_range2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_syncfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:syncfs\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sys_debug_setcontext(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sys_debug_setcontext\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_syscall(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:syscall\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sysfs(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sysfs\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sysinfo(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sysinfo\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_syslog(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:syslog\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_sysmips(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:sysmips\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_tee(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:tee\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_tgkill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:tgkill\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_time(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:time\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timer_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timer_create\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timer_delete(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timer_delete\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timer_getoverrun(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timer_getoverrun\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timer_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timer_gettime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timer_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timer_settime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timerfd_create(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timerfd_create\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timerfd_gettime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timerfd_gettime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_timerfd_settime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:timerfd_settime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_times(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:times\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_tkill(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:tkill\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_truncate(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:truncate\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_truncate64(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:truncate64\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ugetrlimit(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ugetrlimit\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_umask(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:umask\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_umount(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:umount\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_umount2(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:umount2\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_uname(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:uname\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_unlink(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:unlink\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_unlinkat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:unlinkat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_unshare(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:unshare\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_uselib(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:uselib\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_ustat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:ustat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_userfaultfd(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:userfaultfd\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_usr26(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:usr26\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_usr32(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:usr32\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_utime(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:utime\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_utimensat(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:utimensat\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_utimes(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:utimes\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_utrap_install(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:utrap_install\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_vfork(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:vfork\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_vhangup(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:vhangup\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_vm86old(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:vm86old\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_vm86(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:vm86\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_vmsplice(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:vmsplice\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_wait4(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:wait4\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_waitid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:waitid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_waitpid(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:waitpid\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_write(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:write\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_writev(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:writev\n", get_task_uts_name(task));
    }
    return 0;
}

int syscall_xtensa(void *ctx) {
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    char * uts_name = get_task_uts_name(task);

    if (uts_name){
        bpf_trace_printk("%s:xtensa\n", get_task_uts_name(task));
    }
    return 0;
}
