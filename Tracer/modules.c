
int syscall__llseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_llseek\n");
    return 0;
}

int syscall__newselect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_newselect\n");
    return 0;
}

int syscall__sysctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_sysctl\n");
    return 0;
}

int syscall_accept(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept\n");
    return 0;
}

int syscall_accept4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept4\n");
    return 0;
}

int syscall_access(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->access\n");
    return 0;
}

int syscall_acct(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->acct\n");
    return 0;
}

int syscall_add_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->add_key\n");
    return 0;
}

int syscall_adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->adjtimex\n");
    return 0;
}

int syscall_alarm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alarm\n");
    return 0;
}

int syscall_alloc_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alloc_hugepages\n");
    return 0;
}

int syscall_arc_gettls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_gettls\n");
    return 0;
}

int syscall_arc_settls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_settls\n");
    return 0;
}

int syscall_arc_usr_cmpxchg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_usr_cmpxchg\n");
    return 0;
}

int syscall_arch_prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arch_prctl\n");
    return 0;
}

int syscall_atomic_barrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_barrier\n");
    return 0;
}

int syscall_atomic_cmpxchg_32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_cmpxchg_32\n");
    return 0;
}

int syscall_bdflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bdflush\n");
    return 0;
}

int syscall_bfin_spinlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bfin_spinlock\n");
    return 0;
}

int syscall_bind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bind\n");
    return 0;
}

int syscall_bpf(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bpf\n");
    return 0;
}

int syscall_brk(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->brk\n");
    return 0;
}

int syscall_breakpoint(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->breakpoint\n");
    return 0;
}

int syscall_cacheflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cacheflush\n");
    return 0;
}

int syscall_capget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capget\n");
    return 0;
}

int syscall_capset(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capset\n");
    return 0;
}

int syscall_chdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chdir\n");
    return 0;
}

int syscall_chmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chmod\n");
    return 0;
}

int syscall_chown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown\n");
    return 0;
}

int syscall_chown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown32\n");
    return 0;
}

int syscall_chroot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chroot\n");
    return 0;
}

int syscall_clock_adjtime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_adjtime\n");
    return 0;
}

int syscall_clock_getres(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_getres\n");
    return 0;
}

int syscall_clock_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_gettime\n");
    return 0;
}

int syscall_clock_nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_nanosleep\n");
    return 0;
}

int syscall_clock_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_settime\n");
    return 0;
}

int syscall_clone2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone2\n");
    return 0;
}

int syscall_clone(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone\n");
    return 0;
}

int syscall_clone3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone3\n");
    return 0;
}

int syscall_close(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->close\n");
    return 0;
}

int syscall_cmpxchg_badaddr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cmpxchg_badaddr\n");
    return 0;
}

int syscall_connect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->connect\n");
    return 0;
}

int syscall_copy_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->copy_file_range\n");
    return 0;
}

int syscall_creat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->creat\n");
    return 0;
}

int syscall_create_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->create_module\n");
    return 0;
}

int syscall_delete_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->delete_module\n");
    return 0;
}

int syscall_dma_memcpy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dma_memcpy\n");
    return 0;
}

int syscall_dup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup\n");
    return 0;
}

int syscall_dup2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup2\n");
    return 0;
}

int syscall_dup3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup3\n");
    return 0;
}

int syscall_epoll_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create\n");
    return 0;
}

int syscall_epoll_create1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create1\n");
    return 0;
}

int syscall_epoll_ctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_ctl\n");
    return 0;
}

int syscall_epoll_pwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_pwait\n");
    return 0;
}

int syscall_epoll_wait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_wait\n");
    return 0;
}

int syscall_eventfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd\n");
    return 0;
}

int syscall_eventfd2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd2\n");
    return 0;
}

int syscall_execv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execv\n");
    return 0;
}

int syscall_execve(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execve\n");
    return 0;
}

int syscall_execveat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execveat\n");
    return 0;
}

int syscall_exit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit\n");
    return 0;
}

int syscall_exit_group(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit_group\n");
    return 0;
}

int syscall_faccessat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->faccessat\n");
    return 0;
}

int syscall_fadvise64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64\n");
    return 0;
}

int syscall_fadvise64_64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64_64\n");
    return 0;
}

int syscall_fallocate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fallocate\n");
    return 0;
}

int syscall_fanotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_init\n");
    return 0;
}

int syscall_fanotify_mark(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_mark\n");
    return 0;
}

int syscall_fchdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchdir\n");
    return 0;
}

int syscall_fchmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmod\n");
    return 0;
}

int syscall_fchmodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmodat\n");
    return 0;
}

int syscall_fchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown\n");
    return 0;
}

int syscall_fchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown32\n");
    return 0;
}

int syscall_fchownat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchownat\n");
    return 0;
}

int syscall_fcntl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl\n");
    return 0;
}

int syscall_fcntl64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl64\n");
    return 0;
}

int syscall_fdatasync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fdatasync\n");
    return 0;
}

int syscall_fgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fgetxattr\n");
    return 0;
}

int syscall_finit_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->finit_module\n");
    return 0;
}

int syscall_flistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flistxattr\n");
    return 0;
}

int syscall_flock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flock\n");
    return 0;
}

int syscall_fork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fork\n");
    return 0;
}

int syscall_free_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->free_hugepages\n");
    return 0;
}

int syscall_fremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fremovexattr\n");
    return 0;
}

int syscall_fsconfig(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsconfig\n");
    return 0;
}

int syscall_fsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsetxattr\n");
    return 0;
}

int syscall_fsmount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsmount\n");
    return 0;
}

int syscall_fsopen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsopen\n");
    return 0;
}

int syscall_fspick(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fspick\n");
    return 0;
}

int syscall_fstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat\n");
    return 0;
}

int syscall_fstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat64\n");
    return 0;
}

int syscall_fstatat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatat64\n");
    return 0;
}

int syscall_fstatfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs\n");
    return 0;
}

int syscall_fstatfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs64\n");
    return 0;
}

int syscall_fsync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsync\n");
    return 0;
}

int syscall_ftruncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate\n");
    return 0;
}

int syscall_ftruncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate64\n");
    return 0;
}

int syscall_futex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futex\n");
    return 0;
}

int syscall_futimesat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futimesat\n");
    return 0;
}

int syscall_get_kernel_syms(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_kernel_syms\n");
    return 0;
}

int syscall_get_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_mempolicy\n");
    return 0;
}

int syscall_get_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_robust_list\n");
    return 0;
}

int syscall_get_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_thread_area\n");
    return 0;
}

int syscall_get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_tls\n");
    return 0;
}

int syscall_getcpu(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcpu\n");
    return 0;
}

int syscall_getcwd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcwd\n");
    return 0;
}

int syscall_getdents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents\n");
    return 0;
}

int syscall_getdents64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents64\n");
    return 0;
}

int syscall_getdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdomainname\n");
    return 0;
}

int syscall_getdtablesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdtablesize\n");
    return 0;
}

int syscall_getegid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid\n");
    return 0;
}

int syscall_getegid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid32\n");
    return 0;
}

int syscall_geteuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid\n");
    return 0;
}

int syscall_geteuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid32\n");
    return 0;
}

int syscall_getgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid\n");
    return 0;
}

int syscall_getgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid32\n");
    return 0;
}

int syscall_getgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups\n");
    return 0;
}

int syscall_getgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups32\n");
    return 0;
}

int syscall_gethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gethostname\n");
    return 0;
}

int syscall_getitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getitimer\n");
    return 0;
}

int syscall_getpeername(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpeername\n");
    return 0;
}

int syscall_getpagesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpagesize\n");
    return 0;
}

int syscall_getpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgid\n");
    return 0;
}

int syscall_getpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgrp\n");
    return 0;
}

int syscall_getpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpid\n");
    return 0;
}

int syscall_getppid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getppid\n");
    return 0;
}

int syscall_getpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpriority\n");
    return 0;
}

int syscall_getrandom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrandom\n");
    return 0;
}

int syscall_getresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid\n");
    return 0;
}

int syscall_getresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid32\n");
    return 0;
}

int syscall_getresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid\n");
    return 0;
}

int syscall_getresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid32\n");
    return 0;
}

int syscall_getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrlimit\n");
    return 0;
}

int syscall_getrusage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrusage\n");
    return 0;
}

int syscall_getsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsid\n");
    return 0;
}

int syscall_getsockname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockname\n");
    return 0;
}

int syscall_getsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockopt\n");
    return 0;
}

int syscall_gettid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettid\n");
    return 0;
}

int syscall_gettimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettimeofday\n");
    return 0;
}

int syscall_getuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid\n");
    return 0;
}

int syscall_getuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid32\n");
    return 0;
}

int syscall_getunwind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getunwind\n");
    return 0;
}

int syscall_getxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxattr\n");
    return 0;
}

int syscall_getxgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxgid\n");
    return 0;
}

int syscall_getxpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxpid\n");
    return 0;
}

int syscall_getxuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxuid\n");
    return 0;
}

int syscall_init_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->init_module\n");
    return 0;
}

int syscall_inotify_add_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_add_watch\n");
    return 0;
}

int syscall_inotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init\n");
    return 0;
}

int syscall_inotify_init1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init1\n");
    return 0;
}

int syscall_inotify_rm_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_rm_watch\n");
    return 0;
}

int syscall_io_cancel(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_cancel\n");
    return 0;
}

int syscall_io_destroy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_destroy\n");
    return 0;
}

int syscall_io_getevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_getevents\n");
    return 0;
}

int syscall_io_pgetevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_pgetevents\n");
    return 0;
}

int syscall_io_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_setup\n");
    return 0;
}

int syscall_io_submit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_submit\n");
    return 0;
}

int syscall_io_uring_enter(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_enter\n");
    return 0;
}

int syscall_io_uring_register(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_register\n");
    return 0;
}

int syscall_io_uring_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_setup\n");
    return 0;
}

int syscall_ioctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioctl\n");
    return 0;
}

int syscall_ioperm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioperm\n");
    return 0;
}

int syscall_iopl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->iopl\n");
    return 0;
}

int syscall_ioprio_get(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_get\n");
    return 0;
}

int syscall_ioprio_set(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_set\n");
    return 0;
}

int syscall_ipc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ipc\n");
    return 0;
}

int syscall_kcmp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kcmp\n");
    return 0;
}

int syscall_kern_features(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kern_features\n");
    return 0;
}

int syscall_kexec_file_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_file_load\n");
    return 0;
}

int syscall_kexec_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_load\n");
    return 0;
}

int syscall_keyctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->keyctl\n");
    return 0;
}

int syscall_kill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kill\n");
    return 0;
}

int syscall_lchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown\n");
    return 0;
}

int syscall_lchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown32\n");
    return 0;
}

int syscall_lgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lgetxattr\n");
    return 0;
}

int syscall_link(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->link\n");
    return 0;
}

int syscall_linkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->linkat\n");
    return 0;
}

int syscall_listen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listen\n");
    return 0;
}

int syscall_listxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listxattr\n");
    return 0;
}

int syscall_llistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->llistxattr\n");
    return 0;
}

int syscall_lookup_dcookie(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lookup_dcookie\n");
    return 0;
}

int syscall_lremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lremovexattr\n");
    return 0;
}

int syscall_lseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lseek\n");
    return 0;
}

int syscall_lsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lsetxattr\n");
    return 0;
}

int syscall_lstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat\n");
    return 0;
}

int syscall_lstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat64\n");
    return 0;
}

int syscall_madvise(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->madvise\n");
    return 0;
}

int syscall_mbind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mbind\n");
    return 0;
}

int syscall_memory_ordering(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memory_ordering\n");
    return 0;
}

int syscall_metag_get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_get_tls\n");
    return 0;
}

int syscall_metag_set_fpu_flags(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_fpu_flags\n");
    return 0;
}

int syscall_metag_set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_tls\n");
    return 0;
}

int syscall_metag_setglobalbit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_setglobalbit\n");
    return 0;
}

int syscall_membarrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->membarrier\n");
    return 0;
}

int syscall_memfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memfd_create\n");
    return 0;
}

int syscall_migrate_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->migrate_pages\n");
    return 0;
}

int syscall_mincore(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mincore\n");
    return 0;
}

int syscall_mkdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdir\n");
    return 0;
}

int syscall_mkdirat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdirat\n");
    return 0;
}

int syscall_mknod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknod\n");
    return 0;
}

int syscall_mknodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknodat\n");
    return 0;
}

int syscall_mlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock\n");
    return 0;
}

int syscall_mlock2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock2\n");
    return 0;
}

int syscall_mlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlockall\n");
    return 0;
}

int syscall_mmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap\n");
    return 0;
}

int syscall_mmap2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap2\n");
    return 0;
}

int syscall_modify_ldt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->modify_ldt\n");
    return 0;
}

int syscall_mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mount\n");
    return 0;
}

int syscall_move_mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_mount\n");
    return 0;
}

int syscall_move_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_pages\n");
    return 0;
}

int syscall_mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mprotect\n");
    return 0;
}

int syscall_mq_getsetattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_getsetattr\n");
    return 0;
}

int syscall_mq_notify(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_notify\n");
    return 0;
}

int syscall_mq_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_open\n");
    return 0;
}

int syscall_mq_timedreceive(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedreceive\n");
    return 0;
}

int syscall_mq_timedsend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedsend\n");
    return 0;
}

int syscall_mq_unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_unlink\n");
    return 0;
}

int syscall_mremap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mremap\n");
    return 0;
}

int syscall_msgctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgctl\n");
    return 0;
}

int syscall_msgget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgget\n");
    return 0;
}

int syscall_msgrcv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgrcv\n");
    return 0;
}

int syscall_msgsnd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgsnd\n");
    return 0;
}

int syscall_msync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msync\n");
    return 0;
}

int syscall_munlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlock\n");
    return 0;
}

int syscall_munlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlockall\n");
    return 0;
}

int syscall_munmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munmap\n");
    return 0;
}

int syscall_name_to_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->name_to_handle_at\n");
    return 0;
}

int syscall_nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nanosleep\n");
    return 0;
}

int syscall_newfstatat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->newfstatat\n");
    return 0;
}

int syscall_nfsservctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nfsservctl\n");
    return 0;
}

int syscall_nice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nice\n");
    return 0;
}

int syscall_old_adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_adjtimex\n");
    return 0;
}

int syscall_old_getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_getrlimit\n");
    return 0;
}

int syscall_oldfstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldfstat\n");
    return 0;
}

int syscall_oldlstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldlstat\n");
    return 0;
}

int syscall_oldolduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldolduname\n");
    return 0;
}

int syscall_oldstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldstat\n");
    return 0;
}

int syscall_oldumount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldumount\n");
    return 0;
}

int syscall_olduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->olduname\n");
    return 0;
}

int syscall_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open\n");
    return 0;
}

int syscall_open_by_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_by_handle_at\n");
    return 0;
}

int syscall_open_tree(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_tree\n");
    return 0;
}

int syscall_openat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->openat\n");
    return 0;
}

int syscall_or1k_atomic(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->or1k_atomic\n");
    return 0;
}

int syscall_pause(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pause\n");
    return 0;
}

int syscall_pciconfig_iobase(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_iobase\n");
    return 0;
}

int syscall_pciconfig_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_read\n");
    return 0;
}

int syscall_pciconfig_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_write\n");
    return 0;
}

int syscall_perf_event_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perf_event_open\n");
    return 0;
}

int syscall_personality(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->personality\n");
    return 0;
}

int syscall_perfctr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfctr\n");
    return 0;
}

int syscall_perfmonctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfmonctl\n");
    return 0;
}

int syscall_pidfd_send_signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_send_signal\n");
    return 0;
}

int syscall_pidfd_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_open\n");
    return 0;
}

int syscall_pipe(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe\n");
    return 0;
}

int syscall_pipe2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe2\n");
    return 0;
}

int syscall_pivot_root(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pivot_root\n");
    return 0;
}

int syscall_pkey_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_alloc\n");
    return 0;
}

int syscall_pkey_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_free\n");
    return 0;
}

int syscall_pkey_mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_mprotect\n");
    return 0;
}

int syscall_poll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->poll\n");
    return 0;
}

int syscall_ppoll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ppoll\n");
    return 0;
}

int syscall_prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prctl\n");
    return 0;
}

int syscall_pread(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread\n");
    return 0;
}

int syscall_pread64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread64\n");
    return 0;
}

int syscall_preadv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv\n");
    return 0;
}

int syscall_preadv2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv2\n");
    return 0;
}

int syscall_prlimit64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prlimit64\n");
    return 0;
}

int syscall_process_vm_readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_readv\n");
    return 0;
}

int syscall_process_vm_writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_writev\n");
    return 0;
}

int syscall_pselect6(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pselect6\n");
    return 0;
}

int syscall_ptrace(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ptrace\n");
    return 0;
}

int syscall_pwrite(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite\n");
    return 0;
}

int syscall_pwrite64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite64\n");
    return 0;
}

int syscall_pwritev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev\n");
    return 0;
}

int syscall_pwritev2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev2\n");
    return 0;
}

int syscall_query_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->query_module\n");
    return 0;
}

int syscall_quotactl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->quotactl\n");
    return 0;
}

int syscall_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->read\n");
    return 0;
}

int syscall_readahead(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readahead\n");
    return 0;
}

int syscall_readdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readdir\n");
    return 0;
}

int syscall_readlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlink\n");
    return 0;
}

int syscall_readlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlinkat\n");
    return 0;
}

int syscall_readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readv\n");
    return 0;
}

int syscall_reboot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->reboot\n");
    return 0;
}

int syscall_recv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recv\n");
    return 0;
}

int syscall_recvfrom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvfrom\n");
    return 0;
}

int syscall_recvmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmsg\n");
    return 0;
}

int syscall_recvmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmmsg\n");
    return 0;
}

int syscall_remap_file_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->remap_file_pages\n");
    return 0;
}

int syscall_removexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->removexattr\n");
    return 0;
}

int syscall_rename(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rename\n");
    return 0;
}

int syscall_renameat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat\n");
    return 0;
}

int syscall_renameat2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat2\n");
    return 0;
}

int syscall_request_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->request_key\n");
    return 0;
}

int syscall_restart_syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->restart_syscall\n");
    return 0;
}

int syscall_riscv_flush_icache(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->riscv_flush_icache\n");
    return 0;
}

int syscall_rmdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rmdir\n");
    return 0;
}

int syscall_rseq(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rseq\n");
    return 0;
}

int syscall_rt_sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigaction\n");
    return 0;
}

int syscall_rt_sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigpending\n");
    return 0;
}

int syscall_rt_sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigprocmask\n");
    return 0;
}

int syscall_rt_sigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigqueueinfo\n");
    return 0;
}

int syscall_rt_sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigreturn\n");
    return 0;
}

int syscall_rt_sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigsuspend\n");
    return 0;
}

int syscall_rt_sigtimedwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigtimedwait\n");
    return 0;
}

int syscall_rt_tgsigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_tgsigqueueinfo\n");
    return 0;
}

int syscall_rtas(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rtas\n");
    return 0;
}

int syscall_s390_runtime_instr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_runtime_instr\n");
    return 0;
}

int syscall_s390_pci_mmio_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_read\n");
    return 0;
}

int syscall_s390_pci_mmio_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_write\n");
    return 0;
}

int syscall_s390_sthyi(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_sthyi\n");
    return 0;
}

int syscall_s390_guarded_storage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_guarded_storage\n");
    return 0;
}

int syscall_sched_get_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_affinity\n");
    return 0;
}

int syscall_sched_get_priority_max(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_max\n");
    return 0;
}

int syscall_sched_get_priority_min(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_min\n");
    return 0;
}

int syscall_sched_getaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getaffinity\n");
    return 0;
}

int syscall_sched_getattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getattr\n");
    return 0;
}

int syscall_sched_getparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getparam\n");
    return 0;
}

int syscall_sched_getscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getscheduler\n");
    return 0;
}

int syscall_sched_rr_get_interval(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_rr_get_interval\n");
    return 0;
}

int syscall_sched_set_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_set_affinity\n");
    return 0;
}

int syscall_sched_setaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setaffinity\n");
    return 0;
}

int syscall_sched_setattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setattr\n");
    return 0;
}

int syscall_sched_setparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setparam\n");
    return 0;
}

int syscall_sched_setscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setscheduler\n");
    return 0;
}

int syscall_sched_yield(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_yield\n");
    return 0;
}

int syscall_seccomp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->seccomp\n");
    return 0;
}

int syscall_select(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->select\n");
    return 0;
}

int syscall_semctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semctl\n");
    return 0;
}

int syscall_semget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semget\n");
    return 0;
}

int syscall_semop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semop\n");
    return 0;
}

int syscall_semtimedop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semtimedop\n");
    return 0;
}

int syscall_send(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->send\n");
    return 0;
}

int syscall_sendfile(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile\n");
    return 0;
}

int syscall_sendfile64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile64\n");
    return 0;
}

int syscall_sendmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmmsg\n");
    return 0;
}

int syscall_sendmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmsg\n");
    return 0;
}

int syscall_sendto(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendto\n");
    return 0;
}

int syscall_set_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_mempolicy\n");
    return 0;
}

int syscall_set_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_robust_list\n");
    return 0;
}

int syscall_set_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_thread_area\n");
    return 0;
}

int syscall_set_tid_address(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tid_address\n");
    return 0;
}

int syscall_set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tls\n");
    return 0;
}

int syscall_setdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setdomainname\n");
    return 0;
}

int syscall_setfsgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid\n");
    return 0;
}

int syscall_setfsgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid32\n");
    return 0;
}

int syscall_setfsuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid\n");
    return 0;
}

int syscall_setfsuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid32\n");
    return 0;
}

int syscall_setgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid\n");
    return 0;
}

int syscall_setgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid32\n");
    return 0;
}

int syscall_setgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups\n");
    return 0;
}

int syscall_setgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups32\n");
    return 0;
}

int syscall_sethae(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethae\n");
    return 0;
}

int syscall_sethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethostname\n");
    return 0;
}

int syscall_setitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setitimer\n");
    return 0;
}

int syscall_setns(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setns\n");
    return 0;
}

int syscall_setpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgid\n");
    return 0;
}

int syscall_setpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgrp\n");
    return 0;
}

int syscall_setpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpriority\n");
    return 0;
}

int syscall_setregid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid\n");
    return 0;
}

int syscall_setregid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid32\n");
    return 0;
}

int syscall_setresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid\n");
    return 0;
}

int syscall_setresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid32\n");
    return 0;
}

int syscall_setresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid\n");
    return 0;
}

int syscall_setresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid32\n");
    return 0;
}

int syscall_setreuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid\n");
    return 0;
}

int syscall_setreuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid32\n");
    return 0;
}

int syscall_setrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setrlimit\n");
    return 0;
}

int syscall_setsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsid\n");
    return 0;
}

int syscall_setsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsockopt\n");
    return 0;
}

int syscall_settimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->settimeofday\n");
    return 0;
}

int syscall_setuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid\n");
    return 0;
}

int syscall_setuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid32\n");
    return 0;
}

int syscall_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setup\n");
    return 0;
}

int syscall_setxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setxattr\n");
    return 0;
}

int syscall_sgetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sgetmask\n");
    return 0;
}

int syscall_shmat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmat\n");
    return 0;
}

int syscall_shmctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmctl\n");
    return 0;
}

int syscall_shmdt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmdt\n");
    return 0;
}

int syscall_shmget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmget\n");
    return 0;
}

int syscall_shutdown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shutdown\n");
    return 0;
}

int syscall_sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaction\n");
    return 0;
}

int syscall_sigaltstack(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaltstack\n");
    return 0;
}

int syscall_signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signal\n");
    return 0;
}

int syscall_signalfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd\n");
    return 0;
}

int syscall_signalfd4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd4\n");
    return 0;
}

int syscall_sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigpending\n");
    return 0;
}

int syscall_sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigprocmask\n");
    return 0;
}

int syscall_sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigreturn\n");
    return 0;
}

int syscall_sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigsuspend\n");
    return 0;
}

int syscall_socket(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socket\n");
    return 0;
}

int syscall_socketcall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketcall\n");
    return 0;
}

int syscall_socketpair(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketpair\n");
    return 0;
}

int syscall_spill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spill\n");
    return 0;
}

int syscall_splice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->splice\n");
    return 0;
}

int syscall_spu_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_create\n");
    return 0;
}

int syscall_spu_run(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_run\n");
    return 0;
}

int syscall_sram_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_alloc\n");
    return 0;
}

int syscall_sram_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_free\n");
    return 0;
}

int syscall_ssetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ssetmask\n");
    return 0;
}

int syscall_stat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat\n");
    return 0;
}

int syscall_stat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat64\n");
    return 0;
}

int syscall_statfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs\n");
    return 0;
}

int syscall_statfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs64\n");
    return 0;
}

int syscall_statx(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statx\n");
    return 0;
}

int syscall_stime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stime\n");
    return 0;
}

int syscall_subpage_prot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->subpage_prot\n");
    return 0;
}

int syscall_switch_endian(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->switch_endian\n");
    return 0;
}

int syscall_swapcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapcontext\n");
    return 0;
}

int syscall_swapoff(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapoff\n");
    return 0;
}

int syscall_swapon(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapon\n");
    return 0;
}

int syscall_symlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlink\n");
    return 0;
}

int syscall_symlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlinkat\n");
    return 0;
}

int syscall_sync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync\n");
    return 0;
}

int syscall_sync_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range\n");
    return 0;
}

int syscall_sync_file_range2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range2\n");
    return 0;
}

int syscall_syncfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syncfs\n");
    return 0;
}

int syscall_sys_debug_setcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sys_debug_setcontext\n");
    return 0;
}

int syscall_syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syscall\n");
    return 0;
}

int syscall_sysfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysfs\n");
    return 0;
}

int syscall_sysinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysinfo\n");
    return 0;
}

int syscall_syslog(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syslog\n");
    return 0;
}

int syscall_sysmips(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysmips\n");
    return 0;
}

int syscall_tee(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tee\n");
    return 0;
}

int syscall_tgkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tgkill\n");
    return 0;
}

int syscall_time(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->time\n");
    return 0;
}

int syscall_timer_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_create\n");
    return 0;
}

int syscall_timer_delete(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_delete\n");
    return 0;
}

int syscall_timer_getoverrun(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_getoverrun\n");
    return 0;
}

int syscall_timer_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_gettime\n");
    return 0;
}

int syscall_timer_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_settime\n");
    return 0;
}

int syscall_timerfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_create\n");
    return 0;
}

int syscall_timerfd_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_gettime\n");
    return 0;
}

int syscall_timerfd_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_settime\n");
    return 0;
}

int syscall_times(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->times\n");
    return 0;
}

int syscall_tkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tkill\n");
    return 0;
}

int syscall_truncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate\n");
    return 0;
}

int syscall_truncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate64\n");
    return 0;
}

int syscall_ugetrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ugetrlimit\n");
    return 0;
}

int syscall_umask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umask\n");
    return 0;
}

int syscall_umount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount\n");
    return 0;
}

int syscall_umount2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount2\n");
    return 0;
}

int syscall_uname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uname\n");
    return 0;
}

int syscall_unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlink\n");
    return 0;
}

int syscall_unlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlinkat\n");
    return 0;
}

int syscall_unshare(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unshare\n");
    return 0;
}

int syscall_uselib(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uselib\n");
    return 0;
}

int syscall_ustat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ustat\n");
    return 0;
}

int syscall_userfaultfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->userfaultfd\n");
    return 0;
}

int syscall_usr26(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr26\n");
    return 0;
}

int syscall_usr32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr32\n");
    return 0;
}

int syscall_utime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utime\n");
    return 0;
}

int syscall_utimensat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimensat\n");
    return 0;
}

int syscall_utimes(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimes\n");
    return 0;
}

int syscall_utrap_install(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utrap_install\n");
    return 0;
}

int syscall_vfork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vfork\n");
    return 0;
}

int syscall_vhangup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vhangup\n");
    return 0;
}

int syscall_vm86old(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86old\n");
    return 0;
}

int syscall_vm86(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86\n");
    return 0;
}

int syscall_vmsplice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vmsplice\n");
    return 0;
}

int syscall_wait4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->wait4\n");
    return 0;
}

int syscall_waitid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitid\n");
    return 0;
}

int syscall_waitpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitpid\n");
    return 0;
}

int syscall_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->write\n");
    return 0;
}

int syscall_writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->writev\n");
    return 0;
}

int syscall_xtensa(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->xtensa\n");
    return 0;
}
