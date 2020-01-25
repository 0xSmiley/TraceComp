
int syscall__llseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_llseek");
    return 0;
}

int syscall__newselect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_newselect");
    return 0;
}

int syscall__sysctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_sysctl");
    return 0;
}

int syscall_accept(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept");
    return 0;
}

int syscall_accept4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept4");
    return 0;
}

int syscall_access(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->access");
    return 0;
}

int syscall_acct(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->acct");
    return 0;
}

int syscall_add_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->add_key");
    return 0;
}

int syscall_adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->adjtimex");
    return 0;
}

int syscall_alarm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alarm");
    return 0;
}

int syscall_alloc_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alloc_hugepages");
    return 0;
}

int syscall_arc_gettls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_gettls");
    return 0;
}

int syscall_arc_settls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_settls");
    return 0;
}

int syscall_arc_usr_cmpxchg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_usr_cmpxchg");
    return 0;
}

int syscall_arch_prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arch_prctl");
    return 0;
}

int syscall_atomic_barrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_barrier");
    return 0;
}

int syscall_atomic_cmpxchg_32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_cmpxchg_32");
    return 0;
}

int syscall_bdflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bdflush");
    return 0;
}

int syscall_bfin_spinlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bfin_spinlock");
    return 0;
}

int syscall_bind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bind");
    return 0;
}

int syscall_bpf(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bpf");
    return 0;
}

int syscall_brk(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->brk");
    return 0;
}

int syscall_breakpoint(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->breakpoint");
    return 0;
}

int syscall_cacheflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cacheflush");
    return 0;
}

int syscall_capget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capget");
    return 0;
}

int syscall_capset(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capset");
    return 0;
}

int syscall_chdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chdir");
    return 0;
}

int syscall_chmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chmod");
    return 0;
}

int syscall_chown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown");
    return 0;
}

int syscall_chown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown32");
    return 0;
}

int syscall_chroot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chroot");
    return 0;
}

int syscall_clock_adjtime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_adjtime");
    return 0;
}

int syscall_clock_getres(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_getres");
    return 0;
}

int syscall_clock_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_gettime");
    return 0;
}

int syscall_clock_nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_nanosleep");
    return 0;
}

int syscall_clock_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_settime");
    return 0;
}

int syscall_clone2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone2");
    return 0;
}

int syscall_clone(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone");
    return 0;
}

int syscall_clone3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone3");
    return 0;
}

int syscall_close(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->close");
    return 0;
}

int syscall_cmpxchg_badaddr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cmpxchg_badaddr");
    return 0;
}

int syscall_connect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->connect");
    return 0;
}

int syscall_copy_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->copy_file_range");
    return 0;
}

int syscall_creat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->creat");
    return 0;
}

int syscall_create_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->create_module");
    return 0;
}

int syscall_delete_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->delete_module");
    return 0;
}

int syscall_dma_memcpy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dma_memcpy");
    return 0;
}

int syscall_dup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup");
    return 0;
}

int syscall_dup2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup2");
    return 0;
}

int syscall_dup3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup3");
    return 0;
}

int syscall_epoll_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create");
    return 0;
}

int syscall_epoll_create1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create1");
    return 0;
}

int syscall_epoll_ctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_ctl");
    return 0;
}

int syscall_epoll_pwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_pwait");
    return 0;
}

int syscall_epoll_wait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_wait");
    return 0;
}

int syscall_eventfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd");
    return 0;
}

int syscall_eventfd2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd2");
    return 0;
}

int syscall_execv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execv");
    return 0;
}

int syscall_execve(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execve");
    return 0;
}

int syscall_execveat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execveat");
    return 0;
}

int syscall_exit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit");
    return 0;
}

int syscall_exit_group(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit_group");
    return 0;
}

int syscall_faccessat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->faccessat");
    return 0;
}

int syscall_fadvise64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64");
    return 0;
}

int syscall_fadvise64_64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64_64");
    return 0;
}

int syscall_fallocate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fallocate");
    return 0;
}

int syscall_fanotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_init");
    return 0;
}

int syscall_fanotify_mark(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_mark");
    return 0;
}

int syscall_fchdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchdir");
    return 0;
}

int syscall_fchmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmod");
    return 0;
}

int syscall_fchmodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmodat");
    return 0;
}

int syscall_fchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown");
    return 0;
}

int syscall_fchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown32");
    return 0;
}

int syscall_fchownat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchownat");
    return 0;
}

int syscall_fcntl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl");
    return 0;
}

int syscall_fcntl64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl64");
    return 0;
}

int syscall_fdatasync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fdatasync");
    return 0;
}

int syscall_fgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fgetxattr");
    return 0;
}

int syscall_finit_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->finit_module");
    return 0;
}

int syscall_flistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flistxattr");
    return 0;
}

int syscall_flock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flock");
    return 0;
}

int syscall_fork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fork");
    return 0;
}

int syscall_free_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->free_hugepages");
    return 0;
}

int syscall_fremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fremovexattr");
    return 0;
}

int syscall_fsconfig(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsconfig");
    return 0;
}

int syscall_fsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsetxattr");
    return 0;
}

int syscall_fsmount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsmount");
    return 0;
}

int syscall_fsopen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsopen");
    return 0;
}

int syscall_fspick(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fspick");
    return 0;
}

int syscall_fstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat");
    return 0;
}

int syscall_fstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat64");
    return 0;
}

int syscall_fstatat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatat64");
    return 0;
}

int syscall_fstatfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs");
    return 0;
}

int syscall_fstatfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs64");
    return 0;
}

int syscall_fsync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsync");
    return 0;
}

int syscall_ftruncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate");
    return 0;
}

int syscall_ftruncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate64");
    return 0;
}

int syscall_futex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futex");
    return 0;
}

int syscall_futimesat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futimesat");
    return 0;
}

int syscall_get_kernel_syms(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_kernel_syms");
    return 0;
}

int syscall_get_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_mempolicy");
    return 0;
}

int syscall_get_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_robust_list");
    return 0;
}

int syscall_get_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_thread_area");
    return 0;
}

int syscall_get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_tls");
    return 0;
}

int syscall_getcpu(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcpu");
    return 0;
}

int syscall_getcwd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcwd");
    return 0;
}

int syscall_getdents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents");
    return 0;
}

int syscall_getdents64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents64");
    return 0;
}

int syscall_getdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdomainname");
    return 0;
}

int syscall_getdtablesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdtablesize");
    return 0;
}

int syscall_getegid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid");
    return 0;
}

int syscall_getegid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid32");
    return 0;
}

int syscall_geteuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid");
    return 0;
}

int syscall_geteuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid32");
    return 0;
}

int syscall_getgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid");
    return 0;
}

int syscall_getgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid32");
    return 0;
}

int syscall_getgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups");
    return 0;
}

int syscall_getgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups32");
    return 0;
}

int syscall_gethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gethostname");
    return 0;
}

int syscall_getitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getitimer");
    return 0;
}

int syscall_getpeername(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpeername");
    return 0;
}

int syscall_getpagesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpagesize");
    return 0;
}

int syscall_getpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgid");
    return 0;
}

int syscall_getpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgrp");
    return 0;
}

int syscall_getpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpid");
    return 0;
}

int syscall_getppid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getppid");
    return 0;
}

int syscall_getpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpriority");
    return 0;
}

int syscall_getrandom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrandom");
    return 0;
}

int syscall_getresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid");
    return 0;
}

int syscall_getresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid32");
    return 0;
}

int syscall_getresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid");
    return 0;
}

int syscall_getresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid32");
    return 0;
}

int syscall_getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrlimit");
    return 0;
}

int syscall_getrusage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrusage");
    return 0;
}

int syscall_getsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsid");
    return 0;
}

int syscall_getsockname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockname");
    return 0;
}

int syscall_getsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockopt");
    return 0;
}

int syscall_gettid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettid");
    return 0;
}

int syscall_gettimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettimeofday");
    return 0;
}

int syscall_getuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid");
    return 0;
}

int syscall_getuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid32");
    return 0;
}

int syscall_getunwind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getunwind");
    return 0;
}

int syscall_getxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxattr");
    return 0;
}

int syscall_getxgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxgid");
    return 0;
}

int syscall_getxpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxpid");
    return 0;
}

int syscall_getxuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxuid");
    return 0;
}

int syscall_init_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->init_module");
    return 0;
}

int syscall_inotify_add_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_add_watch");
    return 0;
}

int syscall_inotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init");
    return 0;
}

int syscall_inotify_init1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init1");
    return 0;
}

int syscall_inotify_rm_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_rm_watch");
    return 0;
}

int syscall_io_cancel(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_cancel");
    return 0;
}

int syscall_io_destroy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_destroy");
    return 0;
}

int syscall_io_getevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_getevents");
    return 0;
}

int syscall_io_pgetevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_pgetevents");
    return 0;
}

int syscall_io_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_setup");
    return 0;
}

int syscall_io_submit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_submit");
    return 0;
}

int syscall_io_uring_enter(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_enter");
    return 0;
}

int syscall_io_uring_register(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_register");
    return 0;
}

int syscall_io_uring_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_setup");
    return 0;
}

int syscall_ioctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioctl");
    return 0;
}

int syscall_ioperm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioperm");
    return 0;
}

int syscall_iopl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->iopl");
    return 0;
}

int syscall_ioprio_get(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_get");
    return 0;
}

int syscall_ioprio_set(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_set");
    return 0;
}

int syscall_ipc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ipc");
    return 0;
}

int syscall_kcmp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kcmp");
    return 0;
}

int syscall_kern_features(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kern_features");
    return 0;
}

int syscall_kexec_file_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_file_load");
    return 0;
}

int syscall_kexec_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_load");
    return 0;
}

int syscall_keyctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->keyctl");
    return 0;
}

int syscall_kill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kill");
    return 0;
}

int syscall_lchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown");
    return 0;
}

int syscall_lchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown32");
    return 0;
}

int syscall_lgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lgetxattr");
    return 0;
}

int syscall_link(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->link");
    return 0;
}

int syscall_linkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->linkat");
    return 0;
}

int syscall_listen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listen");
    return 0;
}

int syscall_listxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listxattr");
    return 0;
}

int syscall_llistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->llistxattr");
    return 0;
}

int syscall_lookup_dcookie(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lookup_dcookie");
    return 0;
}

int syscall_lremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lremovexattr");
    return 0;
}

int syscall_lseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lseek");
    return 0;
}

int syscall_lsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lsetxattr");
    return 0;
}

int syscall_lstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat");
    return 0;
}

int syscall_lstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat64");
    return 0;
}

int syscall_madvise(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->madvise");
    return 0;
}

int syscall_mbind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mbind");
    return 0;
}

int syscall_memory_ordering(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memory_ordering");
    return 0;
}

int syscall_metag_get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_get_tls");
    return 0;
}

int syscall_metag_set_fpu_flags(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_fpu_flags");
    return 0;
}

int syscall_metag_set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_tls");
    return 0;
}

int syscall_metag_setglobalbit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_setglobalbit");
    return 0;
}

int syscall_membarrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->membarrier");
    return 0;
}

int syscall_memfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memfd_create");
    return 0;
}

int syscall_migrate_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->migrate_pages");
    return 0;
}

int syscall_mincore(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mincore");
    return 0;
}

int syscall_mkdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdir");
    return 0;
}

int syscall_mkdirat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdirat");
    return 0;
}

int syscall_mknod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknod");
    return 0;
}

int syscall_mknodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknodat");
    return 0;
}

int syscall_mlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock");
    return 0;
}

int syscall_mlock2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock2");
    return 0;
}

int syscall_mlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlockall");
    return 0;
}

int syscall_mmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap");
    return 0;
}

int syscall_mmap2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap2");
    return 0;
}

int syscall_modify_ldt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->modify_ldt");
    return 0;
}

int syscall_mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mount");
    return 0;
}

int syscall_move_mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_mount");
    return 0;
}

int syscall_move_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_pages");
    return 0;
}

int syscall_mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mprotect");
    return 0;
}

int syscall_mq_getsetattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_getsetattr");
    return 0;
}

int syscall_mq_notify(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_notify");
    return 0;
}

int syscall_mq_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_open");
    return 0;
}

int syscall_mq_timedreceive(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedreceive");
    return 0;
}

int syscall_mq_timedsend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedsend");
    return 0;
}

int syscall_mq_unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_unlink");
    return 0;
}

int syscall_mremap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mremap");
    return 0;
}

int syscall_msgctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgctl");
    return 0;
}

int syscall_msgget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgget");
    return 0;
}

int syscall_msgrcv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgrcv");
    return 0;
}

int syscall_msgsnd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgsnd");
    return 0;
}

int syscall_msync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msync");
    return 0;
}

int syscall_munlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlock");
    return 0;
}

int syscall_munlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlockall");
    return 0;
}

int syscall_munmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munmap");
    return 0;
}

int syscall_name_to_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->name_to_handle_at");
    return 0;
}

int syscall_nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nanosleep");
    return 0;
}

int syscall_newfstatat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->newfstatat");
    return 0;
}

int syscall_nfsservctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nfsservctl");
    return 0;
}

int syscall_nice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nice");
    return 0;
}

int syscall_old_adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_adjtimex");
    return 0;
}

int syscall_old_getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_getrlimit");
    return 0;
}

int syscall_oldfstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldfstat");
    return 0;
}

int syscall_oldlstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldlstat");
    return 0;
}

int syscall_oldolduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldolduname");
    return 0;
}

int syscall_oldstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldstat");
    return 0;
}

int syscall_oldumount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldumount");
    return 0;
}

int syscall_olduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->olduname");
    return 0;
}

int syscall_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open");
    return 0;
}

int syscall_open_by_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_by_handle_at");
    return 0;
}

int syscall_open_tree(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_tree");
    return 0;
}

int syscall_openat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->openat");
    return 0;
}

int syscall_or1k_atomic(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->or1k_atomic");
    return 0;
}

int syscall_pause(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pause");
    return 0;
}

int syscall_pciconfig_iobase(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_iobase");
    return 0;
}

int syscall_pciconfig_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_read");
    return 0;
}

int syscall_pciconfig_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_write");
    return 0;
}

int syscall_perf_event_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perf_event_open");
    return 0;
}

int syscall_personality(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->personality");
    return 0;
}

int syscall_perfctr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfctr");
    return 0;
}

int syscall_perfmonctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfmonctl");
    return 0;
}

int syscall_pidfd_send_signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_send_signal");
    return 0;
}

int syscall_pidfd_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_open");
    return 0;
}

int syscall_pipe(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe");
    return 0;
}

int syscall_pipe2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe2");
    return 0;
}

int syscall_pivot_root(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pivot_root");
    return 0;
}

int syscall_pkey_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_alloc");
    return 0;
}

int syscall_pkey_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_free");
    return 0;
}

int syscall_pkey_mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_mprotect");
    return 0;
}

int syscall_poll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->poll");
    return 0;
}

int syscall_ppoll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ppoll");
    return 0;
}

int syscall_prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prctl");
    return 0;
}

int syscall_pread(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread");
    return 0;
}

int syscall_pread64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread64");
    return 0;
}

int syscall_preadv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv");
    return 0;
}

int syscall_preadv2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv2");
    return 0;
}

int syscall_prlimit64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prlimit64");
    return 0;
}

int syscall_process_vm_readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_readv");
    return 0;
}

int syscall_process_vm_writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_writev");
    return 0;
}

int syscall_pselect6(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pselect6");
    return 0;
}

int syscall_ptrace(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ptrace");
    return 0;
}

int syscall_pwrite(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite");
    return 0;
}

int syscall_pwrite64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite64");
    return 0;
}

int syscall_pwritev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev");
    return 0;
}

int syscall_pwritev2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev2");
    return 0;
}

int syscall_query_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->query_module");
    return 0;
}

int syscall_quotactl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->quotactl");
    return 0;
}

int syscall_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->read");
    return 0;
}

int syscall_readahead(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readahead");
    return 0;
}

int syscall_readdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readdir");
    return 0;
}

int syscall_readlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlink");
    return 0;
}

int syscall_readlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlinkat");
    return 0;
}

int syscall_readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readv");
    return 0;
}

int syscall_reboot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->reboot");
    return 0;
}

int syscall_recv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recv");
    return 0;
}

int syscall_recvfrom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvfrom");
    return 0;
}

int syscall_recvmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmsg");
    return 0;
}

int syscall_recvmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmmsg");
    return 0;
}

int syscall_remap_file_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->remap_file_pages");
    return 0;
}

int syscall_removexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->removexattr");
    return 0;
}

int syscall_rename(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rename");
    return 0;
}

int syscall_renameat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat");
    return 0;
}

int syscall_renameat2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat2");
    return 0;
}

int syscall_request_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->request_key");
    return 0;
}

int syscall_restart_syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->restart_syscall");
    return 0;
}

int syscall_riscv_flush_icache(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->riscv_flush_icache");
    return 0;
}

int syscall_rmdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rmdir");
    return 0;
}

int syscall_rseq(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rseq");
    return 0;
}

int syscall_rt_sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigaction");
    return 0;
}

int syscall_rt_sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigpending");
    return 0;
}

int syscall_rt_sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigprocmask");
    return 0;
}

int syscall_rt_sigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigqueueinfo");
    return 0;
}

int syscall_rt_sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigreturn");
    return 0;
}

int syscall_rt_sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigsuspend");
    return 0;
}

int syscall_rt_sigtimedwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigtimedwait");
    return 0;
}

int syscall_rt_tgsigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_tgsigqueueinfo");
    return 0;
}

int syscall_rtas(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rtas");
    return 0;
}

int syscall_s390_runtime_instr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_runtime_instr");
    return 0;
}

int syscall_s390_pci_mmio_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_read");
    return 0;
}

int syscall_s390_pci_mmio_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_write");
    return 0;
}

int syscall_s390_sthyi(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_sthyi");
    return 0;
}

int syscall_s390_guarded_storage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_guarded_storage");
    return 0;
}

int syscall_sched_get_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_affinity");
    return 0;
}

int syscall_sched_get_priority_max(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_max");
    return 0;
}

int syscall_sched_get_priority_min(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_min");
    return 0;
}

int syscall_sched_getaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getaffinity");
    return 0;
}

int syscall_sched_getattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getattr");
    return 0;
}

int syscall_sched_getparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getparam");
    return 0;
}

int syscall_sched_getscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getscheduler");
    return 0;
}

int syscall_sched_rr_get_interval(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_rr_get_interval");
    return 0;
}

int syscall_sched_set_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_set_affinity");
    return 0;
}

int syscall_sched_setaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setaffinity");
    return 0;
}

int syscall_sched_setattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setattr");
    return 0;
}

int syscall_sched_setparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setparam");
    return 0;
}

int syscall_sched_setscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setscheduler");
    return 0;
}

int syscall_sched_yield(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_yield");
    return 0;
}

int syscall_seccomp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->seccomp");
    return 0;
}

int syscall_select(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->select");
    return 0;
}

int syscall_semctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semctl");
    return 0;
}

int syscall_semget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semget");
    return 0;
}

int syscall_semop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semop");
    return 0;
}

int syscall_semtimedop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semtimedop");
    return 0;
}

int syscall_send(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->send");
    return 0;
}

int syscall_sendfile(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile");
    return 0;
}

int syscall_sendfile64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile64");
    return 0;
}

int syscall_sendmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmmsg");
    return 0;
}

int syscall_sendmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmsg");
    return 0;
}

int syscall_sendto(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendto");
    return 0;
}

int syscall_set_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_mempolicy");
    return 0;
}

int syscall_set_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_robust_list");
    return 0;
}

int syscall_set_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_thread_area");
    return 0;
}

int syscall_set_tid_address(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tid_address");
    return 0;
}

int syscall_set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tls");
    return 0;
}

int syscall_setdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setdomainname");
    return 0;
}

int syscall_setfsgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid");
    return 0;
}

int syscall_setfsgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid32");
    return 0;
}

int syscall_setfsuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid");
    return 0;
}

int syscall_setfsuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid32");
    return 0;
}

int syscall_setgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid");
    return 0;
}

int syscall_setgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid32");
    return 0;
}

int syscall_setgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups");
    return 0;
}

int syscall_setgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups32");
    return 0;
}

int syscall_sethae(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethae");
    return 0;
}

int syscall_sethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethostname");
    return 0;
}

int syscall_setitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setitimer");
    return 0;
}

int syscall_setns(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setns");
    return 0;
}

int syscall_setpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgid");
    return 0;
}

int syscall_setpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgrp");
    return 0;
}

int syscall_setpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpriority");
    return 0;
}

int syscall_setregid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid");
    return 0;
}

int syscall_setregid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid32");
    return 0;
}

int syscall_setresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid");
    return 0;
}

int syscall_setresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid32");
    return 0;
}

int syscall_setresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid");
    return 0;
}

int syscall_setresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid32");
    return 0;
}

int syscall_setreuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid");
    return 0;
}

int syscall_setreuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid32");
    return 0;
}

int syscall_setrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setrlimit");
    return 0;
}

int syscall_setsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsid");
    return 0;
}

int syscall_setsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsockopt");
    return 0;
}

int syscall_settimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->settimeofday");
    return 0;
}

int syscall_setuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid");
    return 0;
}

int syscall_setuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid32");
    return 0;
}

int syscall_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setup");
    return 0;
}

int syscall_setxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setxattr");
    return 0;
}

int syscall_sgetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sgetmask");
    return 0;
}

int syscall_shmat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmat");
    return 0;
}

int syscall_shmctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmctl");
    return 0;
}

int syscall_shmdt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmdt");
    return 0;
}

int syscall_shmget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmget");
    return 0;
}

int syscall_shutdown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shutdown");
    return 0;
}

int syscall_sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaction");
    return 0;
}

int syscall_sigaltstack(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaltstack");
    return 0;
}

int syscall_signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signal");
    return 0;
}

int syscall_signalfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd");
    return 0;
}

int syscall_signalfd4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd4");
    return 0;
}

int syscall_sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigpending");
    return 0;
}

int syscall_sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigprocmask");
    return 0;
}

int syscall_sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigreturn");
    return 0;
}

int syscall_sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigsuspend");
    return 0;
}

int syscall_socket(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socket");
    return 0;
}

int syscall_socketcall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketcall");
    return 0;
}

int syscall_socketpair(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketpair");
    return 0;
}

int syscall_spill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spill");
    return 0;
}

int syscall_splice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->splice");
    return 0;
}

int syscall_spu_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_create");
    return 0;
}

int syscall_spu_run(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_run");
    return 0;
}

int syscall_sram_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_alloc");
    return 0;
}

int syscall_sram_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_free");
    return 0;
}

int syscall_ssetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ssetmask");
    return 0;
}

int syscall_stat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat");
    return 0;
}

int syscall_stat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat64");
    return 0;
}

int syscall_statfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs");
    return 0;
}

int syscall_statfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs64");
    return 0;
}

int syscall_statx(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statx");
    return 0;
}

int syscall_stime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stime");
    return 0;
}

int syscall_subpage_prot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->subpage_prot");
    return 0;
}

int syscall_switch_endian(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->switch_endian");
    return 0;
}

int syscall_swapcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapcontext");
    return 0;
}

int syscall_swapoff(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapoff");
    return 0;
}

int syscall_swapon(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapon");
    return 0;
}

int syscall_symlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlink");
    return 0;
}

int syscall_symlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlinkat");
    return 0;
}

int syscall_sync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync");
    return 0;
}

int syscall_sync_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range");
    return 0;
}

int syscall_sync_file_range2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range2");
    return 0;
}

int syscall_syncfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syncfs");
    return 0;
}

int syscall_sys_debug_setcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sys_debug_setcontext");
    return 0;
}

int syscall_syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syscall");
    return 0;
}

int syscall_sysfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysfs");
    return 0;
}

int syscall_sysinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysinfo");
    return 0;
}

int syscall_syslog(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syslog");
    return 0;
}

int syscall_sysmips(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysmips");
    return 0;
}

int syscall_tee(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tee");
    return 0;
}

int syscall_tgkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tgkill");
    return 0;
}

int syscall_time(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->time");
    return 0;
}

int syscall_timer_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_create");
    return 0;
}

int syscall_timer_delete(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_delete");
    return 0;
}

int syscall_timer_getoverrun(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_getoverrun");
    return 0;
}

int syscall_timer_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_gettime");
    return 0;
}

int syscall_timer_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_settime");
    return 0;
}

int syscall_timerfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_create");
    return 0;
}

int syscall_timerfd_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_gettime");
    return 0;
}

int syscall_timerfd_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_settime");
    return 0;
}

int syscall_times(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->times");
    return 0;
}

int syscall_tkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tkill");
    return 0;
}

int syscall_truncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate");
    return 0;
}

int syscall_truncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate64");
    return 0;
}

int syscall_ugetrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ugetrlimit");
    return 0;
}

int syscall_umask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umask");
    return 0;
}

int syscall_umount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount");
    return 0;
}

int syscall_umount2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount2");
    return 0;
}

int syscall_uname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uname");
    return 0;
}

int syscall_unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlink");
    return 0;
}

int syscall_unlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlinkat");
    return 0;
}

int syscall_unshare(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unshare");
    return 0;
}

int syscall_uselib(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uselib");
    return 0;
}

int syscall_ustat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ustat");
    return 0;
}

int syscall_userfaultfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->userfaultfd");
    return 0;
}

int syscall_usr26(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr26");
    return 0;
}

int syscall_usr32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr32");
    return 0;
}

int syscall_utime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utime");
    return 0;
}

int syscall_utimensat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimensat");
    return 0;
}

int syscall_utimes(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimes");
    return 0;
}

int syscall_utrap_install(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utrap_install");
    return 0;
}

int syscall_vfork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vfork");
    return 0;
}

int syscall_vhangup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vhangup");
    return 0;
}

int syscall_vm86old(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86old");
    return 0;
}

int syscall_vm86(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86");
    return 0;
}

int syscall_vmsplice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vmsplice");
    return 0;
}

int syscall_wait4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->wait4");
    return 0;
}

int syscall_waitid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitid");
    return 0;
}

int syscall_waitpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitpid");
    return 0;
}

int syscall_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->write");
    return 0;
}

int syscall_writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->writev");
    return 0;
}

int syscall_xtensa(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->xtensa");
    return 0;
}
