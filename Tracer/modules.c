
int _llseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_llseek");
    return 0;
}

int _newselect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_newselect");
    return 0;
}

int _sysctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->_sysctl");
    return 0;
}

int accept(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept");
    return 0;
}

int accept4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->accept4");
    return 0;
}

int access(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->access");
    return 0;
}

int acct(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->acct");
    return 0;
}

int add_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->add_key");
    return 0;
}

int adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->adjtimex");
    return 0;
}

int alarm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alarm");
    return 0;
}

int alloc_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->alloc_hugepages");
    return 0;
}

int arc_gettls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_gettls");
    return 0;
}

int arc_settls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_settls");
    return 0;
}

int arc_usr_cmpxchg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arc_usr_cmpxchg");
    return 0;
}

int arch_prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->arch_prctl");
    return 0;
}

int atomic_barrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_barrier");
    return 0;
}

int atomic_cmpxchg_32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->atomic_cmpxchg_32");
    return 0;
}

int bdflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bdflush");
    return 0;
}

int bfin_spinlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bfin_spinlock");
    return 0;
}

int bind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bind");
    return 0;
}

int bpf(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->bpf");
    return 0;
}

int brk(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->brk");
    return 0;
}

int breakpoint(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->breakpoint");
    return 0;
}

int cacheflush(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cacheflush");
    return 0;
}

int capget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capget");
    return 0;
}

int capset(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->capset");
    return 0;
}

int chdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chdir");
    return 0;
}

int chmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chmod");
    return 0;
}

int chown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown");
    return 0;
}

int chown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chown32");
    return 0;
}

int chroot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->chroot");
    return 0;
}

int clock_adjtime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_adjtime");
    return 0;
}

int clock_getres(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_getres");
    return 0;
}

int clock_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_gettime");
    return 0;
}

int clock_nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_nanosleep");
    return 0;
}

int clock_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clock_settime");
    return 0;
}

int clone2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone2");
    return 0;
}

int clone(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone");
    return 0;
}

int clone3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->clone3");
    return 0;
}

int close(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->close");
    return 0;
}

int cmpxchg_badaddr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->cmpxchg_badaddr");
    return 0;
}

int connect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->connect");
    return 0;
}

int copy_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->copy_file_range");
    return 0;
}

int creat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->creat");
    return 0;
}

int create_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->create_module");
    return 0;
}

int delete_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->delete_module");
    return 0;
}

int dma_memcpy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dma_memcpy");
    return 0;
}

int dup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup");
    return 0;
}

int dup2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup2");
    return 0;
}

int dup3(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->dup3");
    return 0;
}

int epoll_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create");
    return 0;
}

int epoll_create1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_create1");
    return 0;
}

int epoll_ctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_ctl");
    return 0;
}

int epoll_pwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_pwait");
    return 0;
}

int epoll_wait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->epoll_wait");
    return 0;
}

int eventfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd");
    return 0;
}

int eventfd2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->eventfd2");
    return 0;
}

int execv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execv");
    return 0;
}

int execve(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execve");
    return 0;
}

int execveat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->execveat");
    return 0;
}

int exit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit");
    return 0;
}

int exit_group(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->exit_group");
    return 0;
}

int faccessat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->faccessat");
    return 0;
}

int fadvise64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64");
    return 0;
}

int fadvise64_64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fadvise64_64");
    return 0;
}

int fallocate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fallocate");
    return 0;
}

int fanotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_init");
    return 0;
}

int fanotify_mark(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fanotify_mark");
    return 0;
}

int fchdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchdir");
    return 0;
}

int fchmod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmod");
    return 0;
}

int fchmodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchmodat");
    return 0;
}

int fchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown");
    return 0;
}

int fchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchown32");
    return 0;
}

int fchownat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fchownat");
    return 0;
}

int fcntl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl");
    return 0;
}

int fcntl64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fcntl64");
    return 0;
}

int fdatasync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fdatasync");
    return 0;
}

int fgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fgetxattr");
    return 0;
}

int finit_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->finit_module");
    return 0;
}

int flistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flistxattr");
    return 0;
}

int flock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->flock");
    return 0;
}

int fork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fork");
    return 0;
}

int free_hugepages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->free_hugepages");
    return 0;
}

int fremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fremovexattr");
    return 0;
}

int fsconfig(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsconfig");
    return 0;
}

int fsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsetxattr");
    return 0;
}

int fsmount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsmount");
    return 0;
}

int fsopen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsopen");
    return 0;
}

int fspick(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fspick");
    return 0;
}

int fstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat");
    return 0;
}

int fstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstat64");
    return 0;
}

int fstatat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatat64");
    return 0;
}

int fstatfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs");
    return 0;
}

int fstatfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fstatfs64");
    return 0;
}

int fsync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->fsync");
    return 0;
}

int ftruncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate");
    return 0;
}

int ftruncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ftruncate64");
    return 0;
}

int futex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futex");
    return 0;
}

int futimesat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->futimesat");
    return 0;
}

int get_kernel_syms(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_kernel_syms");
    return 0;
}

int get_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_mempolicy");
    return 0;
}

int get_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_robust_list");
    return 0;
}

int get_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_thread_area");
    return 0;
}

int get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->get_tls");
    return 0;
}

int getcpu(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcpu");
    return 0;
}

int getcwd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getcwd");
    return 0;
}

int getdents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents");
    return 0;
}

int getdents64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdents64");
    return 0;
}

int getdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdomainname");
    return 0;
}

int getdtablesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getdtablesize");
    return 0;
}

int getegid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid");
    return 0;
}

int getegid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getegid32");
    return 0;
}

int geteuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid");
    return 0;
}

int geteuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->geteuid32");
    return 0;
}

int getgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid");
    return 0;
}

int getgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgid32");
    return 0;
}

int getgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups");
    return 0;
}

int getgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getgroups32");
    return 0;
}

int gethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gethostname");
    return 0;
}

int getitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getitimer");
    return 0;
}

int getpeername(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpeername");
    return 0;
}

int getpagesize(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpagesize");
    return 0;
}

int getpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgid");
    return 0;
}

int getpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpgrp");
    return 0;
}

int getpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpid");
    return 0;
}

int getppid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getppid");
    return 0;
}

int getpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getpriority");
    return 0;
}

int getrandom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrandom");
    return 0;
}

int getresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid");
    return 0;
}

int getresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresgid32");
    return 0;
}

int getresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid");
    return 0;
}

int getresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getresuid32");
    return 0;
}

int getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrlimit");
    return 0;
}

int getrusage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getrusage");
    return 0;
}

int getsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsid");
    return 0;
}

int getsockname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockname");
    return 0;
}

int getsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getsockopt");
    return 0;
}

int gettid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettid");
    return 0;
}

int gettimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->gettimeofday");
    return 0;
}

int getuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid");
    return 0;
}

int getuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getuid32");
    return 0;
}

int getunwind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getunwind");
    return 0;
}

int getxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxattr");
    return 0;
}

int getxgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxgid");
    return 0;
}

int getxpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxpid");
    return 0;
}

int getxuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->getxuid");
    return 0;
}

int init_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->init_module");
    return 0;
}

int inotify_add_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_add_watch");
    return 0;
}

int inotify_init(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init");
    return 0;
}

int inotify_init1(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_init1");
    return 0;
}

int inotify_rm_watch(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->inotify_rm_watch");
    return 0;
}

int io_cancel(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_cancel");
    return 0;
}

int io_destroy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_destroy");
    return 0;
}

int io_getevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_getevents");
    return 0;
}

int io_pgetevents(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_pgetevents");
    return 0;
}

int io_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_setup");
    return 0;
}

int io_submit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_submit");
    return 0;
}

int io_uring_enter(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_enter");
    return 0;
}

int io_uring_register(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_register");
    return 0;
}

int io_uring_setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->io_uring_setup");
    return 0;
}

int ioctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioctl");
    return 0;
}

int ioperm(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioperm");
    return 0;
}

int iopl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->iopl");
    return 0;
}

int ioprio_get(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_get");
    return 0;
}

int ioprio_set(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ioprio_set");
    return 0;
}

int ipc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ipc");
    return 0;
}

int kcmp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kcmp");
    return 0;
}

int kern_features(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kern_features");
    return 0;
}

int kexec_file_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_file_load");
    return 0;
}

int kexec_load(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kexec_load");
    return 0;
}

int keyctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->keyctl");
    return 0;
}

int kill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->kill");
    return 0;
}

int lchown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown");
    return 0;
}

int lchown32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lchown32");
    return 0;
}

int lgetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lgetxattr");
    return 0;
}

int link(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->link");
    return 0;
}

int linkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->linkat");
    return 0;
}

int listen(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listen");
    return 0;
}

int listxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->listxattr");
    return 0;
}

int llistxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->llistxattr");
    return 0;
}

int lookup_dcookie(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lookup_dcookie");
    return 0;
}

int lremovexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lremovexattr");
    return 0;
}

int lseek(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lseek");
    return 0;
}

int lsetxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lsetxattr");
    return 0;
}

int lstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat");
    return 0;
}

int lstat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->lstat64");
    return 0;
}

int madvise(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->madvise");
    return 0;
}

int mbind(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mbind");
    return 0;
}

int memory_ordering(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memory_ordering");
    return 0;
}

int metag_get_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_get_tls");
    return 0;
}

int metag_set_fpu_flags(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_fpu_flags");
    return 0;
}

int metag_set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_set_tls");
    return 0;
}

int metag_setglobalbit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->metag_setglobalbit");
    return 0;
}

int membarrier(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->membarrier");
    return 0;
}

int memfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->memfd_create");
    return 0;
}

int migrate_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->migrate_pages");
    return 0;
}

int mincore(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mincore");
    return 0;
}

int mkdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdir");
    return 0;
}

int mkdirat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mkdirat");
    return 0;
}

int mknod(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknod");
    return 0;
}

int mknodat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mknodat");
    return 0;
}

int mlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock");
    return 0;
}

int mlock2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlock2");
    return 0;
}

int mlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mlockall");
    return 0;
}

int mmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap");
    return 0;
}

int mmap2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mmap2");
    return 0;
}

int modify_ldt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->modify_ldt");
    return 0;
}

int mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mount");
    return 0;
}

int move_mount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_mount");
    return 0;
}

int move_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->move_pages");
    return 0;
}

int mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mprotect");
    return 0;
}

int mq_getsetattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_getsetattr");
    return 0;
}

int mq_notify(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_notify");
    return 0;
}

int mq_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_open");
    return 0;
}

int mq_timedreceive(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedreceive");
    return 0;
}

int mq_timedsend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_timedsend");
    return 0;
}

int mq_unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mq_unlink");
    return 0;
}

int mremap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->mremap");
    return 0;
}

int msgctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgctl");
    return 0;
}

int msgget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgget");
    return 0;
}

int msgrcv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgrcv");
    return 0;
}

int msgsnd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msgsnd");
    return 0;
}

int msync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->msync");
    return 0;
}

int munlock(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlock");
    return 0;
}

int munlockall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munlockall");
    return 0;
}

int munmap(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->munmap");
    return 0;
}

int name_to_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->name_to_handle_at");
    return 0;
}

int nanosleep(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nanosleep");
    return 0;
}

int newfstatat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->newfstatat");
    return 0;
}

int nfsservctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nfsservctl");
    return 0;
}

int nice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->nice");
    return 0;
}

int old_adjtimex(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_adjtimex");
    return 0;
}

int old_getrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->old_getrlimit");
    return 0;
}

int oldfstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldfstat");
    return 0;
}

int oldlstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldlstat");
    return 0;
}

int oldolduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldolduname");
    return 0;
}

int oldstat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldstat");
    return 0;
}

int oldumount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->oldumount");
    return 0;
}

int olduname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->olduname");
    return 0;
}

int open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open");
    return 0;
}

int open_by_handle_at(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_by_handle_at");
    return 0;
}

int open_tree(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->open_tree");
    return 0;
}

int openat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->openat");
    return 0;
}

int or1k_atomic(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->or1k_atomic");
    return 0;
}

int pause(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pause");
    return 0;
}

int pciconfig_iobase(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_iobase");
    return 0;
}

int pciconfig_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_read");
    return 0;
}

int pciconfig_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pciconfig_write");
    return 0;
}

int perf_event_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perf_event_open");
    return 0;
}

int personality(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->personality");
    return 0;
}

int perfctr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfctr");
    return 0;
}

int perfmonctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->perfmonctl");
    return 0;
}

int pidfd_send_signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_send_signal");
    return 0;
}

int pidfd_open(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pidfd_open");
    return 0;
}

int pipe(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe");
    return 0;
}

int pipe2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pipe2");
    return 0;
}

int pivot_root(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pivot_root");
    return 0;
}

int pkey_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_alloc");
    return 0;
}

int pkey_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_free");
    return 0;
}

int pkey_mprotect(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pkey_mprotect");
    return 0;
}

int poll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->poll");
    return 0;
}

int ppoll(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ppoll");
    return 0;
}

int prctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prctl");
    return 0;
}

int pread(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread");
    return 0;
}

int pread64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pread64");
    return 0;
}

int preadv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv");
    return 0;
}

int preadv2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->preadv2");
    return 0;
}

int prlimit64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->prlimit64");
    return 0;
}

int process_vm_readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_readv");
    return 0;
}

int process_vm_writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->process_vm_writev");
    return 0;
}

int pselect6(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pselect6");
    return 0;
}

int ptrace(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ptrace");
    return 0;
}

int pwrite(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite");
    return 0;
}

int pwrite64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwrite64");
    return 0;
}

int pwritev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev");
    return 0;
}

int pwritev2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->pwritev2");
    return 0;
}

int query_module(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->query_module");
    return 0;
}

int quotactl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->quotactl");
    return 0;
}

int read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->read");
    return 0;
}

int readahead(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readahead");
    return 0;
}

int readdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readdir");
    return 0;
}

int readlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlink");
    return 0;
}

int readlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readlinkat");
    return 0;
}

int readv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->readv");
    return 0;
}

int reboot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->reboot");
    return 0;
}

int recv(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recv");
    return 0;
}

int recvfrom(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvfrom");
    return 0;
}

int recvmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmsg");
    return 0;
}

int recvmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->recvmmsg");
    return 0;
}

int remap_file_pages(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->remap_file_pages");
    return 0;
}

int removexattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->removexattr");
    return 0;
}

int rename(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rename");
    return 0;
}

int renameat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat");
    return 0;
}

int renameat2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->renameat2");
    return 0;
}

int request_key(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->request_key");
    return 0;
}

int restart_syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->restart_syscall");
    return 0;
}

int riscv_flush_icache(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->riscv_flush_icache");
    return 0;
}

int rmdir(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rmdir");
    return 0;
}

int rseq(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rseq");
    return 0;
}

int rt_sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigaction");
    return 0;
}

int rt_sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigpending");
    return 0;
}

int rt_sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigprocmask");
    return 0;
}

int rt_sigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigqueueinfo");
    return 0;
}

int rt_sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigreturn");
    return 0;
}

int rt_sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigsuspend");
    return 0;
}

int rt_sigtimedwait(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_sigtimedwait");
    return 0;
}

int rt_tgsigqueueinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rt_tgsigqueueinfo");
    return 0;
}

int rtas(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->rtas");
    return 0;
}

int s390_runtime_instr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_runtime_instr");
    return 0;
}

int s390_pci_mmio_read(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_read");
    return 0;
}

int s390_pci_mmio_write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_pci_mmio_write");
    return 0;
}

int s390_sthyi(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_sthyi");
    return 0;
}

int s390_guarded_storage(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->s390_guarded_storage");
    return 0;
}

int sched_get_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_affinity");
    return 0;
}

int sched_get_priority_max(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_max");
    return 0;
}

int sched_get_priority_min(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_get_priority_min");
    return 0;
}

int sched_getaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getaffinity");
    return 0;
}

int sched_getattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getattr");
    return 0;
}

int sched_getparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getparam");
    return 0;
}

int sched_getscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_getscheduler");
    return 0;
}

int sched_rr_get_interval(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_rr_get_interval");
    return 0;
}

int sched_set_affinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_set_affinity");
    return 0;
}

int sched_setaffinity(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setaffinity");
    return 0;
}

int sched_setattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setattr");
    return 0;
}

int sched_setparam(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setparam");
    return 0;
}

int sched_setscheduler(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_setscheduler");
    return 0;
}

int sched_yield(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sched_yield");
    return 0;
}

int seccomp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->seccomp");
    return 0;
}

int select(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->select");
    return 0;
}

int semctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semctl");
    return 0;
}

int semget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semget");
    return 0;
}

int semop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semop");
    return 0;
}

int semtimedop(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->semtimedop");
    return 0;
}

int send(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->send");
    return 0;
}

int sendfile(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile");
    return 0;
}

int sendfile64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendfile64");
    return 0;
}

int sendmmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmmsg");
    return 0;
}

int sendmsg(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendmsg");
    return 0;
}

int sendto(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sendto");
    return 0;
}

int set_mempolicy(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_mempolicy");
    return 0;
}

int set_robust_list(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_robust_list");
    return 0;
}

int set_thread_area(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_thread_area");
    return 0;
}

int set_tid_address(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tid_address");
    return 0;
}

int set_tls(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->set_tls");
    return 0;
}

int setdomainname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setdomainname");
    return 0;
}

int setfsgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid");
    return 0;
}

int setfsgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsgid32");
    return 0;
}

int setfsuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid");
    return 0;
}

int setfsuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setfsuid32");
    return 0;
}

int setgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid");
    return 0;
}

int setgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgid32");
    return 0;
}

int setgroups(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups");
    return 0;
}

int setgroups32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setgroups32");
    return 0;
}

int sethae(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethae");
    return 0;
}

int sethostname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sethostname");
    return 0;
}

int setitimer(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setitimer");
    return 0;
}

int setns(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setns");
    return 0;
}

int setpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgid");
    return 0;
}

int setpgrp(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgrp");
    return 0;
}

int setpgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpgid");
    return 0;
}

int setpriority(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setpriority");
    return 0;
}

int setregid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid");
    return 0;
}

int setregid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setregid32");
    return 0;
}

int setresgid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid");
    return 0;
}

int setresgid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresgid32");
    return 0;
}

int setresuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid");
    return 0;
}

int setresuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setresuid32");
    return 0;
}

int setreuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid");
    return 0;
}

int setreuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setreuid32");
    return 0;
}

int setrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setrlimit");
    return 0;
}

int setsid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsid");
    return 0;
}

int setsockopt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setsockopt");
    return 0;
}

int settimeofday(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->settimeofday");
    return 0;
}

int setuid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid");
    return 0;
}

int setuid32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setuid32");
    return 0;
}

int setup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setup");
    return 0;
}

int setxattr(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->setxattr");
    return 0;
}

int sgetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sgetmask");
    return 0;
}

int shmat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmat");
    return 0;
}

int shmctl(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmctl");
    return 0;
}

int shmdt(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmdt");
    return 0;
}

int shmget(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shmget");
    return 0;
}

int shutdown(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->shutdown");
    return 0;
}

int sigaction(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaction");
    return 0;
}

int sigaltstack(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigaltstack");
    return 0;
}

int signal(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signal");
    return 0;
}

int signalfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd");
    return 0;
}

int signalfd4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->signalfd4");
    return 0;
}

int sigpending(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigpending");
    return 0;
}

int sigprocmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigprocmask");
    return 0;
}

int sigreturn(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigreturn");
    return 0;
}

int sigsuspend(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sigsuspend");
    return 0;
}

int socket(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socket");
    return 0;
}

int socketcall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketcall");
    return 0;
}

int socketpair(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->socketpair");
    return 0;
}

int spill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spill");
    return 0;
}

int splice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->splice");
    return 0;
}

int spu_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_create");
    return 0;
}

int spu_run(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->spu_run");
    return 0;
}

int sram_alloc(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_alloc");
    return 0;
}

int sram_free(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sram_free");
    return 0;
}

int ssetmask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ssetmask");
    return 0;
}

int stat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat");
    return 0;
}

int stat64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stat64");
    return 0;
}

int statfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs");
    return 0;
}

int statfs64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statfs64");
    return 0;
}

int statx(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->statx");
    return 0;
}

int stime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->stime");
    return 0;
}

int subpage_prot(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->subpage_prot");
    return 0;
}

int swapcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapcontext");
    return 0;
}

int switch_endian(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->switch_endian");
    return 0;
}

int swapcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapcontext");
    return 0;
}

int swapoff(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapoff");
    return 0;
}

int swapon(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->swapon");
    return 0;
}

int symlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlink");
    return 0;
}

int symlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->symlinkat");
    return 0;
}

int sync(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync");
    return 0;
}

int sync_file_range(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range");
    return 0;
}

int sync_file_range2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sync_file_range2");
    return 0;
}

int syncfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syncfs");
    return 0;
}

int sys_debug_setcontext(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sys_debug_setcontext");
    return 0;
}

int syscall(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syscall");
    return 0;
}

int sysfs(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysfs");
    return 0;
}

int sysinfo(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysinfo");
    return 0;
}

int syslog(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->syslog");
    return 0;
}

int sysmips(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->sysmips");
    return 0;
}

int tee(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tee");
    return 0;
}

int tgkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tgkill");
    return 0;
}

int time(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->time");
    return 0;
}

int timer_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_create");
    return 0;
}

int timer_delete(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_delete");
    return 0;
}

int timer_getoverrun(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_getoverrun");
    return 0;
}

int timer_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_gettime");
    return 0;
}

int timer_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timer_settime");
    return 0;
}

int timerfd_create(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_create");
    return 0;
}

int timerfd_gettime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_gettime");
    return 0;
}

int timerfd_settime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->timerfd_settime");
    return 0;
}

int times(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->times");
    return 0;
}

int tkill(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->tkill");
    return 0;
}

int truncate(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate");
    return 0;
}

int truncate64(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->truncate64");
    return 0;
}

int ugetrlimit(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ugetrlimit");
    return 0;
}

int umask(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umask");
    return 0;
}

int umount(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount");
    return 0;
}

int umount2(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->umount2");
    return 0;
}

int uname(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uname");
    return 0;
}

int unlink(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlink");
    return 0;
}

int unlinkat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unlinkat");
    return 0;
}

int unshare(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->unshare");
    return 0;
}

int uselib(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->uselib");
    return 0;
}

int ustat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->ustat");
    return 0;
}

int userfaultfd(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->userfaultfd");
    return 0;
}

int usr26(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr26");
    return 0;
}

int usr32(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->usr32");
    return 0;
}

int utime(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utime");
    return 0;
}

int utimensat(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimensat");
    return 0;
}

int utimes(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utimes");
    return 0;
}

int utrap_install(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->utrap_install");
    return 0;
}

int vfork(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vfork");
    return 0;
}

int vhangup(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vhangup");
    return 0;
}

int vm86old(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86old");
    return 0;
}

int vm86(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vm86");
    return 0;
}

int vmsplice(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->vmsplice");
    return 0;
}

int wait4(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->wait4");
    return 0;
}

int waitid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitid");
    return 0;
}

int waitpid(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->waitpid");
    return 0;
}

int write(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->write");
    return 0;
}

int writev(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->writev");
    return 0;
}

int xtensa(struct pt_regs *ctx) {
    bpf_trace_printk("Syscall->xtensa");
    return 0;
}
