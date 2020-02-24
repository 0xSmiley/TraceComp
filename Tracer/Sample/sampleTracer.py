

from bcc import BPF

text="""
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}
"""
b = BPF(text=text)
print(b.get_syscall_fnname("clone"))
b.attach_kprobe(event="__x64_sys_clone", fn_name="hello")
b.trace_print()
