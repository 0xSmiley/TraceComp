

from bcc import BPF
import time
import ctypes as ct

text="""
#include <uapi/linux/utsname.h>
#include <linux/pid_namespace.h>


struct uts_namespace {
    struct kref kref;
    struct new_utsname name;
};

BPF_PERF_OUTPUT(data_event);

struct data_t {
    u32 a;
    char comm[30];
};



static __always_inline char * get_task_uts_name(struct task_struct *task){
    return task->nsproxy->uts_ns->name.nodename;
}



int hello(void *ctx) {
  struct task_struct *task;
  task = (struct task_struct *)bpf_get_current_task();
  
  
  struct data_t data = {};
  char * test1 = "aaaa";
  
  if (strcmp(test1,"aa")==0){

    strcpy(data.comm, "?");
    data.a = 1;
  }else{
    strcpy(data.comm, "!");
    data.a = 2;
  }
  data_event.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""
b = BPF(text=text)

class Data(ct.Structure):
  _fields_ = [
      ('a', ct.c_uint64),
      ('comm', ct.c_char * 16), 
  ]


def print_event(cpu, data, size):
  data = ct.cast(data, ct.POINTER(Data)).contents
  print(data.comm,data.a,cpu,size)

b.attach_kprobe(event="__x64_sys_clone", fn_name="hello")

b['data_event'].open_perf_buffer(print_event)

while True:
  try:
    # Poll the data structure till Ctrl+C
    b.perf_buffer_poll()
    print("start")
  except KeyboardInterrupt:
    print('Bye !')
    break
