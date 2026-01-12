#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mm_types.h>

#define PATH_LEN 64
#define CMD_LEN 256

struct data_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[PATH_LEN];
    char exe[PATH_LEN];
    char cmdline[CMD_LEN];
    u64 len;
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(heap_data, struct data_t, 1);

static __always_inline void get_simple_path(struct dentry *dentry, char *buf) {
    struct qstr d_name = dentry->d_name;
    struct dentry *parent = dentry->d_parent;
    struct qstr p_name = parent->d_name;

    char filename[32];
    char parentname[32];

    bpf_probe_read_kernel(&filename, sizeof(filename), d_name.name);
    bpf_probe_read_kernel(&parentname, sizeof(parentname), p_name.name);

    int i = 0;

    // 1. Parent
    #pragma unroll
    for (int j = 0; j < 32; j++) {
        char c = parentname[j];
        if (c == 0) break;
        if (i < PATH_LEN - 1) buf[i++] = c;
    }

    // 2. Separator
    if (i > 0 && buf[0] != '/' && i < PATH_LEN - 1) {
        buf[i++] = '/';
    }

    // 3. Filename
    #pragma unroll
    for (int j = 0; j < 32; j++) {
        char c = filename[j];
        if (c == 0) break;
        if (i < PATH_LEN - 1) buf[i++] = c;
    }

    buf[i] = 0;
}

int trace_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {
    u32 zero = 0;
    struct data_t *data = heap_data.lookup(&zero);
    if (!data) return 0;

    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->ts = bpf_ktime_get_ns();
    data->len = count;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    #pragma unroll
    for(int i=0; i<CMD_LEN; i++) {
         if (i < PATH_LEN) { data->fname[i] = 0; data->exe[i] = 0; }
         data->cmdline[i] = 0;
    }

    if (file) {
        get_simple_path(file->f_path.dentry, data->fname);
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = task->mm;

    if (mm) {
        struct file *exe_file = mm->exe_file;
        if (exe_file) {
            get_simple_path(exe_file->f_path.dentry, data->exe);
        }

        unsigned long arg_start = mm->arg_start;
        if (arg_start != 0) {
            bpf_probe_read_user(&data->cmdline, sizeof(data->cmdline), (void*)arg_start);
        }
    }

    events.perf_submit(ctx, data, sizeof(*data));
    return 0;
}
