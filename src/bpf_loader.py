from bcc import BPF


class BPFProgram:
    def __init__(self, source_file="src/probes.c"):
        with open(source_file, "r") as f:
            program_text = f.read()

        print("Compiling eBPF...")
        self.bpf = BPF(text=program_text)

    def attach(self):
        self.bpf.attach_kprobe(event="vfs_write", fn_name="trace_write")

    def get_events_buffer(self):
        return self.bpf["events"]

    def poll(self):
        self.bpf.perf_buffer_poll()
