import json
import os
import uuid
from dataclasses import asdict
from datetime import datetime

from src.bpf_loader import BPFProgram
from src.models import FileInfo, ProcessInfo, WriteEvent


class FileSpyApp:
    def __init__(self, extensions=(".txt", ".log", ".json")):
        self.extensions = extensions
        self.program = BPFProgram()

    def run(self):
        self.program.attach()

        def handle_event(cpu, data, size):
            raw_event = self.program.get_events_buffer().event(data)
            self.process_event(raw_event)

        self.program.get_events_buffer().open_perf_buffer(handle_event)

        print(f"Monitoring writes to {self.extensions}...")
        print("Format: JSON stream")

        while True:
            try:
                self.program.poll()
            except KeyboardInterrupt:
                break

        def process_event(self, event):
            ebpf_log_path = event.fname.decode("utf-8", "ignore")
            ebpf_exe_path = event.exe.decode("utf-8", "ignore")

            if not ebpf_log_path.endswith(self.extensions):
                return

            raw_cmdline = event.cmdline.decode("utf-8", "ignore")
            cmd_args = [arg.strip() for arg in raw_cmdline.split("\x00") if arg.strip()]

            script_path = "N/A"
            if cmd_args:
                for arg in cmd_args[1:]:
                    if arg.endswith((".py", ".sh", ".js", ".php", ".rb", ".pl")):
                        script_path = arg
                        break

                if script_path == "N/A" and len(cmd_args) > 1:
                    script_path = " ".join(cmd_args[1:])

            short_log_name = os.path.basename(ebpf_log_path)

            dto = WriteEvent(
                id=str(uuid.uuid4()),
                timestamp=datetime.now().isoformat(),
                process=ProcessInfo(
                    name=event.comm.decode("utf-8", "ignore"),
                    file_path=script_path,
                    exe_path=ebpf_exe_path,
                    pid=event.pid,
                    uid=event.uid,
                ),
                file=FileInfo(
                    name=short_log_name,
                    file_path=ebpf_log_path,
                    bytes_written=event.len,
                ),
                system_ts=event.ts,
            )

            print(json.dumps(asdict(dto)))

            self.cache[event.pid] = dto
