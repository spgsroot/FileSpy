from dataclasses import dataclass


@dataclass
class ProcessInfo:
    name: str
    file_path: str
    exe_path: str
    pid: int
    uid: int


@dataclass
class FileInfo:
    name: str
    file_path: str
    bytes_written: int


@dataclass
class WriteEvent:
    id: str
    timestamp: str
    process: ProcessInfo
    file: FileInfo
    system_ts: int
