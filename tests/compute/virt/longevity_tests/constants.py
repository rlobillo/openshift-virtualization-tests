from tests.compute.utils import (
    fetch_pid_from_linux_vm,
    fetch_pid_from_windows_vm,
    start_and_fetch_processid_on_linux_vm,
    start_and_fetch_processid_on_windows_vm,
)


LINUX_OS_PREFIX = "lin"
WINDOWS_OS_PREFIX = "win"

PROC_PER_OS_DICT = {
    LINUX_OS_PREFIX: {
        "proc_name": "sleep",
        "proc_args": "infinity",
        "fetch_pid": fetch_pid_from_linux_vm,
        "create_proc": start_and_fetch_processid_on_linux_vm,
    },
    WINDOWS_OS_PREFIX: {
        "proc_name": "notepad",
        "fetch_pid": fetch_pid_from_windows_vm,
        "create_proc": start_and_fetch_processid_on_windows_vm,
    },
}
