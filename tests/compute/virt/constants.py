import bitmath


MIGRATION_POLICY_VM_LABEL = {"vm-label": "test-vm"}

STRESS_CPU_MEM_IO_COMMAND = (
    "nohup stress-ng --vm {workers} --vm-bytes {memory} --vm-method all "
    "--verify -t {timeout} -v --hdd 1 --io 1 --vm-keep &> /dev/null &"
)

VIRT_PROCESS_MEMORY_LIMITS = {
    "virt-launcher-monitor": bitmath.MiB(25),
    "virt-launcher": bitmath.MiB(100),
    "libvirtd": bitmath.MiB(35),
    "virtlogd": bitmath.MiB(20),
}
