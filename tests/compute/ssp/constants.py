HYPERV_FEATURES_LABELS_DOM_XML = [
    "relaxed",
    "vapic",
    "spinlocks",
    "vpindex",
    "synic",
    "stimer",  # synictimer in VM yaml
    "frequencies",
    "ipi",
    "reenlightenment",
    "reset",
    "runtime",
    "tlbflush",
]

HYPERV_FEATURES_LABELS_VM_YAML = HYPERV_FEATURES_LABELS_DOM_XML.copy()
HYPERV_FEATURES_LABELS_VM_YAML[
    HYPERV_FEATURES_LABELS_VM_YAML.index("stimer")
] = "synictimer"

VIRTIO = "virtio"
PVC_NOT_FOUND_ERROR = "PVC not found"


class MachineTypesNames:
    pc_q35 = "pc-q35"
    pc_q35_rhel7_6 = f"{pc_q35}-rhel7.6.0"
    pc_q35_rhel8_1 = f"{pc_q35}-rhel8.1.0"
    pc_q35_rhel8_6 = f"{pc_q35}-rhel8.6.0"
    pc_i440fx = "pc-i440fx"
    pc_i440fx_rhel7_6 = f"{pc_i440fx}-rhel7.6.0"
