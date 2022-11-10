import logging

import pytest
from ocp_resources.template import Template
from pytest_testconfig import py_config

from tests.os_params import WINDOWS_LATEST, WINDOWS_LATEST_LABELS, WINDOWS_LATEST_OS
from utilities.virt import VirtualMachineForTestsFromTemplate, running_vm


pytestmark = pytest.mark.usefixtures("skip_upstream")


LOGGER = logging.getLogger(__name__)
TESTS_CLASS_NAME = "TestWindowsGuestTools"


class WindowsVMWithGuestTools(VirtualMachineForTestsFromTemplate):
    def __init__(
        self,
        name,
        namespace,
        client,
        data_source,
    ):
        super().__init__(
            name=name,
            namespace=namespace,
            client=client,
            data_source=data_source,
            labels=Template.generate_template_labels(**WINDOWS_LATEST_LABELS),
        )

    def to_dict(self):
        super().to_dict()
        spec = self.res["spec"]["template"]["spec"]
        spec["volumes"].append(
            {
                "containerDisk": {
                    "image": "registry.redhat.io/container-native-virtualization/virtio-win",
                    "imagePullPolicy": "IfNotPresent",
                },
                "name": "windows-guest-tools",
            }
        )
        spec["domain"]["devices"]["disks"].append(
            {
                "cdrom": {"bus": "sata", "readonly": True, "tray": "closed"},
                "name": "windows-guest-tools",
            }
        )


@pytest.fixture(scope="class")
def vm_with_guest_tools(
    cluster_cpu_model_scope_class,
    namespace,
    unprivileged_client,
    golden_image_data_source_scope_class,
):
    """Create Windows with guest-tools cd-rom"""
    with WindowsVMWithGuestTools(
        name="windows-vm-wth-guest-tools",
        namespace=namespace.name,
        client=unprivileged_client,
        data_source=golden_image_data_source_scope_class,
    ) as vm:
        running_vm(vm=vm)
        yield vm


def verify_cdrom_in_xml(vm):
    vmi_devices = vm.vmi.xml_dict["domain"]["devices"]
    cdrom_device_list = [
        device_dict
        for device_dict in vmi_devices["disk"]
        for element, value in device_dict.items()
        if element == "@device" and value == "cdrom"
    ]

    assert cdrom_device_list, f"cdrom device is missing; VMI devices: {vmi_devices}"

    cdrom_device = cdrom_device_list[0]
    try:
        cdrom_device["readonly"]
    except KeyError:
        LOGGER.error(f"readonly is not set, VMI cdrom: {cdrom_device}")
        raise


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_class,",
    [
        pytest.param(
            {
                "dv_name": WINDOWS_LATEST_OS,
                "image": WINDOWS_LATEST["image_path"],
                "dv_size": WINDOWS_LATEST["dv_size"],
                "storage_class": py_config["default_storage_class"],
            },
        ),
    ],
    indirect=True,
)
class TestWindowsGuestTools:
    @pytest.mark.polarion("CNV-6517")
    @pytest.mark.dependency(name=f"{TESTS_CLASS_NAME}::vm_with_guest_tools")
    def test_vm_with_windows_guest_tools(
        self,
        vm_with_guest_tools,
    ):
        LOGGER.info("Test VM with Windows guest tools")
        verify_cdrom_in_xml(vm=vm_with_guest_tools)
