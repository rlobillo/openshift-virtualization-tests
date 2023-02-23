import logging

import pytest
from ocp_resources.configmap import ConfigMap
from ocp_resources.template import Template
from pytest_testconfig import py_config

from tests.os_params import WINDOWS_10
from utilities.constants import VIRTIO_WIN
from utilities.virt import (
    VirtualMachineForTestsFromTemplate,
    migrate_vm_and_verify,
    running_vm,
)


pytestmark = pytest.mark.usefixtures("skip_upstream")


LOGGER = logging.getLogger(__name__)
TESTS_CLASS_NAME = "TestWindowsGuestTools"


class MissingCDRomDeviceError(Exception):
    pass


class WindowsVMWithGuestTools(VirtualMachineForTestsFromTemplate):
    def __init__(self, name, namespace, client, data_source, virtio_image):
        super().__init__(
            name=name,
            namespace=namespace,
            client=client,
            data_source=data_source,
            labels=Template.generate_template_labels(**WINDOWS_10["template_labels"]),
        )
        self.virtio_image = virtio_image

    def to_dict(self):
        super().to_dict()
        spec = self.res["spec"]["template"]["spec"]
        spec["volumes"].append(
            {
                "containerDisk": {
                    "image": self.virtio_image,
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


def verify_cdrom_in_xml(vm):
    vmi_devices = vm.vmi.xml_dict["domain"]["devices"]
    for device_dict in vmi_devices["disk"]:
        for entry in device_dict.items():
            if entry == ("@device", "cdrom"):
                assert not device_dict.get(
                    "readonly"
                ), f"readonly is not set {device_dict}"
                return
    raise MissingCDRomDeviceError("cdrom device is missing; VMI devices: {vmi_devices}")


@pytest.fixture(scope="session")
def virtio_win_image(hco_namespace):
    virtio_win_cm = ConfigMap(name=VIRTIO_WIN, namespace=hco_namespace.name)
    return virtio_win_cm.instance.data["virtio-win-image"]


@pytest.fixture(scope="class")
def vm_with_guest_tools(
    cluster_cpu_model_scope_class,
    namespace,
    unprivileged_client,
    golden_image_data_source_scope_class,
    virtio_win_image,
):
    """Create Windows with guest-tools cd-rom"""
    with WindowsVMWithGuestTools(
        name="windows-vm-wth-guest-tools",
        namespace=namespace.name,
        client=unprivileged_client,
        data_source=golden_image_data_source_scope_class,
        virtio_image=virtio_win_image,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture(scope="class")
def migrated_vm_with_guest_tools(
    vm_with_guest_tools,
):
    migrate_vm_and_verify(vm=vm_with_guest_tools)


@pytest.mark.parametrize(
    "golden_image_data_volume_scope_class,",
    [
        pytest.param(
            {
                "dv_name": "dv-win10",
                "image": WINDOWS_10["image_path"],
                "dv_size": WINDOWS_10["dv_size"],
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

    @pytest.mark.polarion("CNV-6518")
    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::vm_with_guest_tools"])
    def test_migrate_vm_with_windows_guest_tools(
        self,
        skip_when_one_node,
        skip_rwo_default_access_mode,
        vm_with_guest_tools,
        migrated_vm_with_guest_tools,
    ):
        LOGGER.info("Test migration of a VM with Windows guest tools")
        verify_cdrom_in_xml(vm=vm_with_guest_tools)
