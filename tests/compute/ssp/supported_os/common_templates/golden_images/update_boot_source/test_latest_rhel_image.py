import os
import re
import shlex
from pathlib import Path

import pytest
from ocp_utilities.utils import run_ssh_commands

from utilities.constants import Images
from utilities.infra import cluster_resource
from utilities.virt import VirtualMachineForTests, running_vm


@pytest.fixture()
def rhel_vm(request, unprivileged_client, namespace):
    with cluster_resource(VirtualMachineForTests)(
        name=request.param["vm_name"],
        client=unprivileged_client,
        namespace=namespace.name,
        image=request.param["image"],
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def libosinfo_rhel_minor_ver_num(request, downloaded_latest_libosinfo_db):
    rhel_version = request.param
    osinfo_file_folder_path = os.path.join(
        f"{downloaded_latest_libosinfo_db}/os/redhat.com/"
    )

    list_of_rhel_os_files = list(
        sorted(Path(osinfo_file_folder_path).glob(f"{rhel_version}.*.xml"))
    )
    latest_rhel_os_file = list_of_rhel_os_files[-1]
    return re.findall(
        rf"(?<={rhel_version}\.)(\d+[\.]?[\d+]?)(?=\.xml)", latest_rhel_os_file.name
    )[0]


@pytest.fixture()
def rhel_vm_minor_ver_num(rhel_vm):
    rhel_vm_os_ver = run_ssh_commands(
        host=rhel_vm.ssh_exec,
        commands=(shlex.split("cat /etc/redhat-release")),
    )[0]
    return re.findall(r"(?<=\.)(\d+[\.]?[\d+]?)(?= )", rhel_vm_os_ver)[0]


@pytest.mark.parametrize(
    "rhel_vm, libosinfo_rhel_minor_ver_num",
    [
        pytest.param(
            {
                "vm_name": "rhel8-vm",
                "image": Images.Rhel.RHEL8_REGISTRY_GUEST_IMG,
            },
            "rhel-8",
            marks=pytest.mark.polarion("CNV-7666"),
        ),
        pytest.param(
            {
                "vm_name": "rhel9-vm",
                "image": Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
            },
            "rhel-9",
            marks=pytest.mark.polarion("CNV-7716"),
        ),
    ],
    indirect=True,
)
def test_latest_minor_ver_rhel(libosinfo_rhel_minor_ver_num, rhel_vm_minor_ver_num):
    assert libosinfo_rhel_minor_ver_num == rhel_vm_minor_ver_num, (
        f"os versions mismatch, VM minor version: {rhel_vm_minor_ver_num}, "
        f"osinfo DB latest minor version: {libosinfo_rhel_minor_ver_num}"
    )
