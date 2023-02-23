"""
Automation for Memory Dump
"""

import logging
import re
import shlex

import bitmath
import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.virtual_machine import VirtualMachine
from pytest_testconfig import config as py_config

from tests.os_params import WINDOWS_LATEST, WINDOWS_LATEST_LABELS
from utilities.constants import TIMEOUT_2MIN, Images
from utilities.infra import cluster_resource
from utilities.storage import PodWithPVC, virtctl_memory_dump
from utilities.virt import running_vm, vm_instance_from_template


LOGGER = logging.getLogger(__name__)


def wait_for_memory_dump_status(vm, memory_dump_status):
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=1,
        func=lambda: vm.instance.status.memoryDumpRequest.phase,
    )
    try:
        for sample in sampler:
            if sample == memory_dump_status:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"VM {vm.name} memory dump status is {sample}, expected: {memory_dump_status}"
        )
        raise


@pytest.fixture()
def windows_vm_for_memory_dump(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_function,
):
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_function,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def pvc_for_windows_memory_dump(namespace, storage_class_with_filesystem_volume_mode):
    # memory_dump_size is 10Gi(Images.Windows.DEFAULT_MEMORY_SIZE + memory dump overhead size)
    memory_dump_size = (
        (
            bitmath.parse_string_unsafe(Images.Windows.DEFAULT_MEMORY_SIZE)
            + bitmath.parse_string_unsafe("2Gi")
        )
        .to_GiB()
        .format("{value:.2f}{unit}")[:-1]
    )
    with cluster_resource(PersistentVolumeClaim)(
        name="dump-pvc",
        namespace=namespace.name,
        accessmodes=PersistentVolumeClaim.AccessMode.RWO,
        size=memory_dump_size,
        storage_class=storage_class_with_filesystem_volume_mode,
    ) as pvc:
        yield pvc


@pytest.fixture()
def windows_vm_memory_dump(
    namespace, windows_vm_for_memory_dump, pvc_for_windows_memory_dump
):
    status, out, err = virtctl_memory_dump(
        action="get",
        namespace=namespace.name,
        vm_name=windows_vm_for_memory_dump.name,
        claim_name=pvc_for_windows_memory_dump.name,
    )
    assert status, f"Failed to get memory dump, out: {out}, err: {err}."
    yield


@pytest.fixture()
def windows_vm_memory_dump_completed(windows_vm_for_memory_dump):
    wait_for_memory_dump_status(
        vm=windows_vm_for_memory_dump,
        memory_dump_status=VirtualMachine.Status.COMPLETED,
    )


@pytest.fixture()
def consumer_pod_for_verifying_windows_memory_dump(
    namespace, windows_vm_for_memory_dump, pvc_for_windows_memory_dump
):
    with cluster_resource(PodWithPVC)(
        namespace=namespace.name,
        name="consumer-pod",
        pvc_name=pvc_for_windows_memory_dump.name,
        volume_mode=DataVolume.VolumeMode.FILE,
    ) as pod:
        pod.wait_for_status(status=pod.Status.RUNNING, timeout=TIMEOUT_2MIN)

        assert re.match(
            rf"{windows_vm_for_memory_dump.name}-{pvc_for_windows_memory_dump.name}-\d*-\d*.memory.dump",
            pod.execute(command=shlex.split("bash -c 'ls -1 /pvc | grep dump'")),
            re.IGNORECASE,
        ), "Memory dump file doesn't exist"


@pytest.fixture()
def windows_vm_memory_dump_deletion(namespace, windows_vm_for_memory_dump):
    status, out, err = virtctl_memory_dump(
        action="remove",
        namespace=namespace.name,
        vm_name=windows_vm_for_memory_dump.name,
    )
    assert status, f"Failed to remove memory dump, out: {out}, err: {err}."
    yield


@pytest.mark.tier3
@pytest.mark.parametrize(
    "golden_image_data_volume_scope_function, windows_vm_for_memory_dump",
    [
        pytest.param(
            {
                "dv_name": "dv-windows",
                "image": WINDOWS_LATEST["image_path"],
                "storage_class": py_config["default_storage_class"],
                "dv_size": WINDOWS_LATEST["dv_size"],
            },
            {
                "vm_name": "windows-vm-mem",
                "template_labels": WINDOWS_LATEST_LABELS,
            },
            marks=pytest.mark.polarion("CNV-8518"),
        ),
    ],
    indirect=True,
)
def test_windows_memory_dump(
    skip_test_if_no_filesystem_sc,
    namespace,
    windows_vm_for_memory_dump,
    pvc_for_windows_memory_dump,
    windows_vm_memory_dump,
    windows_vm_memory_dump_completed,
    consumer_pod_for_verifying_windows_memory_dump,
    windows_vm_memory_dump_deletion,
):
    wait_for_memory_dump_status(
        vm=windows_vm_for_memory_dump, memory_dump_status="Dissociating"
    )
