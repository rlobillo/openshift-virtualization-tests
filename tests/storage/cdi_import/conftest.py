"""
CDI Import
"""

import logging

import pytest
from ocp_resources.datavolume import DataVolume

from tests.storage.constants import HPP_STORAGE_CLASSES
from tests.storage.utils import (
    clean_up_multiprocess,
    wait_for_processes_exit_successfully,
)
from utilities.constants import (
    LINUX_BRIDGE,
    OS_FLAVOR_FEDORA,
    TIMEOUT_1MIN,
    TIMEOUT_4MIN,
    Images,
)
from utilities.exceptions import ProcessWithException
from utilities.network import network_device, network_nad
from utilities.storage import sc_volume_binding_mode_is_wffc
from utilities.virt import VirtualMachineForTests


LOGGER = logging.getLogger(__name__)
BRIDGE_NAME = "br1-dv"


@pytest.fixture()
def skip_non_shared_storage(storage_class_matrix__function__):
    if [*storage_class_matrix__function__][0] in HPP_STORAGE_CLASSES:
        pytest.skip("Skipping when storage is non-shared")


@pytest.fixture()
def bridge_on_node():
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=BRIDGE_NAME,
        interface_name=BRIDGE_NAME,
    ) as br:
        yield br


@pytest.fixture()
def linux_nad(namespace, bridge_on_node):
    with network_nad(
        namespace=namespace,
        nad_type=LINUX_BRIDGE,
        nad_name=f"{BRIDGE_NAME}-nad",
        interface_name=bridge_on_node.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture()
def dv_list_created_by_multiprocess(
    namespace, storage_class_name_scope_module, number_of_processes
):
    dvs_list = []
    processes = {}
    for i in range(number_of_processes):
        dv = DataVolume(
            source="blank",
            name=f"dv-{i}",
            namespace=namespace.name,
            size=Images.Fedora.DEFAULT_DV_SIZE,
            storage_class=storage_class_name_scope_module,
            api_name="storage",
        )
        dv_process = ProcessWithException(target=dv.create)
        dv_process.start()
        processes[dv.name] = dv_process
        dvs_list.append(dv)
    wait_for_processes_exit_successfully(processes=processes, timeout=TIMEOUT_1MIN)
    yield dvs_list
    clean_up_multiprocess(processes=processes, object_list=dvs_list)


@pytest.fixture()
def vm_list_created_by_multiprocess(
    dv_list_created_by_multiprocess, storage_class_name_scope_module
):
    vms_list = []
    processes = {}
    for dv in dv_list_created_by_multiprocess:
        if sc_volume_binding_mode_is_wffc(sc=storage_class_name_scope_module):
            dv.wait_for_status(
                status=DataVolume.Status.WAIT_FOR_FIRST_CONSUMER, timeout=TIMEOUT_1MIN
            )
        else:
            dv.wait_for_dv_success(timeout=TIMEOUT_1MIN)
        vm = VirtualMachineForTests(
            name=f"vm-{dv.name}",
            namespace=dv.namespace,
            os_flavor=OS_FLAVOR_FEDORA,
            data_volume=dv,
            image=Images.Fedora.FEDORA_CONTAINER_IMAGE,
            memory_requests=Images.Fedora.DEFAULT_MEMORY_SIZE,
        )
        vm.deploy()
        vms_list.append(vm)
    for vm in vms_list:
        vm_process = ProcessWithException(target=vm.start)
        vm_process.start()
        processes[vm.name] = vm_process

    wait_for_processes_exit_successfully(processes=processes, timeout=TIMEOUT_4MIN)
    yield vms_list
    clean_up_multiprocess(processes=processes, object_list=vms_list)
