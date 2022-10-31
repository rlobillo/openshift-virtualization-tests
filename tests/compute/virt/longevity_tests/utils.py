import logging
import shutil

from ocp_resources.template import Template
from ocp_utilities.infra import cluster_resource

from tests.compute.virt.longevity_tests.constants import PROC_PER_OS_DICT
from tests.compute.virt.utils import migrate_and_verify_multi_vms
from utilities.virt import (
    VirtualMachineForTests,
    VirtualMachineForTestsFromTemplate,
    fedora_vm_body,
    running_vm,
)


LOGGER = logging.getLogger(__name__)


def run_migration_loop(iterations, vms_with_pids, os_type):
    def decorate_log(msg):
        terminal_width = int(shutil.get_terminal_size(fallback=(120, 40))[0])
        msg_decor = "-" * round(terminal_width / 4 - 30)
        return f"{msg_decor}{msg}{msg_decor}"

    for iteration in range(iterations):
        LOGGER.info(decorate_log(f"Iteration {iteration + 1}"))
        LOGGER.info(decorate_log("VM Migration"))
        migrate_and_verify_multi_vms(
            vm_list=[vms_with_pids[vm_name]["vm"] for vm_name in vms_with_pids]
        )
        LOGGER.info(decorate_log("PID check"))
        verify_pid_after_migrate_multi_vms(vms_with_pids=vms_with_pids, os_type=os_type)


def start_process_in_guest(vm, os_type):
    vm_and_pid = {}
    os_dict = PROC_PER_OS_DICT[os_type]
    params = {"vm": vm, "process_name": os_dict["proc_name"]}
    if os_dict.get("proc_args"):
        params.update({"args": os_dict["proc_args"]})

    vm_and_pid[vm.name] = {"vm": vm, "pid": os_dict["create_proc"](**params)}
    return vm_and_pid


def verify_pid_after_migrate_multi_vms(vms_with_pids, os_type):
    vms_with_wrong_pids_dict = {}
    os_dict = PROC_PER_OS_DICT[os_type]

    for vm_name in vms_with_pids:
        orig_pid = vms_with_pids[vm_name]["pid"]
        new_pid = None
        try:
            new_pid = os_dict["fetch_pid"](
                vm=vms_with_pids[vm_name]["vm"], process_name=os_dict["proc_name"]
            )
        except (AssertionError, ValueError):
            vms_with_wrong_pids_dict[vm_name] = {
                "orig_pid": orig_pid,
                "new_pid": new_pid,
            }
            continue
        if orig_pid != new_pid:
            vms_with_wrong_pids_dict[vm_name] = {
                "orig_pid": orig_pid,
                "new_pid": new_pid,
            }

    assert (
        not vms_with_wrong_pids_dict
    ), f"Some VMs have wrong pids after migration - {vms_with_wrong_pids_dict}"


def wait_vms_booted_and_start_processes(vms_list, os_type):
    vms_and_pids = {}

    for vm in vms_list:
        running_vm(vm=vm)
        vms_and_pids.update(start_process_in_guest(vm=vm, os_type=os_type))

    return vms_and_pids


def deploy_and_start_vms(vm_list):
    try:
        for vm in vm_list:
            vm.deploy()
            vm.start()
        yield vm_list
    finally:
        for vm in vm_list:
            vm.clean_up()


def create_containerdisk_vms(vm_deploys, request, client, name, namespace):
    vms = [
        cluster_resource(VirtualMachineForTests)(
            name=f"{request.param['vm_name_prefix']}-{name}-{deployment + 1}",
            namespace=namespace.name,
            body=fedora_vm_body(name=name),
            client=client,
            eviction=True,
        )
        for deployment in range(vm_deploys)
    ]

    yield from deploy_and_start_vms(vm_list=vms)


def create_dv_vms(
    vm_deploys,
    request,
    client,
    name,
    namespace,
    data_source,
    cloud_init_data=None,
    attached_secret=None,
):
    vms = [
        cluster_resource(VirtualMachineForTestsFromTemplate)(
            name=f"{request.param['vm_name_prefix']}-{name}-{deployment + 1}",
            labels=Template.generate_template_labels(**request.param["os_labels"]),
            namespace=namespace.name,
            client=client,
            data_source=data_source,
            cloud_init_data=cloud_init_data,
            attached_secret=attached_secret,
        )
        for deployment in range(vm_deploys)
    ]

    yield from deploy_and_start_vms(vm_list=vms)
