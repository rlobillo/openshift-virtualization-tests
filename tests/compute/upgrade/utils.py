import logging

from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.virtual_machine import VirtualMachine
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)

from tests.compute.utils import get_pod_disruption_budget
from utilities.constants import (
    DATA_SOURCE_NAME,
    TIMEOUT_3MIN,
    TIMEOUT_10SEC,
    TIMEOUT_180MIN,
)
from utilities.exceptions import ResourceMissingFieldError
from utilities.infra import get_csv_by_name, get_related_images_name_and_version
from utilities.virt import wait_for_ssh_connectivity


LOGGER = logging.getLogger(__name__)


def verify_vms_ssh_connectivity(vms_list):
    ssh_timeout = TIMEOUT_3MIN
    ssh_failed = {}

    for vm in vms_list:
        try:
            wait_for_ssh_connectivity(
                vm=vm, timeout=ssh_timeout, tcp_timeout=ssh_timeout
            )
        except TimeoutExpiredError as exp:
            ssh_failed[vm.name] = exp

    assert not ssh_failed, f"No ssh connectivity for VMs:\n {ssh_failed}"


def mismatching_src_pvc_names(pre_upgrade_templates, post_upgrade_templates):
    mismatched_templates = {}
    for template in post_upgrade_templates:
        matching_template = [
            temp for temp in pre_upgrade_templates if temp.name == template.name
        ]

        if matching_template:
            expected = get_src_pvc_default_name(template=matching_template[0])
            found = get_src_pvc_default_name(template=template)

            if found != expected:
                mismatched_templates[template.name] = {
                    "expected": expected,
                    "found": found,
                }

    return mismatched_templates


def get_src_pvc_default_name(template):
    param_value_list = [
        param["value"]
        for param in template.instance.parameters
        if param["name"] == DATA_SOURCE_NAME
    ]

    if param_value_list:
        return param_value_list[0]

    raise ResourceMissingFieldError(
        f"Template {template.name} does not have a parameter {DATA_SOURCE_NAME}"
    )


def get_all_migratable_vms(admin_client, namespaces):
    # Check pod disruption budget associated with given namespaces. Collect associated vm names. These vms are
    # the only migratable ones
    pod_disruption_budget_list = [
        pod_disruption_budget
        for ns in namespaces
        for pod_disruption_budget in get_pod_disruption_budget(
            admin_client=admin_client, namespace_name=ns.name
        )
    ]
    pod_disruption_budget_info = {
        pod_disruption_budget.name: pod_disruption_budget.instance.metadata.ownerReferences[
            0
        ][
            "name"
        ]
        for pod_disruption_budget in pod_disruption_budget_list
    }
    LOGGER.info(f"PodDisruptionBudgets: {pod_disruption_budget_info}")

    return [
        VirtualMachine(
            client=admin_client,
            namespace=pod_disruption_budget.namespace,
            name=pod_disruption_budget.instance.metadata.ownerReferences[0]["name"],
        )
        for pod_disruption_budget in pod_disruption_budget_list
    ]


def vms_auto_migration_with_status_success(admin_client, namespaces):
    workload_migrations = [
        migration_job
        for namespace in namespaces
        for migration_job in list(
            VirtualMachineInstanceMigration.get(
                dyn_client=admin_client, namespace=namespace
            )
        )
        if migration_job.name.startswith("kubevirt-workload-update")
    ]
    jobs = {
        migration_job.instance.spec.vmiName: f"{migration_job.name}-{migration_job.instance.status.phase}"
        for migration_job in workload_migrations
    }
    LOGGER.info(f"Workload migration jobs: {jobs}")
    return [
        migration_job.instance.spec.vmiName
        for migration_job in workload_migrations
        if migration_job.instance.status.phase
        == VirtualMachineInstanceMigration.Status.SUCCEEDED
    ]


def wait_for_automatic_vm_migrations(admin_client, vm_list):
    vm_names = [vm.name for vm in vm_list]
    vm_namespaces = [vm.namespace for vm in vm_list]
    LOGGER.info(f"Checking VMIMs for vms: {vm_names}")

    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_180MIN,
        sleep=TIMEOUT_10SEC,
        func=vms_auto_migration_with_status_success,
        admin_client=admin_client,
        namespaces=list(set(vm_namespaces)),
    )

    sample = None
    try:
        for sample in samples:
            LOGGER.info(f"Current migration state for vms:{vm_names}: {sample}")
            if all(vm in sample for vm in vm_names):
                return True
    except TimeoutExpiredError:
        vms_with_failed_vmim = list(set(vm_names) - set(sample))
        LOGGER.error(
            f"Migratable vms: {vm_names}, vms with completed automatic workload update: "
            f"{sample}, and vms with failed automatic workload update: {vms_with_failed_vmim}"
        )
        raise


def validate_vms_pod_updated(admin_client, hco_namespace, hco_target_version, vm_list):
    csv = get_csv_by_name(
        admin_client=admin_client,
        namespace=hco_namespace.name,
        csv_name=hco_target_version,
    )
    target_related_images = get_related_images_name_and_version(csv=csv)
    return [
        {pod.name: pod.instance.spec.containers[0].image}
        for pod in [vm.vmi.virt_launcher_pod for vm in vm_list]
        if pod.instance.spec.containers[0].image not in target_related_images.values()
    ]
