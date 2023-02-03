import pytest
from ocp_resources.deployment import Deployment
from ocp_resources.virtual_machine_instance import VirtualMachineInstance

from tests.chaos.constants import STRESS_NG
from tests.chaos.migration.utils import verify_vmi_was_migrated
from utilities.constants import (
    TIMEOUT_2MIN,
    TIMEOUT_5MIN,
    TIMEOUT_5SEC,
    TIMEOUT_10SEC,
    TIMEOUT_30SEC,
    NamespacesNames,
    StorageClassNames,
)


pytestmark = pytest.mark.usefixtures(
    "skip_if_sno_cluster", "chaos_namespace", "cluster_monitoring_process"
)


@pytest.mark.parametrize(
    "pod_deleting_process",
    [
        pytest.param(
            {
                "pod_prefix": "apiserver",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_APISERVER,
                "ratio": 0.5,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
            marks=pytest.mark.polarion("CNV-5455"),
            id="openshift-apiserver",
        ),
        pytest.param(
            {
                "pod_prefix": "virt-launcher",
                "resource": VirtualMachineInstance,
                "namespace_name": NamespacesNames.CHAOS,
                "ratio": 1,
                "interval": TIMEOUT_30SEC,
                "max_duration": TIMEOUT_2MIN,
            },
            marks=pytest.mark.polarion("CNV-5454"),
            id="virt_launcher",
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
def test_pod_delete_migration(
    chaos_vm_rhel9,
    pod_deleting_process,
    tainted_node_for_vm_chaos_rhel9_migration,
):
    """
    This experiment tests the robustness of the cluster
    by killing random function supported pods in their corresponding namespaces
    while a VM is being migrated and asserting that a given running VMI
    is running on a different node at the end of the test
    """

    verify_vmi_was_migrated(
        vm=chaos_vm_rhel9, initial_node=tainted_node_for_vm_chaos_rhel9_migration
    )


@pytest.mark.parametrize(
    "nginx_monitoring_process, chaos_worker_background_process",
    [
        pytest.param(
            {
                "curl_timeout": TIMEOUT_10SEC,
                "sampling_duration": TIMEOUT_2MIN,
                "sampling_interval": TIMEOUT_5SEC,
            },
            {
                "max_duration": TIMEOUT_2MIN,
                # The background_command may change when we have tools to create more stress.
                "background_command": f"{STRESS_NG}  --io 5 -t 120s",
                "process_name": STRESS_NG,
            },
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
@pytest.mark.polarion("CNV-7302")
def test_io_stress_migration_target_node(
    label_host_node,
    vm_with_nginx_service_and_node_selector,
    nginx_monitoring_process,
    label_migration_target_node_for_chaos,
    chaos_worker_background_process,
    tainted_node_for_vm_nginx_migration,
):
    """
    This experiment generates I/O load on the target node of a VM migration. The expected result is for the VM to
    eventually be successfully migrated.
    """
    verify_vmi_was_migrated(
        vm=vm_with_nginx_service_and_node_selector,
        initial_node=tainted_node_for_vm_nginx_migration,
    )
    chaos_worker_background_process.join()
    nginx_monitoring_process.join()
    assert (
        nginx_monitoring_process.exitcode == 0
    ), "The NGINX server running inside the VM failed to remain responsive during the sampling duration"
    assert (
        chaos_worker_background_process.exitcode == 0
    ), "Background process execution failed"


@pytest.mark.parametrize(
    "chaos_dv_rhel9, pod_deleting_process",
    [
        pytest.param(
            {"storage_class": StorageClassNames.CEPH_RBD},
            {
                "pod_prefix": "rook-ceph-operator",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_STORAGE,
                "ratio": 1,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
            marks=pytest.mark.polarion("CNV-7257"),
            id="rook-ceph-operator",
        ),
        pytest.param(
            {"storage_class": StorageClassNames.CEPH_RBD},
            {
                "pod_prefix": "ocs-operator",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_STORAGE,
                "ratio": 1,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
            marks=pytest.mark.polarion("CNV-7754"),
            id="ocs-operator",
        ),
    ],
    indirect=True,
)
def test_pod_delete_storage_migration(
    chaos_dv_rhel9,
    chaos_vm_rhel9_with_dv_started,
    pod_deleting_process,
    tainted_node_for_vm_chaos_rhel9_with_dv_migration,
):
    """
    This scenario verifies that the migration of a vm with a dv
    is completed while we disrupt different storage resources
    """
    assert verify_vmi_was_migrated(
        vm=chaos_vm_rhel9_with_dv_started,
        initial_node=tainted_node_for_vm_chaos_rhel9_with_dv_migration,
    ), "The VMI has not been migrated to a different node."


@pytest.mark.chaos
@pytest.mark.polarion("CNV-7251")
@pytest.mark.parametrize(
    "nginx_monitoring_process, chaos_worker_background_process",
    [
        pytest.param(
            {
                "curl_timeout": TIMEOUT_10SEC,
                "sampling_duration": TIMEOUT_2MIN,
                "sampling_interval": TIMEOUT_5SEC,
            },
            {
                "max_duration": TIMEOUT_2MIN,
                "background_command": f"{STRESS_NG}  --io 5 -t 120s",
                "process_name": STRESS_NG,
            },
        ),
    ],
    indirect=True,
)
def test_io_stress_migration_source_node(
    vm_with_nginx_service,
    vm_node_with_chaos_label,
    nginx_monitoring_process,
    chaos_worker_background_process,
    tainted_node_for_vm_nginx_migration,
):
    """
    This experiment generates I/O load on the source node of a VM migration. The expected result is for the VM to
    eventually be successfully migrated.
    """
    verify_vmi_was_migrated(
        vm=vm_with_nginx_service,
        initial_node=tainted_node_for_vm_nginx_migration,
    )
    chaos_worker_background_process.join()
    nginx_monitoring_process.join()
    assert (
        nginx_monitoring_process.exitcode == 0
    ), "The NGINX server running inside the VM failed to remain responsive during the sampling duration"
    assert (
        chaos_worker_background_process.exitcode == 0
    ), "Background process execution failed"
