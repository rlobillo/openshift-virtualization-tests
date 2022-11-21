import pytest
from ocp_resources.deployment import Deployment
from ocp_resources.resource import Resource
from ocp_utilities.infra import cluster_resource

from utilities.constants import (
    TIMEOUT_2MIN,
    TIMEOUT_5MIN,
    TIMEOUT_5SEC,
    TIMEOUT_10SEC,
    Images,
    NamespacesNames,
)
from utilities.virt import VirtualMachineForTests, running_vm


pytestmark = pytest.mark.usefixtures("chaos_namespace", "cluster_monitoring_process")


@pytest.mark.parametrize(
    "chaos_vms_list_rhel9, pod_deleting_process",
    [
        pytest.param(
            {
                "number_of_vms": 3,
            },
            {
                "pod_prefix": "apiserver",
                "resource": Deployment,
                "namespace_name": NamespacesNames.OPENSHIFT_APISERVER,
                "ratio": 0.5,
                "interval": TIMEOUT_5SEC,
                "max_duration": TIMEOUT_5MIN,
            },
        )
    ],
    indirect=True,
)
@pytest.mark.polarion("CNV-5428")
@pytest.mark.chaos
def test_pod_delete_openshift_apiserver(
    pod_deleting_process,
    chaos_vms_list_rhel9,
):
    """
    Verifies that VMs can be created, started, stopped and deleted
    while openshift-apiserver pods are continuously being deleted.
    """
    for vm in chaos_vms_list_rhel9:
        vm.deploy()
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)


@pytest.mark.parametrize(
    "rebooted_master_node",
    [
        pytest.param(
            {"master_node_to_reboot": "node_without_kmp_manager"},
            id="nodes_without_kmp_manager",
            marks=pytest.mark.polarion("CNV-9293"),
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
def test_master_node_restart(
    admin_client,
    chaos_namespace,
    rebooting_master_node,
):
    """
    This test verifies that a RHEL VM can be created, started, stopped and deleted
    while a given master node (randomly selected either from the nodes that have
    kubemacpool-mac-controller-manager pod or from the nodes that don't have it) is rebooted.
    """
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos",
        namespace=chaos_namespace.name,
        image=Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)


@pytest.mark.parametrize(
    "chaos_dv_rhel9, downscaled_storage_provisioner_deployment",
    [
        pytest.param(
            {"storage_class": "ocs-storagecluster-ceph-rbd"},
            {"storage_provisioner_deployment": "csi-rbdplugin-provisioner"},
            id="ceph-rbd",
        ),
        pytest.param(
            {"storage_class": "ocs-storagecluster-cephfs"},
            {"storage_provisioner_deployment": "csi-cephfsplugin-provisioner"},
            id="cephfs",
        ),
    ],
    indirect=True,
)
@pytest.mark.polarion("CNV-5438")
def test_ceph_storage_outage(
    chaos_dv_rhel9,
    chaos_vm_rhel9_with_dv,
    downscaled_storage_provisioner_deployment,
):
    """
    This test makes storage unavailable by downscaling the csi-rbdplugin-provisioner deployment to 0
    while creating a vm with a dv, then it verifies
    that the vm can only be created when storage becomes available again.
    """

    # Create a vm with a dv while storage is unavailable.
    chaos_vm_rhel9_with_dv.deploy()

    # Verify that dv and vm are not ready while chaos is being injected.
    chaos_dv_rhel9.wait_for_status(status=Resource.Status.PENDING)
    chaos_vm_rhel9_with_dv.wait_for_specific_status(
        status=chaos_vm_rhel9_with_dv.Status.WAITING_FOR_VOLUME_BINDING
    )

    # Verify that vm creation is resumed and vm reaches running state after deployment is restored.
    downscaled_storage_provisioner_deployment["deployment"].scale_replicas(
        replica_count=downscaled_storage_provisioner_deployment["initial_replicas"]
    )
    downscaled_storage_provisioner_deployment["deployment"].wait_for_replicas()
    running_vm(
        vm=chaos_vm_rhel9_with_dv,
        wait_for_interfaces=False,
        check_ssh_connectivity=False,
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
                "background_command": "stress-ng  --io 5 -t 120s",
            },
        ),
    ],
    indirect=True,
)
@pytest.mark.chaos
@pytest.mark.polarion("CNV-6994")
def test_host_io_stress(
    masters_utility_pods,
    vm_with_nginx_service,
    vm_node_with_chaos_label,
    nginx_monitoring_process,
    chaos_worker_background_process,
):
    """
    This experiment tests the resilience of the worker node and CNV by running an NGINX server within a VM,
    stressing the worker IO and testing to make sure the server
    and its VMI remain responsive throughout chaos duration.
    """
    chaos_worker_background_process.start()
    nginx_monitoring_process.start()
    chaos_worker_background_process.join()
    nginx_monitoring_process.join()
    assert nginx_monitoring_process.exitcode == 0, (
        f"The NGINX server running inside VM {vm_with_nginx_service.vmi.name} failed to remain responsive "
        f"during the sampling duration"
    )

    assert (
        chaos_worker_background_process.exitcode == 0
    ), "Background process execution failed"
