import logging
import random

import pytest
from kubernetes.dynamic.exceptions import ResourceNotFoundError
from ocp_resources.daemonset import DaemonSet
from ocp_resources.datavolume import DataVolume
from ocp_resources.deployment import Deployment
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from tests.chaos.utils import create_pod_deleting_process
from utilities.constants import (
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    OS_FLAVOR_RHEL,
    TIMEOUT_3MIN,
    TIMEOUT_10MIN,
    Images,
)
from utilities.infra import (
    ExecCommandOnPod,
    create_ns,
    get_pod_by_name_prefix,
    scale_deployment_replicas,
    wait_for_node_status,
)
from utilities.virt import VirtualMachineForTests, running_vm, taint_node_no_schedule


LOGGER = logging.getLogger(__name__)

CHAOS_NAMESPACE_NAME = "chaos"


@pytest.fixture()
def chaos_namespace():
    yield from create_ns(name=CHAOS_NAMESPACE_NAME)


@pytest.fixture()
def chaos_vms_list_rhel9(request, admin_client, chaos_namespace):
    vms_list = []
    for idx in range(request.param["number_of_vms"]):
        vm = cluster_resource(VirtualMachineForTests)(
            client=admin_client,
            name=f"vm-chaos-{idx}",
            namespace=chaos_namespace.name,
            image=Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
            memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
        )
        vms_list.append(vm)
    yield vms_list
    for vm in vms_list:
        vm.clean_up()


@pytest.fixture()
def chaos_vm_rhel9(admin_client, chaos_namespace):
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos",
        namespace=chaos_namespace.name,
        image=Images.Rhel.RHEL9_REGISTRY_GUEST_IMG,
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
        eviction=True,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture()
def chaos_vm_rhel9_with_dv(admin_client, chaos_namespace, chaos_dv_rhel9):
    chaos_dv_rhel9.to_dict()
    yield cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name="vm-chaos",
        namespace=chaos_namespace.name,
        os_flavor=OS_FLAVOR_RHEL,
        memory_requests=Images.Rhel.DEFAULT_MEMORY_SIZE,
        data_volume_template={
            "metadata": chaos_dv_rhel9.res["metadata"],
            "spec": chaos_dv_rhel9.res["spec"],
        },
        running=True,
    )


@pytest.fixture()
def chaos_dv_rhel9(request, admin_client, chaos_namespace, rhel9_http_image_url):
    yield cluster_resource(DataVolume)(
        source="http",
        name="chaos-dv",
        api_name="storage",
        namespace=chaos_namespace.name,
        url=rhel9_http_image_url,
        size=Images.Rhel.DEFAULT_DV_SIZE,
        storage_class=request.param["storage_class"],
        client=admin_client,
    )


@pytest.fixture()
def tainted_node_for_vm_migration(admin_client, chaos_vm_rhel9):
    initial_node = chaos_vm_rhel9.vmi.node
    node_editor = taint_node_no_schedule(node=initial_node)
    node_editor.update(backup_resources=True)
    yield initial_node
    node_editor.restore()


@pytest.fixture()
def downscaled_storage_provisioner_deployment(request):
    deployment = cluster_resource(Deployment)(
        namespace="openshift-storage",
        name=request.param["storage_provisioner_deployment"],
    )
    initial_replicas = deployment.instance.spec.replicas
    with scale_deployment_replicas(
        deployment_name=deployment.name,
        namespace=deployment.namespace,
        replica_count=0,
    ):
        yield {"deployment": deployment, "initial_replicas": initial_replicas}


@pytest.fixture()
def kmp_manager_nodes(admin_client):
    yield [
        pod.node
        for pod in get_pod_by_name_prefix(
            dyn_client=admin_client,
            pod_prefix=KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
            namespace=py_config["hco_namespace"],
            get_all=True,
        )
    ]


@pytest.fixture()
def rebooted_master_node(request, admin_client, masters, kmp_manager_nodes):
    master_node_to_reboot = request.param["master_node_to_reboot"]

    if master_node_to_reboot == "node_with_kmp_manager":
        yield random.choice(seq=kmp_manager_nodes)
    else:
        yield random.choice(
            seq=[
                node
                for node in masters
                if node.name not in [node.name for node in kmp_manager_nodes]
            ]
        )


@pytest.fixture()
def rebooting_master_node(
    rebooted_master_node,
    masters_utility_pods,
):
    LOGGER.info(f"Rebooting master node {rebooted_master_node.name}...")
    ExecCommandOnPod(utility_pods=masters_utility_pods, node=rebooted_master_node).exec(
        command="shutdown -r", ignore_rc=True
    )
    wait_for_node_status(
        node=rebooted_master_node, status=False, wait_timeout=TIMEOUT_3MIN
    )
    yield rebooted_master_node
    wait_for_node_status(node=rebooted_master_node, wait_timeout=TIMEOUT_10MIN)


@pytest.fixture()
def pod_deleting_process(request, admin_client):
    def _get_resources_to_recover(_resource, _namespace, _pod_prefix):
        resources = [
            resource
            for resource in cluster_resource(_resource).get(namespace=_namespace)
            if _pod_prefix in resource.name or _resource == VirtualMachineInstance
        ]
        if not resources:
            raise ResourceNotFoundError(
                f"No {_resource}s were found in the {_namespace} namespace."
            )
        return resources

    def _pod_deleting_process_recover(_resource, _namespace, _pod_prefix):
        # This function will make sure that the pods for the affected deployment/daemonset/VMI recover after the test.
        resources = _get_resources_to_recover(
            _resource=_resource, _namespace=_namespace, _pod_prefix=_pod_prefix
        )
        for resource in resources:
            if resource.kind == DaemonSet.kind:
                resource.wait_until_deployed()
            elif resource.kind == Deployment.kind:
                resource.wait_for_replicas()
            elif resource.kind == VirtualMachineInstance.kind:
                resource.wait_until_running()

    pod_prefix = request.param["pod_prefix"]
    namespace_name = request.param["namespace_name"]

    pod_deleting_process = create_pod_deleting_process(
        dyn_client=admin_client,
        pod_prefix=pod_prefix,
        namespace_name=namespace_name,
        ratio=request.param["ratio"],
        interval=request.param["interval"],
        max_duration=request.param["max_duration"],
    )
    pod_deleting_process.start()
    yield pod_deleting_process
    if pod_deleting_process.is_alive():
        LOGGER.info("Terminating pod deleting process...")
        pod_deleting_process.terminate()
        pod_deleting_process.join()
        pod_deleting_process.close()

    _pod_deleting_process_recover(
        _resource=request.param["resource"],
        _namespace=namespace_name,
        _pod_prefix=pod_prefix,
    )
