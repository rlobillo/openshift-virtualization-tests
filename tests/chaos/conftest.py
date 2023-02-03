import logging
import multiprocessing
import random

import pytest
from kubernetes.dynamic.exceptions import ResourceNotFoundError
from ocp_resources.daemonset import DaemonSet
from ocp_resources.datavolume import DataVolume
from ocp_resources.deployment import Deployment
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from tests.chaos.constants import CHAOS_LABEL, CHAOS_LABEL_KEY, HOST_LABEL
from tests.chaos.utils import (
    create_cluster_monitoring_process,
    create_nginx_monitoring_process,
    create_pod_deleting_process,
    create_vm_with_nginx_service,
    terminate_process,
)
from utilities.constants import (
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    OS_FLAVOR_RHEL,
    PORT_80,
    TIMEOUT_3MIN,
    TIMEOUT_5SEC,
    TIMEOUT_10MIN,
    Images,
    NamespacesNames,
)
from utilities.infra import (
    ExecCommandOnPod,
    create_ns,
    get_nodes_with_label,
    get_pod_by_name_prefix,
    label_nodes,
    scale_deployment_replicas,
    wait_for_node_status,
)
from utilities.virt import VirtualMachineForTests, running_vm


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def chaos_namespace():
    yield from create_ns(name=NamespacesNames.CHAOS)


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
        eviction=True,
    )


@pytest.fixture()
def chaos_vm_rhel9_with_dv_started(chaos_dv_rhel9, chaos_vm_rhel9_with_dv):
    chaos_vm_rhel9_with_dv.deploy()
    chaos_vm_rhel9_with_dv.start(wait=True, timeout=TIMEOUT_10MIN)
    yield chaos_vm_rhel9_with_dv


@pytest.fixture()
def downscaled_storage_provisioner_deployment(request):
    deployment = cluster_resource(Deployment)(
        namespace=NamespacesNames.OPENSHIFT_STORAGE,
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
    terminate_process(process=pod_deleting_process)

    _pod_deleting_process_recover(
        _resource=request.param["resource"],
        _namespace=namespace_name,
        _pod_prefix=pod_prefix,
    )


@pytest.fixture()
def cluster_monitoring_process(admin_client, hco_namespace, chaos_namespace):
    LOGGER.info(
        f"Monitoring pods in namespaces: {hco_namespace.name}, {chaos_namespace.name}"
    )

    cluster_monitoring_process = create_cluster_monitoring_process(
        client=admin_client,
        hco_namespace=hco_namespace,
        additional_namespaces=[chaos_namespace],
    )
    cluster_monitoring_process.start()
    yield cluster_monitoring_process
    terminate_process(process=cluster_monitoring_process)


@pytest.fixture()
def chaos_worker_background_process(
    request,
    workers,
    workers_utility_pods,
):
    """
    Creates a process that, when started,
    executes a command on the worker node that has the label "chaos=true".

    request.params:
        max_duration (int): Used for commands with timeouts.
        background_command (str): The command that will be executed inside the node.
        process_name (str): Name for the background process.
    Returns:
        multiprocessing.Process: Process that execute a command inside a worker node .
    """

    process_name = request.param["process_name"]
    target_nodes = get_nodes_with_label(nodes=workers, label=CHAOS_LABEL_KEY)
    assert target_nodes, f"no nodes with label:{CHAOS_LABEL_KEY} were found"
    target_node = target_nodes[0]
    LOGGER.info(f"Target node is: {target_node.name}")
    background_process = multiprocessing.Process(
        name=process_name,
        target=lambda: ExecCommandOnPod(
            utility_pods=workers_utility_pods, node=target_node
        ).exec(
            command=request.param["background_command"],
            chroot_host=False,
            timeout=request.param["max_duration"] + TIMEOUT_5SEC,
        ),
    )
    background_process.start()
    LOGGER.info(f"{process_name} process started")
    yield background_process
    terminate_process(process=background_process)


@pytest.fixture()
def nginx_monitoring_process(
    request,
    masters,
    masters_utility_pods,
    vm_with_nginx_service,
):
    nginx_monitoring_process = create_nginx_monitoring_process(
        url=f"{vm_with_nginx_service.custom_service.instance.spec.clusterIPs[0]}:{PORT_80}",
        curl_timeout=request.param["curl_timeout"],
        sampling_duration=request.param["sampling_duration"],
        sampling_interval=request.param["sampling_interval"],
        utility_pods=masters_utility_pods,
        master_host_node=random.choice(masters),
    )
    nginx_monitoring_process.start()
    LOGGER.info(f"{nginx_monitoring_process} process started")
    yield nginx_monitoring_process
    terminate_process(process=nginx_monitoring_process)


@pytest.fixture()
def vm_with_nginx_service(chaos_namespace, admin_client):
    yield from create_vm_with_nginx_service(
        chaos_namespace=chaos_namespace, admin_client=admin_client
    )


@pytest.fixture()
def vm_with_nginx_service_and_node_selector(chaos_namespace, admin_client):
    yield from create_vm_with_nginx_service(
        chaos_namespace=chaos_namespace,
        admin_client=admin_client,
        node_selector_label=HOST_LABEL,
    )


@pytest.fixture()
def label_host_node(workers):
    yield from label_nodes(nodes=[random.choice(workers)], labels=HOST_LABEL)


@pytest.fixture()
def label_migration_target_node_for_chaos(workers, vm_with_nginx_service):
    target_node = random.choice(
        [node for node in workers if node.name != vm_with_nginx_service.vmi.node.name]
    )
    LOGGER.info(f"Migration target Node is: {target_node.name}")
    yield from label_nodes(
        nodes=[target_node],
        labels={**CHAOS_LABEL, **HOST_LABEL},
    )


@pytest.fixture()
def vm_node_with_chaos_label(vm_with_nginx_service):
    yield from label_nodes(nodes=[vm_with_nginx_service.vmi.node], labels=CHAOS_LABEL)
