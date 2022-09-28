import pytest
from ocp_resources.cluster_role import ClusterRole
from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.configmap import ConfigMap
from ocp_resources.namespace import Namespace
from ocp_resources.service_account import ServiceAccount

from tests.network.checkup_framework.utils import (
    LATENCY_CONFIGMAP,
    compose_configmap_data,
    create_latency_configmap,
    create_latency_job,
)
from utilities.constants import DEFAULT_NAMESPACE, LINUX_BRIDGE, SRIOV, TIMEOUT_10SEC
from utilities.infra import cluster_resource, create_ns, name_prefix
from utilities.network import network_device, network_nad


CHECKUP_FRAMEWORK_NAMESPACE = "kiagnose"
BRIDGE_NAME = "checkup-br"
DISCONNECTED = "disconnected"
DISCONNECTED_BR = f"{DISCONNECTED}-br"
GET = "get"
LIST = "list"
CREATE = "create"
UPDATE = "update"
PATCH = "patch"
DELETE = "delete"
WATCH = "watch"
BIND = "bind"


@pytest.fixture(scope="session")
def default_ns(admin_client):
    yield Namespace(name=DEFAULT_NAMESPACE)


@pytest.fixture(scope="module")
def framework_ns(admin_client):
    yield from create_ns(
        admin_client=admin_client,
        name=CHECKUP_FRAMEWORK_NAMESPACE,
    )


@pytest.fixture(scope="module")
def framework_service_account(framework_ns):
    with cluster_resource(ServiceAccount)(
        name=framework_ns.name, namespace=framework_ns.name
    ) as sa:
        yield sa


@pytest.fixture(scope="module")
def framework_cluster_role(framework_ns):
    cluster_role = ClusterRole(
        name=framework_ns.name,
        api_groups=[""],
        permissions_to_resources=["configmaps"],
        verbs=[GET, CREATE, LIST, UPDATE, PATCH],
    )
    cluster_role.add_rule(
        api_groups=[""],
        permissions_to_resources=["namespaces"],
        verbs=[GET, LIST, CREATE, DELETE, WATCH],
    )
    cluster_role.add_rule(
        api_groups=[""],
        permissions_to_resources=["serviceaccounts"],
        verbs=[GET, LIST, CREATE],
    )
    cluster_role.add_rule(
        api_groups=[ClusterRole.ApiGroup.RBAC_AUTHORIZATION_K8S_IO],
        permissions_to_resources=["roles", "rolebindings", "clusterrolebindings"],
        verbs=[GET, LIST, CREATE, DELETE],
    )
    cluster_role.add_rule(
        api_groups=[ClusterRole.ApiGroup.RBAC_AUTHORIZATION_K8S_IO],
        permissions_to_resources=["clusterroles"],
        verbs=[GET, LIST, CREATE, BIND],
    )
    cluster_role.add_rule(
        api_groups=[ClusterRole.ApiGroup.BATCH],
        permissions_to_resources=["jobs"],
        verbs=[GET, LIST, CREATE, DELETE, WATCH],
    )
    cluster_role.deploy()
    yield cluster_role
    cluster_role.clean_up()


@pytest.fixture(scope="module")
def framework_cluster_role_binding(framework_service_account, framework_cluster_role):
    with cluster_resource(ClusterRoleBinding)(
        name=framework_service_account.name,
        cluster_role=framework_cluster_role.name,
        subjects=[
            {
                "kind": framework_service_account.kind,
                "name": framework_service_account.name,
                "namespace": framework_service_account.namespace,
            }
        ],
    ) as cluster_role_binding:
        yield cluster_role_binding


@pytest.fixture(scope="module")
def framework_resources(
    framework_ns,
    framework_service_account,
    framework_cluster_role,
    framework_cluster_role_binding,
):
    yield


@pytest.fixture(scope="module")
def checkup_linux_bridge_device_worker_1(
    skip_if_no_multinic_nodes, nodes_available_nics, worker_node1
):
    worker_hostname = worker_node1.hostname
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{BRIDGE_NAME}-{worker_hostname}",
        interface_name=BRIDGE_NAME,
        node_selector=worker_hostname,
        ports=[nodes_available_nics[worker_hostname][-1]],
    ) as br_dev:
        yield br_dev


@pytest.fixture(scope="module")
def checkup_linux_bridge_device_worker_2(
    skip_if_no_multinic_nodes, nodes_available_nics, worker_node2
):
    worker_hostname = worker_node2.hostname
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{BRIDGE_NAME}-{worker_hostname}",
        interface_name=BRIDGE_NAME,
        node_selector=worker_hostname,
        ports=[nodes_available_nics[worker_hostname][-1]],
    ) as br_dev:
        yield br_dev


@pytest.fixture(scope="module")
def checkup_nad(
    default_ns,
    checkup_linux_bridge_device_worker_1,
    checkup_linux_bridge_device_worker_2,
):
    with network_nad(
        namespace=default_ns,
        nad_type=checkup_linux_bridge_device_worker_1.bridge_type,
        nad_name="checkup-nad",
        interface_name=checkup_linux_bridge_device_worker_1.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture(scope="module")
def linux_bridge_disconnected_device_worker_1(worker_node1):
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{DISCONNECTED_BR}-{name_prefix(worker_node1.hostname)}",
        interface_name=f"{DISCONNECTED_BR}",
        node_selector=worker_node1.hostname,
    ) as br_dev:
        yield br_dev


@pytest.fixture(scope="module")
def linux_bridge_disconnected_device_worker_2(worker_node2):
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{DISCONNECTED_BR}-{name_prefix(worker_node2.hostname)}",
        interface_name=f"{DISCONNECTED_BR}",
        node_selector=worker_node2.hostname,
    ) as br_dev:
        yield br_dev


@pytest.fixture(scope="module")
def disconnected_checkup_nad(
    default_ns,
    linux_bridge_disconnected_device_worker_1,
    linux_bridge_disconnected_device_worker_2,
):
    with network_nad(
        namespace=default_ns,
        nad_type=linux_bridge_disconnected_device_worker_1.bridge_type,
        nad_name=f"{DISCONNECTED}-checkup-nad",
        interface_name=linux_bridge_disconnected_device_worker_1.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture(scope="module")
def checkup_sriov_network(sriov_node_policy, namespace, sriov_namespace):
    """
    Create a SR-IOV network linked to SR-IOV policy.
    """
    with network_nad(
        nad_type=SRIOV,
        nad_name="sriov-checkup-nad",
        sriov_resource_name=sriov_node_policy.resource_name,
        namespace=sriov_namespace,
        sriov_network_namespace=DEFAULT_NAMESPACE,
    ) as sriov_network:
        yield sriov_network


@pytest.fixture(scope="session")
def latency_cluster_role():
    vm_latency_checker = ClusterRole(
        name="vm-latency-checker",
        api_groups=[ClusterRole.ApiGroup.KUBEVIRT_IO],
        permissions_to_resources=["virtualmachineinstances"],
        verbs=[CREATE, DELETE, GET],
    )
    vm_latency_checker.add_rule(
        api_groups=[ClusterRole.ApiGroup.SUBRESOURCES_KUBEVIRT_IO],
        permissions_to_resources=["virtualmachineinstances/console"],
        verbs=[GET],
    )
    vm_latency_checker.add_rule(
        api_groups=[ClusterRole.ApiGroup.K8S_CNI_CNCF_IO],
        permissions_to_resources=["network-attachment-definitions"],
        verbs=[GET],
    )
    vm_latency_checker.deploy()
    yield vm_latency_checker.name
    vm_latency_checker.clean_up()


@pytest.fixture()
def default_latency_configmap(
    checkup_nad, framework_service_account, latency_cluster_role
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_concurrent_job(
    framework_service_account, default_latency_configmap, latency_job
):
    with create_latency_job(
        service_account=framework_service_account,
        name="concurrent-checkup-job",
    ) as job:
        yield job


@pytest.fixture()
def latency_sriov_configmap(
    skip_insufficient_sriov_workers,
    sriov_workers_node1,
    sriov_workers_node2,
    checkup_sriov_network,
    framework_service_account,
    latency_cluster_role,
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_sriov_network.network_namespace,
        network_attachment_definition_name=checkup_sriov_network.name,
        SOURCE_NODE=sriov_workers_node1.hostname,
        TARGET_NODE=sriov_workers_node2.hostname,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_disconnected_configmap(
    worker_node1,
    worker_node2,
    disconnected_checkup_nad,
    framework_service_account,
    latency_cluster_role,
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=disconnected_checkup_nad.namespace,
        network_attachment_definition_name=disconnected_checkup_nad.name,
        SOURCE_NODE=worker_node1.hostname,
        TARGET_NODE=worker_node2.hostname,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_configmap(
    checkup_nad, framework_service_account, latency_cluster_role
):
    data = compose_configmap_data(
        framework_service_account=framework_service_account,
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    )
    yield ConfigMap(
        name=LATENCY_CONFIGMAP, namespace=framework_service_account.namespace, data=data
    )


@pytest.fixture()
def latency_nonexistent_roles_configmap(checkup_nad, framework_service_account):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        cluster_role="false-cluster-role",
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_no_roles_configmap(checkup_nad, framework_service_account):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_image_configmap(
    checkup_nad,
    framework_service_account,
    latency_cluster_role,
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        image="registry:500/false-image",
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_timeout_configmap(
    checkup_nad,
    framework_service_account,
    latency_cluster_role,
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        timeout=f"{TIMEOUT_10SEC}s",
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_same_node_configmap(
    worker_node1, checkup_nad, framework_service_account, latency_cluster_role
):
    with create_latency_configmap(
        framework_service_account=framework_service_account,
        cluster_role=latency_cluster_role,
        network_attachment_definition_namespace=checkup_nad.namespace,
        network_attachment_definition_name=checkup_nad.name,
        SOURCE_NODE=worker_node1.hostname,
        TARGET_NODE=worker_node1.hostname,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_job(framework_service_account):
    with create_latency_job(service_account=framework_service_account) as job:
        yield job
