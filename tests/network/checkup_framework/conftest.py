import pytest
from ocp_resources.role import Role
from ocp_resources.role_binding import RoleBinding
from ocp_resources.service_account import ServiceAccount
from ocp_utilities.infra import cluster_resource

from tests.network.checkup_framework.utils import (
    create_latency_configmap,
    create_latency_job,
)
from utilities.constants import LINUX_BRIDGE, SRIOV
from utilities.infra import create_ns, label_nodes
from utilities.network import network_device, network_nad


DISCONNECTED = "disconnected"
DISCONNECTED_BR = f"{DISCONNECTED}-br"
CHECKUP_NODE_LABEL = {"checkup_framework": "allow"}
GET = "get"
CREATE = "create"
UPDATE = "update"
DELETE = "delete"


@pytest.fixture(scope="session")
def checkup_ns(unprivileged_client):
    yield from create_ns(
        unprivileged_client=unprivileged_client, name="test-checkup-framework"
    )


@pytest.fixture(scope="module")
def framework_service_account(checkup_ns):
    with cluster_resource(ServiceAccount)(
        name=f"{checkup_ns.name}-sa", namespace=checkup_ns.name
    ) as sa:
        yield sa


@pytest.fixture(scope="module")
def framework_latency_role(checkup_ns):
    rules = [
        {
            "apiGroups": ["kubevirt.io"],
            "resources": ["virtualmachineinstances"],
            "verbs": [GET, CREATE, DELETE],
        },
        {
            "apiGroups": ["subresources.kubevirt.io"],
            "resources": ["virtualmachineinstances/console"],
            "verbs": [GET],
        },
        {
            "apiGroups": ["k8s.cni.cncf.io"],
            "resources": ["network-attachment-definitions"],
            "verbs": [GET],
        },
    ]
    with cluster_resource(Role)(
        name=f"{checkup_ns.name}-latency-role",
        namespace=checkup_ns.name,
        rules=rules,
    ) as latency_role:
        yield latency_role


@pytest.fixture(scope="module")
def framework_latency_role_binding(
    checkup_ns, framework_service_account, framework_latency_role
):
    with cluster_resource(RoleBinding)(
        name=framework_latency_role.name,
        namespace=checkup_ns.name,
        subjects_kind=framework_service_account.kind,
        subjects_name=framework_service_account.name,
        role_ref_kind=framework_latency_role.kind,
        role_ref_name=framework_latency_role.name,
    ) as role_binding:
        yield role_binding


@pytest.fixture(scope="module")
def framework_configmap_role(checkup_ns):
    with cluster_resource(Role)(
        name=f"{checkup_ns.name}-configmap-role",
        namespace=checkup_ns.name,
        rules=[
            {
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": [GET, UPDATE],
            }
        ],
    ) as configmap_role:
        yield configmap_role


@pytest.fixture(scope="module")
def framework_configmap_role_binding(
    checkup_ns, framework_service_account, framework_configmap_role
):
    with cluster_resource(RoleBinding)(
        name=framework_configmap_role.name,
        namespace=checkup_ns.name,
        subjects_kind=framework_service_account.kind,
        subjects_name=framework_service_account.name,
        role_ref_kind=framework_configmap_role.kind,
        role_ref_name=framework_configmap_role.name,
    ) as role_binding:
        yield role_binding


@pytest.fixture(scope="module")
def label_checkup_nodes(worker_node1, worker_node2):
    yield from label_nodes(
        nodes=[worker_node1, worker_node2], labels=CHECKUP_NODE_LABEL
    )


@pytest.fixture(scope="module")
def framework_resources(
    checkup_ns,
    framework_service_account,
    framework_latency_role,
    framework_latency_role_binding,
    framework_configmap_role,
    framework_configmap_role_binding,
    label_checkup_nodes,
):
    yield


@pytest.fixture(scope="module")
def checkup_linux_bridge_device(skip_if_no_multinic_nodes, nodes_available_nics):
    bridge_name = "checkup-br"
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{bridge_name}-nncp",
        interface_name=bridge_name,
        node_selector_labels=CHECKUP_NODE_LABEL,
        ports=[list(nodes_available_nics.values())[0][-1]],
    ) as br_dev:
        yield br_dev


@pytest.fixture(scope="module")
def checkup_nad(
    checkup_ns,
    checkup_linux_bridge_device,
):
    with network_nad(
        namespace=checkup_ns,
        nad_type=checkup_linux_bridge_device.bridge_type,
        nad_name="checkup-nad",
        interface_name=checkup_linux_bridge_device.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture(scope="module")
def checkup_sriov_network(sriov_node_policy, checkup_ns, sriov_namespace):
    """
    Create a SR-IOV network linked to SR-IOV policy.
    """
    with network_nad(
        nad_type=SRIOV,
        nad_name="sriov-checkup-nad",
        sriov_resource_name=sriov_node_policy.resource_name,
        namespace=sriov_namespace,
        sriov_network_namespace=checkup_ns.name,
    ) as sriov_network:
        yield sriov_network


@pytest.fixture()
def network_type(request):
    # This, combining with the lazy_fixture in the test, allows dynamic usage of different networks in the fixtures.
    return request.param


@pytest.fixture()
def default_latency_configmap(
    checkup_ns, cnv_current_version, framework_latency_role, network_type
):
    with create_latency_configmap(
        namespace=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name=network_type.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_job(
    framework_service_account,
    cnv_current_version,
    default_latency_configmap,
):
    with create_latency_job(
        service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        latency_configmap_name=default_latency_configmap.name,
    ) as job:
        yield job
