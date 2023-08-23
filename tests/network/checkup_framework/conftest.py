import logging
import random

import pytest
from ocp_resources.role import Role
from ocp_resources.role_binding import RoleBinding
from ocp_resources.service_account import ServiceAccount
from ocp_utilities.infra import cluster_resource

from tests.network.checkup_framework.constants import (
    CHECKUP_NODE_LABEL,
    CREATE_STR,
    DELETE_STR,
    DISCONNECTED_STR,
    GET_STR,
    NONEXISTING_CONFIGMAP,
    UPDATE_STR,
)
from tests.network.checkup_framework.utils import (
    assert_successful_checkup,
    create_latency_configmap,
    create_latency_job,
    wait_for_job_failure,
)
from utilities.constants import LINUX_BRIDGE, SRIOV
from utilities.infra import create_ns, label_nodes
from utilities.network import network_device, network_nad


LOGGER = logging.getLogger(__name__)
LATENCY_DISCONNECTED_CONFIGMAP = "latency-disconnected-configmap"


@pytest.fixture(scope="module")
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
            "verbs": [GET_STR, CREATE_STR, DELETE_STR],
        },
        {
            "apiGroups": ["subresources.kubevirt.io"],
            "resources": ["virtualmachineinstances/console"],
            "verbs": [GET_STR],
        },
        {
            "apiGroups": ["k8s.cni.cncf.io"],
            "resources": ["network-attachment-definitions"],
            "verbs": [GET_STR],
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
                "verbs": [GET_STR, UPDATE_STR],
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
):
    yield


@pytest.fixture(scope="module")
def checkup_linux_bridge_device(
    skip_if_no_multinic_nodes, nodes_available_nics, label_checkup_nodes
):
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


@pytest.fixture(scope="module")
def checkup_sriov_disconnected_network(
    vlans_list, sriov_node_policy, checkup_ns, sriov_namespace
):
    """
    Create a SR-IOV disconnected network linked to a SR-IOV policy. This is created using a non-configured VLAN tag.
    """
    with network_nad(
        nad_type=SRIOV,
        nad_name="sriov-checkup-disconnected-nad",
        sriov_resource_name=sriov_node_policy.resource_name,
        namespace=sriov_namespace,
        sriov_network_namespace=checkup_ns.name,
        vlan=random.choice([vlan for vlan in range(2, 4094) if vlan not in vlans_list]),
    ) as sriov_network:
        yield sriov_network


@pytest.fixture()
def network_type(request):
    # This, combining with the lazy_fixture in the test, allows dynamic usage of different networks in the fixtures.
    return request.param


@pytest.fixture()
def default_latency_configmap(
    index_number,
    checkup_ns,
    network_type,
):
    with create_latency_configmap(
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name=network_type.name,
        configmap_name=f"default-latency-configmap-{next(index_number)}",
    ) as configmap:
        yield configmap


@pytest.fixture()
def first_latency_job_checkup_ready(
    unprivileged_client, checkup_ns, default_latency_configmap, latency_job
):
    assert_successful_checkup(
        unprivileged_client=unprivileged_client,
        configmap=default_latency_configmap,
        job=latency_job,
        checkup_ns=checkup_ns,
    )


@pytest.fixture()
def latency_concurrent_job(
    framework_service_account,
    default_latency_configmap,
    cnv_current_version,
    first_latency_job_checkup_ready,
):
    # To prevent race condition we must first make sure the first job was configured successfully, and only then
    # create the concurrent one.
    with create_latency_job(
        name="concurrent-checkup-job",
        service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        latency_configmap_name=default_latency_configmap.name,
    ) as job:
        yield job


@pytest.fixture()
def latency_disconnected_configmap(
    checkup_ns,
    disconnected_checkup_nad,
):
    with create_latency_configmap(
        configmap_name=LATENCY_DISCONNECTED_CONFIGMAP,
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=disconnected_checkup_nad.namespace,
        network_attachment_definition_name=disconnected_checkup_nad.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_disconnected_configmap_sriov(
    checkup_ns,
    checkup_sriov_disconnected_network,
):
    with create_latency_configmap(
        configmap_name=f"{LATENCY_DISCONNECTED_CONFIGMAP}-sriov",
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name=checkup_sriov_disconnected_network.name,
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_configmap_env_job(
    framework_service_account,
    cnv_current_version,
):
    with create_latency_job(
        name=f"latency-{NONEXISTING_CONFIGMAP}-env-job",
        service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        latency_configmap_name=NONEXISTING_CONFIGMAP,
    ) as job:
        yield job


@pytest.fixture()
def latency_no_env_variables_job(
    framework_service_account,
    cnv_current_version,
):
    with create_latency_job(
        name="latency-no-env-variables-job",
        service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        latency_configmap_name=None,
        env_variables=False,
    ) as job:
        yield job


@pytest.fixture()
def latency_same_node_configmap(
    worker_node1,
    checkup_ns,
    network_type,
):
    with create_latency_configmap(
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name=network_type.name,
        source_node=worker_node1.hostname,
        target_node=worker_node1.hostname,
        configmap_name="latency-same-node-configmap",
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_node_configmap(
    worker_node1,
    checkup_ns,
    network_type,
):
    with create_latency_configmap(
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name=network_type.name,
        source_node="non-existent-node",
        target_node=worker_node1.hostname,
        configmap_name="latency-nonexistent-node-configmap",
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_nad_configmap(
    checkup_ns,
):
    with create_latency_configmap(
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace=checkup_ns.name,
        network_attachment_definition_name="non-existing-nad",
        configmap_name="latency-nonexistent-nad-configmap",
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_nonexistent_namespace_configmap(
    checkup_ns,
    network_type,
):
    with create_latency_configmap(
        namespace_name=checkup_ns.name,
        network_attachment_definition_namespace="non-existing-namespace",
        network_attachment_definition_name=network_type.name,
        configmap_name="latency-nonexistent-ns-configmap",
    ) as configmap:
        yield configmap


@pytest.fixture()
def latency_job(
    framework_service_account,
    cnv_current_version,
    latency_configmap,
):
    configmap_name = latency_configmap.name
    with create_latency_job(
        name=configmap_name.replace("configmap", "job"),
        service_account=framework_service_account,
        cnv_current_version=cnv_current_version,
        latency_configmap_name=configmap_name,
    ) as job:
        yield job


@pytest.fixture()
def linux_bridge_disconnected_device(label_checkup_nodes):
    bridge_name = f"{DISCONNECTED_STR}-br"
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{bridge_name}-nncp",
        interface_name=bridge_name,
        node_selector_labels=CHECKUP_NODE_LABEL,
    ) as br_dev:
        yield br_dev


@pytest.fixture()
def disconnected_checkup_nad(
    checkup_ns,
    linux_bridge_disconnected_device,
):
    with network_nad(
        namespace=checkup_ns,
        nad_type=linux_bridge_disconnected_device.bridge_type,
        nad_name=f"{DISCONNECTED_STR}-checkup-nad",
        interface_name=linux_bridge_disconnected_device.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture()
def latency_job_success(
    unprivileged_client, checkup_ns, latency_configmap, latency_job
):
    assert_successful_checkup(
        unprivileged_client=unprivileged_client,
        configmap=latency_configmap,
        job=latency_job,
        checkup_ns=checkup_ns,
    )


@pytest.fixture()
def latency_job_failure(latency_job):
    wait_for_job_failure(job=latency_job)


@pytest.fixture()
def latency_concurrent_job_failure(latency_concurrent_job):
    wait_for_job_failure(job=latency_concurrent_job)
