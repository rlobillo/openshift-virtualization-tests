import logging
from copy import deepcopy

import pytest
from ocp_resources.daemonset import DaemonSet
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from pytest_testconfig import config as py_config

from utilities.constants import (
    CLUSTER_NETWORK_ADDONS_OPERATOR,
    KMP_VM_ASSIGNMENT_LABEL,
    KUBE_CNI_LINUX_BRIDGE_PLUGIN,
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    LINUX_BRIDGE,
    TIMEOUT_5MIN,
    TIMEOUT_10MIN,
)
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import (
    cluster_resource,
    create_ns,
    get_pod_by_name_prefix,
    label_project,
)
from utilities.network import network_device, network_nad
from utilities.virt import VirtualMachineForTests, fedora_vm_body


LOGGER = logging.getLogger(__name__)
NON_EXISTS_IMAGE = "non-exists-image-test-cnao-alerts"
DUPLICATE_MAC_STR = "duplicate-mac"


@pytest.fixture()
def vms_mac(mac_pool):
    return mac_pool.get_mac_from_pool()


@pytest.fixture()
def kmp_disabled_namespace(kmp_vm_label):
    kmp_vm_label[KMP_VM_ASSIGNMENT_LABEL] = "ignore"
    yield from create_ns(name="kmp-disabled", labels=kmp_vm_label)


@pytest.fixture()
def updated_namespace_with_kmp(admin_client, kmp_vm_label, kmp_disabled_namespace):
    kmp_vm_label[KMP_VM_ASSIGNMENT_LABEL] = None
    label_project(
        name=kmp_disabled_namespace.name, label=kmp_vm_label, admin_client=admin_client
    )


@pytest.fixture()
def restarted_kmp_controller(admin_client, kmp_deployment):
    get_pod_by_name_prefix(
        dyn_client=admin_client,
        pod_prefix=KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
        namespace=py_config["hco_namespace"],
    ).delete(wait=True)
    kmp_deployment.wait_for_replicas()


@pytest.fixture()
def bridge_device_duplicate_mac(worker_node1):
    with network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name=f"{DUPLICATE_MAC_STR}-nncp",
        interface_name="bridge-dup-mac",
        node_selector=worker_node1.hostname,
    ) as dev:
        yield dev


@pytest.fixture()
def duplicate_mac_nad_vm1(namespace, bridge_device_duplicate_mac):
    with network_nad(
        nad_type=bridge_device_duplicate_mac.bridge_type,
        nad_name=f"{DUPLICATE_MAC_STR}-nad",
        namespace=namespace,
        interface_name=bridge_device_duplicate_mac.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture()
def duplicate_mac_nad_vm2(kmp_disabled_namespace, bridge_device_duplicate_mac):
    with network_nad(
        nad_type=bridge_device_duplicate_mac.bridge_type,
        nad_name=f"{DUPLICATE_MAC_STR}-nad",
        namespace=kmp_disabled_namespace,
        interface_name=bridge_device_duplicate_mac.bridge_name,
    ) as nad:
        yield nad


@pytest.fixture()
def duplicate_mac_vm1(
    namespace, worker_node1, admin_client, vms_mac, duplicate_mac_nad_vm1
):
    networks = {duplicate_mac_nad_vm1.name: duplicate_mac_nad_vm1.name}
    name = f"{DUPLICATE_MAC_STR}-vm1"
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        namespace=namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        networks=networks,
        interfaces=networks.keys(),
        node_selector=worker_node1.hostname,
        macs={duplicate_mac_nad_vm1.name: vms_mac},
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture()
def duplicate_mac_vm2(
    kmp_disabled_namespace, worker_node1, admin_client, vms_mac, duplicate_mac_nad_vm2
):
    networks = {duplicate_mac_nad_vm2.name: duplicate_mac_nad_vm2.name}
    name = f"{DUPLICATE_MAC_STR}-vm2"
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        namespace=kmp_disabled_namespace.name,
        name=name,
        body=fedora_vm_body(name=name),
        networks=networks,
        interfaces=networks.keys(),
        node_selector=worker_node1.hostname,
        macs={duplicate_mac_nad_vm2.name: vms_mac},
    ) as vm:
        vm.start(wait=True)
        yield vm


@pytest.fixture()
def bad_cnao_deployment_linux_bridge(csv_scope_session):
    linux_bridge_image = "LINUX_BRIDGE_IMAGE"
    csv_dict = deepcopy(csv_scope_session.instance.to_dict())
    for deployment in csv_dict["spec"]["install"]["spec"]["deployments"]:
        if deployment["name"] == CLUSTER_NETWORK_ADDONS_OPERATOR:
            deployment_env = deployment["spec"]["template"]["spec"]["containers"][0][
                "env"
            ]
            for env in deployment_env:
                if env["name"] == linux_bridge_image:
                    LOGGER.info(
                        f"Replacing {linux_bridge_image} {env['value']} with {NON_EXISTS_IMAGE}"
                    )
                    env["value"] = NON_EXISTS_IMAGE

    return csv_dict


@pytest.fixture()
def bad_cnao_operator(csv_scope_session):
    operator_image = "OPERATOR_IMAGE"
    csv_dict = deepcopy(csv_scope_session.instance.to_dict())
    for deployment in csv_dict["spec"]["install"]["spec"]["deployments"]:
        if deployment["name"] == CLUSTER_NETWORK_ADDONS_OPERATOR:
            containers = deployment["spec"]["template"]["spec"]["containers"][0]
            containers["image"] = NON_EXISTS_IMAGE
            deployment_env = containers["env"]
            for env in deployment_env:
                if env["name"] == operator_image:
                    LOGGER.info(
                        f"Replacing {operator_image} {env['value']} with {NON_EXISTS_IMAGE}"
                    )
                    env["value"] = NON_EXISTS_IMAGE

    return csv_dict


@pytest.fixture()
def invalid_cnao_linux_bridge(
    admin_client, hco_namespace, csv_scope_session, bad_cnao_deployment_linux_bridge
):
    with ResourceEditorValidateHCOReconcile(
        patches={csv_scope_session: bad_cnao_deployment_linux_bridge},
        list_resource_reconcile=[NetworkAddonsConfig],
    ):
        yield


@pytest.fixture()
def invalid_cnao_operator(
    admin_client, hco_namespace, csv_scope_session, bad_cnao_operator
):
    with ResourceEditorValidateHCOReconcile(
        patches={csv_scope_session: bad_cnao_operator},
        consecutive_checks_count=10,
        list_resource_reconcile=[NetworkAddonsConfig],
    ):
        yield

    linux_bridge_pods = get_pod_by_name_prefix(
        dyn_client=admin_client,
        pod_prefix=KUBE_CNI_LINUX_BRIDGE_PLUGIN,
        namespace=hco_namespace.name,
        get_all=True,
    )

    [pod.delete() for pod in linux_bridge_pods]
    [pod.wait_deleted() for pod in linux_bridge_pods]

    linux_bridge_plugin_ds = DaemonSet(
        name=KUBE_CNI_LINUX_BRIDGE_PLUGIN, namespace=hco_namespace.name
    )
    linux_bridge_plugin_ds.wait_until_deployed(timeout=TIMEOUT_10MIN)


@pytest.fixture()
def cnao_ready(admin_client, hco_namespace):
    yield
    get_pod_by_name_prefix(
        dyn_client=admin_client,
        pod_prefix=CLUSTER_NETWORK_ADDONS_OPERATOR,
        namespace=hco_namespace.name,
    ).delete(wait=True)
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_5MIN,
        sleep=1,
        func=get_pod_by_name_prefix,
        dyn_client=admin_client,
        pod_prefix=CLUSTER_NETWORK_ADDONS_OPERATOR,
        namespace=hco_namespace.name,
    )
    try:
        for sample in samples:
            if sample.status == sample.Status.RUNNING:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"{sample.name} status is {sample.status}. Expected status is: {sample.Status.RUNNING}"
        )
        raise


@pytest.mark.polarion("CNV-7274")
def test_cnao_not_ready(cnao_ready, invalid_cnao_linux_bridge, prometheus):
    prometheus.alert_sampler(alert="NetworkAddonsConfigNotReady")


@pytest.mark.polarion("CNV-7275")
def test_cnao_is_down(cnao_ready, invalid_cnao_operator, prometheus):
    prometheus.alert_sampler(alert="CnaoDown")


@pytest.mark.polarion("CNV-7684")
def test_duplicate_mac_alert(
    prometheus,
    duplicate_mac_vm1,
    duplicate_mac_vm2,
    updated_namespace_with_kmp,
    restarted_kmp_controller,
):
    prometheus.alert_sampler(alert="KubeMacPoolDuplicateMacsFound")
