import shlex

import pytest
from ocp_resources.pod import Pod
from ocp_resources.service_account import ServiceAccount

from tests.network.constants import (
    HTTPBIN_COMMAND,
    HTTPBIN_IMAGE,
    PORT_8080,
    SERVICE_MESH_PORT,
)
from tests.network.utils import (
    CirrosVirtualMachineForServiceMesh,
    ServiceMeshDeployments,
    ServiceMeshDeploymentService,
    ServiceMeshMemberRollForTests,
)
from utilities import console
from utilities.constants import (
    KMP_DISABLED_LABEL,
    KMP_VM_ASSIGNMENT_LABEL,
    LINUX_BRIDGE,
)
from utilities.infra import cluster_resource, create_ns, get_pod_by_name_prefix
from utilities.network import cloud_init, network_nad
from utilities.virt import (
    VirtualMachineForTests,
    fedora_vm_body,
    running_vm,
    wait_for_console,
)


NAD_MAC_SPOOF_NAME = "brspoofupgrade"


@pytest.fixture(scope="session")
def upgrade_linux_macspoof_nad(
    upgrade_namespace_scope_session,
):
    with network_nad(
        namespace=upgrade_namespace_scope_session,
        nad_type=LINUX_BRIDGE,
        nad_name=NAD_MAC_SPOOF_NAME,
        interface_name=NAD_MAC_SPOOF_NAME,
        macspoofchk=True,
        add_resource_name=False,
    ) as nad:
        yield nad


@pytest.fixture(scope="session")
def vm_nad_networks_data(upgrade_linux_macspoof_nad):
    return {upgrade_linux_macspoof_nad.name: upgrade_linux_macspoof_nad.name}


@pytest.fixture(scope="session")
def vma_upgrade_mac_spoof(
    worker_node1, unprivileged_client, upgrade_linux_macspoof_nad, vm_nad_networks_data
):
    name = "vma-macspoof"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=upgrade_linux_macspoof_nad.namespace,
        networks=vm_nad_networks_data,
        interfaces=sorted(vm_nad_networks_data.keys()),
        client=unprivileged_client,
        cloud_init_data=cloud_init(ip_address="10.200.0.1"),
        body=fedora_vm_body(name=name),
        node_selector=worker_node1.hostname,
        running=True,
    ) as vm:
        yield vm


@pytest.fixture(scope="session")
def vmb_upgrade_mac_spoof(
    worker_node1, unprivileged_client, upgrade_linux_macspoof_nad, vm_nad_networks_data
):
    name = "vmb-macspoof"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=upgrade_linux_macspoof_nad.namespace,
        networks=vm_nad_networks_data,
        interfaces=sorted(vm_nad_networks_data.keys()),
        client=unprivileged_client,
        cloud_init_data=cloud_init(ip_address="10.200.0.2"),
        body=fedora_vm_body(name=name),
        node_selector=worker_node1.hostname,
        running=True,
    ) as vm:
        yield vm


@pytest.fixture(scope="session")
def running_vma_upgrade_mac_spoof(vma_upgrade_mac_spoof):
    return running_vm(vm=vma_upgrade_mac_spoof)


@pytest.fixture(scope="session")
def running_vmb_upgrade_mac_spoof(vmb_upgrade_mac_spoof):
    return running_vm(vm=vmb_upgrade_mac_spoof)


@pytest.fixture(scope="session")
def service_mesh_upgrade_ns(skip_if_service_mesh_not_installed, unprivileged_client):
    yield from create_ns(
        unprivileged_client=unprivileged_client,
        name="service-mesh-upgrade-tests",
    )


@pytest.fixture(scope="session")
def httpbin_service_mesh_deployment_for_upgrade(service_mesh_upgrade_ns):
    with ServiceMeshDeployments(
        name="httpbin",
        namespace=service_mesh_upgrade_ns.name,
        version=ServiceMeshDeployments.ApiVersion.V1,
        image=HTTPBIN_IMAGE,
        command=shlex.split(HTTPBIN_COMMAND),
        port=PORT_8080,
        service_port=SERVICE_MESH_PORT,
        service_account=True,
        http_readiness_probe=True,
    ) as dp:
        yield dp


@pytest.fixture(scope="session")
def httpbin_service_mesh_service_account_for_upgrade(
    httpbin_service_mesh_deployment_for_upgrade,
):
    with cluster_resource(ServiceAccount)(
        name=httpbin_service_mesh_deployment_for_upgrade.app_name,
        namespace=httpbin_service_mesh_deployment_for_upgrade.namespace,
    ) as sa:
        yield sa


@pytest.fixture(scope="session")
def httpbin_service_mesh_service_for_upgrade(
    admin_client,
    httpbin_service_mesh_deployment_for_upgrade,
    httpbin_service_mesh_service_account_for_upgrade,
):
    deployment_namespace = httpbin_service_mesh_deployment_for_upgrade.namespace
    with ServiceMeshDeploymentService(
        namespace=deployment_namespace,
        app_name=httpbin_service_mesh_deployment_for_upgrade.app_name,
        port=httpbin_service_mesh_deployment_for_upgrade.service_port,
    ) as sv:
        # TODO: Once Jira issue CNV-24274 is closed, and we have the health-check of the pod working accurately,
        #   the next function call (6 lines) can be removed.
        get_pod_by_name_prefix(
            dyn_client=admin_client,
            pod_prefix=sv.app_name,
            namespace=deployment_namespace,
            get_all=True,
        )[0].wait_for_status(status=Pod.Status.RUNNING)
        yield sv


@pytest.fixture(scope="session")
def service_mesh_member_roll_for_upgrade(service_mesh_upgrade_ns):
    with ServiceMeshMemberRollForTests(members=[service_mesh_upgrade_ns.name]) as smmr:
        yield smmr


@pytest.fixture(scope="session")
def vm_cirros_with_service_mesh_annotation_for_upgrade(
    unprivileged_client,
    service_mesh_upgrade_ns,
    service_mesh_member_roll_for_upgrade,
):
    vm_name = "service-mesh-vm"
    with cluster_resource(CirrosVirtualMachineForServiceMesh)(
        client=unprivileged_client,
        name=vm_name,
        namespace=service_mesh_upgrade_ns.name,
    ) as vm:
        vm.custom_service_enable(
            service_name=vm_name,
            port=SERVICE_MESH_PORT,
        )
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture(scope="session")
def service_mesh_vm_for_upgrade_with_console_ready(
    vm_cirros_with_service_mesh_annotation_for_upgrade,
):
    wait_for_console(
        vm=vm_cirros_with_service_mesh_annotation_for_upgrade,
        console_impl=console.Cirros,
    )


@pytest.fixture(scope="session")
def namespace_with_disabled_kmp():
    yield from create_ns(
        name="kmp-disabled-ns",
        labels={KMP_VM_ASSIGNMENT_LABEL: KMP_DISABLED_LABEL},
    )
