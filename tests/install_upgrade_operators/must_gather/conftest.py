import logging
import os
import re
import shlex

import pytest
import yaml
from ocp_resources.configmap import ConfigMap
from ocp_resources.custom_resource_definition import CustomResourceDefinition
from ocp_resources.pod import Pod
from openshift.dynamic.exceptions import ResourceNotFoundError

import utilities.network
from tests.install_upgrade_operators.must_gather.utils import (
    MUST_GATHER_VM_NAME_PREFIX,
    collect_must_gather,
)
from tests.install_upgrade_operators.utils import create_vms
from utilities.constants import LINUX_BRIDGE
from utilities.infra import (
    ExecCommandOnPod,
    MissingResourceException,
    cluster_resource,
    create_ns,
)
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


LOGGER = logging.getLogger(__name__)
LONG_VM_NAME = "v" * 63


@pytest.fixture(scope="module")
def must_gather_tmpdir(tmpdir_factory):
    return tmpdir_factory.mktemp("must_gather_scope_module")


@pytest.fixture()
def must_gather_tmpdir_scope_function(request, tmpdir_factory):
    return tmpdir_factory.mktemp(f"must_gather_{request.node.callspec.id}")


@pytest.fixture(scope="class")
def collected_cluster_must_gather(
    must_gather_tmpdir,
    must_gather_image_url,
    must_gather_vm,
):
    yield collect_must_gather(
        must_gather_tmpdir=must_gather_tmpdir,
        must_gather_image_url=must_gather_image_url,
    )


@pytest.fixture(scope="class")
def collected_vm_details_must_gather(
    must_gather_tmpdir,
    must_gather_image_url,
):
    yield collect_must_gather(
        must_gather_tmpdir=must_gather_tmpdir,
        must_gather_image_url=must_gather_image_url,
        script_name="gather_vms_details",
    )


@pytest.fixture(scope="module")
def custom_resource_definitions(admin_client):
    yield list(CustomResourceDefinition.get(admin_client))


@pytest.fixture(scope="module")
def kubevirt_crd_resources(admin_client, custom_resource_definitions):
    kubevirt_resources = []
    for resource in custom_resource_definitions:
        if "kubevirt.io" in resource.instance.spec.group:
            kubevirt_resources.append(resource)
    return kubevirt_resources


@pytest.fixture(scope="module")
def kubevirt_crd_names(kubevirt_crd_resources):
    return [crd.name for crd in kubevirt_crd_resources]


@pytest.fixture()
def kubevirt_crd_by_type(
    cnv_crd_matrix__function__, kubevirt_crd_resources, kubevirt_crd_names
):
    for crd in kubevirt_crd_resources:
        if crd.name == cnv_crd_matrix__function__:
            return crd
    raise ResourceNotFoundError(
        f"CRD: {cnv_crd_matrix__function__} not found in kubevirt crds: {kubevirt_crd_names}"
    )


@pytest.fixture(scope="package")
def must_gather_nad(nodenetworkstate_with_bridge, node_gather_unprivileged_namespace):
    with utilities.network.network_nad(
        nad_type=nodenetworkstate_with_bridge.bridge_type,
        nad_name=nodenetworkstate_with_bridge.bridge_name,
        interface_name=nodenetworkstate_with_bridge.bridge_name,
        namespace=node_gather_unprivileged_namespace,
    ) as must_gather_nad:
        yield must_gather_nad


@pytest.fixture(scope="package")
def nodenetworkstate_with_bridge():
    with utilities.network.network_device(
        interface_type=LINUX_BRIDGE,
        nncp_name="must-gather-br",
        interface_name="mg-br1",
    ) as br:
        yield br


@pytest.fixture(scope="module")
def running_hco_containers(admin_client, hco_namespace):
    pods = []
    for pod in Pod.get(admin_client, namespace=hco_namespace.name):
        for container in pod.instance["status"].get("containerStatuses", []):
            if container["ready"]:
                pods.append((pod, container))
    assert pods, f"No running pods in the {hco_namespace.name} namespace were found."
    return pods


@pytest.fixture(scope="package")
def node_gather_unprivileged_namespace(unprivileged_client):
    yield from create_ns(
        unprivileged_client=unprivileged_client,
        name="node-gather-unprivileged",
    )


@pytest.fixture(scope="package")
def must_gather_vm(
    node_gather_unprivileged_namespace,
    nodenetworkstate_with_bridge,
    must_gather_nad,
    unprivileged_client,
):
    name = f"{MUST_GATHER_VM_NAME_PREFIX}-2"
    networks = {
        nodenetworkstate_with_bridge.bridge_name: nodenetworkstate_with_bridge.bridge_name
    }

    with cluster_resource(VirtualMachineForTests)(
        client=unprivileged_client,
        namespace=node_gather_unprivileged_namespace.name,
        name=name,
        networks=networks,
        interfaces=sorted(networks.keys()),
        body=fedora_vm_body(name=name),
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture(scope="function")
def resource_type(request, admin_client):
    resource_type = request.param
    if not next(resource_type.get(admin_client), None):
        raise MissingResourceException(resource_type.__name__)
    return resource_type


@pytest.fixture(scope="function")
def config_map_by_name(request, admin_client):
    cm_name, cm_namespace = request.param
    return ConfigMap(name=cm_name, namespace=cm_namespace)


@pytest.fixture(scope="class")
def config_maps_file(hco_namespace, collected_cluster_must_gather):
    with open(
        f"{collected_cluster_must_gather}/namespaces/{hco_namespace.name}/core/configmaps.yaml",
        "r",
    ) as config_map_file:
        return yaml.safe_load(config_map_file)


@pytest.fixture(scope="session")
def rhcos_workers(worker_node1, workers_utility_pods):
    return (
        ExecCommandOnPod(
            utility_pods=workers_utility_pods, node=worker_node1
        ).release_info["ID"]
        == "rhcos"
    )


@pytest.fixture(scope="session")
def skip_no_rhcos(rhcos_workers):
    if not rhcos_workers:
        pytest.skip("test should run only on rhcos workers")


@pytest.fixture(scope="package")
def nad_mac_address(must_gather_nad, must_gather_vm):
    return [
        interface["macAddress"]
        for interface in must_gather_vm.get_interfaces()
        if interface["name"] == must_gather_nad.name
    ][0]


@pytest.fixture(scope="package")
def vm_interface_name(nad_mac_address, must_gather_vm):
    bridge_command = f"bridge fdb show | grep {nad_mac_address}"
    output = (
        must_gather_vm.vmi.virt_launcher_pod.execute(
            command=shlex.split(f"bash -c {shlex.quote(bridge_command)}"),
            container="compute",
        )
        .splitlines()[0]
        .strip()
    )
    return output.split(" ")[-1]


@pytest.fixture()
def extracted_data_from_must_gather_file(
    request, collected_vm_details_must_gather, must_gather_vm
):
    virt_launcher = must_gather_vm.vmi.virt_launcher_pod
    namespace = virt_launcher.namespace
    vm_name = must_gather_vm.name
    file_suffix = request.param["file_suffix"]
    section_title = request.param["section_title"]
    base_path = os.path.join(
        collected_vm_details_must_gather,
        f"namespaces/{namespace}/vms/{vm_name}",
    )
    if file_suffix == "qemu.log":
        gathered_data_path = os.path.join(
            base_path,
            f"{namespace}_{vm_name}.log",
        )
    else:
        gathered_data_path = os.path.join(
            base_path,
            f"{virt_launcher.name}.{file_suffix}",
        )
    assert os.path.exists(
        gathered_data_path
    ), f"Have not found gathered data file on given path {gathered_data_path}"

    with open(gathered_data_path) as _file:
        gathered_data = _file.read()
        # If the gathered data file consists of multiple sections, extract the one
        # we are interested in.
        if section_title:
            # if section_title is present in the file getting checked out, we would then collect
            # only the sample section, for further checking:
            # bridge fdb show:
            # ###################################
            # 33:33:00:00:00:01 dev eth0 self permanent
            # 01:00:5e:00:00:01 dev eth0 self permanent
            matches = re.findall(
                f"^{section_title}\n" "^#+\n" "(.*?)" "(?:^#+\n|\\Z)",
                gathered_data,
                re.MULTILINE | re.DOTALL,
            )
            assert matches, (
                "Section has not been found in gathered data.\n"
                f"Section title: {section_title}\n"
                f"Gathered data: {gathered_data}"
            )
            gathered_data = matches[0]
        return gathered_data


@pytest.fixture()
def collected_nft_files_must_gather(
    workers_utility_pods, collected_cluster_must_gather
):
    expected_files_dict = {
        pod.node.name: f"{collected_cluster_must_gather}/nodes/{pod.node.name}/nftables"
        for pod in workers_utility_pods
    }
    files_not_found = [
        file for file in expected_files_dict.values() if not os.path.exists(file)
    ]
    assert not files_not_found, f"Missing nftable files: {files_not_found}"
    return expected_files_dict


@pytest.fixture()
def nftables_from_utility_pods(workers_utility_pods):
    nft_command = "nft list tables 2>/dev/null"
    return {
        pod.node.name: pod.execute(
            command=shlex.split(f"bash -c {shlex.quote(nft_command)}")
        ).splitlines()
        for pod in workers_utility_pods
    }


@pytest.fixture()
def collected_vm_details_must_gather_with_params(
    request,
    must_gather_image_url,
    must_gather_vm,
    must_gather_tmpdir_scope_function,
    must_gather_alternate_namespace,
    must_gather_vms_from_alternate_namespace,
):
    command = request.param["command"]
    if "vm_name" in command:
        command = command.format(
            alternate_namespace=must_gather_alternate_namespace.name,
            vm_name=must_gather_vms_from_alternate_namespace[0].name,
        )
    elif "vm_list" in command:
        command = command.format(
            alternate_namespace=must_gather_alternate_namespace.name,
            vm_list=f"{must_gather_vms_from_alternate_namespace[0].name},"
            f"{must_gather_vms_from_alternate_namespace[1].name},"
            f"{must_gather_vms_from_alternate_namespace[2].name}",
        )
    else:
        command = command.format(
            alternate_namespace=must_gather_alternate_namespace.name
        )

    yield collect_must_gather(
        must_gather_tmpdir=must_gather_tmpdir_scope_function,
        must_gather_image_url=must_gather_image_url,
        script_name=f"{command} gather_vms_details",
    )


@pytest.fixture(scope="class")
def must_gather_alternate_namespace(unprivileged_client):
    yield from create_ns(
        unprivileged_client=unprivileged_client,
        name="must-gather-alternate",
    )


@pytest.fixture(scope="class")
def must_gather_vms_alternate_namespace_base_path(
    collected_vm_details_must_gather, must_gather_alternate_namespace
):
    return f"{collected_vm_details_must_gather}/namespaces/{must_gather_alternate_namespace.name}/"


@pytest.fixture(scope="class")
def must_gather_vms_from_alternate_namespace(
    must_gather_alternate_namespace,
    unprivileged_client,
):
    vms_list = create_vms(
        name_prefix=MUST_GATHER_VM_NAME_PREFIX,
        namespace_name=must_gather_alternate_namespace.name,
        vm_count=5,
    )
    for vm in vms_list:
        running_vm(vm=vm)
    yield vms_list
    for vm in vms_list:
        vm.clean_up()


@pytest.fixture(scope="class")
def must_gather_stopped_vms(must_gather_vms_from_alternate_namespace):
    # 'must_gather_stopped_vms' stopping first 3 VM's from the 'must_gather_vms_from_alternate_namespace' fixture.
    stopped_vms_list = []
    for vm in must_gather_vms_from_alternate_namespace[:3]:
        vm.stop()
    for vm in must_gather_vms_from_alternate_namespace[:3]:
        if vm.instance.spec.running:
            vm.wait_for_ready_status(status=False)
        stopped_vms_list.append(vm)
    yield stopped_vms_list
    for vm in stopped_vms_list:
        vm.start()
    for vm in stopped_vms_list:
        running_vm(vm=vm)


@pytest.fixture(scope="class")
def must_gather_long_name_vm(node_gather_unprivileged_namespace, unprivileged_client):
    with cluster_resource(VirtualMachineForTests)(
        client=unprivileged_client,
        namespace=node_gather_unprivileged_namespace.name,
        name=LONG_VM_NAME,
        body=fedora_vm_body(name=LONG_VM_NAME),
        generate_unique_name=False,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture(scope="class")
def gathered_images(
    must_gather_tmpdir,
    must_gather_image_url,
):
    return collect_must_gather(
        must_gather_tmpdir=must_gather_tmpdir,
        must_gather_image_url=must_gather_image_url,
        script_name="gather_images",
    )
