"""
Test node feature discovery.
"""
from xml.etree import ElementTree

import pytest
from ocp_utilities.infra import cluster_resource

from tests.compute.utils import update_hco_annotations
from tests.compute.virt.node_labeller.constants import CPU_MODEL_LABEL_PREFIX
from utilities.virt import (
    VirtualMachineForTests,
    fedora_vm_body,
    running_vm,
    wait_for_kv_stabilize,
    wait_for_updated_kv_value,
)


MIN_CPU = "minCPUModel"
OBSOLETE_CPU = "obsoleteCPUModels"


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]


@pytest.fixture()
def nodes_labels_dict(nodes):
    """
    Collects all labels from nodes and creates dict of cpu-models/features/kvm-info per node.
    Return dict:
    {'<node_name>': {'cpu_models': [<cpu_models>], 'cpu_features': [<cpu_features>], 'kvm-info': [<kvm-info>]}}
    """
    node_labels_dict = {}

    for node in nodes:
        node_labels_dict[node.name] = {}
        labels_dict = dict(node.instance.metadata.labels)
        node_labels_dict[node.name]["cpu_models"] = [
            label.split("/")[1]
            for label in labels_dict
            if label.startswith(CPU_MODEL_LABEL_PREFIX)
        ]
        node_labels_dict[node.name]["cpu_features"] = [
            label.split("/")[1]
            for label in labels_dict
            if label.startswith("cpu-feature.node.kubevirt.io/")
        ]
        node_labels_dict[node.name]["kvm-info"] = [
            label.split("/")[1]
            for label in labels_dict
            if label.startswith("hyperv.node.kubevirt.io/")
        ]

    return node_labels_dict


@pytest.fixture()
def libvirt_min_cpu_features_list(
    request, nodes_common_cpu_model, cpu_test_vm, admin_client
):
    """
    Extract minimal CPU model features from libvirt/cpu_map xml.
    Use x86_Penryn if request.param["default_min_cpu"] else nodes_common_cpu_model
    """
    min_cpu_model = (
        "Penryn" if request.param["default_min_cpu"] else nodes_common_cpu_model
    )
    stdout = cpu_test_vm.vmi.virt_launcher_pod.execute(
        command=[
            "cat",
            f"/usr/share/libvirt/cpu_map/x86_{min_cpu_model}.xml",
        ]
    )
    tree = ElementTree.fromstring(stdout)

    return [
        feature.get("name") for feature in tree.findall("model")[0].findall("feature")
    ]


@pytest.fixture()
def updated_kubevirt_cpus(
    request,
    hyperconverged_resource_scope_function,
    nodes_common_cpu_model,
    admin_client,
    hco_namespace,
):
    is_min_cpu = request.param["cpu_config"] == MIN_CPU  # MIN_CPU or OBSOLETE_CPU

    hco_path = MIN_CPU if is_min_cpu else OBSOLETE_CPU
    hco_value = nodes_common_cpu_model if is_min_cpu else {nodes_common_cpu_model: True}
    kv_path = [MIN_CPU] if is_min_cpu else [OBSOLETE_CPU, nodes_common_cpu_model]
    kv_value = nodes_common_cpu_model if is_min_cpu else True

    with update_hco_annotations(
        resource=hyperconverged_resource_scope_function, path=hco_path, value=hco_value
    ):
        wait_for_updated_kv_value(
            admin_client=admin_client,
            hco_namespace=hco_namespace,
            path=kv_path,
            value=kv_value,
        )
        wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)
        yield
    wait_for_kv_stabilize(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def cpu_test_vm(namespace):
    name = "cpu-test"
    with cluster_resource(VirtualMachineForTests)(
        name=name, namespace=namespace.name, body=fedora_vm_body(name=name)
    ) as vm:
        running_vm(vm=vm, check_ssh_connectivity=False)
        yield vm


def node_label_checker(node_label_dict, label_list, dict_key):
    """
    Check node labels for cpu models/features/kvm-info.
    Return dict:
    {'<node_name>': [<cpu_models/features/kvm-info>]}
    """
    return {
        node: [
            value for value in label_list if value in node_label_dict[node][dict_key]
        ]
        for node in node_label_dict
    }


@pytest.mark.polarion("CNV-2797")
def test_obsolete_cpus_in_node_labels(nodes_labels_dict, kubevirt_config):
    """
    Test obsolete CPUs. Obsolete CPUs don't appear in node labels.
    """
    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=kubevirt_config[OBSOLETE_CPU].keys(),
        dict_key="cpu_models",
    )
    assert not any(test_dict.values()), f"Obsolete CPU found in labels\n{test_dict}"


@pytest.mark.parametrize(
    "libvirt_min_cpu_features_list",
    [
        pytest.param(
            {"default_min_cpu": True},
            marks=pytest.mark.polarion("CNV-2798"),
        )
    ],
    indirect=True,
)
def test_min_cpus_in_node_labels(nodes_labels_dict, libvirt_min_cpu_features_list):
    """
    Test min CPU. Min CPU features don't appear in node labels.
    """
    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=libvirt_min_cpu_features_list,
        dict_key="cpu_features",
    )
    assert not any(test_dict.values()), f"Min CPU feature found in labels\n{test_dict}"


@pytest.mark.polarion("CNV-3607")
def test_hardware_required_node_labels(nodes_labels_dict):
    kvm_info_nfd_labels = [
        "vpindex",
        "runtime",
        "time",
        "synic",
        "synic2",
        "tlbflush",
        "reset",
        "frequencies",
        "reenlightenment",
        "base",
        "ipi",
        "synictimer",
    ]
    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=kvm_info_nfd_labels,
        dict_key="kvm-info",
    )
    assert any(test_dict.values()), f"KVM info not found in labels\n{test_dict}"


@pytest.mark.polarion("CNV-6088")
def test_hardware_non_required_node_labels(nodes_labels_dict):
    hw_supported_hyperv_features = [
        "vapic",
        "relaxes",
        "spinlocks",
        "vendorid",
        "evmcs",
    ]

    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=hw_supported_hyperv_features,
        dict_key="kvm-info",
    )
    assert not any(
        test_dict.values()
    ), f"Some nodes have non required KVM labels: {test_dict}"


@pytest.mark.parametrize(
    "updated_kubevirt_cpus",
    [
        pytest.param(
            {"cpu_config": OBSOLETE_CPU},
            marks=pytest.mark.polarion("CNV-6103"),
        )
    ],
    indirect=True,
)
def test_updated_obsolete_cpus_in_node_labels(
    updated_kubevirt_cpus, nodes_labels_dict, kubevirt_config
):
    """
    Test user-added obsolete CPU does not appear in node labels.
    """
    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=kubevirt_config[OBSOLETE_CPU].keys(),
        dict_key="cpu_models",
    )
    assert not any(test_dict.values()), f"Obsolete CPU found in labels\n{test_dict}"


@pytest.mark.parametrize(
    "updated_kubevirt_cpus, libvirt_min_cpu_features_list",
    [
        pytest.param(
            {"cpu_config": MIN_CPU},
            {"default_min_cpu": False},
            marks=pytest.mark.polarion("CNV-6104"),
        )
    ],
    indirect=True,
)
def test_updated_min_cpu_in_node_labels(
    updated_kubevirt_cpus, nodes_labels_dict, libvirt_min_cpu_features_list
):
    """
    Test user-updated minCPUModel does not appear in node labels.
    """
    test_dict = node_label_checker(
        node_label_dict=nodes_labels_dict,
        label_list=libvirt_min_cpu_features_list,
        dict_key="cpu_features",
    )
    assert not any(test_dict.values()), f"Min CPU feature found in labels\n{test_dict}"
