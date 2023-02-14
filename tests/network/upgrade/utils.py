from kubernetes.dynamic.exceptions import ResourceNotFoundError
from ocp_resources.node_network_state import NodeNetworkState
from ocp_resources.pod import Pod
from ocp_resources.utils import TimeoutSampler

from utilities.constants import TIMEOUT_1MIN
from utilities.infra import get_pod_by_name_prefix


def assert_bridge_and_vms_on_same_node(vm_a, vm_b, bridge):
    for vm in [vm_a, vm_b]:
        assert vm.vmi.node.name == bridge.node_selector


def assert_node_is_marked_by_bridge(bridge_nad, vm):
    for bridge_annotation in bridge_nad.instance.metadata.annotations.values():
        assert bridge_annotation in vm.vmi.node.instance.status.capacity.keys()
        assert bridge_annotation in vm.vmi.node.instance.status.allocatable.keys()


def assert_nmstate_bridge_creation(bridge):
    nns = NodeNetworkState(name=bridge.node_selector)
    bridge_name = bridge.bridge_name
    assert nns.get_interface(
        name=bridge_name
    ), f"Nmstate bridge: {bridge_name} not found"


def assert_label_in_namespace(labeled_namespace, label_key, expected_label_value):
    namespace_labels = labeled_namespace.labels
    assert namespace_labels[label_key] == expected_label_value, (
        f"Namespace {labeled_namespace.name} should have label {label_key} "
        f"set to {expected_label_value}. Actual labels:\n{labeled_namespace.labels}."
    )


def wait_for_http_pod_to_be_in_running_state(
    admin_client, sm_deployment_service, deployment_namespace
):
    # TODO: Once Jira issue CNV-24274 is closed, and we have the health-check of the pod working accurately,
    #   this function can be removed.
    sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=1,
        func=check_if_http_pod_is_in_running_state,
        dyn_client=admin_client,
        pod_prefix=sm_deployment_service.app_name,
        namespace=deployment_namespace,
        exceptions_dict={ResourceNotFoundError: ["No http pod was found."]},
    )
    for sample in sampler:
        if sample:
            return


def check_if_http_pod_is_in_running_state(dyn_client, pod_prefix, namespace):
    pod = get_pod_by_name_prefix(
        dyn_client=dyn_client, pod_prefix=pod_prefix, namespace=namespace
    )
    return pod and pod.status == Pod.Status.RUNNING
