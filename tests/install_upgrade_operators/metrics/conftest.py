import logging

import pytest
from ocp_resources.pod import Pod
from ocp_resources.resource import ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from tests.install_upgrade_operators.metrics.utils import (
    SINGLE_VM,
    enable_swap_fedora_vm,
    get_mutation_component_value_from_prometheus,
    get_not_running_prometheus_pods,
    get_resource_object,
    get_vmi_dommemstat_from_vm,
    get_vmi_memory_domain_metric_value_from_prometheus,
    get_vmi_phase_count,
    pause_unpause_dommemstat,
    run_node_command,
    run_vm_commands,
)
from tests.install_upgrade_operators.utils import create_vms, wait_for_cr_labels_change
from utilities.constants import TIMEOUT_2MIN, TIMEOUT_10MIN
from utilities.hco import wait_for_hco_conditions
from utilities.infra import cluster_resource, create_ns, unique_name
from utilities.virt import Prometheus, running_vm, vm_instance_from_template


LOGGER = logging.getLogger(__name__)


def wait_for_component_value_to_be_expected(prometheus, component_name, expected_count):
    """This function will wait till the expected value is greater than or equal to
    the value from Prometheus for the specific component_name.

    Args:
        prometheus (:obj:`Prometheus`): Prometheus object.
        component_name (String): Name of the component.
        expected_count (int): Expected value of the component after update.

    Returns:
        int: It will return the value of the component once it matches to the expected_count.
    """
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=50,
        func=get_mutation_component_value_from_prometheus,
        prometheus=prometheus,
        component_name=component_name,
    )
    sample = None
    try:
        for sample in samples:
            if sample >= expected_count:
                return sample
    except TimeoutExpiredError:
        LOGGER.error(
            f"{component_name} value did not update. Current value {sample} and expected value {expected_count}"
        )
        raise


@pytest.fixture()
def updated_resource_with_invalid_label(
    request, admin_client, hco_namespace, hco_status_related_objects
):

    resource_name = request.param["name"]
    resource = get_resource_object(
        related_objects=hco_status_related_objects,
        admin_client=admin_client,
        resource_kind=request.param["resource"],
        resource_name=request.param["name"],
    )
    labels = resource.instance.metadata.labels
    LOGGER.info(f"Updating metadata.label for {resource_name} ")
    with ResourceEditor(
        patches={
            resource: {
                "metadata": {
                    "labels": {"test_label": "testing_invalid_label"},
                    "namespace": hco_namespace.name,
                },
            }
        }
    ):
        wait_for_cr_labels_change(component=resource, expected_value=labels)
        yield


@pytest.fixture()
def updated_resource_multiple_times_with_invalid_label(
    request, prometheus, admin_client, hco_namespace, hco_status_related_objects
):
    """
    This fixture will repeatedly modify the given resource with invalid metadata labels.

    Args:
        admin_client (DynamicClient): OCP client with Admin permissions
        hco_namespace (Namespace): HCO namespace

    Returns:
        int: Returns latest metrics value of a given component once it matches to the expected_count
    """
    count = request.param["count"]
    comp_name = request.param["comp_name"]
    resource_name = request.param["name"]
    resource_version = None
    resource = get_resource_object(
        related_objects=hco_status_related_objects,
        admin_client=admin_client,
        resource_kind=request.param["resource"],
        resource_name=resource_name,
    )
    assert resource.exists, f"Resource: {comp_name} does not exist"
    labels = resource.instance.metadata.labels
    # Create the ResourceEditor once and then re-use it to make sure we are modifying
    # the resource exactly X times. Since the resource would be reconciled by HCO, there is no need to restore.
    increasing_value = get_mutation_component_value_from_prometheus(
        prometheus=prometheus, component_name=comp_name
    )
    LOGGER.warning(
        f"For {resource.name} starting value:{increasing_value}, resource version: {resource_version}"
    )
    updated_value = 0
    for index in range(count):
        increasing_value += 1
        resource_editor = ResourceEditor(
            patches={
                resource: {
                    "metadata": {
                        "labels": {"test_label": f"testing_invalid_label_{index}"},
                    },
                }
            }
        )
        resource_editor.update()
        wait_for_cr_labels_change(component=resource, expected_value=labels)
        updated_value = wait_for_component_value_to_be_expected(
            prometheus=prometheus,
            component_name=comp_name,
            expected_count=increasing_value,
        )
    yield updated_value
    wait_for_hco_conditions(admin_client=admin_client, hco_namespace=hco_namespace)


@pytest.fixture()
def mutation_count_before_change(request, prometheus):
    component_name = request.param
    LOGGER.info(f"Getting component '{component_name}' mutation count before change.")
    return get_mutation_component_value_from_prometheus(
        prometheus=prometheus,
        component_name=component_name,
    )


@pytest.fixture(scope="class")
def unique_namespace(unprivileged_client):
    """
    Creates a namespace to be used by key metrics test cases.

    Yields:
        Namespace object to be used by the tests
    """
    namespace_name = unique_name(name="key-metrics")
    yield from create_ns(unprivileged_client=unprivileged_client, name=namespace_name)


@pytest.fixture(scope="class")
def vm_list(unique_namespace):
    """
    Creates n vms, waits for them all to go to running state and cleans them up at the end

    Args:
        unique_namespace (Namespace): Creates namespaces to be used by the test

    Yields:
        list: list of VirtualMachineForTests created
    """
    vms_list = create_vms(
        name_prefix="key-metric-vm", namespace_name=unique_namespace.name
    )
    for vm in vms_list:
        running_vm(vm=vm)
        enable_swap_fedora_vm(vm=vm)
    yield vms_list
    for vm in vms_list:
        vm.clean_up()


@pytest.fixture()
def first_metric_vm(vm_list):
    """
    Returns the first vm from the list of created vms

    Args:
        vm_list (list): list of VirtualMachineForTests created

    Returns:
        VirtualMachineForTests: a VirtualMachineForTests object
    """
    return vm_list[0]


@pytest.fixture()
def node_setup(request, vm_list, workers_utility_pods):
    """
    This fixture runs commands on nodes hosting vms and reverses the changes at the end.

    Args:
        vm_list (list): Gets the list of vms created as a part of suite level set up.
        workers_utility_pods (list): Utility pods from worker nodes.

    """
    node_command = request.param.get("node_command")

    if node_command:
        vms = vm_list[: request.param.get("num_vms", SINGLE_VM)]
        run_node_command(
            vms=vms,
            utility_pods=workers_utility_pods,
            command=node_command["setup"],
        )

        yield
        run_node_command(
            vms=vms,
            utility_pods=workers_utility_pods,
            command=node_command["cleanup"],
        )
    else:
        yield


@pytest.fixture()
def vm_metrics_setup(request, vm_list):
    """
    This fixture runs commands against the vms to generate metrics

    Args:
        vm_list (list): Gets the list of vms created as a part of suite level set up

    Yields:
        list: list of vm objects against which commands to generate metric has been issued
    """
    vm_commands = request.param.get("vm_commands")
    vms = vm_list[: request.param.get("num_vms", SINGLE_VM)]
    if vm_commands:
        run_vm_commands(vms=vms, commands=vm_commands)

    yield vms


@pytest.fixture(scope="class")
def vm_from_template(
    request,
    unprivileged_client,
    namespace,
    golden_image_data_source_scope_class,
):
    """
    The fixture is using the context manager to create a VM instance from template, as described in
    the context manager's docstring.
    After the VM instance is created (& possibly started) according to the provided params (passed to the request arg),
    it yields the VM object.

    Yields:
        VM object after it was created
    """
    with vm_instance_from_template(
        request=request,
        unprivileged_client=unprivileged_client,
        namespace=namespace,
        data_source=golden_image_data_source_scope_class,
    ) as vm:
        yield vm


@pytest.fixture(scope="class")
def vmi_phase_count_before(request, prometheus):
    """
    This fixture queries Prometheus with the query in the get_vmi_phase_count before a VM is created
    and keeps the value for verification
    """
    return get_vmi_phase_count(
        prometheus=prometheus,
        os_name=request.param["labels"]["os"],
        flavor=request.param["labels"]["flavor"],
        workload=request.param["labels"]["workload"],
        query=request.param["query"],
    )


@pytest.fixture(scope="module")
def prometheus_module():
    return Prometheus()


@pytest.fixture(scope="module", autouse=True)
def metrics_sanity(admin_client, prometheus_module):
    """
    Perform verification in order to ensure that the cluster is ready for metrics-related tests
    """
    LOGGER.info("Verify that Prometheus pods exist and running as expected")
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=1,
        func=get_not_running_prometheus_pods,
        admin_client=admin_client,
    )
    sample = None
    try:
        for sample in samples:
            if not sample:
                break
    except TimeoutExpiredError:
        LOGGER.error(
            f"timeout awaiting all Prometheus pods to be in Running status: violating_pods={sample}"
        )
        raise


@pytest.fixture(scope="class")
def stopped_vm(vm_from_template):
    vm_from_template.stop(wait=True)
    return vm_from_template


@pytest.fixture()
def virt_pod_info_from_prometheus(request, prometheus):
    """Get Virt Pod information from the recording rules (query) in the form of query_response dictionary.
    Extract Virt Pod name and it's values from the query_response dictionary and
    store it in the pod_details dictionary.

    Returns:
        set: It contains Pod names from the prometheus query result.
    """
    query_response = prometheus.query_sampler(
        query=request.param,
    )
    return {result["metric"]["pod"] for result in query_response}


@pytest.fixture()
def virt_pod_names_by_label(request, admin_client, hco_namespace):
    """Get pod names by a given label (request.param) in the list."""
    return [
        pod.name
        for pod in cluster_resource(Pod).get(
            dyn_client=admin_client,
            namespace=hco_namespace.name,
            label_selector=request.param,
        )
    ]


@pytest.fixture(scope="class")
def single_metric_vm(namespace):
    """Returns the first vm from the list of created vms"""
    vm = create_vms(
        name_prefix="test-metric-vm",
        namespace_name=namespace.name,
        vm_count=SINGLE_VM,
    )[0]
    running_vm(vm=vm)
    yield vm
    vm.clean_up()


@pytest.fixture()
def virt_up_metrics_values(request, prometheus):
    """Get value(int) from the 'up' recording rules(metrics)."""
    query_response = prometheus.query_sampler(
        query=request.param,
    )
    return int(query_response[0]["value"][1])


@pytest.fixture()
def vmi_domain_total_memory_bytes_metric_value_from_prometheus(
    prometheus, single_metric_vm
):
    return get_vmi_memory_domain_metric_value_from_prometheus(
        prometheus=prometheus,
        vmi_name=single_metric_vm.vmi.name,
        query="kubevirt_vmi_memory_domain_total_bytes",
    )


@pytest.fixture()
def updated_dommemstat(single_metric_vm):
    run_vm_commands(
        vms=[single_metric_vm],
        commands=[
            "stress-ng --vm 1 --vm-bytes 512M --vm-populate --timeout 600s &>1 &"
        ],
    )
    # give the stress-ng command some time to build up load on the vm
    pause_unpause_dommemstat(vm=single_metric_vm)
    yield
    pause_unpause_dommemstat(vm=single_metric_vm, period=1)


@pytest.fixture()
def vmi_domain_total_memory_in_bytes_from_vm(single_metric_vm):
    return get_vmi_dommemstat_from_vm(
        vmi_dommemstat=single_metric_vm.vmi.get_dommemstat(),
        domain_memory_string="actual",
    )
