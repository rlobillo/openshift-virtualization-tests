import pytest
from ocp_resources.resource import Resource
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)

from tests.compute.virt.constants import MIGRATION_POLICY_VM_LABEL
from utilities.constants import TIMEOUT_2MIN, TIMEOUT_3MIN
from utilities.infra import cluster_resource, get_pods
from utilities.virt import VirtualMachineForTests, fedora_vm_body, running_vm


pytestmark = pytest.mark.usefixtures("skip_when_one_node")


def delete_failed_migration_target_pod(admin_client, namespace, vm_name):
    """
    Deletes the virt-launcher pod that stays in Pending state after
    vm migration is triggered, aim is to delete the target pod
    """
    pods = get_pods(dyn_client=admin_client, namespace=namespace)
    for pod in pods:
        if (pod.instance.status.phase == Resource.Status.PENDING) and (
            vm_name in pod.name
        ):
            pod.delete(wait=True)


def get_metric_value(prometheus, metric):
    metrics = prometheus.query(query=metric)
    metrics_result = metrics["data"].get("result", [])
    if metrics_result:
        return sum(
            int(metric_metrics_result["value"][1])
            for metric_metrics_result in metrics_result
        )
    return 0


def metric_value_sampler(prometheus, metric, expected_value):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_2MIN,
        sleep=10,
        func=get_metric_value,
        prometheus=prometheus,
        metric=metric,
    )
    current_check = 0
    for sample in samples:
        if sample == expected_value:
            current_check += 1
            if current_check >= 3:
                return True
        else:
            current_check = 0


def assert_metrics_values(
    prometheus, migration_metrics_dict, initial_values, metric_to_check
):
    """
    Check all migration metrics do not change from initial values,
    except for specified metric which must increase by 1.

    Args:
        initial_values: Dictionary representing initial values of metrics
        metric_to_check: metric expected to be increased by 1
        vm: vm object

    Raises:
        AssertionError: If any metric's value does not match with expected value.
    """
    failed_metrics = {}
    migration_metrics = []
    for metric in migration_metrics_dict.values():
        migration_metrics.append(
            metric
        ) if metric != metric_to_check else migration_metrics.insert(0, metric)
    for metric in migration_metrics:
        initial_value = initial_values[metric]
        expected_value = (
            initial_value + 1 if metric == metric_to_check else initial_value
        )
        try:
            metric_value_sampler(
                prometheus=prometheus,
                metric=metric,
                expected_value=expected_value,
            )
        except TimeoutExpiredError:
            failed_metrics[metric] = {
                "actual": get_metric_value(prometheus=prometheus, metric=metric),
                "expected": expected_value,
            }
    assert (
        not failed_metrics
    ), f"Metrices that failed to match expected value {failed_metrics}"


@pytest.fixture(scope="class")
def migration_metrics_dict():
    migration_metrics = {
        Resource.Status.PENDING: "kubevirt_migrate_vmi_pending_count",
        VirtualMachineInstance.Status.SCHEDULING: "kubevirt_migrate_vmi_scheduling_count",
        Resource.Status.RUNNING: "kubevirt_migrate_vmi_running_count",
        Resource.Status.SUCCEEDED: "kubevirt_migrate_vmi_succeeded",
        Resource.Status.FAILED: "kubevirt_migrate_vmi_failed",
    }
    return migration_metrics


@pytest.fixture(scope="class")
def initial_migration_metrics_values(prometheus, migration_metrics_dict):
    metrics_values = {}
    for metric in migration_metrics_dict.values():
        metrics_values[metric] = get_metric_value(prometheus=prometheus, metric=metric)
    yield metrics_values


@pytest.fixture(scope="class")
def vm_for_migration_metrics_test(namespace):
    name = "vm-for-migration-metrics-test"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        additional_labels=MIGRATION_POLICY_VM_LABEL,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def vm_migration_metrics_vmim(vm_for_migration_metrics_test):
    with cluster_resource(VirtualMachineInstanceMigration)(
        name="vm-migration-metrics-vmim",
        namespace=vm_for_migration_metrics_test.namespace,
        vmi=vm_for_migration_metrics_test.vmi,
    ) as vmim:
        vmim.wait_for_status(status=vmim.Status.RUNNING, timeout=TIMEOUT_3MIN)
        yield vmim


@pytest.fixture()
def vm_with_node_selector(namespace, worker_node1):
    name = "vm-with-node-selector"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        additional_labels=MIGRATION_POLICY_VM_LABEL,
        node_selector=worker_node1.name,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def vm_with_node_selector_vmim(vm_with_node_selector):
    with cluster_resource(VirtualMachineInstanceMigration)(
        name="vm-with-node-selector-vmim",
        namespace=vm_with_node_selector.namespace,
        vmi=vm_with_node_selector.vmi,
    ) as vmim:
        yield vmim


@pytest.fixture()
def migration_succeeded(vm_migration_metrics_vmim):
    vm_migration_metrics_vmim.wait_for_status(
        status=vm_migration_metrics_vmim.Status.SUCCEEDED, timeout=TIMEOUT_3MIN
    )


class TestMigrationMetrics:
    @pytest.mark.polarion("CNV-8479")
    def test_migration_metrics_succeeded(
        self,
        prometheus,
        migration_metrics_dict,
        vm_for_migration_metrics_test,
        initial_migration_metrics_values,
        vm_migration_metrics_vmim,
        migration_succeeded,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.SUCCEEDED],
        )

    @pytest.mark.polarion("CNV-8480")
    def test_migration_metrics_scheduling_and_failed(
        self,
        admin_client,
        namespace,
        prometheus,
        migration_metrics_dict,
        vm_with_node_selector,
        initial_migration_metrics_values,
        vm_with_node_selector_vmim,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[
                VirtualMachineInstance.Status.SCHEDULING
            ],
        )
        delete_failed_migration_target_pod(
            admin_client=admin_client,
            namespace=namespace,
            vm_name=vm_with_node_selector.name,
        )
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.FAILED],
        )

    @pytest.mark.polarion("CNV-8481")
    def test_migration_metrics_running(
        self,
        prometheus,
        migration_metrics_dict,
        migration_policy_with_bandwidth,
        vm_for_migration_metrics_test,
        initial_migration_metrics_values,
        vm_migration_metrics_vmim,
    ):
        assert_metrics_values(
            prometheus=prometheus,
            migration_metrics_dict=migration_metrics_dict,
            initial_values=initial_migration_metrics_values,
            metric_to_check=migration_metrics_dict[Resource.Status.RUNNING],
        )
