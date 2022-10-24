import pytest
from ocp_resources.utils import TimeoutSampler
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_utilities.infra import cluster_resource

from utilities.virt import LOGGER, VirtualMachineForTests, fedora_vm_body, running_vm


@pytest.fixture(scope="class")
def vm_metric_1(namespace, unprivileged_client):
    vm_name = "vm-metrics-1"
    with cluster_resource(VirtualMachineForTests)(
        name=vm_name,
        namespace=namespace.name,
        body=fedora_vm_body(name=vm_name),
        client=unprivileged_client,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture(scope="class")
def vm_metric_2(namespace, unprivileged_client):
    vm_name = "vm-metrics-2"
    with cluster_resource(VirtualMachineForTests)(
        name=vm_name,
        namespace=namespace.name,
        body=fedora_vm_body(name=vm_name),
        client=unprivileged_client,
    ) as vm:
        running_vm(vm=vm, wait_for_interfaces=False, check_ssh_connectivity=False)
        yield vm


@pytest.fixture(scope="class")
def number_of_running_vmis(admin_client):
    return len(list(VirtualMachineInstance.get(dyn_client=admin_client)))


def check_vmi_metric(prometheus):
    response = prometheus.query(query="cnv:vmi_status_running:count")
    assert response["status"] == "success"
    return sum(int(node["value"][1]) for node in response["data"]["result"])


def check_vmi_count_metric(expected_vmi_count, prometheus):
    LOGGER.info(f"Check VMI metric expected: {expected_vmi_count}")
    samples = TimeoutSampler(
        wait_timeout=100,
        sleep=5,
        func=check_vmi_metric,
        prometheus=prometheus,
    )
    for sample in samples:
        if sample == expected_vmi_count:
            return True


class TestVMICountMetric:
    @pytest.mark.polarion("CNV-3048")
    def test_vmi_count_metric_increase(
        self,
        skip_not_openshift,
        prometheus,
        number_of_running_vmis,
        vm_metric_1,
        vm_metric_2,
    ):
        assert check_vmi_count_metric(number_of_running_vmis + 2, prometheus)

    @pytest.mark.polarion("CNV-3589")
    def test_vmi_count_metric_decrease(
        self,
        skip_not_openshift,
        prometheus,
        number_of_running_vmis,
        vm_metric_1,
        vm_metric_2,
    ):
        vm_metric_2.stop(wait=True)
        assert check_vmi_count_metric(number_of_running_vmis + 1, prometheus)
