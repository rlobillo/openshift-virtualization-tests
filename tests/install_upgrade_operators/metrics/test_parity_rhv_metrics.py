import pytest

from tests.install_upgrade_operators.metrics.utils import (
    assert_vm_metric_virt_handler_pod,
    get_vm_metrics,
)


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]


@pytest.mark.parametrize(
    "query",
    [
        pytest.param(
            "kubevirt_vmi_network_receive_packets_dropped_total",
            marks=pytest.mark.polarion("CNV-6657"),
            id="kubevirt_vmi_network_receive_packets_dropped_total",
        ),
        pytest.param(
            "kubevirt_vmi_network_transmit_packets_dropped_total",
            marks=pytest.mark.polarion("CNV-6658"),
            id="kubevirt_vmi_network_transmit_packets_dropped_total",
        ),
        pytest.param(
            "kubevirt_vmi_memory_domain_bytes_total",
            marks=pytest.mark.polarion("CNV-8194"),
            id="kubevirt_vmi_memory_domain_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_memory_unused_bytes",
            marks=pytest.mark.polarion("CNV-6660"),
            id="kubevirt_vmi_memory_unused_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_usable_bytes",
            marks=pytest.mark.polarion("CNV-6661"),
            id="kubevirt_vmi_memory_usable_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_actual_balloon_bytes",
            marks=pytest.mark.polarion("CNV-6662"),
            id="kubevirt_vmi_memory_actual_balloon_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_pgmajfault",
            marks=pytest.mark.polarion("CNV-6663"),
            id="kubevirt_vmi_memory_pgmajfault",
        ),
        pytest.param(
            "kubevirt_vmi_memory_pgminfault",
            marks=pytest.mark.polarion("CNV-6664"),
            id="kubevirt_vmi_memory_pgminfault",
        ),
        pytest.param(
            "kubevirt_vmi_storage_flush_requests_total",
            marks=pytest.mark.polarion("CNV-6665"),
            id="kubevirt_vmi_storage_flush_requests_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_flush_times_ms_total",
            marks=pytest.mark.polarion("CNV-6666"),
            id="kubevirt_vmi_storage_flush_times_ms_total",
        ),
    ],
)
def test_parity_with_rhv_metric(prometheus, first_metric_vm, query):
    """
    Tests validating ability to perform various prometheus api queries on various metrics against a given vm.
    This test also validates ability to pull metric information from a given vm's virt-handler pod and validates
    appropriate information exists for that metrics.
    """
    get_vm_metrics(prometheus=prometheus, query=query, vm_name=first_metric_vm.name)
    assert_vm_metric_virt_handler_pod(query=query, vm=first_metric_vm)
