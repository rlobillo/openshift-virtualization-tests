import pytest

from tests.install_upgrade_operators.metrics.utils import (
    assert_vm_metric_virt_handler_pod,
    assert_vmi_dommemstat_with_metric_value,
    get_vm_metrics,
)


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]


@pytest.mark.parametrize(
    "query",
    [
        pytest.param(
            "kubevirt_vmi_network_receive_packets_dropped_total",
            marks=pytest.mark.polarion("CNV-6657"),
            id="parity_with_rhv_metrics_kubevirt_vmi_network_receive_packets_dropped_total",
        ),
        pytest.param(
            "kubevirt_vmi_network_transmit_packets_dropped_total",
            marks=pytest.mark.polarion("CNV-6658"),
            id="parity_with_rhv_metrics_kubevirt_vmi_network_transmit_packets_dropped_total",
        ),
        pytest.param(
            "kubevirt_vmi_memory_domain_bytes_total",
            marks=pytest.mark.polarion("CNV-8194"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_domain_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_memory_unused_bytes",
            marks=pytest.mark.polarion("CNV-6660"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_unused_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_usable_bytes",
            marks=pytest.mark.polarion("CNV-6661"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_usable_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_actual_balloon_bytes",
            marks=pytest.mark.polarion("CNV-6662"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_actual_balloon_bytes",
        ),
        pytest.param(
            "kubevirt_vmi_memory_pgmajfault",
            marks=pytest.mark.polarion("CNV-6663"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_pgmajfault",
        ),
        pytest.param(
            "kubevirt_vmi_memory_pgminfault",
            marks=pytest.mark.polarion("CNV-6664"),
            id="parity_with_rhv_metrics_kubevirt_vmi_memory_pgminfault",
        ),
        pytest.param(
            "kubevirt_vmi_storage_flush_requests_total",
            marks=pytest.mark.polarion("CNV-6665"),
            id="parity_with_rhv_metrics_kubevirt_vmi_storage_flush_requests_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_flush_times_ms_total",
            marks=pytest.mark.polarion("CNV-6666"),
            id="parity_with_rhv_metrics_kubevirt_vmi_storage_flush_times_ms_total",
        ),
        pytest.param(
            "kubevirt_vmi_network_receive_bytes_total",
            marks=pytest.mark.polarion("CNV-6174"),
            id="passive_key_metrics_kubevirt_vmi_network_receive_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_network_transmit_bytes_total",
            marks=pytest.mark.polarion("CNV-6175"),
            id="passive_key_metrics_kubevirt_vmi_network_transmit_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_iops_write_total",
            marks=pytest.mark.polarion("CNV-6176"),
            id="passive_key_metrics_kubevirt_vmi_storage_iops_write_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_iops_read_total",
            marks=pytest.mark.polarion("CNV-6177"),
            id="passive_key_metrics_kubevirt_vmi_storage_iops_read_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_write_traffic_bytes_total",
            marks=pytest.mark.polarion("CNV-6178"),
            id="passive_key_metrics_kubevirt_vmi_storage_write_traffic_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_storage_read_traffic_bytes_total",
            marks=pytest.mark.polarion("CNV-6179"),
            id="passive_key_metrics_kubevirt_vmi_storage_read_traffic_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_vcpu_wait_seconds",
            marks=pytest.mark.polarion("CNV-6180"),
            id="passive_key_metrics_kubevirt_vmi_vcpu_wait_seconds",
        ),
        pytest.param(
            "kubevirt_vmi_memory_swap_in_traffic_bytes_total",
            marks=pytest.mark.polarion("CNV-6181"),
            id="passive_key_metrics_kubevirt_vmi_memory_swap_in_traffic_bytes_total",
        ),
        pytest.param(
            "kubevirt_vmi_memory_swap_out_traffic_bytes_total",
            marks=pytest.mark.polarion("CNV-6182"),
            id="passive_key_metrics_kubevirt_vmi_memory_swap_out_traffic_bytes_total",
        ),
    ],
)
def test_metrics(prometheus, single_metric_vm, query):
    """
    Tests validating ability to perform various prometheus api queries on various metrics against a given vm.
    This test also validates ability to pull metric information from a given vm's virt-handler pod and validates
    appropriate information exists for that metrics.
    """
    get_vm_metrics(prometheus=prometheus, query=query, vm_name=single_metric_vm.name)
    assert_vm_metric_virt_handler_pod(query=query, vm=single_metric_vm)


class TestVMIMetrics:
    @pytest.mark.polarion("CNV-8262")
    def test_vmi_domain_total_memory_bytes(
        self,
        single_metric_vm,
        vmi_domain_total_memory_in_bytes_from_vm,
        vmi_domain_total_memory_bytes_metric_value_from_prometheus,
    ):
        """This test will check the domain total memory of VMI with given metrics output in bytes."""
        assert (
            vmi_domain_total_memory_in_bytes_from_vm
            == vmi_domain_total_memory_bytes_metric_value_from_prometheus
        ), (
            f"VM {single_metric_vm.name}'s domain memory total {vmi_domain_total_memory_in_bytes_from_vm} "
            f"is not matching with metrics value {vmi_domain_total_memory_bytes_metric_value_from_prometheus} bytes."
        )

    @pytest.mark.polarion("CNV-8931")
    def test_vmi_used_memory_bytes(
        self,
        prometheus,
        single_metric_vm,
        updated_dommemstat,
    ):
        """This test will check the used memory of VMI with given metrics output in bytes."""
        assert_vmi_dommemstat_with_metric_value(
            prometheus=prometheus, vm=single_metric_vm
        )
