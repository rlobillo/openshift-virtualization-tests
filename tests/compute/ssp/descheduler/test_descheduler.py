import logging

import pytest
from ocp_resources.resource import ResourceEditor

from tests.compute.ssp.descheduler.utils import (
    assert_running_process_after_failover,
    assert_vms_consistent_virt_launcher_pods,
    assert_vms_distribution_after_failover,
    verify_at_least_one_vm_migrated,
)


LOGGER = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.tier3,
    pytest.mark.usefixtures(
        "skip_if_1tb_memory_or_more_node",
        "skip_when_one_node",
        "installed_descheduler",
    ),
]

NO_MIGRATION_STORM_ASSERT_MESSAGE = (
    "Verify no migration storm after triggered migrations by the descheduler."
)


@pytest.mark.parametrize(
    "calculated_vm_deployment_without_descheduler_node",
    [pytest.param(0.75)],
    indirect=True,
)
@pytest.mark.usefixtures(
    "calculated_vm_deployment_without_descheduler_node",
)
class TestDeschedulerEvictsVMAfterDrainUncordon:
    TESTS_CLASS_NAME = "TestDeschedulerEvictsVMAfterDrainUncordon"

    @pytest.mark.polarion("CNV-7415")
    def test_descheduler_node_labels(
        self,
        updated_profile_strategy_static_low_node_utilization_for_node_drain,
        node_with_most_available_memory,
        node_labeled_for_test,
        deployed_vms_on_labeled_node,
    ):
        with ResourceEditor(
            patches={
                node_with_most_available_memory: {
                    "metadata": {"labels": {"testnode": "true"}}
                }
            }
        ):
            verify_at_least_one_vm_migrated(
                vms=deployed_vms_on_labeled_node, node_before=node_labeled_for_test
            )

    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::test_descheduler_evicts_vm_after_drain_uncordon"
    )
    @pytest.mark.polarion("CNV-5922")
    def test_descheduler_evicts_vm_after_drain_uncordon(
        self,
        updated_profile_strategy_static_low_node_utilization_for_node_drain,
        deployed_vms_calculated_without_descheduler_node,
        vms_started_process_for_node_drain,
        drain_uncordon_node,
        schedulable_nodes,
    ):
        assert_vms_distribution_after_failover(
            vms=deployed_vms_calculated_without_descheduler_node,
            nodes=schedulable_nodes,
        )

    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::test_no_migrations_storm",
        depends=[
            f"{TESTS_CLASS_NAME}::test_descheduler_evicts_vm_after_drain_uncordon"
        ],
    )
    @pytest.mark.polarion("CNV-7316")
    def test_no_migrations_storm(
        self,
        downscaled_descheduler_cluster_deployment,
        deployed_vms_calculated_without_descheduler_node,
        completed_migrations,
    ):
        LOGGER.info(NO_MIGRATION_STORM_ASSERT_MESSAGE)
        assert_vms_consistent_virt_launcher_pods(
            running_vms=deployed_vms_calculated_without_descheduler_node
        )

    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::test_no_migrations_storm"])
    @pytest.mark.polarion("CNV-8288")
    def test_running_process_after_migrations_complete(
        self,
        deployed_vms_calculated_without_descheduler_node,
        vms_started_process_for_node_drain,
    ):
        assert_running_process_after_failover(
            vms_list=deployed_vms_calculated_without_descheduler_node,
            process_dict=vms_started_process_for_node_drain,
        )


@pytest.mark.parametrize(
    "calculated_vm_deployment_without_descheduler_node",
    [pytest.param(0.40)],
    indirect=True,
)
class TestDeschedulerEvictsVMFromUtilizationImbalance:
    TESTS_CLASS_NAME = "TestDeschedulerEvictsVMFromUtilizationImbalance"

    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::test_descheduler_evicts_vm_from_utilization_imbalance"
    )
    @pytest.mark.polarion("CNV-8217")
    def test_descheduler_evicts_vm_from_utilization_imbalance(
        self,
        schedulable_nodes,
        updated_profile_strategy_static_low_node_utilization_for_utilization_imbalance,
        deployed_evictable_vms_for_utilization_imbalance,
        vms_started_process_for_utilization_imbalance,
        completed_migrations,
        orig_vms_from_target_node_for_utilization_increase,
        target_node_for_utilization_increase,
        utilization_imbalance,
    ):
        possible_destination_nodes = list(
            set(schedulable_nodes) - {target_node_for_utilization_increase}
        )
        assert_vms_distribution_after_failover(
            vms=orig_vms_from_target_node_for_utilization_increase,
            nodes=possible_destination_nodes,
            all_nodes=False,
        )

    @pytest.mark.dependency(
        name=f"{TESTS_CLASS_NAME}::test_no_migrations_storm",
        depends=[
            f"{TESTS_CLASS_NAME}::test_descheduler_evicts_vm_from_utilization_imbalance"
        ],
    )
    @pytest.mark.polarion("CNV-8918")
    def test_no_migrations_storm(
        self,
        downscaled_descheduler_cluster_deployment,
        deployed_evictable_vms_for_utilization_imbalance,
        completed_migrations,
    ):
        LOGGER.info(NO_MIGRATION_STORM_ASSERT_MESSAGE)
        assert_vms_consistent_virt_launcher_pods(
            running_vms=deployed_evictable_vms_for_utilization_imbalance
        )

    @pytest.mark.dependency(depends=[f"{TESTS_CLASS_NAME}::test_no_migrations_storm"])
    @pytest.mark.polarion("CNV-8919")
    def test_running_process_after_migrations_complete(
        self,
        deployed_evictable_vms_for_utilization_imbalance,
        vms_started_process_for_utilization_imbalance,
    ):
        assert_running_process_after_failover(
            vms_list=deployed_evictable_vms_for_utilization_imbalance,
            process_dict=vms_started_process_for_utilization_imbalance,
        )


@pytest.mark.parametrize(
    "calculated_vm_deployment_without_descheduler_node",
    [pytest.param(0.40)],
    indirect=True,
)
class TestDeschedulerDoesNotEvictVMWithNoAnnotationFromUtilizationImbalance:
    @pytest.mark.polarion("CNV-8920")
    def test_descheduler_does_not_evict_vm_with_no_annotation_from_utilization_imbalance(
        self,
        updated_profile_strategy_static_low_node_utilization_for_utilization_imbalance,
        deployed_no_annotation_vms_for_utilization_imbalance,
        no_annotation_vms_started_process_for_utilization_imbalance,
        completed_migrations,
        orig_vms_from_target_node_for_utilization_increase,
        target_node_for_utilization_increase,
        utilization_imbalance,
    ):
        assert_vms_consistent_virt_launcher_pods(
            running_vms=deployed_no_annotation_vms_for_utilization_imbalance
        )
