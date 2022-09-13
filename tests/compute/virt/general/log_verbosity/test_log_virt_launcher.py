# -*- coding: utf-8 -*-

import logging

import pytest
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler

from tests.compute.virt.constants import MIGRATION_POLICY_VM_LABEL
from tests.compute.virt.general.log_verbosity.constants import (
    VIRT_LOG_VERBOSITY_LEVEL_6,
)
from utilities.constants import TIMEOUT_30SEC
from utilities.infra import cluster_resource
from utilities.virt import (
    VirtualMachineForTests,
    fedora_vm_body,
    migrate_vm_and_verify,
    running_vm,
)


LOGGER = logging.getLogger(__name__)


def find_missing_progress_keys_in_pod_log(pod):
    missing_keys = list(
        filter(
            lambda key: key not in pod.log(container="compute"),
            [
                "TimeElapsed",
                "DataProcessed",
                "DataRemaining",
                "DataTotal",
                "MemoryProcessed",
                "MemoryRemaining",
                "MemoryTotal",
                "MemoryBandwidth",
                "DirtyRate",
                "Iteration",
                "PostcopyRequests",
                "ConstantPages",
                "NormalPages",
                "NormalData",
                "ExpectedDowntime",
                "DiskBps",
            ],
        )
    )
    return missing_keys


def wait_for_all_progress_keys_in_pod_log(pod):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_30SEC,
        sleep=4,
        func=find_missing_progress_keys_in_pod_log,
        pod=pod,
    )
    missing_keys = None
    try:
        for missing_keys in samples:
            if not missing_keys:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"The following progress keys are missing: {missing_keys}")
        raise


@pytest.fixture(scope="class")
def vm_for_migration_progress_test(
    namespace,
    unprivileged_client,
):
    name = "vm-for-migration-progress-test"
    with cluster_resource(VirtualMachineForTests)(
        name=name,
        namespace=namespace.name,
        body=fedora_vm_body(name=name),
        additional_labels=MIGRATION_POLICY_VM_LABEL,
    ) as vm:
        running_vm(vm=vm)
        yield vm


@pytest.fixture()
def migrated_vm_with_policy(
    migration_policy_with_bandwidth, vm_for_migration_progress_test
):
    migrate_vm_and_verify(
        vm=vm_for_migration_progress_test, wait_for_migration_success=False
    )


@pytest.mark.parametrize(
    "updated_log_verbosity_config",
    [
        pytest.param(
            {
                "kubevirt": {
                    "virtLauncher": VIRT_LOG_VERBOSITY_LEVEL_6,
                }
            }
        ),
    ],
    indirect=True,
)
class TestProgressOfMigrationInVirtLauncher:
    @pytest.mark.polarion("CNV-9057")
    def test_virt_launcher_log_verbosity(
        self,
        updated_log_verbosity_config,
        vm_for_migration_progress_test,
    ):
        assert (
            f"verbosity to {VIRT_LOG_VERBOSITY_LEVEL_6}"
            in vm_for_migration_progress_test.vmi.virt_launcher_pod.log(
                container="compute"
            )
        ), f"Not found correct log verbosity level: {VIRT_LOG_VERBOSITY_LEVEL_6} in logs"

    @pytest.mark.polarion("CNV-9058")
    def test_progress_of_vm_migration_in_virt_launcher_pod(
        self,
        updated_log_verbosity_config,
        vm_for_migration_progress_test,
        migrated_vm_with_policy,
    ):
        wait_for_all_progress_keys_in_pod_log(
            pod=vm_for_migration_progress_test.vmi.virt_launcher_pod
        )
