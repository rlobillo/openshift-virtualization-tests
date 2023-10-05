import logging
import os

import pytest
from ocp_resources.virtual_machine_restore import VirtualMachineRestore
from ocp_utilities.infra import cluster_resource

from tests.upgrade_params import (
    IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID,
    IUO_UPGRADE_TEST_ORDERING_NODE_ID,
)
from utilities.constants import DEPENDENCY_SCOPE_SESSION, LS_COMMAND, StorageClassNames
from utilities.storage import (
    OCSVirtualizationStorageClass,
    assert_disk_serial,
    assert_hotplugvolume_nonexist_optional_restart,
    run_command_on_cirros_vm_and_check_output,
    wait_for_vm_volume_ready,
)


LOGGER = logging.getLogger(__name__)
DEPENDENCIES_NODE_ID_PREFIX = f"{os.path.abspath(__file__)}::TestUpgradeStorage"


@pytest.mark.sno
@pytest.mark.upgrade
class TestUpgradeStorage:
    """Pre-upgrade tests"""

    @pytest.mark.polarion("CNV-4880")
    @pytest.mark.order(before=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        name=f"{DEPENDENCIES_NODE_ID_PREFIX}::test_cdiconfig_scratch_overriden_before_upgrade"
    )
    def test_cdiconfig_scratch_overriden_before_upgrade(
        self,
        cdi_config,
        storage_class_for_updating_cdiconfig_scratch,
        override_cdiconfig_scratch_spec,
    ):
        """
        Check that the scratch StorageClass configuration should be changed before CNV upgrade
        """
        expected_sc = (
            storage_class_for_updating_cdiconfig_scratch.instance.metadata.name
        )
        actual_sc = cdi_config.scratch_space_storage_class_from_status
        assert (
            actual_sc == expected_sc
        ), "The scratchSpaceStorageClass on CDIConfig config should be changed before upgrade"

    @pytest.mark.polarion("CNV-5993")
    @pytest.mark.order(before=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        name=f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_snapshot_restore_before_upgrade"
    )
    def test_vm_snapshot_restore_before_upgrade(
        self,
        skip_if_no_storage_class_for_snapshot,
        cirros_vm_for_upgrade_a,
        snapshots_for_upgrade_a,
    ):
        with cluster_resource(VirtualMachineRestore)(
            name=f"restore-snapshot-{cirros_vm_for_upgrade_a.name}",
            namespace=snapshots_for_upgrade_a.namespace,
            vm_name=cirros_vm_for_upgrade_a.name,
            snapshot_name=snapshots_for_upgrade_a.name,
        ) as vm_restore:
            vm_restore.wait_restore_done()
            cirros_vm_for_upgrade_a.start(wait=True)
            run_command_on_cirros_vm_and_check_output(
                vm=cirros_vm_for_upgrade_a,
                command=LS_COMMAND,
                expected_result="1",
            )

    @pytest.mark.polarion("CNV-5995")
    @pytest.mark.order(before=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        name=f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_snapshot_created_before_upgrade"
    )
    def test_vm_snapshot_created_before_upgrade(
        self,
        skip_if_no_storage_class_for_snapshot,
        snapshots_for_upgrade_b,
    ):
        snapshots_for_upgrade_b.wait_snapshot_done()

    @pytest.mark.polarion("CNV-7258")
    @pytest.mark.order(before=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        name=f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_with_hotplug_before_upgrade"
    )
    def test_vm_with_hotplug_before_upgrade(
        self,
        upgrade_namespace_scope_session,
        blank_disk_dv_with_default_sc,
        fedora_vm_for_hotplug_upg,
        hotplug_volume_upg,
    ):
        wait_for_vm_volume_ready(vm=fedora_vm_for_hotplug_upg)
        assert_disk_serial(vm=fedora_vm_for_hotplug_upg)
        assert_hotplugvolume_nonexist_optional_restart(
            vm=fedora_vm_for_hotplug_upg, restart=True
        )

    """ Post-upgrade tests """

    @pytest.mark.polarion("CNV-4725")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_dv_api_version_after_upgrade(self, dvs_for_upgrade):
        for dv in dvs_for_upgrade:
            assert dv.api_version == f"{dv.api_group}/{dv.ApiVersion.V1BETA1}"

    @pytest.mark.polarion("CNV-2952")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[
            IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID,
            f"{DEPENDENCIES_NODE_ID_PREFIX}::test_cdiconfig_scratch_overriden_before_upgrade",
        ],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_cdiconfig_scratch_preserved_after_upgrade(
        self,
        skip_if_not_override_cdiconfig_scratch_space,
        cdi_config,
        storage_class_for_updating_cdiconfig_scratch,
    ):
        """
        Check that the scratch StorageClass configuration should be preserved by the upgrade
        """
        expected_sc = (
            storage_class_for_updating_cdiconfig_scratch.instance.metadata.name
        )
        actual_sc = cdi_config.scratch_space_storage_class_from_status
        assert (
            actual_sc == expected_sc
        ), "The scratchSpaceStorageClass on CDIConfig config should not change after upgrade"

    @pytest.mark.polarion("CNV-5994")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[
            IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID,
            f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_snapshot_restore_before_upgrade",
        ],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_vm_snapshot_restore_check_after_upgrade(
        self,
        cirros_vm_for_upgrade_a,
    ):
        run_command_on_cirros_vm_and_check_output(
            vm=cirros_vm_for_upgrade_a,
            command=LS_COMMAND,
            expected_result="1",
        )

    @pytest.mark.polarion("CNV-5996")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[
            IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID,
            f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_snapshot_created_before_upgrade",
        ],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_vm_snapshot_restore_create_after_upgrade(
        self, cirros_vm_for_upgrade_b, snapshots_for_upgrade_b
    ):
        with cluster_resource(VirtualMachineRestore)(
            name=f"restore-snapshot-{cirros_vm_for_upgrade_b.name}",
            namespace=snapshots_for_upgrade_b.namespace,
            vm_name=cirros_vm_for_upgrade_b.name,
            snapshot_name=snapshots_for_upgrade_b.name,
        ) as vm_restore:
            vm_restore.wait_restore_done()
            cirros_vm_for_upgrade_b.start(wait=True)
            run_command_on_cirros_vm_and_check_output(
                vm=cirros_vm_for_upgrade_b,
                command=LS_COMMAND,
                expected_result="1",
            )

    @pytest.mark.polarion("CNV-5310")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[
            IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID,
            f"{DEPENDENCIES_NODE_ID_PREFIX}::test_vm_with_hotplug_before_upgrade",
        ],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_vm_with_hotplug_after_upgrade(
        self,
        upgrade_namespace_scope_session,
        blank_disk_dv_with_default_sc,
        fedora_vm_for_hotplug_upg,
        hotplug_volume_upg,
        fedora_vm_for_hotplug_upg_ssh_connectivity,
    ):
        assert_disk_serial(vm=fedora_vm_for_hotplug_upg)
        assert_hotplugvolume_nonexist_optional_restart(vm=fedora_vm_for_hotplug_upg)

    @pytest.mark.polarion("CNV-10334")
    @pytest.mark.order(after=IUO_UPGRADE_TEST_ORDERING_NODE_ID)
    @pytest.mark.dependency(
        depends=[IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID],
        scope=DEPENDENCY_SCOPE_SESSION,
    )
    def test_install_ocs_virtualization_storage_class(
        self,
        skip_on_ocp_upgrade,
        skip_on_cnv_upgrade,
    ):
        storage_class_name = f"{StorageClassNames.CEPH_RBD}-virtualization"
        storage_class = cluster_resource(OCSVirtualizationStorageClass)(
            name=storage_class_name
        )
        if storage_class.exists:
            LOGGER.info(f"StorageClass {storage_class_name} already exists")
        else:
            storage_class.deploy()
