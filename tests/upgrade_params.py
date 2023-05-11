from pytest_testconfig import config as py_config


if py_config["upgraded_product"] == "eus":
    upgrade_class = "TestEUSToEUSUpgrade"
    test_name = "test_source_eus_to_non_eus_ocp_upgrade_process"
else:
    upgrade_class = "TestUpgrade"
    upgrade_source_suffix = (
        "_production_source" if py_config["cnv_source"] == "production" else ""
    )
    test_name = (
        f"test_{py_config['upgraded_product']}{upgrade_source_suffix}_upgrade_process"
    )

IUO_UPGRADE_TEST_ORDERING_NODE_ID = (
    IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID
) = f"tests/install_upgrade_operators/product_upgrade/test_upgrade.py::{upgrade_class}::{test_name}"


COMPUTE_VMS_RUNNING_AFTER_UPGRADE_TEST_NODE_ID = (
    "tests/compute/upgrade/test_upgrade_compute.py::TestUpgradeCompute::"
    "test_is_vm_running_after_upgrade"
)
IUO_CNV_POD_ORDERING_NODE_ID = (
    "tests/install_upgrade_operators/product_upgrade/test_upgrade_iuo.py::TestUpgradeIUO::"
    "test_cnv_pods_running_after_upgrade"
)
