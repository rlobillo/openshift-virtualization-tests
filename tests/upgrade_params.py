from pytest_testconfig import config as py_config


UPGRADE_PACKAGE_NAME = "tests/install_upgrade_operators/product_upgrade"
if py_config["upgraded_product"] == "eus":
    upgrade_class = "TestEUSToEUSUpgrade"
    test_name = "test_eus_upgrade_process"
    file_name = f"{UPGRADE_PACKAGE_NAME}/test_eus_upgrade.py"
else:
    upgrade_class = "TestUpgrade"
    file_name = f"{UPGRADE_PACKAGE_NAME}/test_upgrade.py"
    upgrade_source_suffix = (
        "_production_source" if py_config["cnv_source"] == "production" else ""
    )
    test_name = (
        f"test_{py_config['upgraded_product']}{upgrade_source_suffix}_upgrade_process"
    )

IUO_UPGRADE_TEST_ORDERING_NODE_ID = (
    IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID
) = f"{file_name}::{upgrade_class}::{test_name}"

IUO_CNV_POD_ORDERING_NODE_ID = (
    "tests/install_upgrade_operators/product_upgrade/test_upgrade_iuo.py::TestUpgradeIUO::"
    "test_cnv_pods_running_after_upgrade"
)

COMPUTE_NODE_ID_PREFIX = (
    "tests/compute/upgrade/test_upgrade_compute.py::TestUpgradeCompute"
)
IMAGE_UPDATE_AFTER_UPGRADE_NODE_ID = (
    f"{COMPUTE_NODE_ID_PREFIX}::test_vmi_pod_image_updates_after_upgrade_optin"
)
