import pytest
from pytest_testconfig import config as py_config

from tests.compute.virt.longevity_tests.constants import (
    LINUX_OS_PREFIX,
    WINDOWS_OS_PREFIX,
)
from tests.compute.virt.longevity_tests.utils import run_migration_loop
from tests.os_params import (
    RHEL_8_5,
    RHEL_8_5_TEMPLATE_LABELS,
    WINDOWS_10,
    WINDOWS_10_TEMPLATE_LABELS,
)


pytestmark = [
    pytest.mark.usefixtures("skip_if_workers_vms", "skip_when_one_node"),
    pytest.mark.longevity,
]


@pytest.mark.parametrize(
    "vm_request, golden_image_data_volume_ocs, golden_image_data_volume_nfs",
    [
        pytest.param(
            {
                "vm_name_prefix": f"{LINUX_OS_PREFIX}-multi-mig-vm",
                "os_labels": RHEL_8_5_TEMPLATE_LABELS,
            },
            {
                "dv_name": f"dv-ocs-{LINUX_OS_PREFIX}",
                "image": RHEL_8_5["image_path"],
                "dv_size": RHEL_8_5["dv_size"],
            },
            {
                "dv_name": f"dv-nfs-{LINUX_OS_PREFIX}",
                "image": RHEL_8_5["image_path"],
                "dv_size": RHEL_8_5["dv_size"],
            },
            marks=pytest.mark.polarion("CNV-8310"),
        )
    ],
    indirect=True,
)
def test_migration_storm_linux_vms(linux_vms_with_pids):
    run_migration_loop(
        iterations=int(py_config["linux_iterations"]),
        vms_with_pids=linux_vms_with_pids,
        os_type=LINUX_OS_PREFIX,
    )


@pytest.mark.parametrize(
    "vm_request, golden_image_data_volume_ocs, golden_image_data_volume_nfs",
    [
        pytest.param(
            {
                "vm_name_prefix": f"{WINDOWS_OS_PREFIX}-multi-mig-vm",
                "os_labels": WINDOWS_10_TEMPLATE_LABELS,
            },
            {
                "dv_name": f"dv-ocs-{WINDOWS_OS_PREFIX}",
                "image": WINDOWS_10["image_path"],
                "dv_size": WINDOWS_10["dv_size"],
            },
            {
                "dv_name": f"dv-nfs-{WINDOWS_OS_PREFIX}",
                "image": WINDOWS_10["image_path"],
                "dv_size": WINDOWS_10["dv_size"],
            },
            marks=pytest.mark.polarion("CNV-8311"),
        )
    ],
    indirect=True,
)
def test_migration_storm_windows_vms(windows_vms_with_pids):
    run_migration_loop(
        iterations=int(py_config["windows_iterations"]),
        vms_with_pids=windows_vms_with_pids,
        os_type=WINDOWS_OS_PREFIX,
    )
