import logging
import re

import pytest
from ocp_resources.data_source import DataSource
from ocp_resources.datavolume import DataVolume
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import py_config

from tests.compute.ssp.supported_os.common_templates.golden_images.update_boot_source.constants import (
    DATA_SOURCE_READY_FOR_CONSUMPTION_MESSAGE,
)
from tests.compute.ssp.supported_os.common_templates.golden_images.update_boot_source.utils import (
    template_labels,
    vm_with_data_source,
    wait_for_condition_message_value,
)
from tests.compute.ssp.supported_os.common_templates.golden_images.utils import (
    assert_missing_golden_image_pvc,
)
from tests.compute.ssp.supported_os.common_templates.utils import (
    validate_os_info_vmi_vs_linux_os,
)
from utilities.constants import OS_FLAVOR_RHEL, TIMEOUT_5MIN, TIMEOUT_10MIN, Images
from utilities.virt import running_vm


LOGGER = logging.getLogger(__name__)
RHEL9_NAME = "rhel9"


def assert_os_version_mismatch_in_vm(vm, expected_os):
    expected_os_params = re.match(
        r"(?P<os_name>[a-z]+)(-stream)?(?P<os_ver>[0-9]+)", expected_os
    ).groupdict()
    vm_os = vm.ssh_exec.os.release_str.lower()
    os_name = (
        "redhat" if expected_os_params["os_name"] == OS_FLAVOR_RHEL else vm.os_flavor
    )
    expected_name_in_vm_os = (
        "red hat" if expected_os_params["os_name"] == OS_FLAVOR_RHEL else os_name
    )
    assert re.match(
        rf"({expected_name_in_vm_os}).*({expected_os_params['os_ver']}).*", vm_os
    ), f"Wrong VM OS, expected: {expected_os_params}, actual: {vm_os}"


@pytest.fixture()
def boot_source_os_from_data_source_dict(auto_update_data_source_matrix__function__):
    return auto_update_data_source_matrix__function__[
        [*auto_update_data_source_matrix__function__][0]
    ]["template_os"]


@pytest.fixture()
def matrix_data_source(
    auto_update_data_source_matrix__function__, golden_images_namespace
):
    return DataSource(
        name=[*auto_update_data_source_matrix__function__][0],
        namespace=golden_images_namespace.name,
    )


@pytest.fixture()
def rhel9_data_source(golden_images_namespace):
    return DataSource(
        name=RHEL9_NAME,
        namespace=golden_images_namespace.name,
    )


@pytest.fixture()
def rhel9_ready_data_source(rhel9_data_source):
    wait_for_condition_message_value(
        resource=rhel9_data_source,
        expected_message=DATA_SOURCE_READY_FOR_CONSUMPTION_MESSAGE,
    )


@pytest.fixture()
def existing_data_source_pvc(
    golden_images_persistent_volume_claims_scope_function, matrix_data_source
):
    pvc_name = matrix_data_source.instance.spec.source.pvc.name
    assert any(
        [
            pvc_name in pvc.name
            for pvc in golden_images_persistent_volume_claims_scope_function
        ]
    ), f"PVC {pvc_name} is missing"


@pytest.fixture()
def auto_update_boot_source_vm(
    unprivileged_client,
    namespace,
    matrix_data_source,
    boot_source_os_from_data_source_dict,
):
    LOGGER.info(f"Create a VM using {matrix_data_source.name} dataSource")
    with vm_with_data_source(
        data_source=matrix_data_source,
        namespace=namespace,
        client=unprivileged_client,
        template_labels=template_labels(os=boot_source_os_from_data_source_dict),
    ) as vm:
        yield vm


@pytest.fixture()
def vm_without_boot_source(unprivileged_client, namespace, rhel9_data_source):
    with vm_with_data_source(
        data_source=rhel9_data_source,
        namespace=namespace,
        client=unprivileged_client,
        template_labels=template_labels(os="rhel9.0"),
        non_existing_pvc=True,
        start_vm=False,
    ) as vm:
        vm.start()
        assert_missing_golden_image_pvc(
            vm=vm, pvc_name=rhel9_data_source.instance.spec.source.pvc.name
        )
        yield vm


@pytest.fixture()
def opted_out_rhel9_data_source(rhel9_data_source):
    LOGGER.info(f"Wait for DataSource {rhel9_data_source.name} to opt out")
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_5MIN,
            sleep=5,
            func=lambda: rhel9_data_source.instance.spec.source.pvc.name == RHEL9_NAME,
        ):
            if sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"{rhel9_data_source.name} DataSource source PVC was not updated.")
        raise


@pytest.fixture()
def rhel9_dv(
    admin_client, golden_images_namespace, rhel9_data_source, rhel9_http_image_url
):
    with cluster_resource(DataVolume)(
        client=admin_client,
        name=rhel9_data_source.instance.spec.source.pvc.name,
        namespace=golden_images_namespace.name,
        url=rhel9_http_image_url,
        source="http",
        size=Images.Rhel.DEFAULT_DV_SIZE,
        storage_class=py_config["default_storage_class"],
        bind_immediate_annotation=True,
        api_name="storage",
    ) as dv:
        dv.wait_for_status(status=dv.Status.SUCCEEDED, timeout=TIMEOUT_10MIN)
        yield dv


@pytest.mark.polarion("CNV-7586")
def test_vm_from_auto_update_boot_source(
    existing_data_source_pvc,
    auto_update_boot_source_vm,
    boot_source_os_from_data_source_dict,
    latest_fedora_release_version,
):
    LOGGER.info(f"Verify {auto_update_boot_source_vm.name} OS version and virtctl info")
    if (
        "fedora" in boot_source_os_from_data_source_dict
        and latest_fedora_release_version
    ):
        boot_source_os_from_data_source_dict = f"fedora{latest_fedora_release_version}"
    assert_os_version_mismatch_in_vm(
        vm=auto_update_boot_source_vm,
        expected_os=boot_source_os_from_data_source_dict,
    )
    validate_os_info_vmi_vs_linux_os(vm=auto_update_boot_source_vm)


@pytest.mark.polarion("CNV-7565")
def test_common_templates_boot_source_reference(base_templates):
    source_ref_str = "sourceRef"
    LOGGER.info(
        f"Verify all common templates use {source_ref_str} in dataVolumeTemplates"
    )
    failed_templates = [
        template.name
        for template in base_templates
        if not template.instance.objects[0]
        .spec.dataVolumeTemplates[0]
        .spec.get(source_ref_str)
    ]
    assert (
        not failed_templates
    ), f"Some templates do not use {source_ref_str}, templates: {failed_templates}"


@pytest.mark.polarion("CNV-7535")
def test_vm_with_uploaded_golden_image_opt_out(
    admin_client,
    golden_images_namespace,
    disabled_common_boot_image_import_feature_gate_scope_function,
    opted_out_rhel9_data_source,
    vm_without_boot_source,
    rhel9_dv,
):
    LOGGER.info(f"Test VM with manually uploaded {rhel9_dv.name} golden image DV")
    running_vm(vm=vm_without_boot_source)


@pytest.mark.polarion("CNV-8031")
def test_vm_with_uploaded_golden_image_opt_in(
    disabled_common_boot_image_import_feature_gate_scope_function,
    vm_without_boot_source,
    enabled_common_boot_image_import_feature_gate_scope_function,
    rhel9_data_source,
    rhel9_ready_data_source,
):
    LOGGER.info(f"Test VM with auto-updated {rhel9_data_source.name} golden image DV")
    running_vm(vm=vm_without_boot_source)
