import logging
import re

import pytest
from ocp_resources.data_import_cron import DataImportCron
from ocp_resources.datavolume import DataVolume
from ocp_resources.resource import ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from openshift.dynamic.exceptions import UnprocessibleEntityError
from pytest_testconfig import py_config

from tests.compute.ssp.supported_os.common_templates.golden_images.update_boot_source.constants import (
    CUSTOM_DATA_IMPORT_CRON_NAME,
    CUSTOM_DATA_SOURCE_NAME,
    DEFAULT_FEDORA_REGISTRY_URL,
)
from tests.compute.ssp.supported_os.common_templates.golden_images.update_boot_source.utils import (
    template_labels,
    vm_with_data_source,
    wait_for_condition_message_value,
)
from utilities.constants import TIMEOUT_2MIN, TIMEOUT_5MIN, TIMEOUT_10MIN
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.ssp import (
    get_data_import_crons,
    matrix_auto_boot_data_import_cron_prefixes,
    wait_for_deleted_data_import_crons,
)
from utilities.storage import DATA_IMPORT_CRON_SUFFIX, wait_for_dvs_import_completed
from utilities.virt import running_vm


LOGGER = logging.getLogger(__name__)


pytestmark = pytest.mark.post_upgrade


def assert_pvcs_using_default_storage_class(pvcs, sc):
    failed_auto_update_pvcs = {
        pvc.name: pvc.instance.spec
        for pvc in pvcs
        if pvc.instance.spec.storageClassName != sc.name
    }
    assert (
        not failed_auto_update_pvcs
    ), f"Some PVCs {failed_auto_update_pvcs} do not use the current default SC: {sc.name}"


def wait_for_existing_auto_update_data_import_crons(admin_client, namespace):
    def _get_missing_data_import_crons(
        _client, _namespace, _auto_boot_data_import_cron_prefixes
    ):
        data_import_crons = get_data_import_crons(
            admin_client=_client, namespace=_namespace
        )
        return [
            data_import_cron_prefix
            for data_import_cron_prefix in _auto_boot_data_import_cron_prefixes
            if data_import_cron_prefix
            not in [
                re.sub(DATA_IMPORT_CRON_SUFFIX, "", data_import_cron.name)
                for data_import_cron in data_import_crons
            ]
        ]

    sample = None
    auto_boot_data_import_cron_prefixes = matrix_auto_boot_data_import_cron_prefixes()
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_2MIN,
            sleep=5,
            func=_get_missing_data_import_crons,
            _client=admin_client,
            _namespace=namespace,
            _auto_boot_data_import_cron_prefixes=auto_boot_data_import_cron_prefixes,
        ):
            if not sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(f"Some dataImportCron resources are missing: {sample}")
        raise


def wait_for_created_dv_from_data_import_cron(admin_client, custom_data_source):
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_5MIN,
            sleep=5,
            func=lambda: custom_data_source.instance.spec.source.get("pvc", {}).get(
                "name"
            ),
        ):
            if sample:
                return list(
                    DataVolume.get(
                        dyn_client=admin_client,
                        name=custom_data_source.instance.spec.source.pvc.name,
                        namespace=custom_data_source.namespace,
                    )
                )
    except TimeoutExpiredError:
        LOGGER.error(
            f"DV was not created under {custom_data_source.namespace} namespace, "
            f"dataSource conditions: {custom_data_source.instance.status.conditions}"
        )
        raise


@pytest.fixture()
def failed_pvc_creation(custom_data_import_cron_scope_function):
    LOGGER.info("Verify PVC was not created.")
    wait_for_condition_message_value(
        resource=custom_data_import_cron_scope_function,
        expected_message="No current import",
    )


@pytest.fixture()
def updated_data_import_cron(
    updated_hco_with_custom_data_import_cron_scope_function,
    hyperconverged_resource_scope_function,
):
    updated_hco_with_custom_data_import_cron_scope_function["spec"]["template"]["spec"][
        "source"
    ]["registry"]["url"] = DEFAULT_FEDORA_REGISTRY_URL
    ResourceEditor(
        patches={
            hyperconverged_resource_scope_function: {
                "spec": {
                    "dataImportCronTemplates": [
                        updated_hco_with_custom_data_import_cron_scope_function
                    ]
                }
            }
        }
    ).update()


@pytest.fixture()
def reconciled_custom_data_source(custom_data_source_scope_function):
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_10MIN,
            sleep=5,
            func=lambda: custom_data_source_scope_function.instance.spec.source.get(
                "pvc", {}
            ).get("name"),
        ):
            if sample:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            "DataSource was not reconciled to refernce a PVC, "
            f"DataSource spec: {custom_data_source_scope_function.instance.spec}"
        )
        raise


@pytest.fixture()
def vm_from_custom_data_import_cron(
    custom_data_source_scope_function, namespace, unprivileged_client
):
    with vm_with_data_source(
        data_source=custom_data_source_scope_function,
        namespace=namespace,
        client=unprivileged_client,
        template_labels=template_labels(os="fedora35"),
    ) as vm:
        yield vm


@pytest.fixture()
def deleted_auto_update_dvs(
    admin_client,
    golden_images_namespace,
):
    for dv in DataVolume.get(
        dyn_client=admin_client, namespace=golden_images_namespace.name
    ):
        dv.clean_up()


@pytest.mark.polarion("CNV-7531")
def test_opt_in_data_import_cron_creation(
    admin_client,
    golden_images_namespace,
):
    LOGGER.info("Verify all DataImportCrons are created when opted in")
    wait_for_existing_auto_update_data_import_crons(
        admin_client=admin_client, namespace=golden_images_namespace
    )


@pytest.mark.parametrize(
    "updated_hco_with_custom_data_import_cron_scope_function",
    [
        pytest.param(
            {
                "data_import_cron_name": CUSTOM_DATA_IMPORT_CRON_NAME,
                "data_import_cron_source_url": DEFAULT_FEDORA_REGISTRY_URL,
                "managed_data_source_name": CUSTOM_DATA_SOURCE_NAME,
            },
            marks=(pytest.mark.polarion("CNV-7885")),
        ),
    ],
    indirect=True,
)
def test_custom_data_import_cron_via_hco(
    updated_hco_with_custom_data_import_cron_scope_function,
    reconciled_custom_data_source,
    vm_from_custom_data_import_cron,
):
    LOGGER.info(
        "Test VM running using DataSource from custom DataImportCron "
        f"{updated_hco_with_custom_data_import_cron_scope_function['metadata']['name']}"
    )
    running_vm(vm=vm_from_custom_data_import_cron)


@pytest.mark.parametrize(
    "updated_hco_with_custom_data_import_cron_scope_function",
    [
        pytest.param(
            {
                "data_import_cron_name": CUSTOM_DATA_IMPORT_CRON_NAME,
                "data_import_cron_source_url": DEFAULT_FEDORA_REGISTRY_URL,
                "managed_data_source_name": CUSTOM_DATA_SOURCE_NAME,
            },
            marks=(pytest.mark.polarion("CNV-8096")),
        ),
    ],
    indirect=True,
)
def test_opt_out_custom_data_import_cron_via_hco_not_deleted(
    admin_client,
    updated_hco_with_custom_data_import_cron_scope_function,
    disabled_common_boot_image_import_feature_gate_scope_function,
    golden_images_namespace,
):
    LOGGER.info("Test Custom DataImportCron is not deleted after opt-out")
    assert DataImportCron(
        client=admin_client,
        name=CUSTOM_DATA_IMPORT_CRON_NAME,
        namespace=golden_images_namespace.name,
    ).exists, (
        f"Custom DataImportCron {CUSTOM_DATA_IMPORT_CRON_NAME} not found after opt out"
    )


@pytest.mark.polarion("CNV-7594")
def test_data_import_cron_using_default_storage_class(
    disabled_common_boot_image_import_feature_gate_scope_function,
    updated_default_storage_class_scope_function,
    deleted_auto_update_dvs,
    enabled_common_boot_image_import_feature_gate_scope_function,
    golden_images_data_volumes_scope_function,
    golden_images_persistent_volume_claims_scope_function,
):
    LOGGER.info(
        "Test DataImportCron and DV creation when using default storage class "
        f"{updated_default_storage_class_scope_function.name}"
    )
    wait_for_dvs_import_completed(dvs_list=golden_images_data_volumes_scope_function)
    assert_pvcs_using_default_storage_class(
        pvcs=golden_images_persistent_volume_claims_scope_function,
        sc=updated_default_storage_class_scope_function,
    )


@pytest.mark.polarion("CNV-7532")
def test_data_import_cron_deletion_on_opt_out(
    golden_images_data_import_crons_scope_function,
    disabled_common_boot_image_import_feature_gate_scope_function,
    golden_images_persistent_volume_claims_scope_function,
):
    LOGGER.info("Verify DataImportCrons are deleted after opt-out.")
    wait_for_deleted_data_import_crons(
        data_import_crons=golden_images_data_import_crons_scope_function
    )
    LOGGER.info("Verify PersistenVolumeClaims are not deleted after opt-out.")
    expected_num_pvcs = len(py_config["auto_update_data_source_matrix"])
    existing_pvcs = [
        pvc.name
        for pvc in golden_images_persistent_volume_claims_scope_function
        if pvc.exists
    ]
    assert (
        len(existing_pvcs) == expected_num_pvcs
    ), f"Not all PVCs exist, existing: {existing_pvcs}"


@pytest.mark.polarion("CNV-7569")
def test_data_import_cron_reconciled_after_deletion(
    golden_images_data_import_crons_scope_function,
):
    data_import_cron = golden_images_data_import_crons_scope_function[0]
    LOGGER.info(
        f"Verify dataImportCron {data_import_cron.name} is reconciled after deletion."
    )

    data_import_cron_orig_uid = data_import_cron.instance.metadata.uid
    # Not passing 'wait' as creation time is almost instant
    data_import_cron.delete()

    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_5MIN,
            sleep=5,
            func=lambda: data_import_cron.instance.metadata.uid
            != data_import_cron_orig_uid,
        ):
            if sample:
                return
    except TimeoutExpiredError:
        LOGGER.error("DataImportCron was not reconciled after deletion")
        raise


@pytest.mark.polarion("CNV-8032")
def test_data_import_cron_blocked_update(
    golden_images_data_import_crons_scope_function,
):
    updated_data_import_cron = golden_images_data_import_crons_scope_function[0]
    LOGGER.info(
        f"Verify dataImportCron {updated_data_import_cron.name} cannot be updated."
    )
    with pytest.raises(
        UnprocessibleEntityError, match="r.*Cannot update DataImportCron Spec.*"
    ):
        with ResourceEditorValidateHCOReconcile(
            patches={
                updated_data_import_cron: {
                    "spec": {"managedDataSource": CUSTOM_DATA_SOURCE_NAME}
                }
            },
        ):
            return


@pytest.mark.parametrize(
    "updated_hco_with_custom_data_import_cron_scope_function",
    [
        pytest.param(
            {
                "data_import_cron_name": "dic-non-existing-source",
                "data_import_cron_source_url": "docker://non-existing-url",
                "managed_data_source_name": "non-existing-url-data-source",
            },
            marks=(pytest.mark.polarion("CNV-7575")),
        ),
    ],
    indirect=True,
)
def test_custom_data_import_cron_image_updated_via_hco(
    admin_client,
    updated_hco_with_custom_data_import_cron_scope_function,
    custom_data_source_scope_function,
    failed_pvc_creation,
    updated_data_import_cron,
):
    LOGGER.info(
        "Verify custom DV is created after DataImportCron update with a valid registry URL."
    )
    wait_for_created_dv_from_data_import_cron(
        admin_client=admin_client, custom_data_source=custom_data_source_scope_function
    )


@pytest.mark.polarion("CNV-7669")
def test_data_import_cron_recreated_after_opt_out_opt_in(
    admin_client,
    golden_images_namespace,
    disabled_common_boot_image_import_feature_gate_scope_function,
    enabled_common_boot_image_import_feature_gate_scope_function,
):
    LOGGER.info("Verify dataImportCron is re-created after opt-out -> opt-in")
    wait_for_existing_auto_update_data_import_crons(
        admin_client=admin_client, namespace=golden_images_namespace
    )


@pytest.mark.parametrize(
    "updated_hco_with_custom_data_import_cron_scope_function",
    [
        pytest.param(
            {
                "data_import_cron_name": "data-import-cron-with-invalid-source-url",
                "data_import_cron_source_url": "non-existing-url",
                "managed_data_source_name": "invalid-source-url-data-source",
            },
            marks=(pytest.mark.polarion("CNV-8078")),
        ),
    ],
    indirect=True,
)
def test_data_import_cron_invalid_source_url_failed_creation(
    updated_hco_with_custom_data_import_cron_scope_function,
    ssp_resource_scope_function,
):
    def get_ssp_degraded_condition(_ssp_cr):
        return [
            condition
            for condition in _ssp_cr.instance.status.conditions
            if condition["type"] == ssp_resource_scope_function.Condition.DEGRADED
        ]

    LOGGER.info("verify SSP reports invalid source URL in custom dataImportCron.")
    expected_degradation_message = "Illegal registry source URL scheme"
    sample = None
    try:
        for sample in TimeoutSampler(
            wait_timeout=TIMEOUT_2MIN,
            sleep=5,
            func=get_ssp_degraded_condition,
            _ssp_cr=ssp_resource_scope_function,
        ):
            if sample and expected_degradation_message in sample[0]["message"]:
                return
    except TimeoutExpiredError:
        LOGGER.error(
            "SSP degraded conditions do not report failed dataImportCron configuration; "
            f"excepted error: {expected_degradation_message}, actual conditions: {sample}"
        )
        raise
