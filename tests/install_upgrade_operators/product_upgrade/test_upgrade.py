import logging

import pytest

from tests.install_upgrade_operators.product_upgrade.utils import (
    perform_cnv_upgrade_and_handle_exceptions,
    verify_eus_ocp_upgrade_and_handle_exceptions,
    verify_upgrade_cnv,
    verify_upgrade_ocp,
)
from tests.upgrade_params import IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID


LOGGER = logging.getLogger(__name__)


@pytest.mark.sno
@pytest.mark.upgrade
class TestUpgrade:
    @pytest.mark.ocp_upgrade
    @pytest.mark.polarion("CNV-8381")
    @pytest.mark.dependency(name=IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID)
    def test_ocp_upgrade_process(
        self,
        admin_client,
        nodes,
        machine_config_pools,
        machine_config_pools_conditions_scope_function,
        extracted_ocp_version_from_image_url,
        fired_alerts_before_ocp_upgrade,
        triggered_ocp_upgrade,
    ):
        verify_upgrade_ocp(
            admin_client=admin_client,
            target_ocp_version=extracted_ocp_version_from_image_url,
            machine_config_pools_list=machine_config_pools,
            initial_mcp_conditions=machine_config_pools_conditions_scope_function,
            nodes=nodes,
        )

    @pytest.mark.cnv_upgrade
    @pytest.mark.polarion("CNV-2991")
    @pytest.mark.dependency(name=IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID)
    def test_cnv_upgrade_process(
        self,
        admin_client,
        hco_namespace,
        cnv_target_version,
        cnv_upgrade_stream,
        fired_alerts_before_cnv_upgrade,
        disabled_default_sources_in_operatorhub,
        updated_image_content_source_policy,
        updated_custom_hco_catalog_source_image,
        updated_cnv_subscription_source,
        approved_cnv_upgrade_install_plan,
        started_cnv_upgrade,
        created_target_hco_csv,
        related_images_from_target_csv,
        upgraded_cnv,
    ):
        """
        Test the CNV upgrade process (using OSBS/stage sources). The main steps of the test are:

        1. Disable the default sources in operatorhub in order to be able to upgrade usg a custom catalog source.
        2. Generate a new ICSP for the IIB image being used.
        3. Update HCO CatalogSource with the image being used.
        4. Update the CNV Subscription source.
        5. Wait for the upgrade InstallPlan to be created and approve it.
        6. Wait until the upgrade has finished:
            6.1. Wait for CSV to be created and reach status SUCCEEDED.
            6.2. Wait for HCO OperatorCondition to reach status Upgradeable=True.
            6.3. Wait until all the pods have been replaced.
            6.4. Wait until HCO is stable and its version is updated.
        """
        verify_upgrade_cnv(
            dyn_client=admin_client,
            hco_namespace=hco_namespace,
            expected_images=related_images_from_target_csv.values(),
        )

    @pytest.mark.cnv_upgrade
    @pytest.mark.polarion("CNV-9933")
    @pytest.mark.dependency(name=IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID)
    def test_cnv_production_source_upgrade_process(
        self,
        admin_client,
        hco_namespace,
        cnv_target_version,
        cnv_upgrade_stream,
        fired_alerts_before_cnv_upgrade,
        updated_cnv_subscription_source,
        approved_cnv_upgrade_install_plan,
        started_cnv_upgrade,
        created_target_hco_csv,
        related_images_from_target_csv,
        upgraded_cnv,
    ):
        """
        Test the CNV upgrade process using the production source.
        The main steps of the test are the same as for OSBS and stage,
        but it is not needed to disable the default sources, create a new ICSP or update the HCO CatalogSource.
        """
        verify_upgrade_cnv(
            dyn_client=admin_client,
            hco_namespace=hco_namespace,
            expected_images=related_images_from_target_csv.values(),
        )


@pytest.mark.dependency(name=IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID)
@pytest.mark.upgrade
@pytest.mark.eus_upgrade
@pytest.mark.usefixtures(
    "eus_target_cnv_version",
    "eus_cnv_upgrade_path",
    "eus_paused_mcp_workload_update",
)
class TestEUSToEUSUpgrade:
    @pytest.mark.polarion("CNV-9509")
    def test_source_eus_to_non_eus_ocp_upgrade_process(
        self,
        admin_client,
        masters,
        master_machine_config_pools,
        master_machine_config_pools_conditions,
        ocp_version_eus_to_non_eus_from_image_url,
        triggered_source_eus_to_non_eus_ocp_upgrade,
    ):
        LOGGER.info(
            f"On first ocp test to upgrade to: {ocp_version_eus_to_non_eus_from_image_url}"
        )
        verify_eus_ocp_upgrade_and_handle_exceptions(
            admin_client=admin_client,
            master_machine_config_pools=master_machine_config_pools,
            master_machine_config_pools_conditions=master_machine_config_pools_conditions,
            masters=masters,
            ocp_version=ocp_version_eus_to_non_eus_from_image_url,
        )

    @pytest.mark.polarion("CNV-10143")
    def test_source_eus_to_non_eus_cnv_upgrade_process(
        self,
        admin_client,
        hco_namespace,
        hyperconverged_resource_scope_function,
        eus_cnv_upgrade_path,
        disabled_default_sources_in_operatorhub,
        updated_cnv_subscription_source,
    ):
        for version, cnv_image_url in sorted(eus_cnv_upgrade_path["non-eus"].items()):
            perform_cnv_upgrade_and_handle_exceptions(
                admin_client=admin_client,
                cnv_image_url=cnv_image_url,
                hco_namespace=hco_namespace,
                hyperconverged_resource_scope_function=hyperconverged_resource_scope_function,
                cnv_version=version,
            )

    @pytest.mark.polarion("CNV-10144")
    def test_non_eus_to_target_eus_ocp_upgrade_process(
        self,
        admin_client,
        masters,
        master_machine_config_pools,
        master_machine_config_pools_conditions,
        ocp_version_non_eus_to_eus_from_image_url,
        triggered_non_eus_to_target_eus_ocp_upgrade,
    ):
        LOGGER.info(
            f"On second ocp test to upgrade to: {ocp_version_non_eus_to_eus_from_image_url}"
        )
        verify_eus_ocp_upgrade_and_handle_exceptions(
            admin_client=admin_client,
            master_machine_config_pools=master_machine_config_pools,
            master_machine_config_pools_conditions=master_machine_config_pools_conditions,
            masters=masters,
            ocp_version=ocp_version_non_eus_to_eus_from_image_url,
        )

    @pytest.mark.polarion("CNV-10145")
    def test_eus_second_cnv_upgrade_process(
        self,
        admin_client,
        hco_namespace,
        hyperconverged_resource_scope_function,
        eus_cnv_upgrade_path,
        disabled_default_sources_in_operatorhub,
        updated_cnv_subscription_source,
    ):

        version, cnv_image_url = next(iter(eus_cnv_upgrade_path["eus"].items()))
        perform_cnv_upgrade_and_handle_exceptions(
            admin_client=admin_client,
            cnv_image_url=cnv_image_url,
            hco_namespace=hco_namespace,
            hyperconverged_resource_scope_function=hyperconverged_resource_scope_function,
            cnv_version=version,
        )


@pytest.mark.upgrade
@pytest.mark.eus_upgrade
@pytest.mark.order(after="IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID")
@pytest.mark.polarion("CNV-10146")
def test_verify_eus_to_eus_upgrade_process(
    admin_client, hco_namespace, eus_related_images_from_target_csv
):
    verify_upgrade_cnv(
        dyn_client=admin_client,
        hco_namespace=hco_namespace,
        expected_images=eus_related_images_from_target_csv.values(),
    )
