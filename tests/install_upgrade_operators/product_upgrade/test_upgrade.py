import logging

import pytest

from tests.install_upgrade_operators.product_upgrade.utils import (
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
        machine_config_pools,
        extracted_ocp_version_from_image_url,
        fired_alerts_before_ocp_upgrade,
        triggered_ocp_upgrade,
    ):
        verify_upgrade_ocp(
            admin_client=admin_client,
            target_ocp_version=extracted_ocp_version_from_image_url,
            machine_config_pools_list=machine_config_pools,
        )

    @pytest.mark.cnv_upgrade
    @pytest.mark.polarion("CNV-2991")
    @pytest.mark.dependency(name=IUO_UPGRADE_TEST_DEPENDENCY_NODE_ID)
    def test_cnv_upgrade_process(
        self,
        admin_client,
        hco_namespace,
        cnv_upgrade_path,
        fired_alerts_before_cnv_upgrade,
        disabled_default_sources_in_operatorhub,
        cnv_registry_source,
        updated_image_content_source,
        cnv_target_version,
        hco_target_version,
        updated_catalog_source_image,
        updated_subscription_channel_and_source,
        approved_upgrade_install_plan,
        started_cnv_upgrade,
        target_csv,
        target_operator_pods_images_name_and_strategy,
        target_tier_2_images_name_and_versions,
    ):
        verify_upgrade_cnv(
            dyn_client=admin_client,
            hco_namespace=hco_namespace,
            cnv_target_version=cnv_target_version,
            hco_target_version=hco_target_version,
            target_csv=target_csv,
            target_operator_pods_images_name_and_strategy=target_operator_pods_images_name_and_strategy,
            target_tier_2_images_name_and_versions=target_tier_2_images_name_and_versions,
        )
