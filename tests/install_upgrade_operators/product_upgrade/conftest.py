import logging
import os
import re

import pytest
from ocp_resources.kubevirt import KubeVirt
from pytest_testconfig import py_config

from tests.install_upgrade_operators.constants import WORKLOADUPDATEMETHODS
from tests.install_upgrade_operators.launcher_updates.constants import (
    WORKLOAD_UPDATE_STRATEGY_KEY_NAME,
)
from tests.install_upgrade_operators.product_upgrade.utils import (
    approve_cnv_upgrade_install_plan,
    extract_ocp_version_from_ocp_image,
    get_alerts_fired_during_upgrade,
    get_all_cnv_alerts,
    get_iib_images_of_cnv_versions,
    get_nodes_labels,
    get_nodes_taints,
    get_shortest_upgrade_path,
    pause_machine_config_pool,
    run_ocp_upgrade_command,
    update_icsp,
    wait_for_hco_csv_creation,
    wait_for_hco_upgrade,
    wait_for_pods_replacement_by_type,
)
from tests.install_upgrade_operators.utils import wait_for_operator_condition
from utilities.constants import HCO_CATALOG_SOURCE, TIMEOUT_10MIN
from utilities.data_collector import get_data_collector_dict
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import get_related_images_name_and_version
from utilities.operator import (
    get_machine_config_pool_by_name,
    update_image_in_catalog_source,
    update_subscription_source,
    wait_for_mcp_update_completion,
)


LOGGER = logging.getLogger(__name__)
POD_STR_NOT_MANAGED_BY_HCO = "hostpath-"


@pytest.fixture(scope="session")
def cnv_image_name(cnv_image_url):
    # Image name format example staging: registry-proxy-stage.engineering.redhat.com/rh-osbs-stage/iib-pub-pending:v4.9
    # Image name format example osbs: registry-proxy.engineering.redhat.com/rh-osbs/iib:45131
    match = re.match(".*/(.*):", cnv_image_url)
    assert match, (
        f"Can not find CNV image name from: {cnv_image_url} "
        f"(example: registry-proxy.engineering.redhat.com/rh-osbs/iib:45131 should find 'iib')"
    )
    return match.group(1)


@pytest.fixture(scope="session")
def nodes_taints_before_upgrade(nodes):
    return get_nodes_taints(nodes=nodes)


@pytest.fixture(scope="session")
def cnv_upgrade(pytestconfig):
    return pytestconfig.option.upgrade == "cnv"


@pytest.fixture(scope="session")
def nodes_labels_before_upgrade(nodes, cnv_upgrade):
    return get_nodes_labels(nodes=nodes, cnv_upgrade=cnv_upgrade)


@pytest.fixture()
def updated_image_content_source_policy(
    admin_client,
    nodes,
    tmpdir_factory,
    machine_config_pools,
    machine_config_pools_conditions_scope_function,
    cnv_image_url,
    cnv_image_name,
    cnv_registry_source,
    pull_secret_directory,
    generated_pulled_secret,
    is_upgrade_from_stage_source,
):
    update_icsp(
        admin_client=admin_client,
        cnv_image_url=cnv_image_url,
        cnv_registry_source=cnv_registry_source,
        generated_pulled_secret=generated_pulled_secret,
        is_upgrade_from_stage_source=is_upgrade_from_stage_source,
        pull_secret_directory=pull_secret_directory,
    )

    LOGGER.info("Wait for MCP update after ICSP modification.")
    wait_for_mcp_update_completion(
        machine_config_pools_list=machine_config_pools,
        initial_mcp_conditions=machine_config_pools_conditions_scope_function,
        nodes=nodes,
    )


@pytest.fixture()
def updated_custom_hco_catalog_source_image(
    admin_client,
    cnv_image_url,
):
    LOGGER.info("Deployment is not from production; updating HCO catalog source image.")
    update_image_in_catalog_source(
        dyn_client=admin_client,
        image=cnv_image_url,
        catalog_source_name=HCO_CATALOG_SOURCE,
        cr_name=py_config["hco_cr_name"],
    )


@pytest.fixture()
def updated_cnv_subscription_source(
    cnv_subscription_scope_session, cnv_registry_source
):
    LOGGER.info("Update subscription source.")
    update_subscription_source(
        subscription=cnv_subscription_scope_session,
        subscription_source=cnv_registry_source["cnv_subscription_source"],
    )


@pytest.fixture()
def approved_cnv_upgrade_install_plan(
    admin_client, hco_namespace, hco_target_version, is_production_source
):
    approve_cnv_upgrade_install_plan(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        hco_target_version=hco_target_version,
        is_production_source=is_production_source,
    )


@pytest.fixture()
def created_target_hco_csv(admin_client, hco_namespace, hco_target_version):
    return wait_for_hco_csv_creation(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hco_target_version=hco_target_version,
    )


@pytest.fixture(scope="module")
def eus_created_target_hco_csv(admin_client, hco_namespace, eus_hco_target_version):
    return wait_for_hco_csv_creation(
        admin_client=admin_client,
        hco_namespace=hco_namespace,
        hco_target_version=eus_hco_target_version,
    )


@pytest.fixture()
def related_images_from_target_csv(created_target_hco_csv):
    return get_related_images_name_and_version(csv=created_target_hco_csv)


@pytest.fixture()
def eus_related_images_from_target_csv(eus_created_target_hco_csv):
    return get_related_images_name_and_version(csv=eus_created_target_hco_csv)


@pytest.fixture()
def target_operator_pods_images(created_target_hco_csv):
    # Operator pods are taken from csv deployment as their names under relatedImages do not exact-match
    # the pods' prefixes
    return {
        deploy.name: deploy.spec.template.spec.containers[0].image
        for deploy in created_target_hco_csv.instance.spec.install.spec.deployments
    }


@pytest.fixture()
def target_images_for_pods_not_managed_by_hco(related_images_from_target_csv):
    LOGGER.info("Get hpp target images names and versions.")
    return [
        image
        for image in related_images_from_target_csv.values()
        if POD_STR_NOT_MANAGED_BY_HCO in image
    ]


@pytest.fixture()
def started_cnv_upgrade(admin_client, hco_namespace, hco_target_version):
    wait_for_operator_condition(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        name=hco_target_version,
        upgradable=False,
    )


@pytest.fixture()
def upgraded_cnv(
    admin_client,
    hco_namespace,
    cnv_target_version,
    hco_target_version,
    created_target_hco_csv,
    target_operator_pods_images,
    target_images_for_pods_not_managed_by_hco,
):
    LOGGER.info(
        f"Wait for csv: {created_target_hco_csv.name} to be in SUCCEEDED state."
    )
    created_target_hco_csv.wait_for_status(
        status=created_target_hco_csv.Status.SUCCEEDED,
        timeout=TIMEOUT_10MIN,
        stop_status=None,
    )
    LOGGER.info(
        f"Wait for operator condition {hco_target_version} to reach upgradable: True"
    )
    wait_for_operator_condition(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        name=hco_target_version,
        upgradable=True,
    )

    LOGGER.info("Wait for all openshift-virtualization operator pod replacement:")
    wait_for_pods_replacement_by_type(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        pod_list=target_operator_pods_images.keys(),
        related_images=target_operator_pods_images.values(),
    )
    LOGGER.info("Wait for non-hco managed pods to be replaced:")
    wait_for_pods_replacement_by_type(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        pod_list=[POD_STR_NOT_MANAGED_BY_HCO],
        related_images=target_images_for_pods_not_managed_by_hco,
    )
    wait_for_hco_upgrade(
        dyn_client=admin_client,
        hco_namespace=hco_namespace,
        cnv_target_version=cnv_target_version,
    )


@pytest.fixture(scope="session")
def ocp_image_url(pytestconfig):
    return pytestconfig.option.ocp_image


@pytest.fixture()
def triggered_ocp_upgrade(ocp_image_url):
    run_ocp_upgrade_command(ocp_image_url=ocp_image_url)


@pytest.fixture(scope="session")
def extracted_ocp_version_from_image_url(ocp_image_url):
    """
    Extract the OCP version from the OCP URL input.

    Expected inputs / output examples:
        quay.io/openshift-release-dev/ocp-release:4.10.9-x86_64 -> 4.10.9
        quay.io/openshift-release-dev/ocp-release:4.10.0-rc.6-x86_64 -> 4.10.0-rc.6
        registry.ci.openshift.org/ocp/release:4.11.0-0.nightly-2022-04-01-172551 -> 4.11.0-0.nightly-2022-04-01-172551
        registry.ci.openshift.org/ocp/release:4.11.0-0.ci-2022-04-06-165430 -> 4.11.0-0.ci-2022-04-06-165430
    """
    ocp_version_match = re.search(r"release:(.*?)(?:-x86_64$|$)", ocp_image_url)
    ocp_version = ocp_version_match.group(1) if ocp_version_match else None
    assert (
        ocp_version
    ), f"Cannot extract OCP version. OCP image url: {ocp_image_url} is invalid"
    LOGGER.info(f"OCP version {ocp_version} extracted from ocp image: {ocp_version}")
    return ocp_version


@pytest.fixture(scope="session")
def alert_dir():
    data_collector_dict = get_data_collector_dict()
    base_directory = data_collector_dict["data_collector_base_directory"]
    return os.path.join(base_directory, "alert_information")


@pytest.fixture(scope="session")
def fired_alerts_before_cnv_upgrade(prometheus, alert_dir):
    return get_all_cnv_alerts(
        prometheus=prometheus,
        file_name="before_cnv_upgrade_alerts.json",
        base_directory=alert_dir,
    )


@pytest.fixture()
def fired_alerts_during_cnv_upgrade(
    fired_alerts_before_cnv_upgrade, prometheus, alert_dir
):
    return get_alerts_fired_during_upgrade(
        prometheus=prometheus,
        before_upgrade_alerts=fired_alerts_before_cnv_upgrade,
        base_directory=alert_dir,
    )


@pytest.fixture(scope="session")
def fired_alerts_before_ocp_upgrade(prometheus, alert_dir):
    return get_all_cnv_alerts(
        prometheus=prometheus,
        file_name="before_ocp_upgrade_alerts.json",
        base_directory=alert_dir,
    )


@pytest.fixture()
def fired_alerts_during_ocp_upgrade(
    fired_alerts_before_ocp_upgrade, prometheus, alert_dir
):
    return get_alerts_fired_during_upgrade(
        prometheus=prometheus,
        before_upgrade_alerts=fired_alerts_before_ocp_upgrade,
        base_directory=alert_dir,
    )


@pytest.fixture(scope="session")
def skip_on_cnv_upgrade(pytestconfig):
    if pytestconfig.option.upgrade == "cnv":
        pytest.skip("This test is not supported for CNV upgrade")


@pytest.fixture(scope="module")
def eus_cnv_upgrade_path(eus_target_cnv_version):
    # Get the shortest path to the target (EUS) version
    upgrade_path_to_target_version = get_shortest_upgrade_path(
        target_version=eus_target_cnv_version
    )
    # Get the shortest path to the intermediate (non-EUS) version
    upgrade_path_to_intermediate_version = get_shortest_upgrade_path(
        target_version=upgrade_path_to_target_version["startVersion"]
    )

    # Return a dictionary with the versions and images for the EUS-to-EUS upgrade
    upgrade_path = {
        "non-eus": get_iib_images_of_cnv_versions(
            versions=upgrade_path_to_intermediate_version["versions"]
        ),
        "eus": get_iib_images_of_cnv_versions(
            versions=upgrade_path_to_target_version["versions"]
        ),
    }
    LOGGER.info(f"Upgrade path for EUS-to-EUS upgrade: {upgrade_path}")
    return upgrade_path


@pytest.fixture(scope="module")
def eus_paused_mcp_workload_update(
    workers,
    worker_machine_config_pools,
    worker_machine_config_pools_conditions,
    eus_target_cnv_version,
    hyperconverged_resource_scope_module,
    eus_applied_all_icsp,
):
    with pause_machine_config_pool(mcp_list=worker_machine_config_pools):
        with ResourceEditorValidateHCOReconcile(
            patches={
                hyperconverged_resource_scope_module: {
                    "spec": {
                        WORKLOAD_UPDATE_STRATEGY_KEY_NAME: {WORKLOADUPDATEMETHODS: []}
                    }
                }
            },
            list_resource_reconcile=[KubeVirt],
            wait_for_reconcile_post_update=True,
        ):
            yield
    LOGGER.info(
        f"Cleaned up hco.spec.{WORKLOAD_UPDATE_STRATEGY_KEY_NAME}. After un-pausing worker mcp, wait for "
        "worker mcp to complete update."
    )
    wait_for_mcp_update_completion(
        machine_config_pools_list=worker_machine_config_pools,
        initial_mcp_conditions=worker_machine_config_pools_conditions,
        nodes=workers,
    )


@pytest.fixture(scope="session")
def eus_ocp_image_urls(pytestconfig):
    return pytestconfig.option.eus_ocp_images.split(",")


@pytest.fixture()
def triggered_source_eus_to_non_eus_ocp_upgrade(eus_ocp_image_urls):
    run_ocp_upgrade_command(ocp_image_url=eus_ocp_image_urls[0])


@pytest.fixture()
def triggered_non_eus_to_target_eus_ocp_upgrade(eus_ocp_image_urls):
    run_ocp_upgrade_command(ocp_image_url=eus_ocp_image_urls[1])


@pytest.fixture(scope="session")
def ocp_version_eus_to_non_eus_from_image_url(eus_ocp_image_urls):
    return extract_ocp_version_from_ocp_image(ocp_image_url=eus_ocp_image_urls[0])


@pytest.fixture(scope="session")
def ocp_version_non_eus_to_eus_from_image_url(eus_ocp_image_urls):
    return extract_ocp_version_from_ocp_image(ocp_image_url=eus_ocp_image_urls[1])


@pytest.fixture(scope="module")
def eus_applied_all_icsp(
    admin_client,
    nodes,
    tmpdir_factory,
    pull_secret_directory,
    generated_pulled_secret,
    machine_config_pools,
    machine_config_pools_conditions_scope_module,
    cnv_registry_source,
    eus_cnv_upgrade_path,
    is_upgrade_from_stage_source,
):
    for entry in eus_cnv_upgrade_path:
        for version in eus_cnv_upgrade_path[entry]:
            cnv_image_url = eus_cnv_upgrade_path[entry][version]
            update_icsp(
                admin_client=admin_client,
                cnv_image_url=cnv_image_url,
                cnv_registry_source=cnv_registry_source,
                generated_pulled_secret=generated_pulled_secret,
                is_upgrade_from_stage_source=is_upgrade_from_stage_source,
                pull_secret_directory=pull_secret_directory,
            )
    LOGGER.info("Wait for MCP update after ICSP modification.")
    wait_for_mcp_update_completion(
        machine_config_pools_list=machine_config_pools,
        initial_mcp_conditions=machine_config_pools_conditions_scope_module,
        nodes=nodes,
    )


@pytest.fixture(scope="session")
def worker_machine_config_pools():
    return [get_machine_config_pool_by_name(mcp_name="worker")]


@pytest.fixture(scope="session")
def master_machine_config_pools():
    return [get_machine_config_pool_by_name(mcp_name="master")]
