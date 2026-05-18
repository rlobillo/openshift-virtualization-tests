import logging
import os
import re

import packaging
import pytest
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.resource import ResourceEditor
from ocp_resources.utils import TimeoutExpiredError
from packaging.version import Version
from pytest_testconfig import py_config

from tests.install_upgrade_operators.constants import (
    WORKLOAD_UPDATE_STRATEGY_KEY_NAME,
    WORKLOADUPDATEMETHODS,
)
from tests.install_upgrade_operators.product_upgrade.utils import (
    approve_cnv_upgrade_install_plan,
    extract_ocp_version_from_ocp_image,
    get_alerts_fired_during_upgrade,
    get_all_cnv_alerts,
    get_iib_images_of_cnv_versions,
    get_mcp_conditions,
    get_nodes_labels,
    get_nodes_taints,
    get_shortest_upgrade_path,
    perform_cnv_upgrade,
    run_ocp_upgrade_command,
    verify_upgrade_ocp,
    wait_for_hco_csv_creation,
    wait_for_hco_upgrade,
    wait_for_odf_update,
    wait_for_pods_replacement_by_type,
    wait_for_version_explorer_response,
)
from tests.install_upgrade_operators.utils import (
    apply_konflux_icsp,
    is_konflux_pipeline,
    konflux_mirror_url,
    wait_for_operator_condition,
)
from utilities.constants import (
    HCO_CATALOG_SOURCE,
    TIMEOUT_10MIN,
    TIMEOUT_180MIN,
    NamespacesNames,
)
from utilities.data_collector import get_data_collector_dict
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.infra import (
    exit_pytest_execution,
    get_related_images_name_and_version,
    get_subscription,
)
from utilities.operator import (
    get_machine_config_pool_by_name,
    update_image_in_catalog_source,
    update_subscription_source,
    wait_for_mcp_update_completion,
)
from utilities.virt import get_oc_image_info


LOGGER = logging.getLogger(__name__)
POD_STR_NOT_MANAGED_BY_HCO = "hostpath-"
ODF_URL = "quay.io/rhceph-dev"


@pytest.fixture(scope="session")
def iib_build_info(cnv_source, cnv_image_url):
    if cnv_source in ("osbs", "fbc"):
        iib_format_match = re.search(r"/iib:(\d+)$", cnv_image_url)
        if not iib_format_match:
            exit_pytest_execution(
                message=(
                    f"Cannot extract IIB number from: {cnv_image_url}"
                    f" (expected format: .../iib:<number>)"
                ),
            )
        iib_number = iib_format_match.group(1)

        try:
            return wait_for_version_explorer_response(
                api_end_point="GetBuildByIIB",
                query_string=f"iib_number={iib_number}",
            )
        except TimeoutExpiredError:
            exit_pytest_execution(
                message=f"Version Explorer returned empty response for IIB {iib_number}.",
            )
    return {}


@pytest.fixture(scope="session")
def nodes_taints_before_upgrade(nodes):
    return get_nodes_taints(nodes=nodes)


@pytest.fixture(scope="session")
def cnv_upgrade(pytestconfig):
    return pytestconfig.option.upgrade == "cnv"


@pytest.fixture(scope="session")
def nodes_labels_before_upgrade(nodes, cnv_upgrade):
    return get_nodes_labels(nodes=nodes, cnv_upgrade=cnv_upgrade)


@pytest.fixture(scope="session")
def required_konflux_mirrors(cnv_target_version, cnv_current_version):
    target = Version(version=cnv_target_version)
    current = Version(version=cnv_current_version)
    return [
        konflux_mirror_url(version=Version(version=f"{target.major}.{minor}"))
        for minor in range(target.minor, current.minor - 1, -1)
    ]


@pytest.fixture()
def updated_image_content_source_policy(
    admin_client,
    nodes,
    required_konflux_mirrors,
    is_disconnected_cluster,
    machine_config_pools,
    machine_config_pools_conditions_scope_function,
    iib_build_info,
):
    if is_disconnected_cluster:
        LOGGER.warning("Skip applying ICSP in a disconnected setup.")
        return
    if not is_konflux_pipeline(build_info=iib_build_info):
        return

    apply_konflux_icsp(
        admin_client=admin_client,
        required_mirrors=required_konflux_mirrors,
        machine_config_pools=machine_config_pools,
        mcp_conditions=machine_config_pools_conditions_scope_function,
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
        subscription_channel=py_config["cnv_subscription_channel"],
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


@pytest.fixture()
def related_images_from_target_csv(created_target_hco_csv):
    return get_related_images_name_and_version(csv=created_target_hco_csv)


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
        stop_status="fakestatus",  # to bypass intermittent FAILED status that is not permanent.
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
def triggered_ocp_upgrade(ocp_image_url, is_disconnected_cluster):
    image_url = ocp_image_url
    if is_disconnected_cluster:
        image_info = get_oc_image_info(image=ocp_image_url)
        assert image_info, f"For ocp image {ocp_image_url}, image information not found"
        image_url = f"quay.io/openshift-release-dev/ocp-release@{image_info['digest']}"
    run_ocp_upgrade_command(ocp_image_url=image_url)


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
def skip_on_eus_upgrade(pytestconfig):
    if pytestconfig.option.upgrade == "eus":
        pytest.skip("This test is not supported for EUS upgrade")


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


@pytest.fixture()
def default_workload_update_strategy(hyperconverged_resource_scope_module):
    return hyperconverged_resource_scope_module.instance.to_dict()["spec"][
        WORKLOAD_UPDATE_STRATEGY_KEY_NAME
    ]


@pytest.fixture()
def eus_paused_mcp(
    workers,
    worker_machine_config_pools,
    worker_machine_config_pools_conditions,
    eus_target_cnv_version,
    eus_applied_all_icsp,
):
    LOGGER.info("Pausing worker MCP updates before starting EUS upgrade.")
    for mcp in worker_machine_config_pools:
        ResourceEditor(patches={mcp: {"spec": {"paused": True}}}).update()


@pytest.fixture()
def eus_paused_workload_update(
    hyperconverged_resource_scope_module,
    default_workload_update_strategy,
):
    ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_module: {
                "spec": {WORKLOAD_UPDATE_STRATEGY_KEY_NAME: {WORKLOADUPDATEMETHODS: []}}
            }
        },
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ).update()


@pytest.fixture()
def eus_unpaused_workload_update(
    hyperconverged_resource_scope_module,
    default_workload_update_strategy,
):
    LOGGER.info(f"Reset hco.spec.{WORKLOAD_UPDATE_STRATEGY_KEY_NAME}.")
    ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_module: {
                "spec": {
                    WORKLOAD_UPDATE_STRATEGY_KEY_NAME: {
                        WORKLOADUPDATEMETHODS: default_workload_update_strategy[
                            WORKLOADUPDATEMETHODS
                        ]
                    }
                }
            }
        },
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ).update()


@pytest.fixture()
def eus_unpaused_mcp(
    workers,
    worker_machine_config_pools,
    worker_machine_config_pools_conditions,
):
    LOGGER.info("Un-pause worker mcp and wait for worker mcp to complete update.")
    for mcp in worker_machine_config_pools:
        ResourceEditor(patches={mcp: {"spec": {"paused": False}}}).update()

    wait_for_mcp_update_completion(
        machine_config_pools_list=worker_machine_config_pools,
        initial_mcp_conditions=worker_machine_config_pools_conditions,
        nodes=workers,
        update_timeout=TIMEOUT_180MIN,
    )


@pytest.fixture(scope="session")
def eus_ocp_image_urls(pytestconfig):
    return pytestconfig.option.eus_ocp_images.split(",")


@pytest.fixture()
def triggered_source_eus_to_non_eus_ocp_upgrade(eus_ocp_image_urls):
    run_ocp_upgrade_command(ocp_image_url=eus_ocp_image_urls[0])


@pytest.fixture()
def source_eus_to_non_eus_ocp_upgraded(
    admin_client,
    masters,
    master_machine_config_pools,
    ocp_version_eus_to_non_eus_from_image_url,
    triggered_source_eus_to_non_eus_ocp_upgrade,
):
    LOGGER.info(f"Upgrading OCP to: {ocp_version_eus_to_non_eus_from_image_url}")
    verify_upgrade_ocp(
        admin_client=admin_client,
        machine_config_pools_list=master_machine_config_pools,
        target_ocp_version=ocp_version_eus_to_non_eus_from_image_url,
        initial_mcp_conditions=get_mcp_conditions(
            machine_config_pools=master_machine_config_pools
        ),
        nodes=masters,
    )


@pytest.fixture()
def updated_odf_subscription_source(odf_subscription, odf_version):
    LOGGER.info("Update odf subscription source.")
    LOGGER.info(
        f"Update subscription {odf_subscription.name} source channel: {odf_version}"
    )
    ResourceEditor(
        patches={
            odf_subscription: {
                "spec": {
                    "channel": f"stable-{odf_version}",
                }
            }
        }
    ).update()


@pytest.fixture()
def odf_subscription(admin_client):
    return get_subscription(
        admin_client=admin_client,
        namespace=NamespacesNames.OPENSHIFT_STORAGE,
        subscription_name="ocs-subscription",
    )


@pytest.fixture()
def source_eus_to_non_eus_cnv_upgraded(
    admin_client,
    hco_namespace,
    eus_cnv_upgrade_path,
    hyperconverged_resource_scope_function,
    updated_cnv_subscription_source,
):
    for version, cnv_image_url in sorted(
        eus_cnv_upgrade_path["non-eus"].items(), key=lambda item: Version(item[0])
    ):
        LOGGER.info(f"Cnv upgrade to version {version} using image: {cnv_image_url}")
        perform_cnv_upgrade(
            admin_client=admin_client,
            cnv_image_url=cnv_image_url,
            cr_name=hyperconverged_resource_scope_function.name,
            hco_namespace=hco_namespace,
            cnv_target_version=version.lstrip("v"),
        )
    LOGGER.info(
        "Successfully performed cnv upgrades from source EUS to non-EUS version."
    )


@pytest.fixture()
def triggered_non_eus_to_target_eus_ocp_upgrade(eus_ocp_image_urls):
    run_ocp_upgrade_command(ocp_image_url=eus_ocp_image_urls[1])


@pytest.fixture(scope="session")
def ocp_version_eus_to_non_eus_from_image_url(eus_ocp_image_urls):
    return extract_ocp_version_from_ocp_image(ocp_image_url=eus_ocp_image_urls[0])


@pytest.fixture(scope="session")
def ocp_version_non_eus_to_eus_from_image_url(eus_ocp_image_urls):
    return extract_ocp_version_from_ocp_image(ocp_image_url=eus_ocp_image_urls[1])


@pytest.fixture()
def non_eus_to_target_eus_ocp_upgraded(
    admin_client,
    masters,
    master_machine_config_pools,
    ocp_version_non_eus_to_eus_from_image_url,
    triggered_non_eus_to_target_eus_ocp_upgrade,
):
    LOGGER.info(f"Upgrading OCP to: {ocp_version_non_eus_to_eus_from_image_url}")
    verify_upgrade_ocp(
        admin_client=admin_client,
        machine_config_pools_list=master_machine_config_pools,
        target_ocp_version=ocp_version_non_eus_to_eus_from_image_url,
        initial_mcp_conditions=get_mcp_conditions(
            machine_config_pools=master_machine_config_pools
        ),
        nodes=masters,
    )


@pytest.fixture()
def non_eus_to_target_eus_cnv_upgraded(
    admin_client,
    hco_namespace,
    eus_cnv_upgrade_path,
    hyperconverged_resource_scope_function,
    updated_cnv_subscription_source,
):
    version, cnv_image_url = next(iter(eus_cnv_upgrade_path["eus"].items()))
    LOGGER.info(f"Cnv upgrade to version {version} using image: {cnv_image_url}")
    perform_cnv_upgrade(
        admin_client=admin_client,
        cnv_image_url=cnv_image_url,
        cr_name=hyperconverged_resource_scope_function.name,
        hco_namespace=hco_namespace,
        cnv_target_version=version.lstrip("v"),
    )


@pytest.fixture(scope="module")
def eus_applied_all_icsp(
    admin_client,
    nodes,
    is_disconnected_cluster,
    machine_config_pools,
    machine_config_pools_conditions_scope_module,
    iib_build_info,
    eus_cnv_upgrade_path,
):
    if is_disconnected_cluster:
        LOGGER.warning("Skip applying ICSP in a disconnected setup.")
        return
    if not is_konflux_pipeline(build_info=iib_build_info):
        return

    required_mirrors = list(dict.fromkeys(
        konflux_mirror_url(version=Version(version=version))
        for phase in eus_cnv_upgrade_path
        for version in eus_cnv_upgrade_path[phase]
    ))

    apply_konflux_icsp(
        admin_client=admin_client,
        required_mirrors=required_mirrors,
        machine_config_pools=machine_config_pools,
        mcp_conditions=machine_config_pools_conditions_scope_module,
        nodes=nodes,
    )


@pytest.fixture(scope="session")
def worker_machine_config_pools():
    return [get_machine_config_pool_by_name(mcp_name="worker")]


@pytest.fixture(scope="session")
def master_machine_config_pools():
    return [get_machine_config_pool_by_name(mcp_name="master")]


@pytest.fixture()
def odf_version(openshift_current_version):
    ocp_version = packaging.version.parse(
        version=openshift_current_version.split("-")[0]
    )
    return f"{ocp_version.major}.{ocp_version.minor+1}"


@pytest.fixture()
def upgraded_odf(
    odf_version,
    updated_odf_subscription_source,
):
    wait_for_odf_update(target_version=odf_version)
