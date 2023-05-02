import logging
import os
import re

import pytest
from ocp_resources.cluster_service_version import ClusterServiceVersion
from ocp_resources.machine_config_pool import MachineConfigPool
from ocp_resources.resource import ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.utils import run_command
from ocp_wrapper_data_collector.data_collector import collect_resources_yaml_instance
from pytest_testconfig import py_config

from tests.install_upgrade_operators.product_upgrade.utils import (
    approve_cnv_upgrade_install_plan,
    get_alerts_fired_during_upgrade,
    get_all_cnv_alerts,
    get_nodes_labels,
    get_nodes_taints,
    update_icsp_stage_mirror,
    wait_for_hco_upgrade,
    wait_for_pods_replacement_by_type,
)
from tests.install_upgrade_operators.utils import wait_for_operator_condition
from utilities.constants import BREW_REGISTERY_SOURCE, HCO_CATALOG_SOURCE, TIMEOUT_10MIN
from utilities.data_collector import get_data_collector_dict
from utilities.infra import (
    cluster_resource,
    get_csv_by_name,
    get_related_images_name_and_version,
)
from utilities.operator import (
    create_icsp_command,
    create_icsp_from_file,
    delete_existing_icsp,
    generate_icsp_file,
    update_image_in_catalog_source,
    update_subscription_channel_and_source,
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
def updated_image_content_source(
    admin_client,
    tmpdir_factory,
    machine_config_pools,
    cnv_image_url,
    cnv_image_name,
    cnv_registry_source,
    pull_secret_directory,
    generated_pulled_secret,
    is_production_source,
    is_upgrade_from_stage_source,
    tmpdir,
):
    if is_production_source:
        LOGGER.info("ICSP updates skipped as upgrading using production source")
        return
    source_url = cnv_registry_source["source_map"]
    pull_secret = None
    if BREW_REGISTERY_SOURCE in cnv_image_url:
        source_url = BREW_REGISTERY_SOURCE
        pull_secret = generated_pulled_secret

    cnv_mirror_cmd = create_icsp_command(
        image=cnv_image_url,
        source_url=source_url,
        folder_name=pull_secret_directory,
        pull_secret=pull_secret,
    )
    icsp_file_path = generate_icsp_file(
        folder_name=pull_secret_directory,
        command=cnv_mirror_cmd,
    )
    if is_upgrade_from_stage_source:
        update_icsp_stage_mirror(icsp_file_path=icsp_file_path)

    LOGGER.info("pausing MCP updates while modifying ICSP")
    with ResourceEditor(
        patches={
            mcp: {"spec": {"paused": True}}
            for mcp in cluster_resource(MachineConfigPool).get(dyn_client=admin_client)
        }
    ):
        # Due to the amount of annotations in ICSP yaml, `oc apply` may fail. Existing ICSP is deleted.
        LOGGER.info("Deleting existing ICSP.")
        delete_existing_icsp(admin_client=admin_client, name="iib")
        LOGGER.info("Creating new ICSP.")
        create_icsp_from_file(icsp_file_path=icsp_file_path)

    LOGGER.info("Wait for MCP update after ICSP modification.")
    wait_for_mcp_update_completion(machine_config_pools_list=machine_config_pools)


@pytest.fixture()
def updated_catalog_source_image(
    admin_client,
    is_production_source,
    cnv_image_url,
):
    if not is_production_source:
        LOGGER.info("Deployment is not from production; update catalog source image.")
        update_image_in_catalog_source(
            dyn_client=admin_client,
            image=cnv_image_url,
            catalog_source_name=HCO_CATALOG_SOURCE,
            cr_name=py_config["hco_cr_name"],
        )


@pytest.fixture()
def updated_subscription_channel_and_source(
    cnv_subscription_scope_session, cnv_registry_source
):
    LOGGER.info("Update subscription channel and source.")
    update_subscription_channel_and_source(
        subscription=cnv_subscription_scope_session,
        subscription_channel="stable",
        subscription_source=cnv_registry_source["cnv_subscription_source"],
    )


@pytest.fixture()
def approved_upgrade_install_plan(admin_client, hco_namespace, hco_target_version):
    approve_cnv_upgrade_install_plan(
        dyn_client=admin_client,
        hco_namespace=hco_namespace.name,
        hco_target_version=hco_target_version,
    )


@pytest.fixture()
def created_target_csv(admin_client, hco_namespace, hco_target_version):
    LOGGER.info(f"Wait for new CSV {hco_target_version} to be created")
    csv_sampler = TimeoutSampler(
        wait_timeout=TIMEOUT_10MIN,
        sleep=1,
        func=get_csv_by_name,
        admin_client=admin_client,
        namespace=hco_namespace.name,
        csv_name=hco_target_version,
    )
    try:
        for csv in csv_sampler:
            if csv:
                return csv
    except TimeoutExpiredError:
        LOGGER.error(
            f"timeout waiting for target cluster service version: {hco_target_version}"
        )
        if py_config.get("data_collector"):
            data_collector_dict = get_data_collector_dict()
            collect_resources_yaml_instance(
                resources_to_collect=[ClusterServiceVersion],
                base_directory=data_collector_dict["data_collector_base_directory"],
            )
        raise


@pytest.fixture()
def related_images_from_target_csv(created_target_csv):
    LOGGER.info(
        f"Get all related images names and versions from target CSV {created_target_csv.name}"
    )
    return get_related_images_name_and_version(csv=created_target_csv)


@pytest.fixture()
def target_operator_pods_images(created_target_csv):
    # Operator pods are taken from csv deployment as their names under relatedImages do not exact-match
    # the pods' prefixes
    return {
        deploy.name: deploy.spec.template.spec.containers[0].image
        for deploy in created_target_csv.instance.spec.install.spec.deployments
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
    created_target_csv,
    target_operator_pods_images,
    target_images_for_pods_not_managed_by_hco,
):
    LOGGER.info(f"Wait for csv: {created_target_csv.name} to be in SUCCEEDED state.")
    created_target_csv.wait_for_status(
        status=created_target_csv.Status.SUCCEEDED,
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
    LOGGER.info(f"Executing OCP upgrade command to image {ocp_image_url}")
    rc, out, err = run_command(
        command=[
            "oc",
            "adm",
            "upgrade",
            "--force=true",
            "--allow-explicit-upgrade",
            "--allow-upgrade-with-warnings",
            "--to-image",
            ocp_image_url,
        ],
        verify_stderr=False,
    )
    assert rc, f"OCP upgrade command failed. out: {out}. err: {err}"


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
