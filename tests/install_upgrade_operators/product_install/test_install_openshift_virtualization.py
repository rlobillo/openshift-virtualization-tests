import logging

import pytest
from ocp_resources.hyperconverged import HyperConverged
from pytest_testconfig import py_config

from utilities.constants import (
    BREW_REGISTERY_SOURCE,
    HCO_CATALOG_SOURCE,
    HCO_SUBSCRIPTION,
    ICSP_FILE,
    PRODUCTION_CATALOG_SOURCE,
)
from utilities.hco import wait_for_hco_conditions
from utilities.infra import (
    create_ns,
    get_hyperconverged_resource,
    wait_for_pods_running,
)
from utilities.operator import (
    create_catalog_source,
    create_icsp_from_file,
    create_operator,
    create_operator_group,
    create_subscription,
    delete_existing_icsp,
    generate_icsp_file,
    get_install_plan_from_subscription,
    get_mcp_updating_transition_times,
    wait_for_catalogsource_ready,
    wait_for_mcp_update_end,
    wait_for_mcp_update_start,
    wait_for_operator_install,
)


OPENSHIFT_VIRTUALIZATION = "openshift-virtualization"
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def hyperconverged_directory(tmpdir_factory, is_production_source):
    if is_production_source:
        yield
    else:
        yield tmpdir_factory.mktemp(f"{OPENSHIFT_VIRTUALIZATION}-folder")


@pytest.fixture()
def generated_hyperconverged_icsp(
    admin_client,
    is_production_source,
    hyperconverged_directory,
    generated_pulled_secret,
    cnv_image_url,
):
    if is_production_source:
        LOGGER.info(
            "This is installation from production source, icsp update is not needed."
        )
        return
    folder_name = f"{hyperconverged_directory}/{OPENSHIFT_VIRTUALIZATION}-manifest"
    LOGGER.info(f"Create CNV ICSP file {ICSP_FILE} in {hyperconverged_directory}")
    mirror_cmd = (
        f"oc adm catalog mirror {cnv_image_url} {BREW_REGISTERY_SOURCE} --manifests-only"
        f" --to-manifests {folder_name} --registry-config={generated_pulled_secret}"
    )

    return generate_icsp_file(folder_name=folder_name, command=mirror_cmd)


@pytest.fixture()
def updated_icsp_hyperconverged(
    admin_client,
    is_production_source,
    generated_hyperconverged_icsp,
    machine_config_pools,
    machine_config_pools_conditions,
):
    initial_updating_transition_times = get_mcp_updating_transition_times(
        mcp_conditions=machine_config_pools_conditions
    )
    if is_production_source:
        LOGGER.info(
            "This is installation from production source, icsp update is not needed."
        )
        return
    delete_existing_icsp(admin_client=admin_client, name="iib-0")
    create_icsp_from_file(icsp_file_path=generated_hyperconverged_icsp)
    LOGGER.info("Wait for MCP update after ICSP modification.")
    wait_for_mcp_update_start(
        machine_config_pools_list=machine_config_pools,
        initial_transition_times=initial_updating_transition_times,
    )
    wait_for_mcp_update_end(machine_config_pools_list=machine_config_pools)


@pytest.fixture()
def hyperconverged_catalog_source(admin_client, is_production_source, cnv_image_url):
    if is_production_source:
        LOGGER.info(
            "No creation or update to catalogsource is needed for installation from production source."
        )
        return
    LOGGER.info(f"Creating catalog source {HCO_CATALOG_SOURCE}")
    catalog_source = create_catalog_source(
        catalog_name=HCO_CATALOG_SOURCE,
        image=cnv_image_url,
    )
    wait_for_catalogsource_ready(
        admin_client=admin_client,
        catalog_name=HCO_CATALOG_SOURCE,
    )
    return catalog_source


@pytest.fixture()
def created_cnv_namespace(admin_client):
    cnv_namespace_name = py_config["hco_namespace"]
    yield from create_ns(
        admin_client=admin_client,
        name=cnv_namespace_name,
        teardown=False,
        labels={
            "pod-security.kubernetes.io/enforce": "privileged",
            "security.openshift.io/scc.podSecurityLabelSync": "false",
        },
    )


@pytest.fixture()
def created_cnv_operator_group(created_cnv_namespace):
    cnv_namespace_name = created_cnv_namespace.name
    return create_operator_group(
        namespace_name=cnv_namespace_name,
        operator_group_name="openshift-cnv-group",
        target_namespaces=[cnv_namespace_name],
    )


@pytest.fixture()
def installed_cnv_subscription(
    admin_client,
    is_production_source,
    hyperconverged_catalog_source,
    created_cnv_namespace,
):
    catalogsource_name = (
        PRODUCTION_CATALOG_SOURCE
        if is_production_source
        else hyperconverged_catalog_source.name
    )
    return create_subscription(
        subscription_name=HCO_SUBSCRIPTION,
        package_name=py_config["hco_cr_name"],
        namespace_name=created_cnv_namespace.name,
        catalogsource_name=catalogsource_name,
    )


@pytest.fixture()
def updated_subscription_with_install_plan(installed_cnv_subscription):
    return get_install_plan_from_subscription(subscription=installed_cnv_subscription)


@pytest.fixture()
def cnv_install_plan_installed(
    admin_client,
    created_cnv_namespace,
    updated_subscription_with_install_plan,
):
    wait_for_operator_install(
        admin_client=admin_client,
        install_plan_name=updated_subscription_with_install_plan,
        namespace_name=created_cnv_namespace.name,
        subscription_name=HCO_SUBSCRIPTION,
    )


@pytest.fixture()
def installed_openshift_virtualization(
    admin_client,
    disabled_default_sources_in_operatorhub,
    updated_icsp_hyperconverged,
    hyperconverged_catalog_source,
    created_cnv_namespace,
    created_cnv_operator_group,
    installed_cnv_subscription,
    cnv_install_plan_installed,
):
    return create_operator(
        operator_class=HyperConverged,
        operator_name=py_config["hco_cr_name"],
        namespace_name=created_cnv_namespace.name,
    )


@pytest.mark.install
@pytest.mark.polarion("CNV-9311")
def test_cnv_installation(
    admin_client,
    created_cnv_namespace,
    installed_openshift_virtualization,
):
    hco = get_hyperconverged_resource(
        client=admin_client, hco_ns_name=created_cnv_namespace.name
    )
    wait_for_hco_conditions(
        admin_client=admin_client, hco_namespace=created_cnv_namespace
    )
    LOGGER.info(f"Installed cnv version: {hco.instance.status.versions}")
    wait_for_pods_running(admin_client=admin_client, namespace=created_cnv_namespace)
