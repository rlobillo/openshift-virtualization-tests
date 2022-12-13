import logging

import pytest
from ocp_resources.metallb import MetalLB

from utilities.infra import create_ns
from utilities.operator import (
    create_catalog_source,
    create_folder_and_icsp_file,
    create_icsp_from_file,
    create_operator,
    create_operator_group,
    create_subscription,
    delete_existing_icsp,
    get_install_plan_from_subscription,
    wait_for_catalogsource_ready,
    wait_for_operator_install,
)


LOGGER = logging.getLogger(__name__)
METALLB_CATALOG_SOURCE = "metallb-catalog"
METALLB_OPERATOR = "metallb-operator"


@pytest.fixture(scope="module")
def generated_metallb_icsp(
    tmp_path_factory,
    generated_pulled_secret,
    nightly_art_image_url,
):
    return create_folder_and_icsp_file(
        path_factory=tmp_path_factory,
        operator_name=METALLB_OPERATOR,
        image=nightly_art_image_url,
        pull_secret=generated_pulled_secret,
    )


@pytest.fixture(scope="module")
def updated_icsp_metallb(
    admin_client,
    generated_metallb_icsp,
):
    LOGGER.info(f"Creating MetalLB ICSP from {generated_metallb_icsp} path...")
    create_icsp_from_file(icsp_file_path=generated_metallb_icsp)
    yield
    delete_existing_icsp(admin_client=admin_client, name="ocp-release-nightly-0")


@pytest.fixture(scope="module")
def metallb_catalog_source(admin_client, nightly_art_image_url):
    catalog_source = create_catalog_source(
        catalog_name=METALLB_CATALOG_SOURCE,
        image=nightly_art_image_url,
        display_name="MetalLB Index Image",
    )
    wait_for_catalogsource_ready(
        admin_client=admin_client,
        catalog_name=METALLB_CATALOG_SOURCE,
    )
    yield catalog_source
    catalog_source.clean_up()


@pytest.fixture(scope="module")
def created_metallb_namespace(admin_client):
    yield from create_ns(
        admin_client=admin_client,
        name="metallb-system",
    )


@pytest.fixture(scope="module")
def created_metallb_operator_group(created_metallb_namespace):
    metallb_operator_group = create_operator_group(
        namespace_name=created_metallb_namespace.name,
        operator_group_name=METALLB_OPERATOR,
    )
    yield
    metallb_operator_group.clean_up()


@pytest.fixture(scope="module")
def created_metallb_subscription(
    metallb_catalog_source,
    created_metallb_namespace,
):
    metallb_subscription = create_subscription(
        subscription_name=METALLB_OPERATOR,
        package_name=METALLB_OPERATOR,
        namespace_name=created_metallb_namespace.name,
        catalogsource_name=metallb_catalog_source.name,
    )
    yield metallb_subscription
    metallb_subscription.clean_up()


@pytest.fixture(scope="module")
def subscription_with_metallb_install_plan(created_metallb_subscription):
    return get_install_plan_from_subscription(subscription=created_metallb_subscription)


@pytest.fixture(scope="module")
def metallb_install_plan_installed(
    admin_client,
    created_metallb_namespace,
    created_metallb_subscription,
    subscription_with_metallb_install_plan,
):
    wait_for_operator_install(
        admin_client=admin_client,
        install_plan_name=subscription_with_metallb_install_plan,
        namespace_name=created_metallb_namespace.name,
        subscription_name=created_metallb_subscription.name,
    )


@pytest.fixture(scope="module")
def installed_metallb_operator(
    disabled_default_sources_in_operatorhub_scope_module,
    updated_icsp_metallb,
    created_metallb_namespace,
    created_metallb_operator_group,
    created_metallb_subscription,
    metallb_install_plan_installed,
):
    metallb_operator = create_operator(
        operator_class=MetalLB,
        operator_name=METALLB_OPERATOR,
        namespace_name=created_metallb_namespace.name,
    )
    yield
    metallb_operator.clean_up()
