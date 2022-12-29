import pytest

from utilities.constants import DEFAULT_HCO_CONDITIONS
from utilities.infra import cluster_sanity


# flake8: noqa: PID001


@pytest.mark.cluster_health_check
def test_cluster_sanity(
    request,
    admin_client,
    cluster_storage_classes_names,
    nodes,
    hco_namespace,
    junitxml_plugin,
    hyperconverged_resource_scope_session,
):
    cluster_sanity(
        request=request,
        admin_client=admin_client,
        cluster_storage_classes_names=cluster_storage_classes_names,
        nodes=nodes,
        hco_namespace=hco_namespace,
        junitxml_property=junitxml_plugin,
        hco_status_conditions=hyperconverged_resource_scope_session.instance.status.conditions,
        expected_hco_status=DEFAULT_HCO_CONDITIONS,
    )
