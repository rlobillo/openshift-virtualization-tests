import pytest
from ocp_resources.pod import Pod

from tests.install_upgrade_operators.relationship_labels.constants import (
    ALL_EXPECTED_LABELS_DICTS,
    MANAGED_BY_LABEL_KEY,
    VERSION_LABEL_KEY,
)
from tests.install_upgrade_operators.relationship_labels.utils import (
    verify_labels_in_hco_components,
    verify_labels_values_in_olm_deployments,
    verify_no_missing_labels_in_olm_deployments,
)
from utilities.constants import MANAGED_BY_LABEL_VALUE_OLM
from utilities.infra import cluster_resource


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]


@pytest.fixture(scope="class")
def init_labels_dicts(hco_version_scope_class):
    """
    Populate each labels dict with updates with cnv current version
    """
    for label_dict in ALL_EXPECTED_LABELS_DICTS.copy():
        label_dict[VERSION_LABEL_KEY] = hco_version_scope_class


@pytest.fixture(scope="class")
def pod_name_labels_managed_by_olm_dict(admin_client, hco_namespace):
    return {
        pod.name: pod.labels
        for pod in cluster_resource(Pod).get(
            dyn_client=admin_client,
            namespace=hco_namespace.name,
            label_selector=f"{MANAGED_BY_LABEL_KEY}={MANAGED_BY_LABEL_VALUE_OLM}",
        )
    }


class TestRelationshipLabels:
    @pytest.mark.polarion("CNV-7189")
    def test_verify_relationship_labels_hco_components(
        self,
        admin_client,
        hco_namespace,
        init_labels_dicts,
    ):
        verify_labels_in_hco_components(
            admin_client=admin_client, hco_namespace=hco_namespace
        )

    @pytest.mark.polarion("CNV-7190")
    def test_verify_mismatch_relationship_labels_deployments(
        self,
        pod_name_labels_managed_by_olm_dict,
    ):
        verify_labels_values_in_olm_deployments(
            pod_name_labels_managed_by_olm_dict=pod_name_labels_managed_by_olm_dict
        )

    @pytest.mark.polarion("CNV-7269")
    def test_verify_no_missing_relationship_labels_deployments(
        self, pod_name_labels_managed_by_olm_dict
    ):
        verify_no_missing_labels_in_olm_deployments(
            pod_name_labels_managed_by_olm_dict=pod_name_labels_managed_by_olm_dict
        )
