import copy
import logging

import pytest
from openshift.dynamic.exceptions import ResourceNotFoundError

from tests.install_upgrade_operators.relationship_labels.constants import (
    EXPECTED_COMPONENT_LABELS_DICT_MAP,
    EXPECTED_RELATED_OBJECTS_LABELS_DICT_MAP,
    VERSION_LABEL_KEY,
)
from tests.install_upgrade_operators.relationship_labels.utils import (
    verify_component_labels_by_resource,
)
from tests.install_upgrade_operators.strict_reconciliation.utils import (
    get_resource_from_module_name,
)


pytestmark = [pytest.mark.post_upgrade, pytest.mark.sno]
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def updated_labels_version(hco_version_scope_class, request):
    """
    Populate each labels dict (RELATED_OBJECTS_LABELS_DICT_MAP / COMPONENT_LABELS_DICT_MAP)
    with updates cnv current version, deepcopy and return  updated expected labels dict
    """
    expected_labels_dict = request.param["expected_labels_dict"]
    updated_expected_labels_dict = copy.deepcopy(expected_labels_dict)
    for deployment_labels in updated_expected_labels_dict.values():
        deployment_labels[VERSION_LABEL_KEY] = hco_version_scope_class
    return updated_expected_labels_dict


@pytest.fixture()
def matching_single_related_object(
    hco_status_related_objects, cnv_related_object_matrix__function__
):
    for object_name, object_kind in cnv_related_object_matrix__function__.items():
        for obj in hco_status_related_objects:
            if obj.name == object_name and obj.kind == object_kind:
                return obj
        raise ResourceNotFoundError(
            f"For cnv related object {object_name} {object_kind} not been found name/kind"
            f" in hco_status_related_objects"
        )


class TestRelationshipLabels:
    @pytest.mark.parametrize(
        "updated_labels_version",
        [
            pytest.param(
                {
                    "expected_labels_dict": EXPECTED_COMPONENT_LABELS_DICT_MAP,
                },
                marks=(pytest.mark.polarion("CNV-7190")),
            ),
        ],
        indirect=True,
    )
    def test_verify_mismatch_relationship_labels_deployments(
        self, updated_labels_version, cnv_deployment_by_name
    ):
        verify_component_labels_by_resource(
            component=cnv_deployment_by_name,
            expected_component_labels=updated_labels_version,
        )

    @pytest.mark.parametrize(
        "updated_labels_version",
        [
            pytest.param(
                {
                    "expected_labels_dict": EXPECTED_RELATED_OBJECTS_LABELS_DICT_MAP,
                },
                marks=(pytest.mark.polarion("CNV-7189")),
            ),
        ],
        indirect=True,
    )
    def test_verify_relationship_labels_hco_components(
        self,
        ocp_resources_submodule_list,
        admin_client,
        updated_labels_version,
        matching_single_related_object,
    ):
        verify_component_labels_by_resource(
            component=get_resource_from_module_name(
                related_obj=matching_single_related_object,
                ocp_resources_submodule_list=ocp_resources_submodule_list,
                admin_client=admin_client,
            ),
            expected_component_labels=updated_labels_version,
        )
