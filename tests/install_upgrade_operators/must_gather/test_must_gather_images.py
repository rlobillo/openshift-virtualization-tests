import os

import pytest
from ocp_resources.image import Image
from ocp_resources.image_stream import ImageStream
from ocp_resources.imagestreamtag import ImageStreamTag

from tests.install_upgrade_operators.must_gather.utils import (
    VALIDATE_UID_NAME,
    check_list_of_resources,
)
from utilities.constants import NamespacesNames


class TestImageGathering:
    @pytest.mark.parametrize(
        "resource_path, resource",
        [
            pytest.param(
                "cluster-scoped-resources/images",
                Image,
                marks=(pytest.mark.polarion("CNV-9234")),
            ),
            pytest.param(
                f"namespaces/{NamespacesNames.OPENSHIFT}/imagestreams",
                ImageStream,
                marks=(pytest.mark.polarion("CNV-9235")),
            ),
            pytest.param(
                f"namespaces/{NamespacesNames.OPENSHIFT}/imagestreamtags",
                ImageStreamTag,
                marks=(pytest.mark.polarion("CNV-9236")),
            ),
        ],
    )
    def test_image_gather(self, admin_client, gathered_images, resource, resource_path):
        check_list_of_resources(
            dyn_client=admin_client,
            resource_type=resource,
            temp_dir=gathered_images,
            resource_path=f"{os.path.join(gathered_images, resource_path)}/"
            "{name}.yaml",
            checks=VALIDATE_UID_NAME,
            filter_resource="redhat",
        )
