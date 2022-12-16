"""
Automation for DataImportCron
"""

import logging
import re

import pytest
from ocp_resources.data_import_cron import DataImportCron
from ocp_resources.datavolume import DataVolume
from ocp_resources.image_stream import ImageStream
from ocp_resources.resource import ResourceEditor
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from openshift.dynamic.exceptions import NotFoundError

from utilities.constants import TIMEOUT_1MIN, TIMEOUT_3MIN, TIMEOUT_6MIN, Images
from utilities.infra import cluster_resource


RHEL8_IMAGE_STREAM = "rhel8-image-stream"
RHEL8_DIGEST = "947541648d7f12fd56d2224d55ce708d369f76ffeb4938c8846b287197f30970"
# Login Red Hat Registry using the Customer Portal credentials,
# and get the rhel8 digest from oc image info registry.redhat.io/rhel8/rhel-guest-image:8.4.0-423


LOGGER = logging.getLogger(__name__)


def wait_for_succeeded_dv(namespace, image_sha):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=5,
        func=lambda: DataVolume(namespace=namespace.name, name=f"rhel8-{image_sha}"),
        exceptions_dict={NotFoundError: []},
    )
    for sample in samples:
        if sample:
            sample.wait_for_dv_success(timeout=TIMEOUT_6MIN)
            return sample


@pytest.fixture()
def rhel8_image_stream(admin_client, namespace):
    tags = [
        {
            "from": {
                "kind": "DockerImage",
                "name": Images.Rhel.RHEL8_REGISTRY_GUEST_IMG,
            },
            "importPolicy": {"scheduled": True},
            "name": "latest",
            "referencePolicy": {"type": "Source"},
        }
    ]
    with cluster_resource(ImageStream)(
        name=RHEL8_IMAGE_STREAM,
        namespace=namespace.name,
        tags=tags,
    ) as image_stream:
        yield image_stream


@pytest.fixture()
def rhel8_latest_image_truncated_sha_from_image_stream(namespace, rhel8_image_stream):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_1MIN,
        sleep=5,
        func=lambda: rhel8_image_stream.instance.status.tags[0]["items"][0]["image"],
    )
    for sample in samples:
        if sample:
            match = re.match(r"^.*sha256:(.*)$", sample)
            assert match, f"image sha256 doesn't exist in {sample}"
            return match.group(1)[
                0:12
            ]  # The DV is created by dataimportcron which named datasource_name + [0:12] of the digest


@pytest.fixture()
def data_import_cron_image_stream(namespace, storage_class_matrix__function__):
    with cluster_resource(DataImportCron)(
        name="rhel8-image-import-cron",
        namespace=namespace.name,
        image_stream=RHEL8_IMAGE_STREAM,
        storage_class=[*storage_class_matrix__function__][0],
        pull_method="node",
        size="10Gi",
        schedule="* * * * *",
        garbage_collect="Outdated",
        managed_data_source="rhel8",
        imports_to_keep=1,
        bind_immediate_annotation=True,
    ) as dic:
        yield dic


@pytest.fixture()
def first_dv(namespace, rhel8_latest_image_truncated_sha_from_image_stream):
    return wait_for_succeeded_dv(
        namespace=namespace,
        image_sha=rhel8_latest_image_truncated_sha_from_image_stream,
    )  # The DV is created by dataimportcron which named datasource_name + [0:12] of the digest


@pytest.fixture()
def rhel8_image_stream_digest_update(rhel8_image_stream):
    ResourceEditor(
        patches={
            rhel8_image_stream: {
                "spec": {
                    "tags": [
                        {
                            "from": {
                                "kind": "DockerImage",
                                "name": f"{rhel8_image_stream.instance.spec['tags'][0]['from']['name']}"
                                f"@sha256:{RHEL8_DIGEST}",
                            },
                            "name": "8.4.0-423",
                        }
                    ]
                }
            }
        }
    ).update()


@pytest.fixture()
def second_dv(namespace):
    return wait_for_succeeded_dv(namespace=namespace, image_sha=RHEL8_DIGEST[0:12])


@pytest.mark.polarion("CNV-7602")
def test_data_import_cron_garbage_collection(
    admin_client,
    namespace,
    rhel8_image_stream,
    data_import_cron_image_stream,
    first_dv,
    rhel8_image_stream_digest_update,
    second_dv,
):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_3MIN, sleep=1, func=lambda: first_dv.pvc.exists
    )
    try:
        for sample in samples:
            if not sample:
                break
    except TimeoutExpiredError:
        LOGGER.error(f"Garbage collection failed, {first_dv.pvc.name} is not deleted")
        raise
    assert second_dv.pvc.exists, f"Second PVC {second_dv.pvc.name} was deleted"
