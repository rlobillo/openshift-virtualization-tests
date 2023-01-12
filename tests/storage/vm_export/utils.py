"""
Pytest utils file for CNV VMExport tests
"""
import logging
import shlex

import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.storage_profile import StorageProfile
from ocp_utilities.infra import cluster_resource

from utilities.storage import PodWithPVC


LOGGER = logging.getLogger(__name__)


CNV_EXPORT_TOKEN = "cnv-export-token"
VMEXPORT_FROM_SNAPSHOT = "vmexport-from-snapshot"
FROM_VMEXPORT_SNAPSHOT = "from-vmexport-snapshot"


def get_vmexport_external_url(vmexport, image_format="raw"):
    vmexport_links = vmexport.instance.status.links
    for vmexport_format in vmexport_links.external.volumes[0]["formats"]:
        if vmexport_format["format"] == image_format:
            url = vmexport_format["url"]
            LOGGER.info(f"vmexport url: {url}")
            return url
    pytest.fail(
        f"Failed to get vmexport '{vmexport.name}' external url for '{image_format}' format.'\n'"
        f"vmexport links: {vmexport_links}"
    )


def get_pvc_sha256sum(pvc_dict, snapshot_source=False):
    pvc_metadata = pvc_dict["metadata"]
    pvc_name = pvc_metadata["name"]
    volume_mode = cluster_resource(StorageProfile)(
        name=pvc_dict["spec"]["storage"]["storageClassName"]
    ).instance.status["claimPropertySets"][0]["volumeMode"]
    if snapshot_source:
        pvc_name = f"{VMEXPORT_FROM_SNAPSHOT}-{pvc_name}"
    with cluster_resource(PodWithPVC)(
        namespace=pvc_metadata["namespace"],
        name=f"{pvc_name}-pod",
        pvc_name=pvc_name,
        volume_mode=volume_mode,
    ) as pod:
        pod.wait_for_status(status=pod.Status.RUNNING)
        pvc_disk_img = "/pvc/disk.img"
        checksum = "sha256sum"
        command = (
            f"bash -c 'head -c 1000000 {pvc_disk_img} | {checksum}'"
            if volume_mode == DataVolume.VolumeMode.BLOCK
            else f"{checksum} {pvc_disk_img}"
        )
        return pod.execute(command=shlex.split(command))


def check_pvc_sha256sum(source_pvc_dict, target_pvc_dict, snapshot_source=False):
    source_pvc_sha256sum = get_pvc_sha256sum(
        pvc_dict=source_pvc_dict, snapshot_source=snapshot_source
    )
    target_pvc_sha256sum = get_pvc_sha256sum(pvc_dict=target_pvc_dict)
    assert (
        source_pvc_sha256sum == target_pvc_sha256sum
    ), f"Source sha256sum: '\n'{source_pvc_sha256sum} is not equal to the target: '\n'{target_pvc_sha256sum}"
