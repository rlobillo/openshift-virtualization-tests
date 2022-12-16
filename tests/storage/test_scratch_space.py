# -*- coding: utf-8 -*-

import logging
from multiprocessing.pool import ThreadPool

import pytest
from ocp_resources.datavolume import DataVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.secret import Secret
from ocp_resources.upload_token_request import UploadTokenRequest
from ocp_resources.utils import TimeoutSampler

import utilities.storage
from tests.storage import utils as storage_utils
from utilities.constants import TIMEOUT_2MIN, TIMEOUT_3MIN, TIMEOUT_5MIN, Images
from utilities.infra import cluster_resource
from utilities.storage import downloaded_image


LOGGER = logging.getLogger(__name__)
PRIVATE_REGISTRY_IMAGE = "cirros-registry-disk-demo:latest"
ACCESS_KEY_ID = "cmVkaGF0"
SECRET_KEY = "MTIz"


@pytest.fixture()
def scratch_space_secret(namespace):
    with cluster_resource(Secret)(
        name="http-secret",
        namespace=namespace.name,
        accesskeyid=ACCESS_KEY_ID,
        secretkey=SECRET_KEY,
    ) as scratch_space_secret:
        yield scratch_space_secret


@pytest.fixture()
def dv_name(request):
    return request.param["dv_name"]


@pytest.fixture()
def scratch_bound_reached(namespace, dv_name):
    thread_pool = ThreadPool(processes=1)
    return thread_pool.apply_async(
        func=scratch_pvc_bound,
        kwds={
            "scratch_pvc": DataVolume(
                name=dv_name, namespace=namespace.name
            ).scratch_pvc
        },
    )


def scratch_pvc_bound(scratch_pvc):
    """
    Used to sample scratch pvc status in the background,
    in order to avoid 'missing' it and assuring 'Bound' status was reached on it
    """
    sampler = TimeoutSampler(
        wait_timeout=60,
        sleep=1,
        func=lambda: scratch_pvc.exists
        and scratch_pvc.status == cluster_resource(PersistentVolumeClaim).Status.BOUND,
    )
    for sample in sampler:
        if sample:
            return True


@pytest.mark.parametrize(
    "dv_name",
    [
        pytest.param(
            {"dv_name": "scratch-space-upload-qcow2-https"},
            marks=(pytest.mark.polarion("CNV-2327")),
        ),
    ],
    indirect=True,
)
def test_upload_https_scratch_space_delete_pvc(
    skip_upstream,
    namespace,
    storage_class_matrix__module__,
    dv_name,
    scratch_bound_reached,
    tmpdir,
):
    local_name = f"{tmpdir}/{Images.Cirros.QCOW2_IMG}"
    remote_name = f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}"
    downloaded_image(remote_name=remote_name, local_name=local_name)
    with utilities.storage.create_dv(
        source="upload",
        dv_name=dv_name,
        namespace=namespace.name,
        size="3Gi",
        storage_class=[*storage_class_matrix__module__][0],
    ) as dv:
        # Blocks test until we get the return value indicating that scratch pvc reached 'Bound'
        scratch_bound_reached.get()
        dv.wait_for_status(status=DataVolume.Status.UPLOAD_READY, timeout=TIMEOUT_3MIN)
        with cluster_resource(UploadTokenRequest)(
            name="scratch-space-upload-qcow2-https",
            namespace=namespace.name,
            pvc_name=dv.pvc.name,
        ) as utr:
            token = utr.create().status.token
            LOGGER.info("Ensure upload was successful")
            sampler = TimeoutSampler(
                wait_timeout=TIMEOUT_2MIN,
                sleep=5,
                func=storage_utils.upload_image,
                token=token,
                data=local_name,
            )
            for sample in sampler:
                if sample == 200:
                    dv.scratch_pvc.delete()
                    dv.wait_for_dv_success(timeout=TIMEOUT_5MIN)
                    with storage_utils.create_vm_from_dv(dv=dv) as vm_dv:
                        storage_utils.check_disk_count_in_vm(vm=vm_dv)
                    return True
