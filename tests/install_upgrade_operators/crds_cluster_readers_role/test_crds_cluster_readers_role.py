import logging
import shlex
from subprocess import check_output

import pytest
from ocp_resources.custom_resource_definition import CustomResourceDefinition
from ocp_resources.resource import Resource

from utilities.constants import VM_CLONE_CRD, VM_EXPORT_CRD
from utilities.infra import is_bug_open


LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def crds(admin_client):
    crds_to_check = []
    for crd in CustomResourceDefinition.get(dyn_client=admin_client):
        if any(
            [
                crd.name.endswith(suffix)
                for suffix in [
                    Resource.ApiGroup.KUBEVIRT_IO,
                    Resource.ApiGroup.NMSTATE_IO,
                ]
            ]
        ):
            crds_to_check.append(crd)
    return crds_to_check


@pytest.mark.polarion("CNV-8263")
def test_crds_cluster_readers_role(crds):
    LOGGER.info(f"CRds: {crds}")
    cluster_readers = "system:cluster-readers"
    cannot_read = []
    for crd in crds:
        can_read = check_output(shlex.split(f"oc adm policy who-can get {crd.name}"))
        if cluster_readers not in str(can_read):
            cannot_read.append(crd.name)

    # TODO: This block is to be removed when BZ: 2139144 is closed.
    if is_bug_open(bug_id="2139144"):
        for crd in [VM_EXPORT_CRD, VM_CLONE_CRD]:
            if crd in cannot_read:
                cannot_read.remove(crd)

    if cannot_read:
        cannot_read_str = "\n".join(cannot_read)
        pytest.fail(
            msg=f"The following crds are missing {cluster_readers} role:\n{cannot_read_str}"
        )
