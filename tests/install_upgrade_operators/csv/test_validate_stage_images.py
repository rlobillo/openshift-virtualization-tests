import json
import logging
import shlex
from json import JSONDecodeError

import pytest
from ocp_utilities.utils import run_command

from utilities.constants import HCO_CATALOG_SOURCE, TIMEOUT_10SEC
from utilities.operator import get_catalog_source


NEWLINE = "\n"
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def cnv_build_info(cnv_current_version):
    cnv_version_explorer_url = (
        "http://cnv-version-explorer.apps.cnv2.engineering.redhat.com"
    )
    curl_command = f"curl -s -m{TIMEOUT_10SEC} {cnv_version_explorer_url}/GetSuccessfulBuildsByVersion?version\
={cnv_current_version}&errata_status=true"
    return_status, out_value, _ = run_command(command=shlex.split(curl_command))
    LOGGER.info(
        f"Executed the command: '{curl_command}'{NEWLINE}return_code:'{return_status}', "
        f"out_decoded:'{out_value}'"
    )
    if return_status:
        try:
            build_info = json.loads(out_value)
        except JSONDecodeError:
            pytest.fail(
                f"Failed to parse JSON return value: {out_value}{NEWLINE}"
                f"for API Query: {curl_command}"
            )
    else:
        pytest.fail(
            f"Failed API query to 'CNV Version Explorer': {cnv_version_explorer_url}"
        )
    yield build_info["successful_builds"][0]


@pytest.fixture()
def skip_if_no_builds_available(cnv_build_info, cnv_current_version):
    if not cnv_build_info:
        pytest.skip(f"No successful builds available for CNV v{cnv_current_version}")


@pytest.fixture()
def skip_if_errata_not_in_qe(cnv_build_info, cnv_current_version):
    if cnv_build_info["errata_status"] != "QE":
        pytest.skip(
            f"Errata for CNV v{cnv_current_version} build is not in QE state{NEWLINE}"
            f"Build info from CNV version explorer tool: {cnv_build_info}"
        )


@pytest.fixture()
def skip_if_cluster_cnv_build_differs_from_errata_build(cnv_build_info):
    catalogsource_image = get_catalog_source(
        catalog_name=HCO_CATALOG_SOURCE
    ).instance.to_dict()["spec"]["image"]
    errata_cnv_build = cnv_build_info["iib"]
    if not (
        "iib-pub-pending" in catalogsource_image
        or errata_cnv_build in catalogsource_image
    ):
        pytest.skip(
            "Cluster CNV build differs from the errata build{NEWLINE}"
            f"Cluster CNV build: {catalogsource_image}{NEWLINE}Errata CNV build iib: "
            f"{errata_cnv_build}{NEWLINE}"
        )


@pytest.fixture()
def csv_related_images(csv_scope_session):
    return [
        image_entry["image"].replace("registry", "registry.stage")
        for image_entry in csv_scope_session.instance.spec.relatedImages
    ]


@pytest.mark.polarion("CNV-9982")
def test_validate_stage_images(
    skip_if_no_builds_available,
    skip_if_errata_not_in_qe,
    skip_if_cluster_cnv_build_differs_from_errata_build,
    generated_pulled_secret,
    csv_related_images,
):
    images_unavailable = []
    for image in csv_related_images:
        if not run_command(
            command=shlex.split(
                f"skopeo inspect --authfile={generated_pulled_secret} --tls-verify=0 docker://{image}"
            ),
            timeout=TIMEOUT_10SEC,
        )[0]:
            images_unavailable.append(image)
    assert (
        not images_unavailable
    ), f"Failed to inspect following container images:{NEWLINE}{NEWLINE.join(images_unavailable)}"
