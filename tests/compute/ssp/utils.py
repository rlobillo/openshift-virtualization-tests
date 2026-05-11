import logging
import tarfile
from io import BytesIO

import requests

from utilities.infra import get_artifactory_header


LOGGER = logging.getLogger(__name__)


def check_vm_xml_smbios(vm, cm_values):
    """
    Verify SMBIOS on VM XML [sysinfo type=smbios][system] match kubevirt-config
    config map.
    """

    LOGGER.info("Verify VM XML - SMBIOS values.")
    smbios_vm = vm.vmi.xml_dict["domain"]["sysinfo"]["system"]["entry"]
    smbios_vm_dict = {entry["@name"]: entry["#text"] for entry in smbios_vm}
    assert smbios_vm, "VM XML missing SMBIOS values."
    results = {
        "manufacturer": smbios_vm_dict["manufacturer"] == cm_values["manufacturer"],
        "product": smbios_vm_dict["product"] == cm_values["product"],
        "family": smbios_vm_dict["family"] == cm_values["family"],
        "version": smbios_vm_dict["version"] == cm_values["version"],
    }
    LOGGER.info(f"Results: {results}")
    assert all(results.values())


def check_smbios_defaults(smbios_defaults, cm_values):
    LOGGER.info("Compare SMBIOS config map values to expected default values.")
    assert (
        cm_values == smbios_defaults
    ), f"Configmap values {cm_values} do not match default values {smbios_defaults}"


def download_and_extract_tar(tarfile_url, dest_path):
    """Download and Extract the tar file."""
    artifactory_header = get_artifactory_header()
    request = requests.get(url=tarfile_url, verify=False, headers=artifactory_header)
    thetarfile = tarfile.open(fileobj=BytesIO(request.content), mode="r|xz")
    thetarfile.extractall(path=dest_path)


def get_parameters_from_template(template, parameter_subset):
    """Retruns a dict with matching template parameters.

    Args:
        template (Template): Template
        parameter_subset (str): Parameter name subset; may apply to a number of parameters

    Returns:
        dict: {parameter name: parameter value}
    """
    return {
        parameter["name"]: parameter["value"]
        for parameter in template.instance.parameters
        if parameter_subset in parameter["name"]
    }
