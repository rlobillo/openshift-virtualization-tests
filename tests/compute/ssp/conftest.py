import os
import re
from pathlib import Path

import pytest
import requests
from bs4 import BeautifulSoup
from pytest_testconfig import py_config

from tests.compute.ssp.utils import download_and_extract_tar


@pytest.fixture(scope="module")
def smbios_from_kubevirt_config(kubevirt_config_scope_module):
    """Extract SMBIOS default from kubevirt CR."""
    return kubevirt_config_scope_module["smbios"]


@pytest.fixture(scope="module")
def machine_type_from_kubevirt_config(kubevirt_config_scope_module):
    """Extract machine type default from kubevirt CR."""
    return kubevirt_config_scope_module["machineType"]


@pytest.fixture(scope="module")
def downloaded_latest_libosinfo_db(
    tmpdir_factory, latest_osinfo_db_file_name, osinfo_repo
):
    """Obtain the osinfo path."""
    osinfo_path = tmpdir_factory.mktemp("osinfodb")
    download_and_extract_tar(
        tarfile_url=f"{osinfo_repo}{latest_osinfo_db_file_name}",
        dest_path=osinfo_path,
    )
    osinfo_db_file_name_no_suffix = latest_osinfo_db_file_name.partition(".")[0]
    yield os.path.join(osinfo_path, osinfo_db_file_name_no_suffix)


@pytest.fixture(scope="module")
def latest_osinfo_db_file_name(osinfo_repo):
    sorted_osinfo_repo = f"{osinfo_repo}/?C=M;O=A"
    soup_page = BeautifulSoup(
        markup=requests.get(sorted_osinfo_repo).text, features="html.parser"
    )
    full_link = soup_page.findAll(
        name="a", attrs={"href": re.compile(r"osinfo-db-[0-9]*.tar.xz")}
    )

    assert full_link, "No osinfo-db file was found."

    return full_link[-1].get("href")


@pytest.fixture(scope="module")
def latest_fedora_release_version(downloaded_latest_libosinfo_db):
    """
    Extract the version from file name, if no files found raise KeyError
    file example: /tmp/pytest-6axFnW3vzouCkjWokhvbDi/osinfodb0/osinfo-db-20221121/os/fedoraproject.org/fedora-37.xml
    """
    osinfo_file_folder_path = os.path.join(
        downloaded_latest_libosinfo_db, "os/fedoraproject.org/"
    )
    list_of_fedora_os_files = list(
        sorted(Path(osinfo_file_folder_path).glob("*fedora-[0-9][0-9]*.xml"))
    )
    if not list_of_fedora_os_files:
        raise FileNotFoundError("No fedora files were found in osinfo db")
    latest_fedora_os_file = list_of_fedora_os_files[-1]
    return re.findall(r"\d+", latest_fedora_os_file.name)[0]


@pytest.fixture(scope="module")
def osinfo_repo():
    return f"{py_config['servers']['http_server']}cnv-tests/osinfo-db/"
