from pytest_testconfig import config as py_config

from utilities.virt import get_rhel_os_dict, get_windows_os_dict


# Common templates

RHEL_LATEST = py_config["latest_rhel_os_dict"]
RHEL_LATEST_LABELS = RHEL_LATEST["template_labels"]
RHEL_LATEST_OS = RHEL_LATEST_LABELS["os"]
RHEL_6_10 = get_rhel_os_dict(rhel_version="rhel-6-10")
RHEL_6_10_TEMPLATE_LABELS = RHEL_6_10["template_labels"]
RHEL_7_6 = get_rhel_os_dict(rhel_version="rhel-7-6")
RHEL_7_6_TEMPLATE_LABELS = RHEL_7_6["template_labels"]

WINDOWS_10 = get_windows_os_dict(windows_version="win-10")
WINDOWS_10_TEMPLATE_LABELS = WINDOWS_10["template_labels"]
WINDOWS_LATEST = py_config["latest_windows_os_dict"]
WINDOWS_LATEST_LABELS = WINDOWS_LATEST["template_labels"]
WINDOWS_LATEST_OS = WINDOWS_LATEST_LABELS["os"]
WINDOWS_LATEST_VERSION = WINDOWS_LATEST["os_version"]

FEDORA_LATEST = py_config["latest_fedora_os_dict"]
FEDORA_LATEST_LABELS = FEDORA_LATEST["template_labels"]
FEDORA_LATEST_OS = FEDORA_LATEST_LABELS["os"]
