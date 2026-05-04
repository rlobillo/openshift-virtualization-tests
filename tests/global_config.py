import os

from ocp_resources.datavolume import DataVolume
from ocp_resources.deployment import Deployment
from ocp_resources.pod import Pod
from ocp_resources.replicaset import ReplicaSet
from ocp_resources.service import Service
from ocp_resources.template import Template
from ocp_resources.virtual_machine import VirtualMachine

from utilities.constants import (
    ALL_CNV_CRDS,
    ALL_CNV_DAEMONSETS,
    ALL_CNV_DEPLOYMENTS,
    ALL_CNV_PODS,
    ALL_HCO_RELATED_OBJECTS,
    BASE_ARTIFACTORY_LOCATION,
    BREW_REGISTERY_SOURCE,
    HCO_CATALOG_SOURCE,
    INTEL,
    IPV4_STR,
    IPV6_STR,
    LINUX_BRIDGE,
    OVS_BRIDGE,
    PRODUCTION_CATALOG_SOURCE,
    TLS_CUSTOM_POLICY,
    TLS_OLD_POLICY,
    Images,
    StorageClassNames,
)
from utilities.infra import get_latest_os_dict_list
from utilities.storage import HppCsiStorageClass


global config


def _get_default_storage_class(sc_list):
    """
    Args:
        sc_list (list): storage class dict - a list of dicts

    Returns:
        tuple: (default storage class name, default storage class dict) else raises an exception.
    """
    for sc_dict in sc_list:
        for sc_name, sc_values in sc_dict.items():
            if sc_values.get("default"):
                return sc_name, sc_values
    assert False, f"No SC is marked as 'default': {sc_list}"


no_unprivileged_client = False
distribution = "downstream"
hco_cr_name = "kubevirt-hyperconverged"
hco_namespace = "openshift-cnv"
sriov_namespace = "openshift-sriov-network-operator"
marketplace_namespace = "openshift-marketplace"
machine_api_namespace = "openshift-machine-api"
golden_images_namespace = "openshift-virtualization-os-images"
hco_subscription = ""  # TODO: remove constants/HCO_SUBSCRIPTION and use this instead.
disconnected_cluster = False

linux_bridge_cni = "cnv-bridge"
bridge_tuning = "cnv-tuning"
nodes_cpu_architecture = INTEL  # INTEL = "Intel" AMD = "AMD"

windows_username = "Administrator"
windows_password = "Heslo123"

server_url = ""  # Send --tc=server_url:<url> to override servers URL
servers = {
    "https_server": "https://{server}" f"/{BASE_ARTIFACTORY_LOCATION}/",
    "registry_server": "docker://{server}",
}

cnv_registry_sources = {
    "osbs": {
        "cnv_subscription_source": HCO_CATALOG_SOURCE,
        "source_map": BREW_REGISTERY_SOURCE,
    },
    "hotfix": {
        "cnv_subscription_source": HCO_CATALOG_SOURCE,
    },
    "production": {
        "cnv_subscription_source": PRODUCTION_CATALOG_SOURCE,
    },
    "fbc": {
        "cnv_subscription_source": HCO_CATALOG_SOURCE,
        "source_map": BREW_REGISTERY_SOURCE,
    },
}

nic_models_matrix = [
    "virtio",
    "e1000e",
]
bridge_device_matrix = [LINUX_BRIDGE, OVS_BRIDGE]

HPP_VOLUME_MODE_ACCESS_MODE = {
    "volume_mode": DataVolume.VolumeMode.FILE,
    "access_mode": DataVolume.AccessMode.RWO,
}

new_hpp_storage_class_matrix = [
    {HppCsiStorageClass.Name.HOSTPATH_CSI_BASIC: HPP_VOLUME_MODE_ACCESS_MODE},
    {HppCsiStorageClass.Name.HOSTPATH_CSI_PVC_BLOCK: HPP_VOLUME_MODE_ACCESS_MODE},
]

legacy_hpp_storage_class_matrix = [
    {StorageClassNames.HOSTPATH: HPP_VOLUME_MODE_ACCESS_MODE},
    {HppCsiStorageClass.Name.HOSTPATH_CSI_LEGACY: HPP_VOLUME_MODE_ACCESS_MODE},
]

storage_class_matrix = [
    {
        StorageClassNames.CEPH_RBD: {
            "volume_mode": DataVolume.VolumeMode.BLOCK,
            "access_mode": DataVolume.AccessMode.RWX,
            "default": True,
        }
    },
]

default_storage_class, default_storage_class_configuration = _get_default_storage_class(
    sc_list=storage_class_matrix
)
default_volume_mode = default_storage_class_configuration["volume_mode"]
default_access_mode = default_storage_class_configuration["access_mode"]

link_aggregation_mode_matrix = [
    "active-backup",
    "balance-tlb",
    "balance-alb",
]
link_aggregation_mode_no_connectivity_matrix = [
    "balance-xor",
    "802.3ad",
]

vm_volumes_matrix = ["container_disk_vm", "data_volume_vm"]
run_strategy_matrix = [
    VirtualMachine.RunStrategy.MANUAL,
    VirtualMachine.RunStrategy.ALWAYS,
    VirtualMachine.RunStrategy.HALTED,
    VirtualMachine.RunStrategy.RERUNONFAILURE,
]

sysprep_source_matrix = ["ConfigMap", "Secret"]

# If the DataImportCron uses a different prefix than the DataSource name
# use data_import_cron_prefix in matrix dict to specify new prefix.
auto_update_data_source_matrix = [
    {"centos-stream9": {"template_os": "centos-stream9"}},
    {"fedora": {"template_os": "fedora"}},
    {"rhel8": {"template_os": "rhel8.4"}},
    {"rhel9": {"template_os": "rhel9.0"}},
]

IMAGE_NAME_STR = "image_name"
IMAGE_PATH_STR = "image_path"
DV_SIZE_STR = "dv_size"
TEMPLATE_LABELS_STR = "template_labels"
OS_STR = "os"
WORKLOAD_STR = "workload"
FLAVOR_STR = "flavor"
LATEST_RELEASE_STR = "latest_released"
OS_VERSION_STR = "os_version"

rhel_os_matrix = [
    {
        "rhel-6-10": {
            OS_VERSION_STR: "6.10",
            IMAGE_NAME_STR: Images.Rhel.RHEL6_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL6_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel6.0",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-7-8": {
            OS_VERSION_STR: "7.8",
            IMAGE_NAME_STR: Images.Rhel.RHEL7_8_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL7_8_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel7.8",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-7-9": {
            OS_VERSION_STR: "7.9",
            IMAGE_NAME_STR: Images.Rhel.RHEL7_9_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL7_9_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel7.9",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-8-6": {
            OS_VERSION_STR: "8.6",
            IMAGE_NAME_STR: Images.Rhel.RHEL8_6_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL8_6_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel8.6",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-8-7": {
            OS_VERSION_STR: "8.7",
            IMAGE_NAME_STR: Images.Rhel.RHEL8_7_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL8_7_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            LATEST_RELEASE_STR: True,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel8.7",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-9-0": {
            OS_VERSION_STR: "9.0",
            IMAGE_NAME_STR: Images.Rhel.RHEL9_0_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL9_0_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel9.0",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "rhel-9-1": {
            OS_VERSION_STR: "9.1",
            IMAGE_NAME_STR: Images.Rhel.RHEL9_1_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Rhel.DIR, Images.Rhel.RHEL9_1_IMG),
            DV_SIZE_STR: Images.Rhel.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "rhel9.1",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
]

windows_os_matrix = [
    {
        "win-10": {
            OS_VERSION_STR: "10",
            IMAGE_NAME_STR: Images.Windows.WIN10_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Windows.DIR, Images.Windows.WIN10_IMG),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win10",
                WORKLOAD_STR: Template.Workload.DESKTOP,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
    {
        "win-2012": {
            OS_VERSION_STR: "2012",
            IMAGE_NAME_STR: Images.Windows.WIN12_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Windows.DIR, Images.Windows.WIN12_IMG),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win2k12r2",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
    {
        "win-2016": {
            OS_VERSION_STR: "2016",
            IMAGE_NAME_STR: Images.Windows.WIN16_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Windows.DIR, Images.Windows.WIN16_IMG),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win2k16",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
    {
        "win-2019": {
            OS_VERSION_STR: "2019",
            IMAGE_NAME_STR: Images.Windows.WIN19_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Windows.DIR, Images.Windows.WIN19_IMG),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            LATEST_RELEASE_STR: True,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win2k19",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
    {
        "win-11": {
            OS_VERSION_STR: "11",
            IMAGE_NAME_STR: Images.Windows.WIN11_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Windows.DIR, Images.Windows.WIN11_IMG),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win11",
                WORKLOAD_STR: Template.Workload.DESKTOP,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
    {
        "win-2022": {
            OS_VERSION_STR: "2022",
            IMAGE_NAME_STR: Images.Windows.WIN2022_IMG,
            IMAGE_PATH_STR: os.path.join(
                Images.Windows.DIR, Images.Windows.WIN2022_IMG
            ),
            DV_SIZE_STR: Images.Windows.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "win2k22",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.MEDIUM,
            },
        }
    },
]

fedora_os_matrix = [
    {
        "fedora-37": {
            IMAGE_NAME_STR: Images.Fedora.FEDORA37_IMG,
            IMAGE_PATH_STR: os.path.join(Images.Fedora.DIR, Images.Fedora.FEDORA37_IMG),
            DV_SIZE_STR: Images.Fedora.DEFAULT_DV_SIZE,
            LATEST_RELEASE_STR: True,
            TEMPLATE_LABELS_STR: {
                OS_STR: "fedora37",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
]

centos_os_matrix = [
    {
        "centos-7": {
            IMAGE_NAME_STR: Images.CentOS.CENTOS7_IMG,
            IMAGE_PATH_STR: os.path.join(Images.CentOS.DIR, Images.CentOS.CENTOS7_IMG),
            DV_SIZE_STR: Images.CentOS.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "centos7.0",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "centos-stream-8": {
            IMAGE_NAME_STR: Images.CentOS.CENTOS_STREAM_8_IMG,
            IMAGE_PATH_STR: os.path.join(
                Images.CentOS.DIR, Images.CentOS.CENTOS_STREAM_8_IMG
            ),
            DV_SIZE_STR: Images.CentOS.DEFAULT_DV_SIZE,
            TEMPLATE_LABELS_STR: {
                OS_STR: "centos-stream8",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
    {
        "centos-stream-9": {
            IMAGE_NAME_STR: Images.CentOS.CENTOS_STREAM_9_IMG,
            IMAGE_PATH_STR: os.path.join(
                Images.CentOS.DIR, Images.CentOS.CENTOS_STREAM_9_IMG
            ),
            DV_SIZE_STR: Images.CentOS.DEFAULT_DV_SIZE,
            LATEST_RELEASE_STR: True,
            TEMPLATE_LABELS_STR: {
                OS_STR: "centos-stream9",
                WORKLOAD_STR: Template.Workload.SERVER,
                FLAVOR_STR: Template.Flavor.TINY,
            },
        }
    },
]

(
    latest_rhel_os_dict,
    latest_windows_os_dict,
    latest_fedora_os_dict,
    latest_centos_os_dict,
) = get_latest_os_dict_list(
    os_list=[rhel_os_matrix, windows_os_matrix, fedora_os_matrix, centos_os_matrix]
)

ip_stack_version_matrix = [
    IPV4_STR,
    IPV6_STR,
]
cnv_pod_matrix = ALL_CNV_PODS
cnv_crd_matrix = ALL_CNV_CRDS
cnv_crypto_policy_matrix = [TLS_OLD_POLICY, TLS_CUSTOM_POLICY]

cnv_related_object_matrix = ALL_HCO_RELATED_OBJECTS


cnv_deployment_matrix = ALL_CNV_DEPLOYMENTS
cnv_daemonset_matrix = ALL_CNV_DAEMONSETS
nmo_removal_matrix = [Service, ReplicaSet, Deployment, Pod]
pod_resource_validation_matrix = [{"cpu": 5}, {"memory": None}]

# VM migration storm test params
vm_deploys = 1  # How many vm of each type to deploy
linux_iterations = 250  # Number of migration iterations of linux VMs
windows_iterations = 500  # Number of migration iterations of windows VMs


# Network configuration
vlans = [f"{_id}" for _id in range(1000, 1020)]

for _dir in dir():
    val = locals()[_dir]
    if type(val) not in [bool, list, dict, str, int]:
        continue

    if _dir in ["encoding", "py_file"]:
        continue

    config[_dir] = locals()[_dir]  # noqa: F821
