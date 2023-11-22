import os

from ocp_resources.cdi import CDI
from ocp_resources.hyperconverged import HyperConverged
from ocp_resources.kubevirt import KubeVirt
from ocp_resources.network_addons_config import NetworkAddonsConfig
from ocp_resources.resource import Resource
from ocp_resources.ssp import SSP
from openshift.dynamic.exceptions import InternalServerError
from urllib3.exceptions import (
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ResponseError,
)


# Images
BASE_IMAGES_DIR = "cnv-tests"
NON_EXISTS_IMAGE = "non-exists-image-test-cnao-alerts"


class Images:
    class Cirros:
        RAW_IMG = "cirros-0.4.0-x86_64-disk.raw"
        RAW_IMG_GZ = "cirros-0.4.0-x86_64-disk.raw.gz"
        RAW_IMG_XZ = "cirros-0.4.0-x86_64-disk.raw.xz"
        QCOW2_IMG = "cirros-0.4.0-x86_64-disk.qcow2"
        QCOW2_IMG_GZ = "cirros-0.4.0-x86_64-disk.qcow2.gz"
        QCOW2_IMG_XZ = "cirros-0.4.0-x86_64-disk.qcow2.xz"
        DISK_DEMO = "cirros-registry-disk-demo"
        DIR = f"{BASE_IMAGES_DIR}/cirros-images"
        MOD_AUTH_BASIC_DIR = f"{BASE_IMAGES_DIR}/mod-auth-basic/cirros-images"
        DEFAULT_DV_SIZE = "1Gi"
        DEFAULT_MEMORY_SIZE = "64M"

    class Rhel:
        RHEL6_IMG = "rhel-610.qcow2"
        RHEL7_8_IMG = "rhel-78.qcow2"
        RHEL7_9_IMG = "rhel-79.qcow2"
        RHEL8_0_IMG = "rhel-8.qcow2"
        RHEL8_2_IMG = "rhel-82.qcow2"
        RHEL8_2_EFI_IMG = "rhel-82-efi.qcow2"
        RHEL8_6_IMG = "rhel-86.qcow2"
        RHEL8_7_IMG = "rhel-87.qcow2"
        RHEL9_0_IMG = "rhel-90.qcow2"
        RHEL9_1_IMG = "rhel-91.qcow2"
        RHEL8_REGISTRY_GUEST_IMG = "registry.redhat.io/rhel8/rhel-guest-image"
        RHEL9_REGISTRY_GUEST_IMG = "registry.redhat.io/rhel9/rhel-guest-image"
        DIR = f"{BASE_IMAGES_DIR}/rhel-images"
        DEFAULT_DV_SIZE = "20Gi"
        DEFAULT_MEMORY_SIZE = "1.5Gi"

    class Windows:
        WIN10_IMG = "win_10.qcow2"
        WIN10_WSL2_IMG = "win_10_wsl2.qcow2"
        WIN10_EFI_IMG = "win_10_efi.qcow2"
        WIN12_IMG = "win_12.qcow2"
        WIN16_IMG = "win_16.qcow2"
        WIN19_IMG = "win_19.qcow2"
        WIN11_IMG = "win_11.qcow2"
        WIN19_NVIDIA_IMG = "win_19_nv.qcow2"
        WIN19_RAW = "win19.raw"
        WIN2022_IMG = "win_2022.qcow2"
        DIR = f"{BASE_IMAGES_DIR}/windows-images"
        RAW_DIR = f"{DIR}/raw_images"
        DEFAULT_DV_SIZE = "70Gi"
        WSL2_DV_SIZE = "40Gi"
        DEFAULT_MEMORY_SIZE = "8Gi"
        DEFAULT_MEMORY_SIZE_WSL = "12Gi"
        DEFAULT_CPU_THREADS = 2

    class Fedora:
        FEDORA37_IMG = "Fedora-Cloud-Base-37-1.7.x86_64.qcow2"
        DISK_DEMO = "fedora-cloud-registry-disk-demo"
        DIR = f"{BASE_IMAGES_DIR}/fedora-images"
        DEFAULT_DV_SIZE = "10Gi"

    class CentOS:
        CENTOS7_IMG = "CentOS-7-x86_64-GenericCloud-2009.qcow2"
        CENTOS_STREAM_8_IMG = "CentOS-Stream-GenericCloud-8-20210603.0.x86_64.qcow2"
        CENTOS_STREAM_9_IMG = "CentOS-Stream-GenericCloud-9-20220107.0.x86_64.qcow2"
        DIR = f"{BASE_IMAGES_DIR}/centos-images"
        DEFAULT_DV_SIZE = "15Gi"

    class Cdi:
        QCOW2_IMG = "cirros-qcow2.img"
        DIR = f"{BASE_IMAGES_DIR}/cdi-test-images"


# Virtctl constants
VIRTCTL_CLI_DOWNLOADS = "virtctl-clidownloads-kubevirt-hyperconverged"

#  Network constants
SRIOV = "sriov"
IP_FAMILY_POLICY_PREFER_DUAL_STACK = "PreferDualStack"
MTU_9000 = 9000
IPV4_STR = "ipv4"
IPV6_STR = "ipv6"
CLUSTER_NETWORK_ADDONS_OPERATOR = "cluster-network-addons-operator"
BRIDGE_MARKER = "bridge-marker"
KUBE_CNI_LINUX_BRIDGE_PLUGIN = "kube-cni-linux-bridge-plugin"
LINUX_BRIDGE = "linux-bridge"
OVS_BRIDGE = "ovs-bridge"
KUBEMACPOOL_CERT_MANAGER = "kubemacpool-cert-manager"
KUBEMACPOOL_MAC_CONTROLLER_MANAGER = "kubemacpool-mac-controller-manager"
KUBEMACPOOL_MAC_RANGE_CONFIG = "kubemacpool-mac-range-config"
NMSTATE_HANDLER = "nmstate-handler"
ISTIO_SYSTEM_DEFAULT_NS = "istio-system"
SSH_PORT_22 = 22
PORT_80 = 80
ACTIVE_BACKUP = "active-backup"

#  Time constants
TIMEOUT_5SEC = 5
TIMEOUT_10SEC = 10
TIMEOUT_15SEC = 15
TIMEOUT_20SEC = 20
TIMEOUT_30SEC = 30
TIMEOUT_90SEC = 90
TIMEOUT_1MIN = 60
TIMEOUT_2MIN = 2 * 60
TIMEOUT_3MIN = 3 * 60
TIMEOUT_4MIN = 4 * 60
TIMEOUT_5MIN = 5 * 60
TIMEOUT_6MIN = 6 * 60
TIMEOUT_8MIN = 8 * 60
TIMEOUT_9MIN = 9 * 60
TIMEOUT_10MIN = 10 * 60
TIMEOUT_11MIN = 11 * 60
TIMEOUT_12MIN = 12 * 60
TIMEOUT_15MIN = 15 * 60
TIMEOUT_20MIN = 20 * 60
TIMEOUT_25MIN = 25 * 60
TIMEOUT_30MIN = 30 * 60
TIMEOUT_35MIN = 35 * 60
TIMEOUT_40MIN = 40 * 60
TIMEOUT_60MIN = 60 * 60
TIMEOUT_75MIN = 75 * 60
TIMEOUT_90MIN = 90 * 60
TIMEOUT_180MIN = 180 * 60
TIMEOUT_12HRS = 12 * 60 * 60

TCP_TIMEOUT_30SEC = 30.0

#  OS constants
OS_FLAVOR_CIRROS = "cirros"
OS_FLAVOR_WINDOWS = "win"
OS_FLAVOR_RHEL = "rhel"
OS_FLAVOR_FEDORA = "fedora"
OS_FLAVOR_CENTOS = "centos"

OS_LOGIN_PASSWORD = "password"
OS_LOGIN_PARAMS = {
    OS_FLAVOR_RHEL: {
        "username": "cloud-user",
        "password": OS_LOGIN_PASSWORD,
    },
    OS_FLAVOR_FEDORA: {
        "username": "fedora",
        "password": OS_LOGIN_PASSWORD,
    },
    OS_FLAVOR_CENTOS: {
        "username": "centos",
        "password": OS_LOGIN_PASSWORD,
    },
    OS_FLAVOR_CIRROS: {
        "username": "cirros",
        "password": "gocubsgo",
    },
    OS_FLAVOR_WINDOWS: {
        "username": "Administrator",
        "password": "Heslo123",
    },
}

# OpenShift Virtualization components constants
VIRT_OPERATOR = "virt-operator"
VIRT_LAUNCHER = "virt-launcher"
VIRT_API = "virt-api"
VIRT_CONTROLLER = "virt-controller"
VIRT_HANDLER = "virt-handler"
VIRT_TEMPLATE_VALIDATOR = "virt-template-validator"
VIRT_EXPORTPROXY = "virt-exportproxy"
SSP_KUBEVIRT_HYPERCONVERGED = "ssp-kubevirt-hyperconverged"
SSP_OPERATOR = "ssp-operator"
CDI_OPERATOR = "cdi-operator"
CDI_APISERVER = "cdi-apiserver"
CDI_DEPLOYMENT = "cdi-deployment"
CDI_UPLOADPROXY = "cdi-uploadproxy"
HCO_OPERATOR = "hco-operator"
HCO_WEBHOOK = "hco-webhook"
HOSTPATH_CSI_BASIC = "hostpath-csi-basic"
HOSTPATH_PROVISIONER_CSI = "hostpath-provisioner-csi"
HOSTPATH_PROVISIONER = "hostpath-provisioner"
HOSTPATH_PROVISIONER_OPERATOR = "hostpath-provisioner-operator"
HYPERCONVERGED_CLUSTER_CLI_DOWNLOAD = "hyperconverged-cluster-cli-download"
KUBEVIRT_HCO_NAME = "kubevirt-kubevirt-hyperconverged"
HCO_PART_OF_LABEL_VALUE = "hyperconverged-cluster"
MANAGED_BY_LABEL_VALUE_OLM = "olm"
HPP_POOL = "hpp-pool"
HCO_CATALOG_SOURCE = "hco-catalogsource"
TEKTON_TASK_OPERATOR = "tekton-tasks-operator"
KUBEVIRT_PLUGIN = "kubevirt-plugin"
CNAO_OPERATOR = "cnao-operator"
HYPERCONVERGED_CLUSTER = "hyperconverged-cluster"

# CDI related constants
CDI_SECRETS = [
    "cdi-apiserver-server-cert",
    "cdi-apiserver-signer",
    "cdi-uploadproxy-server-cert",
    "cdi-uploadproxy-signer",
    "cdi-uploadserver-client-cert",
    "cdi-uploadserver-client-signer",
    "cdi-uploadserver-signer",
]

CDI_CONFIGMAPS = [
    "cdi-apiserver-signer-bundle",
    "cdi-config",
    "cdi-controller-leader-election-helper",
    "cdi-insecure-registries",
    "cdi-uploadproxy-signer-bundle",
    "cdi-uploadserver-client-signer-bundle",
    "cdi-uploadserver-signer-bundle",
]

# Miscellaneous constants
UTILITY = "utility"
OPERATOR_NAME_SUFFIX = "operator"
PODS_TO_COLLECT_INFO = [
    HCO_OPERATOR,
    VIRT_OPERATOR,
    SSP_OPERATOR,
    VIRT_LAUNCHER,
    VIRT_API,
    VIRT_CONTROLLER,
    VIRT_HANDLER,
    VIRT_TEMPLATE_VALIDATOR,
    "cdi-importer",
    UTILITY,
    NMSTATE_HANDLER,
]
WORKERS_TYPE = "WORKERS_TYPE"
FILTER_BY_OS_OPTION = "filter-by-os=linux/amd64"


# GPU/vGPU Common constants
# The GPU tests require GPU Device on the Worker Nodes.
# ~]$ lspci -nnv | grep -i NVIDIA  , should display the GPU_DEVICE_ID
GPU_DEVICE_MANUFACTURER = "nvidia.com"
GPU_DEVICE_ID = "10de:1eb8"

# GPU Passthrough constants
NVIDIA_VFIO_MANAGER_DS = "nvidia-vfio-manager"
GPU_DEVICE_NAME = f"{GPU_DEVICE_MANUFACTURER}/TU104GL_Tesla_T4"

# vGPU constants
NVIDIA_VGPU_MANAGER_DS = "nvidia-vgpu-manager-daemonset"
VGPU_DEVICE_NAME = f"{GPU_DEVICE_MANUFACTURER}/GRID_T4_2Q"
MDEV_NAME = "GRID T4-2Q"
MDEV_AVAILABLE_INSTANCES = "8"
MDEV_TYPE = "nvidia-231"
NVIDIA_GRID_DRIVER_NAME = "NVIDIA GRID"

VGPU_GRID_T4_16Q_NAME = f"{GPU_DEVICE_MANUFACTURER}/GRID_T4_16Q"
MDEV_GRID_T4_16Q_NAME = "GRID T4-16Q"
MDEV_GRID_T4_16Q_AVAILABLE_INSTANCES = "1"
MDEV_GRID_T4_16Q_TYPE = "nvidia-234"

# Kernel Device Driver
# Compute: GPU Devices are bound to this Kernel Driver for GPU Passthrough.
# Networking: For SRIOV Node Policy, The driver type for the virtual functions
KERNEL_DRIVER = "vfio-pci"

# cloud-init constants
CLOUD_INIT_DISK_NAME = "cloudinitdisk"
CLOUND_INIT_CONFIG_DRIVE = "cloudInitConfigDrive"
CLOUD_INIT_NO_CLOUD = "cloudInitNoCloud"

# Kubemacpool constants
KMP_VM_ASSIGNMENT_LABEL = "mutatevirtualmachines.kubemacpool.io"
KMP_ENABLED_LABEL = "allocate"
KMP_DISABLED_LABEL = "ignore"

# SSH constants
CNV_SSH_KEY_PATH = os.path.join(os.getcwd(), "utilities/cnv-qe-jenkins.key")

# CPU ARCH
INTEL = "Intel"
AMD = "AMD"

# unprivileged_client constants
UNPRIVILEGED_USER = "unprivileged-user"
UNPRIVILEGED_PASSWORD = "unprivileged-password"

# Red Hat Subscription Manager credentials.
RHSM_USER = "cnv-qe-automation-stage"
RHSM_PASSWD = "redhatredhat"

# KUBECONFIG variables
KUBECONFIG = "KUBECONFIG"

# commands
LS_COMMAND = "ls -1 | sort | tr '\n' ' '"

# hotplug disk serial
HOTPLUG_DISK_SERIAL = "1234567890"

# pyetest configuration
SANITY_TESTS_FAILURE = 99
HCO_SUBSCRIPTION = "hco-operatorhub"

# VM configuration
LIVE_MIGRATE = "LiveMigrate"
ROOTDISK = "rootdisk"

# Upgrade tests configuration
DEPENDENCY_SCOPE_SESSION = "session"

# Feature gates
ENABLE_COMMON_BOOT_IMAGE_IMPORT_FEATURE_GATE = "enableCommonBootImageImport"

# Common templates constants
DATA_SOURCE_NAME = "DATA_SOURCE_NAME"
DATA_SOURCE_NAMESPACE = "DATA_SOURCE_NAMESPACE"
SSP_CR_COMMON_TEMPLATES_LIST_KEY_NAME = "dataImportCronTemplates"
COMMON_TEMPLATES_KEY_NAME = "commonTemplates"

KUBEVIRT_HYPERCONVERGED_PROMETHEUS_RULE = "kubevirt-hyperconverged-prometheus-rule"
HYPERCONVERGED_CLUSTER_OPERATOR_METRICS = "hyperconverged-cluster-operator-metrics"
KUBEVIRT_HYPERCONVERGED_OPERATOR_METRICS = "kubevirt-hyperconverged-operator-metrics"
KUBEVIRT_CLUSTER_CRITICAL = "kubevirt-cluster-critical"
KUBEVIRT_KUBEVIRT_HYPERCONVERGED = "kubevirt-kubevirt-hyperconverged"
CDI_KUBEVIRT_HYPERCONVERGED = "cdi-kubevirt-hyperconverged"
CLUSTER = "cluster"
TTO_KUBEVIRT_HYPERCONVERGED = "tto-kubevirt-hyperconverged"
VIRTCTL_CLIDOWNLOADS_KUBEVIRT_HYPERCONVERGED = (
    "virtctl-clidownloads-kubevirt-hyperconverged"
)
KUBEVIRT_PLUGIN_SERVICE = "kubevirt-plugin-service"
CREATING_VIRTUAL_MACHINE = "creating-virtual-machine"
UPLOAD_BOOT_SOURCE = "upload-boot-source"
GRAFANA_DASHBOARD_KUBEVIRT_TOP_CONSUMERS = "grafana-dashboard-kubevirt-top-consumers"
RHEL8_GUEST = "rhel8-guest"
RHEL9_GUEST = "rhel9-guest"
VIRTIO_WIN = "virtio-win"
NGINX_CONF = "nginx-conf"


# components kind
ROLEBINDING_STR = "RoleBinding"
PROMETHEUSRULE_STR = "PrometheusRule"
ROLE_STR = "Role"
SERVICE_STR = "Service"
SERVICEMONITOR_STR = "ServiceMonitor"
PRIORITYCLASS_STR = "PriorityClass"
KUBEVIRT_STR = "KubeVirt"
NETWORKADDONSCONFIG_STR = "NetworkAddonsConfig"
TEKTONTASKS_STR = "TektonTasks"
CONSOLECLIDOWNLOAD_STR = "ConsoleCLIDownload"
ROUTE_STR = "Route"
CONSOLEQUICKSTART_STR = "ConsoleQuickStart"
CONFIGMAP_STR = "ConfigMap"
IMAGESTREAM_STR = "ImageStream"
DEPLOYMENT_STR = "Deployment"
CONSOLE_PLUGIN_STR = "ConsolePlugin"
KUBEVIRT_PLUGIN = "kubevirt-plugin"
CDI_STR = "CDI"
SSP_STR = "SSP"
# All hco relate objects with kind
ALL_HCO_RELATED_OBJECTS = [
    {KUBEVIRT_HYPERCONVERGED_PROMETHEUS_RULE: PROMETHEUSRULE_STR},
    {HYPERCONVERGED_CLUSTER_OPERATOR_METRICS: ROLE_STR},
    {HYPERCONVERGED_CLUSTER_OPERATOR_METRICS: ROLEBINDING_STR},
    {KUBEVIRT_HYPERCONVERGED_OPERATOR_METRICS: SERVICE_STR},
    {KUBEVIRT_HYPERCONVERGED_OPERATOR_METRICS: SERVICEMONITOR_STR},
    {KUBEVIRT_CLUSTER_CRITICAL: PRIORITYCLASS_STR},
    {KUBEVIRT_KUBEVIRT_HYPERCONVERGED: KUBEVIRT_STR},
    {CDI_KUBEVIRT_HYPERCONVERGED: CDI_STR},
    {CLUSTER: NETWORKADDONSCONFIG_STR},
    {SSP_KUBEVIRT_HYPERCONVERGED: SSP_STR},
    {TTO_KUBEVIRT_HYPERCONVERGED: TEKTONTASKS_STR},
    {VIRTCTL_CLIDOWNLOADS_KUBEVIRT_HYPERCONVERGED: CONSOLECLIDOWNLOAD_STR},
    {HYPERCONVERGED_CLUSTER_CLI_DOWNLOAD: ROUTE_STR},
    {HYPERCONVERGED_CLUSTER_CLI_DOWNLOAD: SERVICE_STR},
    {KUBEVIRT_PLUGIN_SERVICE: SERVICE_STR},
    {CREATING_VIRTUAL_MACHINE: CONSOLEQUICKSTART_STR},
    {UPLOAD_BOOT_SOURCE: CONSOLEQUICKSTART_STR},
    {GRAFANA_DASHBOARD_KUBEVIRT_TOP_CONSUMERS: CONFIGMAP_STR},
    {RHEL8_GUEST: IMAGESTREAM_STR},
    {RHEL9_GUEST: IMAGESTREAM_STR},
    {VIRTIO_WIN: CONFIGMAP_STR},
    {VIRTIO_WIN: ROLE_STR},
    {VIRTIO_WIN: ROLEBINDING_STR},
    {KUBEVIRT_PLUGIN: DEPLOYMENT_STR},
    {NGINX_CONF: CONFIGMAP_STR},
    {KUBEVIRT_PLUGIN: CONSOLE_PLUGIN_STR},
]

ALL_CNV_PODS = [
    BRIDGE_MARKER,
    CDI_APISERVER,
    CDI_DEPLOYMENT,
    CDI_OPERATOR,
    CDI_UPLOADPROXY,
    CLUSTER_NETWORK_ADDONS_OPERATOR,
    HCO_OPERATOR,
    HCO_WEBHOOK,
    HOSTPATH_PROVISIONER_CSI,
    HOSTPATH_PROVISIONER_OPERATOR,
    HYPERCONVERGED_CLUSTER_CLI_DOWNLOAD,
    KUBE_CNI_LINUX_BRIDGE_PLUGIN,
    KUBEMACPOOL_CERT_MANAGER,
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    KUBEVIRT_PLUGIN,
    SSP_OPERATOR,
    VIRT_API,
    VIRT_CONTROLLER,
    VIRT_HANDLER,
    VIRT_OPERATOR,
    VIRT_TEMPLATE_VALIDATOR,
    TEKTON_TASK_OPERATOR,
    VIRT_EXPORTPROXY,
]
ALL_CNV_DEPLOYMENTS = [
    CDI_APISERVER,
    CDI_DEPLOYMENT,
    CDI_OPERATOR,
    CDI_UPLOADPROXY,
    CLUSTER_NETWORK_ADDONS_OPERATOR,
    HCO_OPERATOR,
    HCO_WEBHOOK,
    HOSTPATH_PROVISIONER_OPERATOR,
    HPP_POOL,
    HYPERCONVERGED_CLUSTER_CLI_DOWNLOAD,
    KUBEMACPOOL_CERT_MANAGER,
    KUBEMACPOOL_MAC_CONTROLLER_MANAGER,
    KUBEVIRT_PLUGIN,
    SSP_OPERATOR,
    VIRT_API,
    VIRT_CONTROLLER,
    VIRT_OPERATOR,
    VIRT_TEMPLATE_VALIDATOR,
    TEKTON_TASK_OPERATOR,
    VIRT_EXPORTPROXY,
]
ALL_CNV_DAEMONSETS = [
    BRIDGE_MARKER,
    KUBE_CNI_LINUX_BRIDGE_PLUGIN,
    HOSTPATH_PROVISIONER_CSI,
    VIRT_HANDLER,
]
# Node labels
NODE_TYPE_WORKER_LABEL = {"node-type": "worker"}
CPU_MODEL_LABEL_PREFIX = f"cpu-model.node.{Resource.ApiGroup.KUBEVIRT_IO}"
NODE_ROLE_KUBERNETES_IO = "node-role.kubernetes.io"
WORKER_NODE_LABEL_KEY = f"{NODE_ROLE_KUBERNETES_IO}/worker"
MASTER_NODE_LABEL_KEY = f"{NODE_ROLE_KUBERNETES_IO}/master"
CDI_KUBEVIRT_HYPERCONVERGED = "cdi-kubevirt-hyperconverged"
TSC_FREQUENCY = "tsc-frequency"

# Container constants
CNV_TESTS_CONTAINER = "CNV_TESTS_CONTAINER"
DEFAULT_HCO_CONDITIONS = {
    Resource.Condition.AVAILABLE: Resource.Condition.Status.TRUE,
    Resource.Condition.PROGRESSING: Resource.Condition.Status.FALSE,
    Resource.Condition.RECONCILE_COMPLETE: Resource.Condition.Status.TRUE,
    Resource.Condition.DEGRADED: Resource.Condition.Status.FALSE,
    Resource.Condition.UPGRADEABLE: Resource.Condition.Status.TRUE,
}
DEFAULT_KUBEVIRT_CONDITIONS = {
    Resource.Condition.AVAILABLE: Resource.Condition.Status.TRUE,
    Resource.Condition.PROGRESSING: Resource.Condition.Status.FALSE,
    Resource.Condition.CREATED: Resource.Condition.Status.TRUE,
    Resource.Condition.DEGRADED: Resource.Condition.Status.FALSE,
}
DEFAULT_RESOURCE_CONDITIONS = {
    Resource.Condition.AVAILABLE: Resource.Condition.Status.TRUE,
    Resource.Condition.PROGRESSING: Resource.Condition.Status.FALSE,
    Resource.Condition.DEGRADED: Resource.Condition.Status.FALSE,
}
EXPECTED_STATUS_CONDITIONS = {
    HyperConverged: DEFAULT_HCO_CONDITIONS,
    KubeVirt: DEFAULT_KUBEVIRT_CONDITIONS,
    CDI: DEFAULT_RESOURCE_CONDITIONS,
    SSP: DEFAULT_RESOURCE_CONDITIONS,
    NetworkAddonsConfig: DEFAULT_RESOURCE_CONDITIONS,
}
MACHINE_CONFIG_PODS_TO_COLLECT = [
    "machine-config-operator",
    "machine-config-daemon",
    "machine-config-controller",
]
BREW_REGISTERY_SOURCE = "brew.registry.redhat.io"
ICSP_FILE = "imageContentSourcePolicy.yaml"
BASE_EXCEPTIONS_DICT = {
    NewConnectionError: [],
    ConnectionRefusedError: [],
    ProtocolError: [],
    ResponseError: [],
    MaxRetryError: [],
    InternalServerError: [],
    ConnectionResetError: [],
}
OC_ADM_LOGS_COMMAND = "oc adm node-logs"
AUDIT_LOGS_PATH = "--path=kube-apiserver"
CNV_TEST_SERVICE_ACCOUNT = "cnv-tests-sa"
VM_CRD = f"virtualmachines.{Resource.ApiGroup.KUBEVIRT_IO}"
ALL_CNV_CRDS = [
    f"cdiconfigs.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"cdis.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"dataimportcrons.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"datasources.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"datavolumes.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"hostpathprovisioners.{Resource.ApiGroup.HOSTPATHPROVISIONER_KUBEVIRT_IO}",
    f"hyperconvergeds.{Resource.ApiGroup.HCO_KUBEVIRT_IO}",
    f"kubevirts.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"migrationpolicies.{Resource.ApiGroup.MIGRATIONS_KUBEVIRT_IO}",
    f"networkaddonsconfigs.{Resource.ApiGroup.NETWORKADDONSOPERATOR_NETWORK_KUBEVIRT_IO}",
    f"objecttransfers.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"ssps.{Resource.ApiGroup.SSP_KUBEVIRT_IO}",
    f"storageprofiles.{Resource.ApiGroup.CDI_KUBEVIRT_IO}",
    f"tektontasks.{Resource.ApiGroup.TEKTONTASKS_KUBEVIRT_IO}",
    f"virtualmachineclusterinstancetypes.{Resource.ApiGroup.INSTANCETYPE_KUBEVIRT_IO}",
    f"virtualmachineinstancetypes.{Resource.ApiGroup.INSTANCETYPE_KUBEVIRT_IO}",
    f"virtualmachineinstancemigrations.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachineinstancepresets.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachineinstancereplicasets.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachineinstances.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachinepools.{Resource.ApiGroup.POOL_KUBEVIRT_IO}",
    f"virtualmachinerestores.{Resource.ApiGroup.SNAPSHOT_KUBEVIRT_IO}",
    VM_CRD,
    f"virtualmachinesnapshotcontents.{Resource.ApiGroup.SNAPSHOT_KUBEVIRT_IO}",
    f"virtualmachinesnapshots.{Resource.ApiGroup.SNAPSHOT_KUBEVIRT_IO}",
    f"virtualmachineclones.clone.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachineclusterpreferences.{Resource.ApiGroup.INSTANCETYPE_KUBEVIRT_IO}",
    f"virtualmachineexports.export.{Resource.ApiGroup.KUBEVIRT_IO}",
    f"virtualmachinepreferences.{Resource.ApiGroup.INSTANCETYPE_KUBEVIRT_IO}",
]
PRODUCTION_CATALOG_SOURCE = "redhat-operators"
TLS_OLD_POLICY = "old"
TLS_CUSTOM_POLICY = "custom"
IMAGE_CRON_STR = "image-cron"
TLS_SECURITY_PROFILE = "tlsSecurityProfile"
KUBELET_READY_CONDITION = {"KubeletReady": "True"}
ICSP_FILTER_BY_OS_LINUX_AMD64 = "filter-by-os=linux/amd64"


class StorageClassNames:
    CEPH_RBD = "ocs-storagecluster-ceph-rbd"
    HOSTPATH = "hostpath-provisioner"
    NFS = "nfs"
    TOPOLVM = "lvms-vg1"
    RH_INTERNAL_NFS = "rh-internal-nfs"


# Namespace constants
class NamespacesNames:
    OPENSHIFT = "openshift"
    OPENSHIFT_CONFIG = "openshift-config"
    OPENSHIFT_APISERVER = "openshift-apiserver"
    OPENSHIFT_STORAGE = "openshift-storage"
    OPENSHIFT_CLUSTER_STORAGE_OPERATOR = "openshift-cluster-storage-operator"
    CHAOS = "chaos"
    DEFAULT = "default"
    NVIDIA_GPU_OPERATOR = "nvidia-gpu-operator"


class UpgradeStreams:
    X_STREAM = "x-stream"
    Y_STREAM = "y-stream"
    Z_STREAM = "z-stream"


EUS_ERROR_CODE = 98
EVICTION_STRATEGY = "evictionStrategy"
POD_SECURITY_NAMESPACE_LABELS = {
    "pod-security.kubernetes.io/enforce": "privileged",
    "security.openshift.io/scc.podSecurityLabelSync": "false",
}
CNV_TEST_RUN_IN_PROGRESS = "cnv-tests-run-in-progress"
