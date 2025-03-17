from utilities.constants import Images, StorageClassNames
from utilities.storage import HppCsiStorageClass


DV_PARAMS = {
    "dv_name": "source-dv",
    "source": "http",
    "image": f"{Images.Cirros.DIR}/{Images.Cirros.QCOW2_IMG}",
    "dv_size": "500Mi",
}

ADMIN_NAMESPACE_PARAM = {"use_unprivileged_client": False}

HPP_STORAGE_CLASSES = [
    StorageClassNames.HOSTPATH,
    HppCsiStorageClass.Name.HOSTPATH_CSI_LEGACY,
    HppCsiStorageClass.Name.HOSTPATH_CSI_BASIC,
    HppCsiStorageClass.Name.HOSTPATH_CSI_PVC_BLOCK,
]

REGISTRY_STR = "registry"
INTERNAL_HTTP_CONFIGMAP_NAME = "internal-https-configmap"
