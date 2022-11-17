import pytest_testconfig
from ocp_resources.datavolume import DataVolume

from utilities.constants import StorageClassNames
from utilities.storage import HppCsiStorageClass


global config
global_config = pytest_testconfig.load_python(
    py_file="tests/global_config.py", encoding="utf-8"
)

HPP_VOLUME_MODE_ACCESS_MODE = {
    "volume_mode": DataVolume.VolumeMode.FILE,
    "access_mode": DataVolume.AccessMode.RWO,
}

new_hpp_storage_class_matrix = [
    {HppCsiStorageClass.Name.HOSTPATH_CSI_BASIC: HPP_VOLUME_MODE_ACCESS_MODE},
    {HppCsiStorageClass.Name.HOSTPATH_CSI_PVC_BLOCK: HPP_VOLUME_MODE_ACCESS_MODE},
]

storage_class_matrix = [
    {
        StorageClassNames.NFS: {
            "volume_mode": DataVolume.VolumeMode.FILE,
            "access_mode": DataVolume.AccessMode.RWX,
        }
    },
]

for _dir in dir():
    val = locals()[_dir]
    if type(val) not in [bool, list, dict, str, int]:
        continue

    if _dir in ["encoding", "py_file"]:
        continue

    config[_dir] = locals()[_dir]  # noqa: F821
