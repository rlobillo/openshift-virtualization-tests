"""
all function in this file must accept only matrix arg.
def foo_matrix(matrix):
    <customize matrix code>
    return matrix
"""
from ocp_resources.storage_class import StorageClass
from ocp_utilities.infra import get_client

from utilities.infra import cluster_resource
from utilities.storage import is_snapshot_supported_by_sc


def snapshot_matrix(matrix):
    matrix_to_return = []
    for storage_class in matrix:
        if is_snapshot_supported_by_sc(
            sc_name=[*storage_class][0],
            client=get_client(),
        ):
            matrix_to_return.append(storage_class)
    return matrix_to_return


def without_snapshot_capability_matrix(matrix):
    matrix_to_return = []
    for storage_class in matrix:
        if not is_snapshot_supported_by_sc(
            sc_name=[*storage_class][0],
            client=get_client(),
        ):
            matrix_to_return.append(storage_class)
    return matrix_to_return


def online_resize_matrix(matrix):
    matrix_to_return = []
    for storage_class in matrix:
        storage_class_object = StorageClass(name=[*storage_class][0])
        if storage_class_object.instance.get("allowVolumeExpansion"):
            matrix_to_return.append(storage_class)
    return matrix_to_return


def hpp_matrix(matrix):
    matrix_to_return = []
    for storage_class in matrix:
        storage_class_object = cluster_resource(StorageClass)(name=[*storage_class][0])
        if (
            storage_class_object.instance.provisioner
            == cluster_resource(StorageClass).Provisioner.HOSTPATH_CSI
        ):
            matrix_to_return.append(storage_class)
    return matrix_to_return
