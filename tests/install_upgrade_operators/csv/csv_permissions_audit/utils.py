"""
Test for https://issues.redhat.com/browse/CNV-22907
"""

import os
import pathlib

from ocp_resources.cluster_service_version import ClusterServiceVersion
from ocp_utilities.infra import cluster_resource


def get_yaml_file_path():
    file_path = pathlib.Path(__file__).parent.resolve()
    return os.path.join(str(file_path), "csv-permissions.yaml")


def get_csv_permissions(namespace="openshift-cnv"):
    result_dict = {}
    service_account_name_str = "serviceAccountName"
    csv = list(cluster_resource(ClusterServiceVersion).get(namespace=namespace))
    assert csv, f"CSV not found under {namespace} namespace"
    csv_dict = csv[0].instance.to_dict()
    spec = csv_dict["spec"]["install"]["spec"]
    permissions_dict = spec["permissions"]
    cluster_permissions_dict = spec["clusterPermissions"]

    for permissions in permissions_dict:
        result_dict.setdefault(permissions[service_account_name_str], {})[
            "permission"
        ] = permissions["rules"]

    for cluster_permissions in cluster_permissions_dict:
        result_dict.setdefault(cluster_permissions[service_account_name_str], {})[
            "cluster_permission"
        ] = cluster_permissions["rules"]

    return result_dict


def get_global_permissions(errors_dict, permissions, service_account_name, key_name):
    for _permission in permissions:
        if "*" in _permission["verbs"]:
            for _resource in _permission["resources"]:
                errors_dict.setdefault(service_account_name, {})[key_name] = {
                    "resource": _resource,
                    "permission-verbs": _permission["verbs"],
                }
