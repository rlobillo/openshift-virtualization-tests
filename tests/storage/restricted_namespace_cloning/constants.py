# Permissions and Verbs for set_permissions
from ocp_resources.resource import Resource


DATAVOLUMES = ["datavolumes"]
DATAVOLUMES_SRC = ["datavolumes/source"]
DATAVOLUMES_AND_DVS_SRC = ["datavolumes", "datavolumes/source"]
PERSISTENT_VOLUME_CLAIMS = ["persistentvolumeclaims"]

CREATE = ["create"]
CREATE_DELETE = ["create", "delete"]
LIST_GET = ["list", "get"]
CREATE_DELETE_LIST_GET = ["create", "delete", "list", "get"]
ALL = ["*"]

PERMISSIONS_SRC = "permissions_src"
PERMISSIONS_DST = "permissions_dst"
VERBS_SRC = "verbs_src"
VERBS_DST = "verbs_dst"

TARGET_DV = "target-dv"
PVC = "pvc"

PERMISSIONS_SRC_SA = "permissions_src_sa"
PERMISSIONS_DST_SA = "permissions_dst_sa"
VERBS_SRC_SA = "verbs_src_sa"
VERBS_DST_SA = "verbs_dst_sa"
VM_FOR_TEST = "vm-for-test"
METADATA = "metadata"
SPEC = "spec"

RBAC_AUTHORIZATION_API_GROUP = Resource.ApiGroup.RBAC_AUTHORIZATION_K8S_IO
