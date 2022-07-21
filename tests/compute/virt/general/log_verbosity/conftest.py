import pytest
from ocp_resources.kubevirt import KubeVirt

from utilities.hco import ResourceEditorValidateHCOReconcile


@pytest.fixture(scope="class")
def updated_log_verbosity_config(
    request,
    admin_client,
    hco_namespace,
    hyperconverged_resource_scope_class,
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_class: {
                "spec": {"logVerbosityConfig": request.param}
            }
        },
        list_resource_reconcile=[KubeVirt],
        wait_for_reconcile_post_update=True,
    ):
        yield
