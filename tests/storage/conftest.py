"""
Pytest conftest file for CNV CDI tests
"""

import base64
import logging
import os
import ssl

import pytest
from ocp_resources.cdi import CDI
from ocp_resources.configmap import ConfigMap
from ocp_resources.datavolume import DataVolume
from ocp_resources.deployment import Deployment
from ocp_resources.resource import ResourceEditor
from ocp_resources.route import Route
from ocp_resources.secret import Secret
from ocp_resources.storage_class import StorageClass
from ocp_resources.utils import TimeoutSampler
from ocp_resources.virtual_machine_snapshot import VirtualMachineSnapshot
from openshift.dynamic.exceptions import ResourceNotFoundError
from pytest_testconfig import config as py_config

from tests.storage.constants import HPP_STORAGE_CLASSES, REGISTRY_STR
from tests.storage.utils import (
    HttpService,
    check_snapshot_indication,
    get_hpp_daemonset,
    get_storage_class_with_specified_volume_mode,
    hpp_cr_suffix,
    is_hpp_cr_legacy,
)
from utilities.constants import (
    CDI_OPERATOR,
    CDI_UPLOADPROXY,
    CNV_TESTS_CONTAINER,
    OS_FLAVOR_CIRROS,
    Images,
)
from utilities.hco import (
    ResourceEditorValidateHCOReconcile,
    hco_cr_jsonpatch_annotations_dict,
)
from utilities.infra import INTERNAL_HTTP_SERVER_ADDRESS, cluster_resource, is_jira_open
from utilities.storage import (
    HttpDeployment,
    create_cirros_dv_for_snapshot_dict,
    data_volume,
    downloaded_image,
    sc_volume_binding_mode_is_wffc,
    write_file,
)
from utilities.virt import VirtualMachineForTests


LOGGER = logging.getLogger(__name__)
LOCAL_PATH = f"/tmp/{Images.Cdi.QCOW2_IMG}"
ROUTER_CERT_NAME = "router.crt"


@pytest.fixture()
def cdi_resources(request, admin_client):
    rcs_object = request.param
    LOGGER.info(f"Get all resources with kind: {rcs_object.kind}")
    resource_list = list(rcs_object.get(dyn_client=admin_client))
    return [rcs for rcs in resource_list if rcs.name.startswith("cdi-")]


@pytest.fixture()
def hpp_resources(request, admin_client):
    rcs_object = request.param
    LOGGER.info(f"Get all resources with kind: {rcs_object.kind}")
    resource_list = list(rcs_object.get(dyn_client=admin_client))
    return [rcs for rcs in resource_list if rcs.name.startswith("hostpath-")]


@pytest.fixture(scope="module")
def internal_http_configmap(namespace):
    path = os.path.join("containers/internal_http/certs", "tls.crt")
    with open(path, "r") as cert_content:
        with cluster_resource(ConfigMap)(
            name="internal-https-configmap",
            namespace=namespace.name,
            data={"tlsregistry.crt": cert_content.read()},
        ) as configmap:
            yield configmap


@pytest.fixture(scope="module")
def internal_http_secret(namespace):
    with cluster_resource(Secret)(
        name="internal-http-secret",
        namespace=namespace.name,
        accesskeyid="YWRtaW4=",
        secretkey="cGFzc3dvcmQ=",
    ) as secret:
        yield secret


@pytest.fixture(scope="session")
def internal_http_deployment(cnv_tests_utilities_namespace):
    """
    Deploy internal HTTP server Deployment into the kube-system namespace.
    This Deployment deploys a pod that runs an HTTP server
    """
    with cluster_resource(HttpDeployment)(
        name="internal-http", namespace=cnv_tests_utilities_namespace.name
    ) as dep:
        dep.wait_for_replicas()
        yield dep


@pytest.fixture(scope="session")
def internal_http_service(cnv_tests_utilities_namespace, internal_http_deployment):
    with cluster_resource(HttpService)(
        name=internal_http_deployment.name, namespace=cnv_tests_utilities_namespace.name
    ) as svc:
        yield svc


@pytest.fixture(scope="session")
def images_internal_http_server(internal_http_deployment, internal_http_service):
    return {
        "http": f"http://{INTERNAL_HTTP_SERVER_ADDRESS}/",
        "https": f"https://{INTERNAL_HTTP_SERVER_ADDRESS}/",
        "http_auth": f"http://{INTERNAL_HTTP_SERVER_ADDRESS}:81/",
    }


@pytest.fixture(scope="session")
def images_private_registry_server():
    return py_config["servers"]["registry_server"]


@pytest.fixture()
def upload_proxy_route(admin_client):
    routes = Route.get(admin_client)
    upload_route = None
    for route in routes:
        if route.exposed_service == CDI_UPLOADPROXY:
            upload_route = route
    assert upload_route is not None
    yield upload_route


@pytest.fixture(scope="session")
def skip_test_if_no_hpp_sc(cluster_storage_classes):
    existing_hpp_sc = [
        sc.name for sc in cluster_storage_classes if sc.name in HPP_STORAGE_CLASSES
    ]
    if not existing_hpp_sc:
        pytest.skip(
            f"This test runs only on one of the hpp storage classes: {HPP_STORAGE_CLASSES}"
        )


@pytest.fixture(scope="module")
def skip_when_hpp_no_waitforfirstconsumer(storage_class_matrix_hpp_matrix__module__):
    if not sc_volume_binding_mode_is_wffc(
        sc=[*storage_class_matrix_hpp_matrix__module__][0]
    ):
        pytest.skip("Test only run when volumeBindingMode is WaitForFirstConsumer")


@pytest.fixture()
def uploadproxy_route_deleted(hco_namespace):
    """
    Delete uploadproxy route from kubevirt-hyperconverged namespace.

    This scales down cdi-operator replicas to 0 so that the route is not auto-created by the cdi-operator pod.
    Once the cdi-operator is terminated, route is deleted to perform the test.
    """
    ns = hco_namespace.name
    deployment = Deployment(name=CDI_OPERATOR, namespace=ns)
    try:
        deployment.scale_replicas(replica_count=0)
        deployment.wait_for_replicas(deployed=False)
        Route(name=CDI_UPLOADPROXY, namespace=ns).delete(wait=True)
        yield
    finally:
        deployment.scale_replicas(replica_count=1)
        deployment.wait_for_replicas()
        Route(name=CDI_UPLOADPROXY, namespace=ns).wait()


@pytest.fixture()
def cdi_config_upload_proxy_overridden(
    hco_namespace,
    hyperconverged_resource_scope_function,
    cdi_config,
    new_route_created,
):
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_function: hco_cr_jsonpatch_annotations_dict(
                component="cdi",
                path="uploadProxyURLOverride",
                value=new_route_created.host,
            )
        },
        list_resource_reconcile=[CDI],
    ):
        cdi_config.wait_until_upload_url_changed(uploadproxy_url=new_route_created.host)
        yield


@pytest.fixture()
def new_route_created(hco_namespace):
    existing_route = Route(name=CDI_UPLOADPROXY, namespace=hco_namespace.name)
    route = Route(
        name="newuploadroute-cdi",
        namespace=hco_namespace.name,
        destination_ca_cert=existing_route.ca_cert,
        service=CDI_UPLOADPROXY,
    )
    route.create(wait=True)
    yield route
    route.delete(wait=True)


@pytest.fixture(scope="session")
def https_server_certificate():
    yield ssl.get_server_certificate(addr=(py_config["server_url"], 443))


@pytest.fixture()
def https_config_map(request, namespace, https_server_certificate):
    data = (
        {"ca.pem": request.param["data"]}
        if hasattr(request, "param")
        else {"ca.pem": https_server_certificate}
    )
    with cluster_resource(ConfigMap)(
        name="https-cert",
        namespace=namespace.name,
        data=data,
    ) as configmap:
        yield configmap


@pytest.fixture()
def registry_config_map(namespace, https_server_certificate):
    with cluster_resource(ConfigMap)(
        name=f"{REGISTRY_STR}-cert",
        namespace=namespace.name,
        data={"tlsregistry.crt": https_server_certificate},
    ) as configmap:
        yield configmap


@pytest.fixture()
def download_image():
    downloaded_image(
        remote_name=f"{Images.Cdi.DIR}/{Images.Cdi.QCOW2_IMG}", local_name=LOCAL_PATH
    )


def _skip_block_volumemode(storage_class_matrix):
    storage_class = [*storage_class_matrix][0]
    if storage_class_matrix[storage_class]["volume_mode"] == "Block":
        pytest.skip("Test is not supported on Block volume mode")


@pytest.fixture()
def skip_block_volumemode_scope_function(storage_class_matrix__function__):
    _skip_block_volumemode(storage_class_matrix=storage_class_matrix__function__)


@pytest.fixture(scope="module")
def skip_block_volumemode_scope_module(storage_class_matrix__module__):
    _skip_block_volumemode(storage_class_matrix=storage_class_matrix__module__)


@pytest.fixture()
def default_fs_overhead(cdi_config):
    return float(cdi_config.instance.status.filesystemOverhead["global"])


@pytest.fixture()
def unset_predefined_scratch_sc(hyperconverged_resource_scope_module, cdi_config):
    if cdi_config.instance.spec.scratchSpaceStorageClass:
        empty_scratch_space_spec = {"spec": {"scratchSpaceStorageClass": ""}}
        with ResourceEditorValidateHCOReconcile(
            patches={hyperconverged_resource_scope_module: empty_scratch_space_spec},
            list_resource_reconcile=[CDI],
        ):
            LOGGER.info(f"wait for {empty_scratch_space_spec} in CDIConfig")
            for sample in TimeoutSampler(
                wait_timeout=20,
                sleep=1,
                func=lambda: not cdi_config.instance.spec.scratchSpaceStorageClass,
            ):
                if sample:
                    break
            yield
    else:
        yield


@pytest.fixture()
def default_sc_as_fallback_for_scratch(
    unset_predefined_scratch_sc, admin_client, cdi_config, default_sc
):
    # Based on py_config["default_storage_class"], update default SC, if needed
    if default_sc:
        yield default_sc
    else:
        for sc in cluster_resource(StorageClass).get(
            dyn_client=admin_client, name=py_config["default_storage_class"]
        ):
            assert (
                sc
            ), f'The cluster does not include {py_config["default_storage_class"]} storage class'
            with ResourceEditor(
                patches={
                    sc: {
                        "metadata": {
                            "annotations": {
                                StorageClass.Annotations.IS_DEFAULT_CLASS: "true"
                            },
                            "name": sc.name,
                        }
                    }
                }
            ):
                yield sc


@pytest.fixture()
def router_cert_secret(admin_client):
    router_secret = "router-certs-default"
    for secret in Secret.get(
        dyn_client=admin_client,
        name=router_secret,
        namespace="openshift-ingress",
    ):
        return secret
    raise ResourceNotFoundError(f"secret: {router_secret} not found")


@pytest.fixture()
def temp_router_cert(tmpdir, router_cert_secret):
    router_cert_path = f"{tmpdir}/{ROUTER_CERT_NAME}"
    with open(router_cert_path, "w") as the_file:
        the_file.write(
            (
                base64.standard_b64decode(router_cert_secret.instance.data["tls.crt"])
            ).decode("utf-8")
        )
    yield router_cert_path


@pytest.fixture()
def skip_from_container_if_jira_18870_not_closed():
    jira_id = "CNV-18870"
    if os.environ.get(CNV_TESTS_CONTAINER) and is_jira_open(jira_id=jira_id):
        pytest.skip(
            f"Skipping the test because it's running from the container and jira card {jira_id} not closed"
        )


@pytest.fixture()
def enabled_ca(skip_from_container_if_jira_18870_not_closed, temp_router_cert):
    update_ca_trust_command = "sudo update-ca-trust"
    ca_path = "/etc/pki/ca-trust/source/anchors/"
    # copy to the trusted secure list and update
    os.popen(f"sudo cp {temp_router_cert} {ca_path}")
    os.popen(update_ca_trust_command)
    yield
    os.popen(f"sudo rm {ca_path}{ROUTER_CERT_NAME}")
    os.popen(update_ca_trust_command)


@pytest.fixture(scope="module")
def is_hpp_cr_legacy_scope_module(hostpath_provisioner_scope_module):
    return is_hpp_cr_legacy(hostpath_provisioner=hostpath_provisioner_scope_module)


@pytest.fixture(scope="session")
def is_hpp_cr_legacy_scope_session(hostpath_provisioner_scope_session):
    return is_hpp_cr_legacy(hostpath_provisioner=hostpath_provisioner_scope_session)


@pytest.fixture(scope="module")
def hpp_cr_suffix_scope_module(is_hpp_cr_legacy_scope_module):
    return hpp_cr_suffix(is_hpp_cr_legacy=is_hpp_cr_legacy_scope_module)


@pytest.fixture(scope="session")
def hpp_cr_suffix_scope_session(is_hpp_cr_legacy_scope_session):
    return hpp_cr_suffix(is_hpp_cr_legacy=is_hpp_cr_legacy_scope_session)


@pytest.fixture(scope="session")
def hpp_daemonset_scope_session(hco_namespace, hpp_cr_suffix_scope_session):
    yield get_hpp_daemonset(
        hco_namespace=hco_namespace, hpp_cr_suffix=hpp_cr_suffix_scope_session
    )


@pytest.fixture(scope="module")
def hpp_daemonset_scope_module(hco_namespace, hpp_cr_suffix_scope_module):
    yield get_hpp_daemonset(
        hco_namespace=hco_namespace, hpp_cr_suffix=hpp_cr_suffix_scope_module
    )


@pytest.fixture()
def skip_if_sc_volume_binding_mode_is_wffc(storage_class_matrix__module__):
    storage_class = [*storage_class_matrix__module__][0]
    if sc_volume_binding_mode_is_wffc(sc=storage_class):
        pytest.skip(
            "Test does not support storage class with WaitForFirstConsumer binding mode"
        )


@pytest.fixture()
def cirros_vm_name(request):
    return request.param["vm_name"]


@pytest.fixture(scope="module")
def data_volume_multi_hpp_storage(
    request,
    namespace,
    schedulable_nodes,
    storage_class_matrix_hpp_matrix__module__,
):
    yield from data_volume(
        request=request,
        namespace=namespace,
        storage_class=[*storage_class_matrix_hpp_matrix__module__][0],
        schedulable_nodes=schedulable_nodes,
    )


@pytest.fixture(scope="session")
def available_hpp_storage_class(skip_test_if_no_hpp_sc, cluster_storage_classes):
    """
    Get an HPP storage class if there is any in the cluster
    """
    for storage_class in cluster_storage_classes:
        if storage_class.name in HPP_STORAGE_CLASSES:
            return storage_class


@pytest.fixture(scope="session")
def available_storage_classes_names():
    return [[*sc][0] for sc in py_config["storage_class_matrix"]]


@pytest.fixture(scope="session")
def storage_class_with_filesystem_volume_mode(available_storage_classes_names):
    yield get_storage_class_with_specified_volume_mode(
        volume_mode=DataVolume.VolumeMode.FILE, sc_names=available_storage_classes_names
    )


@pytest.fixture(scope="session")
def skip_test_if_no_filesystem_sc(storage_class_with_filesystem_volume_mode):
    if not storage_class_with_filesystem_volume_mode:
        pytest.skip("Skip the test: no Storage class with Filesystem volume mode")


# TODO remove once all storage failing tests because of GC are all addressed
@pytest.fixture(scope="function")
def disabled_cdi_garbage_collector(
    skip_upstream,
    installing_cnv,
    hyperconverged_resource_scope_function,
):
    if installing_cnv:
        yield
    else:
        with ResourceEditorValidateHCOReconcile(
            patches={
                hyperconverged_resource_scope_function: hco_cr_jsonpatch_annotations_dict(
                    component="cdi",
                    path="dataVolumeTTLSeconds",
                    value=-1,
                )
            },
            list_resource_reconcile=[CDI],
        ):
            yield


@pytest.fixture()
def cirros_dv_for_snapshot_dict(
    namespace,
    cirros_vm_name,
    storage_class_matrix_snapshot_matrix__module__,
):
    yield create_cirros_dv_for_snapshot_dict(
        name=cirros_vm_name,
        namespace=namespace.name,
        storage_class=[*storage_class_matrix_snapshot_matrix__module__][0],
    )


@pytest.fixture()
def cirros_vm_for_snapshot(
    admin_client,
    namespace,
    cirros_vm_name,
    cirros_dv_for_snapshot_dict,
):
    """
    Create a VM with a DV that supports snapshots
    """
    dv_metadata = cirros_dv_for_snapshot_dict["metadata"]
    with cluster_resource(VirtualMachineForTests)(
        client=admin_client,
        name=cirros_vm_name,
        namespace=dv_metadata["namespace"],
        os_flavor=OS_FLAVOR_CIRROS,
        memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
        data_volume_template={
            "metadata": dv_metadata,
            "spec": cirros_dv_for_snapshot_dict["spec"],
        },
    ) as vm:
        yield vm


@pytest.fixture()
def snapshots_with_content(
    request,
    namespace,
    admin_client,
    cirros_vm_for_snapshot,
):
    """
    Creates a requested number of snapshots with content
    The default behavior of the fixture is creating an offline
    snapshot unless {online_vm = True} declared in the test
    """
    vm_snapshots = []
    is_online_test = request.param.get("online_vm", False)
    for idx in range(request.param["number_of_snapshots"]):
        # write_file check if the vm is running and if not, start the vm
        # after the file have been written the function stops the vm
        index = idx + 1
        before_snap_index = f"before-snap-{index}"
        write_file(
            vm=cirros_vm_for_snapshot,
            filename=f"{before_snap_index}.txt",
            content=before_snap_index,
        )
        if is_online_test:
            cirros_vm_for_snapshot.start(wait=True)
        with cluster_resource(VirtualMachineSnapshot)(
            name=f"snapshot-{cirros_vm_for_snapshot.name}-number-{index}",
            namespace=cirros_vm_for_snapshot.namespace,
            vm_name=cirros_vm_for_snapshot.name,
            client=admin_client,
            teardown=False,
        ) as vm_snapshot:
            vm_snapshots.append(vm_snapshot)
            vm_snapshot.wait_snapshot_done()
            after_snap_index = f"after-snap-{index}"
            write_file(
                vm=cirros_vm_for_snapshot,
                filename=f"{after_snap_index}.txt",
                content=after_snap_index,
            )
    check_snapshot_indication(snapshot=vm_snapshot, is_online=is_online_test)
    yield vm_snapshots

    for vm_snapshot in vm_snapshots:
        vm_snapshot.clean_up()
