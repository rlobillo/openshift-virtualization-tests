import logging
import ssl

import pytest
from kubernetes.client.rest import ApiException
from ocp_resources.cdi import CDI
from ocp_resources.cdi_config import CDIConfig
from ocp_resources.configmap import ConfigMap
from ocp_resources.datavolume import DataVolume
from ocp_resources.resource import ResourceEditor, get_client
from ocp_resources.utils import TimeoutExpiredError, TimeoutSampler
from ocp_utilities.infra import cluster_resource

import utilities.storage
from tests.storage import utils
from tests.storage.constants import REGISTRY_STR
from tests.storage.utils import (
    check_disk_count_in_vm,
    clean_up_multiprocess,
    create_vm_from_dv,
    get_importer_pod,
    wait_for_importer_container_message,
    wait_for_processes_exit_successfully,
)
from utilities.constants import (
    OS_FLAVOR_CIRROS,
    TIMEOUT_1MIN,
    TIMEOUT_1SEC,
    TIMEOUT_5MIN,
    TIMEOUT_10MIN,
    TIMEOUT_20SEC,
    Images,
)
from utilities.exceptions import ProcessWithException
from utilities.hco import ResourceEditorValidateHCOReconcile
from utilities.ssp import wait_for_condition_message_value
from utilities.storage import ErrorMsg, create_dv
from utilities.virt import VirtualMachineForTests, running_vm


pytestmark = pytest.mark.post_upgrade


LOGGER = logging.getLogger(__name__)

QUAY_IMAGE = "docker://quay.io/kubevirt/cirros-registry-disk-demo"
PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE = "cirros-registry-disk-demo:latest"
PRIVATE_REGISTRY_CIRROS_RAW_IMAGE = "cirros.raw:latest"
PRIVATE_REGISTRY_CIRROS_QCOW2_IMAGE = "cirros.qcow2:latest"
REGISTRY_CERT_NAME = f"{REGISTRY_STR}.crt"
REGISTRY_HTTPS_PORT = 8443
REGISTRY_HTTP_PORT = 5000
INSECURE_REGISTRY_STR = "insecureRegistries"


def wait_for_cdi_config_registry_updated(
    cdi_config, registry_server, expected_present=True
):
    samples = TimeoutSampler(
        wait_timeout=TIMEOUT_20SEC,
        sleep=TIMEOUT_1SEC,
        func=lambda: registry_server
        in cdi_config.instance["spec"].get(INSECURE_REGISTRY_STR, []),
    )
    try:
        for sample in samples:
            if bool(expected_present) == bool(sample):
                return
    except TimeoutExpiredError:
        LOGGER.error(
            f"Expected:{expected_present}, actual CdiConfig.spec.{INSECURE_REGISTRY_STR} value: {sample}"
        )
        raise


@pytest.fixture()
def registry_config_map(namespace, registry_server_certificate):
    with cluster_resource(ConfigMap)(
        name=f"{REGISTRY_STR}-cert",
        namespace=namespace.name,
        data={"tlsregistry.crt": registry_server_certificate},
    ) as configmap:
        yield configmap


@pytest.fixture(scope="session")
def cluster_host_url():
    return get_client().configuration.host


@pytest.fixture(scope="session")
def registry_server(cluster_host_url):
    default_server = "cnv-qe-server.rhos-psi.cnv-qe.rhood.us"
    ibm_server = f"cnv-qe-server.{cluster_host_url.replace('https://api.', '').replace(':6443', '')}"
    rhood_server = "cnv-qe-server.cnv-qe.rhood.us"
    servers = {
        "rhos-psi.cnv-qe.rhood.us": default_server,
        "ibmc.cnv-qe.rhood.us": ibm_server,
        "ibmc-upi.cnv-qe.rhood.us": ibm_server,
        "qe.azure.devcluster.openshift.com": rhood_server,
        "cnv-ci.rhood.us": rhood_server,
        "cnv-qe.rhood.us": rhood_server,
        "lab.eng.tlv2.redhat.com": "cnv-qe-server.apps.cnv2.engineering.redhat.com",
    }
    matching_registry_server_url = default_server
    for domain_key in servers:
        if domain_key in cluster_host_url:
            matching_registry_server_url = servers[domain_key]
            break
    LOGGER.info(f"Registry server url: {matching_registry_server_url}")
    return matching_registry_server_url


@pytest.fixture(scope="session")
def registry_server_url(registry_server):
    return f"docker://{registry_server}"


@pytest.fixture(scope="session")
def registry_server_certificate(registry_server):
    yield ssl.get_server_certificate(addr=(registry_server, 443))


@pytest.fixture()
def cdi_config_scope_function():
    cdi_config = CDIConfig(name="config")
    assert cdi_config.instance is not None
    return cdi_config


@pytest.fixture()
def insecure_registry(
    request,
    hyperconverged_resource_scope_function,
    cdi_config_scope_function,
    registry_server,
):
    """
    To disable TLS security for a registry
    """
    updated_registry_server_url = (
        f"{registry_server}:{request.param['server_port']}"
        if request.param["server_port"]
        else registry_server
    )
    with ResourceEditorValidateHCOReconcile(
        patches={
            hyperconverged_resource_scope_function: {
                "spec": {
                    "storageImport": {
                        INSECURE_REGISTRY_STR: [
                            *cdi_config_scope_function.instance.to_dict()
                            .get("spec", {})
                            .get(INSECURE_REGISTRY_STR, []),
                            updated_registry_server_url,
                        ]
                    }
                }
            }
        },
        list_resource_reconcile=[CDI],
    ):
        wait_for_cdi_config_registry_updated(
            cdi_config=cdi_config_scope_function,
            registry_server=updated_registry_server_url,
            expected_present=True,
        )
        yield
    wait_for_cdi_config_registry_updated(
        cdi_config=cdi_config_scope_function,
        registry_server=updated_registry_server_url,
        expected_present=False,
    )


@pytest.fixture()
def configmap_with_cert(namespace, registry_server_certificate):
    with cluster_resource(ConfigMap)(
        name=f"{REGISTRY_STR}-cm-cert",
        namespace=namespace.name,
        data={REGISTRY_CERT_NAME: registry_server_certificate},
    ) as configmap:
        yield configmap


@pytest.fixture()
def update_configmap_with_cert(request, configmap_with_cert):
    injected_content = request.param["injected_content"]
    ResourceEditor(
        {
            configmap_with_cert: {
                "data": {
                    REGISTRY_CERT_NAME: f"{configmap_with_cert.data[REGISTRY_CERT_NAME][:50]}{injected_content}"
                    f"{configmap_with_cert.data[REGISTRY_CERT_NAME][50:]}"
                }
            }
        }
    ).update()


@pytest.mark.sno
@pytest.mark.parametrize(
    "file_name",
    [
        pytest.param(
            PRIVATE_REGISTRY_CIRROS_RAW_IMAGE,
            marks=(pytest.mark.polarion("CNV-2343")),
            id="import_cirros_raw",
        ),
        pytest.param(
            PRIVATE_REGISTRY_CIRROS_QCOW2_IMAGE,
            marks=(pytest.mark.polarion("CNV-2341")),
            id="import_cirros_qcow2_image",
        ),
    ],
)
def test_private_registry_cirros(
    skip_upstream,
    namespace,
    registry_server_url,
    registry_config_map,
    file_name,
    storage_class_matrix__function__,
):
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name="import-private-registry-cirros-image",
        namespace=namespace.name,
        url=f"{registry_server_url}:{REGISTRY_HTTPS_PORT}/{file_name}",
        cert_configmap=registry_config_map.name,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success()
        with create_vm_from_dv(dv=dv) as vm_dv:
            check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.parametrize(
    ("dv_name", "url"),
    [
        pytest.param(
            "cnv-2198",
            "docker://quay.io/openshift-cnv/qe-cnv-tests-registry-official-cirros",
            marks=pytest.mark.polarion("CNV-2198"),
            id="image-registry-not-conform-registrydisk",
        ),
        pytest.param(
            "cnv-2340",
            "docker://quay.io/openshift-cnv/qe-cnv-tests-registry-fedora29-qcow2-rootdir",
            marks=pytest.mark.polarion("CNV-2340"),
            id="import-registry-fedora29-qcow-rootdir",
        ),
    ],
)
def test_disk_image_not_conform_to_registy_disk(
    admin_client, dv_name, url, namespace, storage_class_matrix__function__
):
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name=dv_name,
        namespace=namespace.name,
        url=url,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_status(
            status=DataVolume.Status.IMPORT_IN_PROGRESS,
            timeout=TIMEOUT_5MIN,
            stop_status=DataVolume.Status.SUCCEEDED,
        )
        importer_pod = get_importer_pod(dyn_client=admin_client, namespace=dv.namespace)
        wait_for_importer_container_message(
            importer_pod=importer_pod,
            msg=ErrorMsg.DISK_IMAGE_IN_CONTAINER_NOT_FOUND,
        )


@pytest.mark.sno
@pytest.mark.polarion("CNV-2028")
def test_public_registry_multiple_data_volume(
    admin_client, namespace, storage_class_matrix__function__
):
    dvs = []
    vms = []
    dvs_processes = {}
    vms_processes = {}
    try:
        for dv in ("dv1", "dv2", "dv3"):
            rdv = DataVolume(
                source=REGISTRY_STR,
                name=f"import-public-registry-quay-{dv}",
                namespace=namespace.name,
                url=QUAY_IMAGE,
                size="5Gi",
                content_type=DataVolume.ContentType.KUBEVIRT,
                **utils.storage_params(
                    storage_class_matrix=storage_class_matrix__function__
                ),
                privileged_client=admin_client,
            )

            dv_process = ProcessWithException(target=rdv.create)
            dv_process.start()
            dvs_processes[dv] = dv_process
            dvs.append(rdv)

        wait_for_processes_exit_successfully(
            processes=dvs_processes, timeout=TIMEOUT_10MIN
        )

        for vm in [vm for vm in dvs]:
            rvm = cluster_resource(VirtualMachineForTests)(
                name=vm.name,
                namespace=namespace.name,
                os_flavor=OS_FLAVOR_CIRROS,
                data_volume=vm,
                memory_requests=Images.Cirros.DEFAULT_MEMORY_SIZE,
            )
            rvm.deploy()
            vms.append(rvm)

        for vm in vms:
            vm_process = ProcessWithException(target=vm.start)
            vm_process.start()
            vms_processes[vm.name] = vm_process

        wait_for_processes_exit_successfully(
            processes=vms_processes, timeout=TIMEOUT_5MIN
        )
        for vm in vms:
            running_vm(vm=vm, wait_for_interfaces=False)
            check_disk_count_in_vm(vm=vm)
    finally:
        clean_up_multiprocess(processes=vms_processes, object_list=vms)
        clean_up_multiprocess(processes=dvs_processes, object_list=dvs)


@pytest.mark.parametrize(
    "insecure_registry",
    [
        pytest.param(
            {"server_port": REGISTRY_HTTP_PORT},
        ),
    ],
    indirect=True,
)
@pytest.mark.sno
@pytest.mark.polarion("CNV-2183")
def test_private_registry_insecured_configmap(
    skip_upstream,
    insecure_registry,
    namespace,
    registry_server_url,
    storage_class_matrix__function__,
):
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name="import-private-insecured-registry",
        namespace=namespace.name,
        url=f"{registry_server_url}:{REGISTRY_HTTP_PORT}/{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success()
        with create_vm_from_dv(dv=dv) as vm_dv:
            check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.polarion("CNV-2182")
def test_private_registry_recover_after_missing_configmap(
    skip_upstream,
    namespace,
    registry_server_url,
    registry_config_map,
    storage_class_matrix__function__,
):
    # creating DV before configmap with certificate is created
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name="import-private-registry-with-no-configmap",
        namespace=namespace.name,
        url=f"{registry_server_url}:{REGISTRY_HTTPS_PORT}/{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
        cert_configmap=registry_config_map.name,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success()
        with create_vm_from_dv(dv=dv) as vm_dv:
            check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.polarion("CNV-2344")
def test_private_registry_with_untrusted_certificate(
    skip_upstream,
    admin_client,
    namespace,
    registry_server_url,
    registry_config_map,
    storage_class_matrix__function__,
):
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name="import-private-registry-with-untrusted-certificate",
        namespace=namespace.name,
        url=f"{registry_server_url}:{REGISTRY_HTTPS_PORT}/{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
        cert_configmap=registry_config_map.name,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success()
        with create_vm_from_dv(dv=dv) as vm_dv:
            check_disk_count_in_vm(vm=vm_dv)

        # negative flow - remove certificate from configmap
        registry_config_map.update(
            resource_dict={
                "data": {"tlsregistry.crt": ""},
                "metadata": {"name": registry_config_map.name},
            }
        )
        with utilities.storage.create_dv(
            source=REGISTRY_STR,
            dv_name="import-private-registry-no-certificate",
            namespace=namespace.name,
            url=f"{registry_server_url}:{REGISTRY_HTTPS_PORT}/{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
            cert_configmap=registry_config_map.name,
            content_type="",
            storage_class=[*storage_class_matrix__function__][0],
        ) as dv:
            dv.wait_for_status(
                status=DataVolume.Status.IMPORT_IN_PROGRESS, timeout=TIMEOUT_5MIN
            )
            importer_pod = get_importer_pod(
                dyn_client=admin_client, namespace=dv.namespace
            )
            wait_for_importer_container_message(
                importer_pod=importer_pod,
                msg=ErrorMsg.CERTIFICATE_SIGNED_UNKNOWN_AUTHORITY,
            )


@pytest.mark.sno
@pytest.mark.parametrize(
    ("dv_name", "url", "cert_configmap", "content_type", "size"),
    [
        pytest.param(
            "import-public-registry-no-content-type-dv",
            QUAY_IMAGE,
            None,
            None,
            "5Gi",
            marks=(pytest.mark.polarion("CNV-2195")),
        ),
        pytest.param(
            "import-public-registry-empty-content-type-dv",
            QUAY_IMAGE,
            None,
            "",
            "5Gi",
            marks=(pytest.mark.polarion("CNV-2197"), pytest.mark.smoke()),
        ),
        pytest.param(
            "import-public-registry-quay-dv",
            QUAY_IMAGE,
            None,
            DataVolume.ContentType.KUBEVIRT,
            "5Gi",
            marks=(pytest.mark.polarion("CNV-2026")),
        ),
    ],
    ids=[
        "import-public-registry-no-content-type-dv",
        "import-public-registry-empty-content-type-dv",
        "import-public-registry-quay-dv",
    ],
)
def test_public_registry_data_volume(
    namespace,
    dv_name,
    url,
    cert_configmap,
    content_type,
    size,
    storage_class_matrix__function__,
):
    with utilities.storage.create_dv(
        source=REGISTRY_STR,
        dv_name=dv_name,
        namespace=namespace.name,
        url=url,
        cert_configmap=cert_configmap,
        content_type=content_type,
        size=size,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_dv_success()
        with create_vm_from_dv(dv=dv) as vm_dv:
            check_disk_count_in_vm(vm=vm_dv)


# The following test is to show after imports fails because low capacity storage,
# we can overcome by updating to the right requested volume size and import successfully
@pytest.mark.sno
@pytest.mark.polarion("CNV-2024")
def test_public_registry_data_volume_low_capacity(
    namespace,
    storage_class_matrix__function__,
):
    dv_param = {
        "dv_name": "import-public-registry-low-capacity-dv",
        "source": REGISTRY_STR,
        "url": QUAY_IMAGE,
        "storage_class": [*storage_class_matrix__function__][0],
    }
    # negative flow - low capacity volume
    with create_dv(
        source=dv_param["source"],
        dv_name=dv_param["dv_name"],
        namespace=namespace.name,
        url=dv_param["url"],
        content_type="",
        size="16Mi",
        storage_class=dv_param["storage_class"],
    ) as dv:
        dv.wait_for_status(
            status=DataVolume.Status.IMPORT_IN_PROGRESS,
            timeout=TIMEOUT_5MIN,
            stop_status=DataVolume.Status.SUCCEEDED,
        )
        wait_for_condition_message_value(
            resource=dv, expected_message=ErrorMsg.DATA_VOLUME_TOO_SMALL
        )
    # positive flow
    with create_dv(
        source=dv_param["source"],
        dv_name=dv_param["dv_name"],
        namespace=namespace.name,
        url=dv_param["url"],
        storage_class=dv_param["storage_class"],
    ) as dv:
        dv.wait_for_dv_success()
        with utils.create_vm_from_dv(dv=dv) as vm_dv:
            utils.check_disk_count_in_vm(vm=vm_dv)


@pytest.mark.sno
@pytest.mark.polarion("CNV-2150")
def test_public_registry_data_volume_archive(
    namespace, storage_class_matrix__function__
):
    with pytest.raises(
        ApiException, match=r".*ContentType must be kubevirt when Source is Registry.*"
    ):
        with create_dv(
            source=REGISTRY_STR,
            dv_name="import-public-registry-archive",
            namespace=namespace.name,
            url=QUAY_IMAGE,
            content_type=DataVolume.ContentType.ARCHIVE,
            storage_class=[*storage_class_matrix__function__][0],
        ):
            return


@pytest.mark.parametrize(
    "insecure_registry",
    [
        pytest.param(
            {"server_port": REGISTRY_HTTPS_PORT},
        ),
    ],
    indirect=True,
)
@pytest.mark.sno
@pytest.mark.polarion("CNV-2347")
def test_fqdn_name(
    namespace,
    configmap_with_cert,
    insecure_registry,
    registry_server_url,
    storage_class_matrix__function__,
):
    """
    Test that it does a full name string check in the insecure registry ConfigMap,
    not a partial check of just the prefix.
    """
    storage_class = [*storage_class_matrix__function__][0]
    with create_dv(
        source=REGISTRY_STR,
        dv_name=f"cnv-2347-{storage_class}",
        namespace=namespace.name,
        # Substring of the FQDN name
        url=f"{registry_server_url[:22]}{registry_server_url[30:]}:{REGISTRY_HTTPS_PORT}/"
        f"{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
        cert_configmap=configmap_with_cert.name,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        # Import fails because FQDN is verified from the registry certificate and a substring is not supported.
        dv.wait_for_condition(
            condition=DataVolume.Condition.Type.BOUND,
            status=DataVolume.Condition.Status.TRUE,
            timeout=TIMEOUT_1MIN,
        )
        dv.wait_for_status(
            status=DataVolume.Status.IMPORT_IN_PROGRESS,
            timeout=TIMEOUT_5MIN,
            stop_status=DataVolume.Status.SUCCEEDED,
        )
        dv.wait_for_condition(
            condition=DataVolume.Condition.Type.RUNNING,
            status=DataVolume.Condition.Status.FALSE,
            timeout=TIMEOUT_5MIN,
        )
        dv.wait_for_condition(
            condition=DataVolume.Condition.Type.READY,
            status=DataVolume.Condition.Status.FALSE,
            timeout=TIMEOUT_5MIN,
        )


@pytest.mark.sno
@pytest.mark.parametrize(
    ("dv_name", "update_configmap_with_cert"),
    [
        pytest.param(
            "cnv-2351",
            {"injected_content": "\0,^@%$!#$%~*()"},
            marks=(pytest.mark.polarion("CNV-2351")),
            id="invalid_control_characters_in_cert_configmap",
        ),
        pytest.param(
            "cnv-2352",
            {"injected_content": "0101010101010010010101001010"},
            marks=(pytest.mark.polarion("CNV-2352")),
            id="binary_string_in_cert_configmap",
        ),
    ],
    indirect=["update_configmap_with_cert"],
)
def test_inject_invalid_cert_to_configmap(
    admin_client,
    dv_name,
    configmap_with_cert,
    update_configmap_with_cert,
    namespace,
    registry_server_url,
    storage_class_matrix__function__,
):
    """
    Test that generate ConfigMap from cert file, then inject invalid content in the cert of ConfigMap, import will fail.
    """
    with create_dv(
        source=REGISTRY_STR,
        dv_name=dv_name,
        namespace=namespace.name,
        url=f"{registry_server_url}:{REGISTRY_HTTPS_PORT}/{PRIVATE_REGISTRY_CIRROS_DEMO_IMAGE}",
        cert_configmap=configmap_with_cert.name,
        size=Images.Cirros.DEFAULT_DV_SIZE,
        storage_class=[*storage_class_matrix__function__][0],
    ) as dv:
        dv.wait_for_status(
            status=DataVolume.Status.IMPORT_IN_PROGRESS, timeout=TIMEOUT_10MIN
        )
        importer_pod = get_importer_pod(dyn_client=admin_client, namespace=dv.namespace)
        wait_for_importer_container_message(
            importer_pod=importer_pod,
            msg=ErrorMsg.CERTIFICATE_SIGNED_UNKNOWN_AUTHORITY,
        )
