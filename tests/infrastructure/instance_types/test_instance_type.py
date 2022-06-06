import pytest
from kubernetes.dynamic.exceptions import UnprocessibleEntityError

from tests.infrastructure.instance_types.utils import (
    VirtualMachineClusterInstanceTypeForTest,
    VirtualMachineInstanceTypeForTest,
)
from utilities.infra import cluster_resource


@pytest.fixture(scope="class")
def instance_type_for_test(namespace, common_instance_type_param_dict):
    instance_type_param_dict = common_instance_type_param_dict.copy()
    instance_type_param_dict["namespace"] = namespace.name
    return cluster_resource(VirtualMachineInstanceTypeForTest)(
        **instance_type_param_dict
    )


@pytest.fixture(scope="class")
def cluster_instance_type_for_test(common_instance_type_param_dict):
    return cluster_resource(VirtualMachineClusterInstanceTypeForTest)(
        **common_instance_type_param_dict
    )


@pytest.fixture(scope="class")
def common_instance_type_param_dict(request):
    return {
        "name": request.param["name"],
        "cpu_cores": request.param.get("cpu_cores"),
        "memory_requests": request.param.get("memory_requests"),
        "dedicated_cpu_placement": request.param.get("dedicated_cpu_placement"),
        "cpu_model": request.param.get("cpu_model"),
        "cpu_isolate_emulator_thread": request.param.get("cpu_isolate_emulator_thread"),
        "cpu_numa": request.param.get("cpu_numa"),
        "cpu_realtime": request.param.get("cpu_realtime"),
        "gpus_list": request.param.get("gpus_list"),
        "host_devices_list": request.param.get("host_devices_list"),
        "io_thread_policy": request.param.get("io_thread_policy"),
        "memory_huge_pages": request.param.get("memory_huge_pages"),
    }


class TestInstanceTypes:
    @pytest.mark.parametrize(
        "common_instance_type_param_dict",
        [
            pytest.param(
                {
                    "name": "basic",
                    "cpu_cores": 1,
                    "memory_requests": "2Gi",
                },
            ),
            pytest.param(
                {
                    "name": "all-options-instance-type",
                    "cpu_cores": 1,
                    "memory_requests": "2Gi",
                    "dedicated_cpu_placement": True,
                    "cpu_isolate_emulator_thread": False,
                    "cpu_model": "demi-cpu-model",
                    "cpu_numa": {"guestMappingPassthrough": {}},
                    "cpu_realtime": {"mask": "demi-mask"},
                    "gpus_list": [
                        {
                            "deviceName": "demi-gpu-device-name",
                            "name": "demi-gpu-name",
                            "tag": "demi-gpu-tag",
                            "virtualGPUOptions": {
                                "display": {
                                    "enabled": False,
                                    "ramFB": {"enabled": True},
                                },
                            },
                        }
                    ],
                    "host_devices_list": [
                        {
                            "deviceName": "demi-host-device-name",
                            "name": "demi-host-name",
                            "tag": "demi-host-tag",
                        }
                    ],
                    "io_thread_policy": "demi-io-thread-policy",
                    "launch_security": {"sev": {}},
                    "memory_huge_pages": {"pageSize": "1Gi"},
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9082")
    def test_create_instance_type(self, instance_type_for_test):
        instance_type_for_test.deploy()
        instance_type_for_test.clean_up()

    @pytest.mark.parametrize(
        "common_instance_type_param_dict",
        [
            pytest.param(
                {
                    "name": "only-cpu-instance-type",
                    "cpu_cores": 1,
                },
            ),
            pytest.param(
                {
                    "name": "only-memory-instance-type",
                    "memory_requests": "2Gi",
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9083")
    def test_create_instance_type_negative(self, instance_type_for_test):
        with pytest.raises(UnprocessibleEntityError, match=r".*FieldValueRequired.*"):
            instance_type_for_test.deploy()
            assert (
                not instance_type_for_test.exists
            ), f"flavor: {instance_type_for_test.name} was created"


class TestClusterInstanceTypes:
    @pytest.mark.parametrize(
        "common_instance_type_param_dict",
        [
            pytest.param(
                {
                    "name": "basic-cluster-instance-type",
                    "cpu_cores": 1,
                    "memory_requests": "2Gi",
                },
            ),
            pytest.param(
                {
                    "name": "all-options-cluster-instance-type",
                    "cpu_cores": 1,
                    "memory_requests": "2Gi",
                    "dedicated_cpu_placement": True,
                    "cpu_isolate_emulator_thread": False,
                    "cpu_model": "demi-cpu-model",
                    "cpu_numa": {"guestMappingPassthrough": {}},
                    "cpu_realtime": {"mask": "demi-mask"},
                    "gpus_list": [
                        {
                            "deviceName": "demi-gpu-device-name",
                            "name": "demi-gpu-name",
                            "tag": "demi-gpu-tag",
                            "virtualGPUOptions": {
                                "display": {
                                    "enabled": False,
                                    "ramFB": {"enabled": True},
                                },
                            },
                        }
                    ],
                    "host_devices_list": [
                        {
                            "deviceName": "demi-host-device-name",
                            "name": "demi-host-name",
                            "tag": "demi-host-tag",
                        }
                    ],
                    "io_thread_policy": "demi-io-thread-policy",
                    "launch_security": {"sev": {}},
                    "memory_huge_pages": {"pageSize": "1Gi"},
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9103")
    def test_create_cluster_instance_type(self, cluster_instance_type_for_test):
        cluster_instance_type_for_test.deploy()
        cluster_instance_type_for_test.clean_up()

    @pytest.mark.parametrize(
        "common_instance_type_param_dict",
        [
            pytest.param(
                {
                    "name": "only-cpu-cluster-instance-type",
                    "cpu_cores": 1,
                },
            ),
            pytest.param(
                {
                    "name": "only-memory-instance-type",
                    "memory_requests": "2Gi",
                },
            ),
        ],
        indirect=True,
    )
    @pytest.mark.polarion("CNV-9104")
    def test_create_cluster_instance_type_negative(
        self, cluster_instance_type_for_test
    ):
        with pytest.raises(UnprocessibleEntityError, match=r".*FieldValueRequired.*"):
            cluster_instance_type_for_test.deploy()
            assert (
                not cluster_instance_type_for_test.exists
            ), f"flavor: {cluster_instance_type_for_test.name} was created"
