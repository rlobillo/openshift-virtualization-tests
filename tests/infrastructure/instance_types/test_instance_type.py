import pytest
from kubernetes.dynamic.exceptions import UnprocessibleEntityError


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
    def test_create_instance_type(self, instance_type_for_test_scope_class):
        with instance_type_for_test_scope_class as instance_type:
            assert instance_type.exists

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
    def test_create_instance_type_negative(self, instance_type_for_test_scope_class):
        with pytest.raises(UnprocessibleEntityError, match=r".*FieldValueRequired.*"):
            instance_type_for_test_scope_class.deploy()
            assert (
                not instance_type_for_test_scope_class.exists
            ), f"flavor: {instance_type_for_test_scope_class.name} was created"


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
    def test_create_cluster_instance_type(
        self, cluster_instance_type_for_test_scope_class
    ):
        with cluster_instance_type_for_test_scope_class as cluster_instance_type:
            assert cluster_instance_type.exists

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
        self, cluster_instance_type_for_test_scope_class
    ):
        with pytest.raises(UnprocessibleEntityError, match=r".*FieldValueRequired.*"):
            cluster_instance_type_for_test_scope_class.deploy()
            assert (
                not cluster_instance_type_for_test_scope_class.exists
            ), f"flavor: {cluster_instance_type_for_test_scope_class.name} was created"
