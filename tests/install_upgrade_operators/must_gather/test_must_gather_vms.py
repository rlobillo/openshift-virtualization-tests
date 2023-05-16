import logging
import re

import pytest
from ocp_resources.network_attachment_definition import NetworkAttachmentDefinition
from ocp_resources.virtual_machine import VirtualMachine

from tests.install_upgrade_operators.must_gather.utils import (
    TABLE_IP_FILTER,
    TABLE_IP_NAT,
    VALIDATE_FIELDS,
    assert_files_exists_for_running_vms,
    assert_must_gather_stopped_vm_yaml_file_collection,
    assert_path_not_exists_for_stopped_vms,
    check_list_of_resources,
    validate_files_collected,
)


LOGGER = logging.getLogger(__name__)


@pytest.mark.usefixtures("collected_vm_details_must_gather")
class TestMustGatherClusterWithVMs:
    @pytest.mark.parametrize(
        ("resource_type", "resource_path", "checks"),
        [
            pytest.param(
                NetworkAttachmentDefinition,
                "namespaces/{namespace}/"
                f"{NetworkAttachmentDefinition.ApiGroup.K8S_CNI_CNCF_IO}/"
                "network-attachment-definitions/{name}.yaml",
                VALIDATE_FIELDS,
                marks=(pytest.mark.polarion("CNV-2720")),
                id="test_network_attachment_definitions_resources",
            ),
            pytest.param(
                VirtualMachine,
                "namespaces/{namespace}/"
                f"{VirtualMachine.ApiGroup.KUBEVIRT_IO}/virtualmachines/custom"
                "/{name}.yaml",
                VALIDATE_FIELDS,
                marks=(pytest.mark.polarion("CNV-3043")),
                id="test_virtualmachine_resources",
            ),
        ],
        indirect=["resource_type"],
    )
    def test_resource_type(
        self,
        admin_client,
        collected_cluster_must_gather_with_vms,
        resource_type,
        resource_path,
        checks,
    ):
        check_list_of_resources(
            dyn_client=admin_client,
            resource_type=resource_type,
            temp_dir=collected_cluster_must_gather_with_vms,
            resource_path=resource_path,
            checks=checks,
        )


@pytest.mark.usefixtures(
    "collected_vm_details_must_gather", "nftables_ruleset_from_utility_pods"
)
class TestMustGatherVmDetails:
    @pytest.mark.parametrize(
        "extracted_data_from_must_gather_file, format_regex",
        [
            pytest.param(
                {"file_suffix": "bridge.txt", "section_title": "bridge fdb show:"},
                "{mac_address}",
                marks=(pytest.mark.polarion("CNV-2735")),
            ),
            pytest.param(
                {"file_suffix": "bridge.txt", "section_title": "bridge vlan show:"},
                "{interface_name}",
                marks=(pytest.mark.polarion("CNV-2736")),
            ),
            pytest.param(
                {"file_suffix": "ip.txt", "section_title": None},
                "{interface_name}",
                marks=(pytest.mark.polarion("CNV-2734")),
            ),
            pytest.param(
                {"file_suffix": "ruletables.txt", "section_title": None},
                TABLE_IP_FILTER,
                marks=(pytest.mark.polarion("CNV-2737"),),
            ),
            pytest.param(
                {"file_suffix": "ruletables.txt", "section_title": None},
                TABLE_IP_NAT,
                marks=(pytest.mark.polarion("CNV-2741"),),
            ),
            pytest.param(
                {"file_suffix": "qemu.log", "section_title": None},
                "-name guest={namespace}_{name},debug-threads=on \\\\$",
                marks=(pytest.mark.polarion("CNV-2725")),
            ),
            pytest.param(
                {"file_suffix": "dumpxml.xml", "section_title": None},
                "^ +<name>{namespace}_{name}</name>$",
                marks=(pytest.mark.polarion("CNV-3477")),
            ),
        ],
        indirect=["extracted_data_from_must_gather_file"],
    )
    def test_data_collected_from_virt_launcher(
        self,
        must_gather_vm,
        collected_vm_details_must_gather,
        nad_mac_address,
        vm_interface_name,
        extracted_data_from_must_gather_file,
        nftables_ruleset_from_utility_pods,
        format_regex,
    ):
        if "name" in format_regex and "namespace" in format_regex:
            format_regex = format_regex.format(
                namespace=must_gather_vm.namespace, name=must_gather_vm.name
            )
        if "mac_address" in format_regex:
            format_regex = format_regex.format(mac_address=nad_mac_address)
        if "interface_name" in format_regex:
            format_regex = format_regex.format(interface_name=vm_interface_name)
        LOGGER.info(
            f"Results from search: "
            f"{re.search(format_regex, extracted_data_from_must_gather_file, re.MULTILINE | re.IGNORECASE)}"
        )
        # Make sure that gathered data roughly matches expected format.
        matches = re.search(
            format_regex,
            extracted_data_from_must_gather_file,
            re.MULTILINE | re.IGNORECASE,
        )

        if not matches:
            if format_regex in (TABLE_IP_NAT, TABLE_IP_FILTER):
                if nftables_ruleset_from_utility_pods.values():
                    assert extracted_data_from_must_gather_file, (
                        f"{format_regex} does not contains nftables output: "
                        f"{nftables_ruleset_from_utility_pods}, file is empty"
                    )
                else:
                    LOGGER.warning(
                        f"For vm: {must_gather_vm.name} data collected from virt launcher associated with section "
                        f"{format_regex}: {extracted_data_from_must_gather_file} while nftables output collected from "
                        f"the cluster is: {nftables_ruleset_from_utility_pods}"
                    )
            else:
                raise AssertionError(
                    f"Gathered data are not matching expected format.\nExpected format:\n{format_regex}\n "
                    f"Gathered data:\n{extracted_data_from_must_gather_file}"
                )


@pytest.mark.usefixtures("must_gather_stopped_vms")
class TestMustGatherStoppedVmDetails:
    @pytest.mark.polarion("CNV-9039")
    def test_must_gather_stopped_vm(
        self,
        must_gather_vms_alternate_namespace_base_path,
        must_gather_vms_from_alternate_namespace,
        must_gather_stopped_vms,
    ):
        """
        Test must-gather collects information for stopped virtual machines.
        Also test colletion of other files of running virtual machines.
        """
        assert_must_gather_stopped_vm_yaml_file_collection(
            base_path=must_gather_vms_alternate_namespace_base_path,
            must_gather_stopped_vms=must_gather_stopped_vms,
        )
        running_vms = list(
            set(must_gather_vms_from_alternate_namespace) - set(must_gather_stopped_vms)
        )
        assert_files_exists_for_running_vms(
            base_path=must_gather_vms_alternate_namespace_base_path,
            running_vms=running_vms,
        )

        assert_path_not_exists_for_stopped_vms(
            base_path=must_gather_vms_alternate_namespace_base_path,
            stopped_vms=must_gather_stopped_vms,
        )


class TestMustGatherVmLongNameDetails:
    @pytest.mark.polarion("CNV-9233")
    def test_data_collected_from_virt_launcher_long(
        self,
        must_gather_long_name_vm,
        collected_vm_details_must_gather,
        nftables_ruleset_from_utility_pods,
    ):
        validate_files_collected(
            base_path=collected_vm_details_must_gather,
            vm_list=[must_gather_long_name_vm],
            nftables_ruleset_from_utility_pods=nftables_ruleset_from_utility_pods,
        )
