import pytest

from tests.install_upgrade_operators.must_gather.utils import (
    MUST_GATHER_VM_NAME_PREFIX,
    validate_must_gather_vm_file_collection,
)


@pytest.mark.usefixtures(
    "must_gather_vms_from_alternate_namespace", "nftables_ruleset_from_utility_pods"
)
class TestMustGatherVmDetailsWithParams:
    @pytest.mark.parametrize(
        "collected_vm_details_must_gather_with_params, expected",
        [
            pytest.param(
                {"command": "NS={alternate_namespace}"},
                None,
                marks=(pytest.mark.polarion("CNV-7882"),),
                id="test_vm_gather_alternate_namespace",
            ),
            pytest.param(
                {"command": "NS={alternate_namespace} VM={vm_name}"},
                {"alt_ns_vm": [0]},
                marks=(pytest.mark.polarion("CNV-7868"),),
                id="test_vm_gather_specific_vm",
            ),
            pytest.param(
                {"command": "NS={alternate_namespace} VM={vm_list}"},
                {"alt_ns_vm": [0, 1, 2]},
                marks=(pytest.mark.polarion("CNV-7865"),),
                id="test_vm_gather_vm_list",
            ),
            pytest.param(
                {
                    "command": "NS={alternate_namespace} "
                    f'VM_EXP="^{MUST_GATHER_VM_NAME_PREFIX}-[1,4]"'
                },
                {"alt_ns_vm": [1, 4]},
                marks=(pytest.mark.polarion("CNV-7867"),),
                id="test_vm_gather_regex_namespace",
            ),
            pytest.param(
                {"command": f'VM_EXP="^{MUST_GATHER_VM_NAME_PREFIX}-[2-4]"'},
                {"alt_ns_vm": [2, 3, 4], "must_gather_ns_vm": [0]},
                marks=(pytest.mark.polarion("CNV-7866"),),
                id="test_vm_gather_regex",
            ),
        ],
        indirect=["collected_vm_details_must_gather_with_params"],
    )
    def test_must_gather_params(
        self,
        must_gather_vm,
        collected_vm_details_must_gather_with_params,
        expected,
        must_gather_vms_from_alternate_namespace,
        nftables_ruleset_from_utility_pods,
    ):
        validate_must_gather_vm_file_collection(
            collected_vm_details_must_gather_with_params=collected_vm_details_must_gather_with_params,
            expected=expected,
            must_gather_vm=must_gather_vm,
            must_gather_vms_from_alternate_namespace=must_gather_vms_from_alternate_namespace,
            nftables_ruleset_from_utility_pods=nftables_ruleset_from_utility_pods,
        )
