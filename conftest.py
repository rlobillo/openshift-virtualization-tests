# -*- coding: utf-8 -*-

"""
Pytest conftest file for CNV tests
"""
import logging
import os
import os.path
import pathlib
import re
import shutil

import pytest
import shortuuid
import yaml
from ocp_resources.datavolume import DataVolume
from ocp_resources.namespace import Namespace
from ocp_resources.network_attachment_definition import NetworkAttachmentDefinition
from ocp_resources.node import Node
from ocp_resources.node_network_configuration_enactment import (
    NodeNetworkConfigurationEnactment,
)
from ocp_resources.node_network_configuration_policy import (
    NodeNetworkConfigurationPolicy,
)
from ocp_resources.node_network_state import NodeNetworkState
from ocp_resources.persistent_volume import PersistentVolume
from ocp_resources.persistent_volume_claim import PersistentVolumeClaim
from ocp_resources.pod import Pod
from ocp_resources.pod_disruption_budget import PodDisruptionBudget
from ocp_resources.service import Service
from ocp_resources.storage_class import StorageClass
from ocp_resources.virtual_machine import VirtualMachine
from ocp_resources.virtual_machine_instance import VirtualMachineInstance
from ocp_resources.virtual_machine_instance_migration import (
    VirtualMachineInstanceMigration,
)
from ocp_utilities.data_collector import (
    collect_pods_data,
    collect_resources_yaml_instance,
    prepare_pytest_item_data_dir,
)
from ocp_utilities.infra import cluster_resource
from pytest_testconfig import config as py_config

import utilities.infra
from utilities.infra import get_admin_client
from utilities.logger import setup_logging
from utilities.pytest_utils import (
    config_default_storage_class,
    deploy_run_in_progress_config_map,
    get_base_matrix_name,
    get_cnv_qe_server_url,
    get_matrix_params,
    reorder_early_fixtures,
    run_in_progress_config_map,
    separator,
    skip_if_pytest_flags_exists,
    stop_if_run_in_progress,
)


LOGGER = logging.getLogger(__name__)
BASIC_LOGGER = logging.getLogger("basic")

EXCLUDE_MARKER_FROM_TIER2_MARKER = [
    "destructive",
    "chaos",
    "tier3",
    "install",
    "benchmark",
    "sap_hana",
    "scale",
    "longevity",
    "ovs_brcnv",
]

TEAM_MARKERS = {
    "chaos": ["chaos", "deprecated_api"],
    "compute": ["compute", "deprecated_api"],
    "network": ["network", "deprecated_api"],
    "storage": ["storage", "deprecated_api"],
    "iuo": ["install_upgrade_operators", "deprecated_api"],
}

RESOURCES_TO_COLLECT_INFO = [
    DataVolume,
    PersistentVolume,
    PersistentVolumeClaim,
    VirtualMachine,
    VirtualMachineInstance,
    VirtualMachineInstanceMigration,
    NetworkAttachmentDefinition,
    NodeNetworkConfigurationPolicy,
    NodeNetworkState,
    Service,
    Namespace,
    NodeNetworkConfigurationEnactment,
    PodDisruptionBudget,
    Node,
]


def data_collector_enabled(session):
    data_collector = session.config.getoption("--data-collector")
    data_collector_failed_tests = session.config.getoption(
        "--data-collector-failed-tests"
    )
    if data_collector or data_collector_failed_tests:
        return data_collector


def pytest_addoption(parser):
    matrix_group = parser.getgroup(name="Matrix")
    os_group = parser.getgroup(name="OS")
    install_upgrade_group = parser.getgroup(name="Upgrade")
    storage_group = parser.getgroup(name="Storage")
    cluster_sanity_group = parser.getgroup(name="ClusterSanity")
    data_collector_group = parser.getgroup(name="DataCollector")
    deprecate_api_test_group = parser.getgroup(name="DeprecateTestAPI")
    leftovers_collector = parser.getgroup(name="LeftoversCollector")
    scale_group = parser.getgroup(name="Scale")
    session_group = parser.getgroup(name="Session")

    # Upgrade addoption
    install_upgrade_group.addoption(
        "--upgrade", choices=["cnv", "ocp"], help="Run OCP or CNV upgrade tests"
    )
    install_upgrade_group.addoption(
        "--upgrade_resilience",
        action="store_true",
        help="If provided, run upgrade with disruptions",
    )

    # CNV upgrade options
    install_upgrade_group.addoption(
        "--cnv-version", help="CNV version to install or upgrade to"
    )
    install_upgrade_group.addoption("--cnv-image", help="Path to CNV index-image")
    install_upgrade_group.addoption(
        "--cnv-source",
        help="CNV source lane",
        default="osbs",
        choices=["production", "stage", "osbs"],
    )

    # OCP upgrade options
    install_upgrade_group.addoption(
        "--ocp-image",
        help="OCP image to upgrade to. Images can be found under "
        "https://openshift-release.apps.ci.l2s4.p1.openshiftapps.com/",
    )
    # CNV install options:
    install_upgrade_group.addoption(
        "--install",
        help="Runs cnv install tests",
        action="store_true",
    )
    # Matrix addoption
    matrix_group.addoption("--storage-class-matrix", help="Storage class matrix to use")
    matrix_group.addoption("--bridge-device-matrix", help="Bridge device matrix to use")
    matrix_group.addoption("--rhel-os-matrix", help="RHEL OS matrix to use")
    matrix_group.addoption("--windows-os-matrix", help="Windows OS matrix to use")
    matrix_group.addoption("--fedora-os-matrix", help="Fedora OS matrix to use")
    matrix_group.addoption("--centos-os-matrix", help="CentOS matrix to use")
    matrix_group.addoption("--provider-matrix", help="External provider matrix to use")
    matrix_group.addoption("--vm-volumes-matrix", help="VM volumes matrix to use")
    matrix_group.addoption("--run-strategy-matrix", help="RunStrategy matrix to use")
    matrix_group.addoption(
        "--sysprep-source-matrix",
        help="Sysprep resource types to use (ConfigMap, Secret)",
    )

    # OS addoption
    os_group.addoption(
        "--latest-rhel",
        action="store_true",
        help="Run matrix tests with latest RHEL OS",
    )
    os_group.addoption(
        "--latest-fedora",
        action="store_true",
        help="Run matrix tests with latest Fedora OS",
    )
    os_group.addoption(
        "--latest-windows",
        action="store_true",
        help="Run matrix tests with latest Windows OS",
    )
    os_group.addoption(
        "--latest-centos",
        action="store_true",
        help="Run matrix tests with latest CentOS",
    )

    # Storage addoption
    storage_group.addoption(
        "--default-storage-class",
        help="Overwrite default storage class in storage_class_matrix",
    )

    # Cluster sanity addoption
    cluster_sanity_group.addoption(
        "--cluster-sanity-skip-storage-check",
        help="Skip storage class check in cluster_sanity fixture",
        action="store_true",
    )
    cluster_sanity_group.addoption(
        "--cluster-sanity-skip-nodes-check",
        help="Skip nodes check in cluster_sanity fixture",
        action="store_true",
    )
    cluster_sanity_group.addoption(
        "--cluster-sanity-skip-check",
        help="Skip cluster_sanity check",
        action="store_true",
    )
    cluster_sanity_group.addoption(
        "--cluster-sanity-skip-hco-check",
        help="Skip HCO status conditions check in cluster_sanity fixture",
        action="store_true",
    )

    # Log collector group
    data_collector_group.addoption(
        "--data-collector",
        help="pass YAML file path to enable data collector to capture additional logs and resources",
    )
    data_collector_group.addoption(
        "--data-collector-failed-tests",
        help="pass YAML file path to enable data collector to capture additional logs and resources",
    )
    data_collector_group.addoption(
        "--pytest-log-file",
        help="Path to pytest log file",
        default="pytest-tests.log",
    )

    # Deprecate api test_group
    deprecate_api_test_group.addoption(
        "--skip-deprecated-api-test",
        help="By default test_deprecation_audit_logs will always run, pass this flag to skip it",
        action="store_true",
    )

    # LeftoversCollector group
    leftovers_collector.addoption(
        "--leftovers-collector",
        help="By default will not run, to run pass --leftovers-collector.",
        action="store_true",
    )

    # Scale group
    scale_group.addoption(
        "--scale-params-file",
        help="Path to scale test params file, default is tests/scale/scale_params.yaml",
        default="tests/scale/scale_params.yaml",
    )

    # Session group
    session_group.addoption(
        "--session-id",
        help="Session id to use for the test run.",
        default=shortuuid.uuid(),
    )


def pytest_cmdline_main(config):
    # TODO: Reduce cognitive complexity
    # Make pytest tmp dir unique for current session
    config.option.basetemp = f"{config.option.basetemp}-{config.option.session_id}"

    deprecation_tests_dir_path = "tests/deprecated_api"
    if (
        not (
            config.getoption("--skip-deprecated-api-test")
            or config.getoption("--install")
        )
        and getattr(config, "args", None)
        and not any([deprecation_tests_dir_path in arg for arg in config.args])
    ):
        # test_deprecation_audit_logs should always run regardless the path that passed to pytest.
        config.args.append(
            os.path.join(deprecation_tests_dir_path, "test_deprecation_audit_logs.py")
        )

    if config.getoption("upgrade") == "ocp" and not config.getoption("ocp_image"):
        raise ValueError("Running with --upgrade ocp: Missing --ocp-image")

    if config.getoption("upgrade") == "cnv":
        if not config.getoption("cnv_version"):
            raise ValueError("Missing --cnv-version")
        if not config.getoption("cnv_image"):
            raise ValueError("Missing --cnv-image")

    # Default value is set as this value is used to set test name in
    # tests.upgrade_params.UPGRADE_TEST_DEPENDENCY_NODE_ID which is needed for pytest dependency marker
    py_config["upgraded_product"] = config.getoption("--upgrade") or "cnv"

    # [rhel|fedora|windows|centos]-os-matrix and latest-[rhel|fedora|windows|centos] are mutually exclusive
    rhel_os_violation = config.getoption("rhel_os_matrix") and config.getoption(
        "latest_rhel"
    )
    windows_os_violation = config.getoption("windows_os_matrix") and config.getoption(
        "latest_windows"
    )
    fedora_os_violation = config.getoption("fedora_os_matrix") and config.getoption(
        "latest_fedora"
    )
    centos_os_violation = config.getoption("centos_os_matrix") and config.getoption(
        "latest_centos"
    )
    if (
        rhel_os_violation
        or windows_os_violation
        or fedora_os_violation
        or centos_os_violation
    ):
        raise ValueError("os matrix and latest os options are mutually exclusive.")

    if (
        config.getoption("upgrade") == "cnv"
        and config.getoption("cnv_source")
        and not config.getoption("cnv_version")
    ):
        raise ValueError("Running with --cnv-source: Missing --cnv-version")


def pytest_collection_modifyitems(session, config, items):
    """
    Add polarion test case it from tests to junit xml
    """
    # TODO: Reduce cognitive complexity
    for item in items:
        scope_match = re.compile(r"__(module|class|function)__$")
        for fixture_name in [
            fixture_name
            for fixture_name in item.fixturenames
            if "_matrix" in fixture_name
        ]:
            _matrix_name = scope_match.sub("", fixture_name)
            # In case we got dynamic matrix (see get_matrix_params() in infra.py)
            matrix_name = get_base_matrix_name(matrix_name=_matrix_name)

            if _matrix_name != matrix_name:
                matrix_params = get_matrix_params(
                    pytest_config=config, matrix_name=_matrix_name
                )
                if not matrix_params:
                    skip = pytest.mark.skip(
                        reason=f"Dynamic matrix {_matrix_name} returned empty list"
                    )
                    item.add_marker(marker=skip)

            values = re.findall("(#.*?#)", item.name)
            for value in values:
                value = value.strip("#").strip("#")
                for param in py_config[matrix_name]:
                    if isinstance(param, dict):
                        param = [*param][0]

                    if value == param:
                        item.user_properties.append(
                            (f"polarion-parameter-{matrix_name}", value)
                        )

        for marker in item.iter_markers(name="polarion"):
            test_id = marker.args[0]
            item.user_properties.append(("polarion-testcase-id", test_id))

        for marker in item.iter_markers(name="bugzilla"):
            test_id = marker.args[0]
            item.user_properties.append(("bugzilla", test_id))

        for marker in item.iter_markers(name="jira"):
            test_id = marker.args[0]
            item.user_properties.append(("jira", test_id))

        for _ in item.iter_markers(name="upgrade_resilience"):
            item.user_properties.append(
                (
                    "polarion-parameter-upgrade_resilience",
                    config.getoption("upgrade_resilience"),
                )
            )

        # Add tier2 marker for tests without an exclution marker.
        markers = [mark.name for mark in list(item.iter_markers())]
        if not [mark for mark in markers if mark in EXCLUDE_MARKER_FROM_TIER2_MARKER]:
            item.add_marker(marker="tier2")

        # Mark tests by team.
        def _mark_tests_by_team(_item):
            for team, vals in TEAM_MARKERS.items():
                if _item.location[0].split("/")[1] in vals:
                    _item.add_marker(marker=team)

        _mark_tests_by_team(_item=item)

    #  Collect only 'upgrade' tests when running pytest with --upgrade
    upgrade_tests = [item for item in items if "upgrade" in item.keywords]
    non_upgrade_tests = [item for item in items if "upgrade" not in item.keywords]
    if config.getoption("--upgrade"):
        # Remove test marked with pytest.mark.ocp_upgrade if CNV upgrade else remove
        # test marked with pytest.mark.cnv_upgrade
        ocp_upgrade_test = [
            test for test in upgrade_tests if "ocp_upgrade" in test.keywords
        ][0]
        cnv_upgrade_test = [
            test for test in upgrade_tests if "cnv_upgrade" in test.keywords
        ][0]
        upgrade_tests.remove(
            ocp_upgrade_test
            if py_config["upgraded_product"] == "cnv"
            else cnv_upgrade_test
        )

        discard = non_upgrade_tests
        keep = upgrade_tests

    else:
        discard = upgrade_tests
        keep = non_upgrade_tests

    items[:] = keep
    config.hook.pytest_deselected(items=discard)


def pytest_report_teststatus(report, config):
    test_name = report.head_line
    when = report.when
    call_str = "call"
    if report.passed:
        if when == call_str:
            BASIC_LOGGER.info(f"\nTEST: {test_name} STATUS: \033[0;32mPASSED\033[0m")

    elif report.skipped:
        BASIC_LOGGER.info(f"\nTEST: {test_name} STATUS: \033[1;33mSKIPPED\033[0m")

    elif report.failed:
        if when != call_str:
            BASIC_LOGGER.info(
                f"\nTEST: {test_name} STATUS: [{when}] \033[0;31mERROR\033[0m"
            )
        else:
            BASIC_LOGGER.info(f"\nTEST: {test_name} STATUS: \033[0;31mFAILED\033[0m")


def pytest_runtest_makereport(item, call):
    """
    incremental tests implementation
    """
    if call.excinfo is not None and "incremental" in item.keywords:
        parent = item.parent
        parent._previousfailed = item


def pytest_fixture_setup(fixturedef, request):
    LOGGER.info(f"Executing {fixturedef.scope} fixture: {fixturedef.argname}")


def pytest_runtest_setup(item):
    """
    Use incremental
    """
    BASIC_LOGGER.info(f"\n{separator(symbol_='-', val=item.name)}")
    BASIC_LOGGER.info(f"{separator(symbol_='-', val='SETUP')}")
    if "incremental" in item.keywords:
        previousfailed = getattr(item.parent, "_previousfailed", None)
        if previousfailed is not None:
            pytest.xfail("previous test failed (%s)" % previousfailed.name)

    if data_collector_enabled(session=item.session):
        base_directory = py_config["data_collector"]["data_collector_base_directory"]
        py_config["data_collector"][
            "collector_directory"
        ] = prepare_pytest_item_data_dir(
            item=item, base_directory=base_directory, subdirectory_name="setup"
        )


def pytest_runtest_call(item):
    BASIC_LOGGER.info(f"{separator(symbol_='-', val='CALL')}")
    if data_collector_enabled(session=item.session):
        base_directory = py_config["data_collector"]["data_collector_base_directory"]
        py_config["data_collector"][
            "collector_directory"
        ] = prepare_pytest_item_data_dir(
            item=item, base_directory=base_directory, subdirectory_name="call"
        )


def pytest_runtest_teardown(item):
    BASIC_LOGGER.info(f"{separator(symbol_='-', val='TEARDOWN')}")
    if data_collector_enabled(session=item.session):
        base_directory = py_config["data_collector"]["data_collector_base_directory"]
        py_config["data_collector"][
            "collector_directory"
        ] = prepare_pytest_item_data_dir(
            item=item,
            base_directory=base_directory,
            subdirectory_name="teardown",
        )


def pytest_generate_tests(metafunc):
    scope_match = re.compile(r"__(module|class|function)__$")
    for fixture_name in [
        fname for fname in metafunc.fixturenames if "_matrix" in fname
    ]:
        scope = scope_match.findall(fixture_name)
        if not scope:
            raise ValueError(f"{fixture_name} is missing scope (__<scope>__)")

        matrix_name = scope_match.sub("", fixture_name)
        matrix_params = get_matrix_params(
            pytest_config=metafunc.config, matrix_name=matrix_name
        )
        ids = []
        for matrix_param in matrix_params:
            if isinstance(matrix_param, dict):
                ids.append(f"#{[*matrix_param][0]}#")
            else:
                ids.append(f"#{matrix_param}#")

        if matrix_params:
            metafunc.parametrize(
                fixture_name,
                matrix_params,
                ids=ids,
                scope=scope[0],
            )

    reorder_early_fixtures(metafunc=metafunc)


def pytest_sessionstart(session):
    # TODO: Reduce cognitive complexity
    def _update_os_related_config():
        # Save the default windows_os_matrix before it is updated
        # with runtime windows_os_matrix value(s).
        # Some tests extract a single OS from the matrix and may fail if running with
        # passed values from cli
        py_config["system_windows_os_matrix"] = py_config["windows_os_matrix"]
        py_config["system_rhel_os_matrix"] = py_config["rhel_os_matrix"]

        # Update OS matrix list with the latest OS if running with os_group
        if session.config.getoption("latest_rhel"):
            py_config["rhel_os_matrix"] = [
                utilities.infra.generate_latest_os_dict(
                    os_list=py_config["rhel_os_matrix"]
                )
            ]
        if session.config.getoption("latest_windows"):
            py_config["windows_os_matrix"] = [
                utilities.infra.generate_latest_os_dict(
                    os_list=py_config["windows_os_matrix"]
                )
            ]
        if session.config.getoption("latest_centos"):
            py_config["centos_os_matrix"] = [
                utilities.infra.generate_latest_os_dict(
                    os_list=py_config["centos_os_matrix"]
                )
            ]
        if session.config.getoption("latest_fedora"):
            py_config["fedora_os_matrix"] = [
                utilities.infra.generate_latest_os_dict(
                    os_list=py_config["fedora_os_matrix"]
                )
            ]

    data_collector = data_collector_enabled(session=session)
    if data_collector:
        with open(data_collector, "r") as fd:
            py_config["data_collector"] = yaml.safe_load(fd.read())
            shutil.rmtree(
                py_config["data_collector"]["data_collector_base_directory"],
                ignore_errors=True,
            )

    tests_log_file = session.config.getoption("pytest_log_file")
    if os.path.exists(tests_log_file):
        pathlib.Path(tests_log_file).unlink()

    setup_logging(
        log_file=tests_log_file,
        log_level=session.config.getoption("log_cli_level") or logging.INFO,
    )
    py_config_scs = py_config.get("storage_class_matrix", {})

    # Set py_config["storage_class_matrix"]
    # By default - new HPP (CSI) storage classes are added to the matrix
    py_config["hpp_storage_class_matrix"] = py_config["new_hpp_storage_class_matrix"]

    if not skip_if_pytest_flags_exists(pytest_config=session.config):
        # If Legacy storage 'hostpath-provisioner' is present in the cluster,
        # add Legacy HPP storage classes instead of new HPP (CSI) storage classes
        if cluster_resource(StorageClass).Types.HOSTPATH in [
            sc.name
            for sc in list(
                cluster_resource(StorageClass).get(dyn_client=get_admin_client())
            )
        ]:
            py_config["hpp_storage_class_matrix"] = py_config[
                "legacy_hpp_storage_class_matrix"
            ]
    py_config_scs.extend(py_config["hpp_storage_class_matrix"])

    # Save the default storage_class_matrix before it is updated
    # with runtime storage_class_matrix value(s)
    py_config["system_storage_class_matrix"] = py_config_scs

    _update_os_related_config()

    matrix_addoptions = [
        matrix
        for matrix in session.config.invocation_params.args
        if "-matrix=" in matrix
    ]
    for matrix_addoption in matrix_addoptions:
        items_list = []
        key, vals = matrix_addoption.split("=")
        key = key.strip("--").replace("-", "_")
        vals = vals.split(",")

        for val in vals:
            for item in py_config[key]:
                # Extract only the dicts item which has the requested key from
                if isinstance(item, dict) and [*item][0] == val:
                    items_list.append(item)

                # Extract only the items item which has the requested key from
                if isinstance(item, str) and item == val:
                    items_list.append(item)

        py_config[key] = items_list

    config_default_storage_class(session=session)

    # Set py_config["servers"]
    # Send --tc=server_url:<url> to override servers URL
    if not skip_if_pytest_flags_exists(pytest_config=session.config):
        server = py_config["server_url"] or get_cnv_qe_server_url(
            cluster_host_url=utilities.infra.get_admin_client().configuration.host
        )
        py_config["servers"] = {
            name: _server.format(server=server)
            for name, _server in py_config["servers"].items()
        }

    # must be at the end to make sure we create it only after all pytest_sessionstart checks pass.
    if not skip_if_pytest_flags_exists(pytest_config=session.config):
        stop_if_run_in_progress()
        deploy_run_in_progress_config_map(session=session)


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(path=session.config.option.basetemp, ignore_errors=True)
    if not skip_if_pytest_flags_exists(pytest_config=session.config):
        run_in_progress_config_map().clean_up()

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    deselected_str = "deselected"
    deselected = len(reporter.stats.get(deselected_str, []))
    summary = (
        f"{deselected} {deselected_str}, "
        f"{reporter.pass_count} {'passed'}, "
        f"{reporter.skip_count} {'skipped'}, "
        f"{reporter.fail_count} {'failed'}, "
        f"{reporter.error_count} {'error'}, "
        f"{reporter.xfail_count} {'xfail'}, "
        f"{reporter.xpass_count} {'xpass'}, "
        f"exit status {exitstatus} "
    )
    BASIC_LOGGER.info(f"{separator(symbol_='-', val=summary)}")

    # Remove empty directories from data collector directory
    if data_collector_enabled(session=session):
        collector_directory = py_config["data_collector"][
            "data_collector_base_directory"
        ]
        for root, dirs, files in os.walk(collector_directory, topdown=False):
            for _dir in dirs:
                dir_path = os.path.join(root, _dir)
                if not os.listdir(dir_path):
                    shutil.rmtree(dir_path, ignore_errors=True)


def pytest_exception_interact(node, call, report):
    BASIC_LOGGER.error(report.longreprtext)
    if node.session.config.getoption("--data-collector-failed-tests"):
        try:
            base_directory = os.path.join(
                py_config["data_collector"]["collector_directory"],
                "pytest_exception_interact",
            )
            namespace_name = utilities.infra.generate_namespace_name(
                file_path=node.fspath.strpath.split(f"{os.path.dirname(__file__)}/")[1]
            )
            dyn_client = utilities.infra.get_admin_client()
            collect_resources_yaml_instance(
                namespace_name=namespace_name,
                resources_to_collect=RESOURCES_TO_COLLECT_INFO,
                base_directory=base_directory,
            )
            pods = list(Pod.get(dyn_client=dyn_client))
            collect_pods_data(
                pods_list=pods,
                base_directory=base_directory,
                collect_pod_logs=py_config["data_collector"]["collect_pod_logs"],
            )

        except Exception as exp:
            LOGGER.warning(f"Failed to collect logs: {exp}")
            return
