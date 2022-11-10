import pytest


@pytest.fixture(scope="module")
def skip_if_no_cpumanager_workers(schedulable_nodes):
    if not any([node.labels.cpumanager == "true" for node in schedulable_nodes]):
        pytest.skip("Test should run on cluster with CPU Manager")
