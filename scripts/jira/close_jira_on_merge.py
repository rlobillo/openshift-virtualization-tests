import os
import re
import shlex
import subprocess

from jira import JIRA

from scripts.utils import get_connection_params


def get_jira_connection():
    connection_params = get_connection_params(conf_file_name="jira.cfg")
    return JIRA(
        token_auth=connection_params["token"],
        options={"server": connection_params["url"]},
    )


def get_jira_id_from_commit_msg():
    jira_ids = []
    data = subprocess.check_output(shlex.split("git log HEAD^-1"))
    data = data.decode("utf-8")
    match = re.findall("closes jira ticket: *(.*)", data, re.IGNORECASE)
    if match:
        jira_ids = match[0].split(",")
        jira_ids = [_id.strip() for _id in jira_ids]

    return jira_ids


if __name__ == "__main__":
    jira_connection = get_jira_connection()
    _jira_ids = get_jira_id_from_commit_msg()
    for _id in _jira_ids:
        jira_connection.transition_issue(
            issue=_id,
            transition="closed",
            comment=(
                f"Closed by PR: https://code.engineering.redhat.com/gerrit/c/cnv-tests/+/"
                f"{os.getenv('GERRIT_CHANGE_NUMBER')}"
            ),
        )
