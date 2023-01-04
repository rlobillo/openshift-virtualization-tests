import os
import re
import shlex
import subprocess
import sys

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
    match = re.findall("closes jira (?:ticket|issue)s?: *(.*)", data, re.IGNORECASE)
    if match:
        jira_ids = match[0].split(",")
        jira_ids = [_id.strip() for _id in jira_ids]

    return jira_ids


if __name__ == "__main__":
    change_url = os.getenv("GERRIT_CHANGE_URL")
    if change_url is None:
        sys.exit("GERRIT_CHANGE_URL environment variable is not set")

    print(f"Change {change_url} was merged, looking for Jira linked issues")
    _jira_ids = get_jira_id_from_commit_msg()
    if len(_jira_ids) == 0:
        print("No linked issues found in commit message.")
    else:
        jira_connection = get_jira_connection()
        for jira_issue_id in _jira_ids:
            print(f"Closing Jira ticket {jira_issue_id}")
            jira_connection.transition_issue(
                issue=jira_issue_id,
                transition="closed",
                comment=f"Closed by PR: {change_url}",
            )
