import re
from xmlrpc.client import Fault

import bugzilla
from git import Repo
from packaging.version import InvalidVersion, Version

from scripts.utils import all_python_files, get_connection_params, print_status


# Needs to be update based on the branch.
EXPECTED_TARGET_BRANCH = "cnv-4.12"
BUG_STATUS_CLOSED = ("VERIFIED", "CLOSED", "RELEASE_PENDING")
KNOWN_BRANCHES = {
    EXPECTED_TARGET_BRANCH: "4.12",
    "cnv-4.11": "4.11",
    "cnv-4.10": "4.10",
    "cnv-4.9": "4.9",
    "cnv-4.8": "4.8",
}


class ParentBranchNotFound(Exception):
    pass


def get_parent_branch():
    repo = Repo(path=".")
    for parent in repo.head.commit.iter_parents():
        commit_parent = parent.name_rev
        if "/" in commit_parent:
            # In some cases we get remotes/origin/<branch>
            parent_branch = commit_parent.rsplit("/", 1)[-1]
        else:
            # In other cases we get <branch>
            parent_branch = commit_parent.split()[-1]

        if KNOWN_BRANCHES.get(parent_branch):
            return KNOWN_BRANCHES[parent_branch]

    raise ParentBranchNotFound(
        "Could not determine tracking branch, Please rebase the PR"
    )


def get_bug(bug_id):
    """
    Get bug instance from bugzilla.

    Args:
        bug_id (int): Bug ID.

    Returns:
        Bug: Bugzilla bug instance.
    """
    if not isinstance(bug_id, int):
        raise ValueError("bug_id ARG must be int")

    bugzilla_connection_params = get_connection_params(conf_file_name="bugzilla.cfg")
    bzapi = bugzilla.Bugzilla(
        url=bugzilla_connection_params["bugzilla_url"],
        user=bugzilla_connection_params["bugzilla_username"],
        api_key=bugzilla_connection_params["bugzilla_api_key"],
    )
    return bzapi.getbug(objid=bug_id)


def get_all_bugs_from_file(file_content):
    """
    Try to find all bugs in the file.
    Looking for the following patterns:
    - bug_id=12345  # call in is_bug_open
    - bug_id = 12345  # when bug is constant
    - https://bugzilla.redhat.com/show_bug.cgi?id=12345  # when bug is in a link in comments
    - pytest.mark.bugzilla(12345)  # when bug is in a marker

    Args:
        file_content (str): The content of the file.

    Returns:
        list: A list of bugs.
    """
    _pytest_bugzilla_marker_bugs = re.findall(
        r"pytest.mark.bugzilla.*?(\d{7,})", file_content, re.DOTALL
    )
    _is_bug_open_bugs = re.findall(r"(?:bug_id=|.*bug.* = )(\d{7,})", file_content)
    _bugzilla_url_bugs = re.findall(
        r"https://bugzilla.redhat.com/show_bug.cgi\?id=(\d{7,}(?! <skip-bug-check>))",
        file_content,
    )
    bugzilla_comments = re.findall(
        r"(?:BZ |.*BZ)(\d{7,}(?! <skip-bug-check>))", file_content, re.IGNORECASE
    )
    return set(
        _pytest_bugzilla_marker_bugs
        + _is_bug_open_bugs
        + _bugzilla_url_bugs
        + bugzilla_comments
    )


def main():
    parent_branch = get_parent_branch()
    closed_bugs = {}
    mismatch_bugs_version = {}
    bugs_with_errors = {}
    for filename in all_python_files():
        filename_for_key = re.findall(r"cnv-tests/.*", filename)[0]
        with open(filename, "r") as fd:
            file_content = fd.read()

        for _bug in get_all_bugs_from_file(file_content=file_content):
            try:
                bug = get_bug(bug_id=int(_bug))
            except Fault as exp:
                bugs_with_errors.setdefault(filename_for_key, []).append(
                    f"{_bug} [{exp.faultString}]"
                )
                continue

            bug_status = bug.status
            if bug_status in BUG_STATUS_CLOSED:
                closed_bugs.setdefault(filename_for_key, []).append(
                    f"{_bug} [{bug_status}]"
                )

            else:
                bug_target_release = bug.target_release[0]
                try:
                    bug_target_release_version = Version(bug_target_release)
                    expected_target_branch = Version(
                        KNOWN_BRANCHES[EXPECTED_TARGET_BRANCH]
                    )
                    if (
                        expected_target_branch.major != bug_target_release_version.major
                        and expected_target_branch.minor
                        != bug_target_release_version.minor
                    ):
                        mismatch_bugs_version.setdefault(filename_for_key, []).append(
                            f"{_bug} [{bug_target_release}]"
                        )
                except InvalidVersion:
                    # Ignore bugs with 'future' target release version
                    if bug_target_release == "future":
                        continue

                if parent_branch not in bug_target_release:
                    mismatch_bugs_version.setdefault(filename_for_key, []).append(
                        f"{_bug} [{bug_status}] [{bug_target_release}]"
                    )

    if closed_bugs:
        print(
            f"The following bugs are closed and needs to be removed ({len(closed_bugs)}):"
        )
        print_status(status_dict=closed_bugs)

    if mismatch_bugs_version:
        print(
            f"The following bugs are not matched the current branch {parent_branch} "
            f"and needs to be removed ({len(mismatch_bugs_version)}):"
        )
        print_status(status_dict=mismatch_bugs_version)

    if bugs_with_errors:
        print(f"The following bugs had errors ({len(bugs_with_errors)}):")
        print_status(status_dict=bugs_with_errors)

    if closed_bugs or mismatch_bugs_version or bugs_with_errors:
        exit(1)


if __name__ == "__main__":
    main()
