import os
from configparser import ConfigParser
from pathlib import Path

from git import Repo


# TODO: Reuse the code from infra.py once we move bugzilla
def get_connection_params(conf_file_name):
    conf_file = os.path.join(Path(".").resolve(), conf_file_name)
    parser = ConfigParser()
    # Open the file with the correct encoding
    parser.read(conf_file, encoding="utf-8")
    params_dict = {}
    for params in parser.items("DEFAULT"):
        params_dict[params[0]] = params[1]
    return params_dict


def print_status(status_dict):
    for key, value in status_dict.items():
        print(f"    {key}:  {' '.join(list(set(value)))}")
    print("\n")


def all_python_files():
    exclude_dirs = [".tox", "cnv-tests/scripts"]
    for root, _, files in os.walk(os.path.abspath(os.curdir)):
        if [_dir for _dir in exclude_dirs if _dir in root]:
            continue

        for filename in files:
            file_path = os.path.join(root, filename)
            if filename.endswith(".py") and file_path != os.path.abspath(__file__):
                yield file_path


class ParentBranchNotFound(Exception):
    pass


def get_parent_branch(known_branches):
    repo = Repo(path=".")
    for parent in repo.head.commit.iter_parents():
        commit_parent = parent.name_rev
        if "/" in commit_parent:
            # In some cases we get remotes/origin/<branch>
            parent_branch = commit_parent.rsplit("/", 1)[-1]
        else:
            # In other cases we get <branch>
            parent_branch = commit_parent.split()[-1]

        if known_branches.get(parent_branch):
            return known_branches[parent_branch]

    raise ParentBranchNotFound(
        "Could not determine tracking branch, Please rebase the PR"
    )
