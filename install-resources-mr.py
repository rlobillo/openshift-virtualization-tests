import os
import shutil

import click


@click.command()
@click.option("--branch", "-b", help="Github branch to fetch", required=True)
def install_mr(branch):
    """
    Install ocp-python-wrapper (resources) merge-requests from github into poetry cnv-tests.
    """
    tmp_dir = "/tmp"
    ocp_python_wrapper_name = "openshift-python-wrapper"
    mr_branch = f"cnv-qe/{ocp_python_wrapper_name}-{branch}"
    ocp_cloned_path = os.path.join(tmp_dir, ocp_python_wrapper_name)
    ocp_python_wrapper_git = (
        f"https://github.com/RedHatQE/{ocp_python_wrapper_name}.git"
    )
    current_dir = os.path.abspath(path=os.curdir)
    os.chdir(path=tmp_dir)
    os.system(command=f"git clone {ocp_python_wrapper_git}")
    os.chdir(path=ocp_cloned_path)
    os.system(command=f"git fetch {ocp_python_wrapper_git} {branch}")
    os.system(command=f"git checkout -b {mr_branch} FETCH_HEAD")
    os.chdir(path=current_dir)
    os.system(f"pip install -U {ocp_cloned_path}")
    shutil.rmtree(path=ocp_cloned_path, ignore_errors=True)


if __name__ == "__main__":
    install_mr()
