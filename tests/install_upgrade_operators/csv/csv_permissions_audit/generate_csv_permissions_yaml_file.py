import yaml

from tests.install_upgrade_operators.csv.csv_permissions_audit.utils import (
    get_csv_permissions,
    get_yaml_file_path,
)


# To update permissions.yaml run: `poetry run python tests/csv_permissions_audit/utils.py`
if __name__ == "__main__":
    with open(get_yaml_file_path(), "w") as fd:
        fd.write(yaml.dump(get_csv_permissions()))
