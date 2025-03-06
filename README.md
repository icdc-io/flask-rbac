# RBAC library for Flask

## Overview

This library provides role-based access control (RBAC) for Flask applications using a YAML configuration file.

## Installation

```sh
pip install flask-rbac-icdc
```

## Usage
### Configuration
Create a YAML configuration file for RBAC rules. For example, `rbac_config.yaml`:
```yaml
roles:
  admin:
    products:
      permissions:
        - list
        - create
        - update
        - delete
      filters: {}
    accounts:
      permissions:
        - list
        - get
      filters:
        id: account_id
  member:
    products:
      permissions:
        - list
      filters:
        account_id: account_id
        owner: owner
```
### Define Account Class
Implement the `RbacAccount` abstract class:
```py
from flask_rbac_icdc import RbacAccount

class Account(RbacAccount):
    def __init__(self, account_id, name):
        self._id = account_id
        self._name = name

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    def subject_role(self, x_auth_role, roles):
        return roles[x_auth_role.upper()]
```

### Initialize RBAC
Initialize the RBAC instance in your Flask application:
```py
from flask import Flask
from flask_rbac_icdc import RBAC

app = Flask(__name__)

def get_account(account_name):
    # Replace with your logic to get the account by name
    return Account(1, account_name)

rbac = RBAC(config_path='rbac_config.yaml', get_account=get_account)
```

### Protect Endpoints
Use the `allow` decorator to protect your endpoints:
```py
@app.route('/create', methods=['POST'])
@rbac.allow('products.create')
def create_product():
    # Your logic to create a product
    return 'Product created', 201

@app.route('/read', methods=['GET'])
@rbac.allow('products.list')
def list_products():
    # Your logic to list products
    return 'Products data', 200
```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.