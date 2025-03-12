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
from flask_sqlalchemy import SQLAlchemy
from flask_rbac_icdc import RbacAccount

db = SQLAlchemy()

class Account(db.Model, RbacAccount):
    __tablename__ = "accounts"
    object_name = "accounts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False)
    # ...Other account properties here

    @classmethod
    def get_by_name(cls, account_name: str) -> Optional["Account"]:
        return cls.query.filter_by(name=account_name).first()

    def subject_role(self, x_auth_role: str) -> str:
        operator = is_operator(self.name, x_auth_role)
        if x_auth_role == "operator" and not operator:
            raise PermissionException("You are not operator")
        if operator:
            return "operator"
        return x_auth_role
```

### Initialize RBAC
Initialize the RBAC instance in your Flask application:
```py
from flask_rbac_icdc import RBAC
from app.models.accounts import Account

rbac = RBAC(config_path='rbac_config.yaml', Accounts)
```

### Protect Endpoints
Use the `allow` decorator to protect your endpoints:
```py
@app.route('/create', methods=['POST'])
@rbac.allow('products.create')
def create_product(subject):
    # Your logic to create a product
    return 'Product created', 201

@app.route('/read', methods=['GET'])
@rbac.allow('products.list')
def list_products(subject):
    # Your logic to list products
    return 'Products data', 200
```

## License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/icdc-io/flask-rbac/blob/main/LICENSE) file for details.