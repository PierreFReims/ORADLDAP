# ORADLDAP
Outil de Récuperation Automatique de Données LDAP

Les points de contrôles sont effectués sur deux bases distinctes, le DIT (Directory Information Tree) et la base de configuration cn=config.
Veuillez renseigner deux comptes ayant les permissions administrateurs sur la base à auditer et 

## Installation

Make sure you have Python installed. Clone the repository and install the dependencies:

```bash
git clone https://github.com/PierreFReims/ORADLDAP.git
cd ORADLDAP
pip3 install -r requirements.txt
```

## Usage

```bash
./main.py conf.yaml
```

>Administrator privileges on cn=config are required 
