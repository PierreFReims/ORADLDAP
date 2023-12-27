# ORADLDAP
ORADLDAP, acronyme pour "Outil de Récupération Automatique de Données LDAP", est un outil destiné à la récupération automatisée de données LDAP.

Les points de contrôle s'effectuent sur deux bases distinctes : l'Arbre d'Information du Répertoire (DIT) et la base de configuration cn=config. Le script est exécuté avec trois niveaux de privilèges différents :

    Utilisateur Anonyme : Fournit des informations minimales.
    Utilisateur Authentifié : Offre des résultats plus détaillés.
    Utilisateur Administrateur : Fournit les résultats les plus complets et précis.

Bien qu'il ne soit pas obligatoire de fournir des informations d'identification d'utilisateur authentifié, le faire améliore considérablement la précision des résultats.

## Installation

Assurez-vous que Python est installé sur votre système. Clonez le dépôt et installez les dépendances :

```bash
git clone https://github.com/PierreFReims/ORADLDAP.git
cd ORADLDAP
pip3 install -r requirements.txt
```

## Usage

```bash
./main.py conf.yaml
```