# Config Auditor

Un outil d'audit de configuration Node.js qui analyse et optimise les paramètres de votre application.

## 🚀 Fonctionnalités

- Analyse des dépendances et détection des vulnérabilités
- Vérification des versions obsolètes des packages
- Optimisation des flags Node.js selon votre environnement
- Analyse des ressources système
- Recommandations de sécurité personnalisées

## 📋 Prérequis

- Node.js (v14 ou supérieur)
- NPM ou Yarn
- Une clé API Snyk (pour l'analyse des vulnérabilités)

## 🛠️ Installation

```bash
# Cloner le repository
git clone [url-du-repo]

# Installer les dépendances
npm install

# Copier le fichier .env.example
cp .env.example .env
```

## ⚙️ Configuration

Configurez les variables d'environnement dans le fichier `.env` :

```env
API_URL=http://localhost:3000
PORT=3000
MONGODB_URI=mongodb://localhost:27017/votre_base
NODE_ENV=development
```

## 📦 Utilisation

1. Mettre index.js + audit_conf.js dans le même dossier
2. Installer les dépendances axios et chalk : `npm install axios chalk`
3. Lancer le script avec la commande : `node index.js`
4. Voir les résultats dans la console

## 🔍 Fonctionnalités détaillées

### Analyse des dépendances
- Vérifie les versions des packages
- Détecte les vulnérabilités via l'API Snyk
- Suggère des mises à jour

### Optimisation des flags Node.js
- Recommandations basées sur l'environnement (dev/prod)
- Optimisations selon les ressources système
- Flags de sécurité personnalisés

### Analyse système
- Vérification des ressources CPU
- Analyse de la mémoire disponible
- Recommandations d'optimisation

## 🔐 Sécurité

L'outil inclut plusieurs vérifications de sécurité :
- Validation des versions TLS
- Contrôle des flags de sécurité
- Détection des configurations sensibles

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## ✨ Auteur

Chuky Fredj - chukyfredj@gmail.com

## 📄 Changelog

### Version 1.0.0
- Première version stable
- Implémentation de l'analyse des dépendances
- Ajout des recommandations de flags Node.js
- Intégration de l'API Snyk
```