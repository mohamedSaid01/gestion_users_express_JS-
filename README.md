# Système de Gestion des Utilisateurs 🧑‍💻

Ce projet est un système de gestion des utilisateurs basé sur Node.js avec des fonctionnalités d'authentification, de gestion de profil, de réinitialisation de mot de passe et de détection des connexions suspectes à l'aide d'une API Flask utilisant un modèle d'apprentissage automatique. Il inclut le verrouillage temporaire des comptes après plusieurs tentatives de connexion échouées, des notifications par email pour les activités suspectes et des prédictions sur le comportement des utilisateurs basées sur leurs métriques de connexion.

---

## 🚀 Fonctionnalités Principales

### 🔐 Authentification des utilisateurs
  - Inscription avec email, mot de passe et informations de profil.
  - Connexion avec authentification basée sur JWT et stockage dans des cookies.
  - Déconnexion avec suivi de la durée des sessions.

### 🔑 Gestion des mots de passe
  - Réinitialisation du mot de passe via un code envoyé par email.
  - Modification du mot de passe pour les utilisateurs authentifiés.

### 👤 Gestion de Profil
- Mise à jour des informations de profil (par exemple, prénom, nom, téléphone, adresse).

### 🔒 Sécurité 
- Verrouillage temporaire du compte après 3 tentatives de connexion échouées (verrouillage de 15 minutes).
- Détection des connexions suspectes à l'aide d'un modèle de régression logistique via une API Flask.
- Notifications par email pour les activités suspectes (via Nodemailer).

### 🧠 Prédiction du comportement des utilisateurs
- Prédiction de la catégorie d'utilisateur (par exemple, actif, inactif) basée sur la fréquence des connexions et la durée des sessions.
- Endpoint réservé aux administrateurs pour prédire les catégories de tous les utilisateurs non-admin.
- Endpoint réservé aux administrateurs pour détecter les tentatives de connexion suspectes pour tous les utilisateurs.

---

## 🛠️ Technologies Utilisées

- Backend : Node.js, Express.js, MongoDB (Mongoose), JWT, bcrypt, Nodemailer, Axios.
- Apprentissage automatique : API Flask avec scikit-learn (régression logistique).
- Base de données : MongoDB pour le stockage des utilisateurs.

---

## ✅ Pré-requis

- Node.js (v16 ou supérieur)
- MongoDB (v4.4 ou supérieur)
- Python (v3.8 ou supérieur)
- Git (pour cloner le dépôt)
- Un serveur de messagerie (par exemple, Gmail) pour l'envoi des emails (configurer avec un mot de passe spécifique à l'application)

---

## ⚙️ Installation

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/mohamedSaid01/gestion_users_express_JS-.git
   cd gestion_users_express_JS-
2. Installer les dépendances Node.js :
   ```bash
   npm install
3. Installer les dépendances Python pour l'API Flask :
   ```bash
   cd ml_api
   pip install flask scikit-learn joblib pandas numpy
4. Entraîner le modèle d'apprentissage automatique :
   ```bash
   cd ml_api
   python train_failed_logins_model.py

  ---

  ## 🚀 Utilisation

1. Démarrer l'API Flask :
   ```bash
   cd ml_api
   python api.py
2. Démarrer le serveur Node.js  :
   ```bash
   cd gestion_users_express_JS-
   npm run dev 


   
