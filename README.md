# 🔐 Hybrid KEM: RSA + Kyber (Post-Quantum Cryptography)

Ce projet implémente un **échange de clés hybride** combinant :

- 🔒 **RSA-OAEP** (cryptographie classique)
- 🧪 **Kyber512 simplifié** (cryptographie post-quantique)
- 🔄 **HKDF (SHA-256)** pour dériver une **clé finale partagée K_final**
- 🔐 **AES-GCM** pour le chiffrement sécurisé des messages
- 🖥️ Interface graphique simple entre **Alice** et **Bob**

---

## 📚 Fonctionnalités

- Génération de paires de clés RSA et Kyber (public/privé)
- Encapsulation des clés symétriques (RSA + Kyber)
- Décapsulation par l’autre partie
- Fusion avec KDF → Clé finale commune `K_final`
- Chiffrement/Déchiffrement AES-GCM
- Interface GUI pour échange de messages

---

## 🧠 Principe cryptographique

1. **Alice et Bob** génèrent chacun :
   - une paire de clés RSA : `(e, d, n)`
   - une paire de clés Kyber : `(pk, sk)`

2. Chaque partie encapsule deux clés symétriques :
   - 🔐 Avec la **clé publique RSA** de l'autre → `K_RSA`
   - 🧪 Avec la **clé publique Kyber** de l'autre → `K_Kyber`

3. Chaque partie reçoit :
   - les encapsulations `C_RSA`, `C_Kyber`
   - puis récupère les clés symétriques via **décapsulation**

4. 🧬 La **clé finale `K_final`** est calculée :

```python
K_final = HKDF_SHA256(K_RSA_from + K_Kyber_from + K_RSA_to + K_Kyber_to)
```

🔐 Cette clé K_final permet un chiffrement symétrique AES-GCM sécurisé pour échanger les messages.

---

## 📁 Arborescence du projet

```
Projet_Crypto/
├── Alice/
│   ├── alice_rsa_private.pem
│   ├── alice_rsa_public.pem
│   ├── alice_kyber_pk.bin
│   ├── alice_kyber_sk.bin
│   └── ...
├── Bob/
│   ├── bob_rsa_private.pem
│   ├── bob_rsa_public.pem
│   ├── bob_kyber_pk.bin
│   └── ...
├── interface_alice.py
├── interface_bob.py
├── KEM_RSA_Alice.py
├── KEM_RSA_Bob.py
├── simple_kyber512.py
└── README.md
```

---

## ⚙️ Dépendances

Installe les dépendances avec :

```bash
pip install cryptography numpy
```

---

## ▶️ Utilisation

### 1. Lancer les scripts d’échange

Ouvrir deux terminaux :

**Terminal 1 (Alice)** :

```bash
python KEM_RSA_Alice.py
```

**Terminal 2 (Bob)** :

```bash
python KEM_RSA_Bob.py
```

Les fichiers d’échange sont générés dans les dossiers respectifs.

### 2. Lancer l’interface graphique

**Alice** :

```bash
python interface_alice.py
```

**Bob** :

```bash
python interface_bob.py
```

---

## 🔍 Exemple de sortie

```
K_RSA_to_alice : 7c6211...
K_Kyber_to_alice : e134fa...
K_final : 8cf43c911bb372...
Message reçu de Bob : Hello Alice!
```

---

## 🧠 À propos de Kyber (simplifié)

Ce projet utilise une implémentation pédagogique de Kyber :

- Bruit simplifié
- Pas de polynômes NTT
- Extraction de clé partagée avec un hash SHA-256

---

## 🔒 Sécurité

Le projet montre comment combiner une sécurité classique (RSA) et post-quantique (Kyber)

Le protocole garantit :

- Authenticité (signature possible à étendre)
- Confidentialité
- Résistance aux attaques quantiques (via Kyber)

---

## 📜 Licence

Projet open-source à usage éducatif – MIT License.

---

## ✨ Auteur

**Zoran** – 2025  
Projet d’études en cryptographie post quantique.
