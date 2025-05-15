import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import simple_kyber512
import time

# Dossiers absolus pour Bob et Alice
bob_dir = r"C:\Users\zoran\Documents\Projet_Crypto\Bob"
alice_dir = r"C:\Users\zoran\Documents\Projet_Crypto\Alice"

# --- Fonctions utilitaires partagées ---
def file_exists_anywhere(filename, dir1, dir2):
    return (
        os.path.exists(os.path.join(dir1, filename)) or
        os.path.exists(os.path.join(dir2, filename))
    )

def read_anywhere(filename, prefer_dir, other_dir):
    dirs = [prefer_dir, other_dir]
    for d in dirs:
        path = os.path.join(d, filename)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
    raise FileNotFoundError(f"{filename} introuvable dans {dirs[0]} ou {dirs[1]}")

def export_keys_if_needed():
    # Exporte toujours la clé publique de Bob dans le dossier d'Alice
    os.makedirs(alice_dir, exist_ok=True)
    with open(os.path.join(alice_dir, "bob_rsa_public.pem"), "wb") as f:
        f.write(rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(os.path.join(alice_dir, "bob_kyber_pk.bin"), "wb") as f:
        f.write(pk)

# --- Vérification des fichiers d'échange ---
exchange_files = [
    "C_RSA_to_alice.bin", "C_Kyber_to_alice.bin", "K_RSA_to_alice.bin", "K_Kyber_to_alice.bin",
    "C_RSA_to_bob.bin", "C_Kyber_to_bob.bin", "K_RSA_to_bob.bin", "K_Kyber_to_bob.bin"
]
existing = [f for f in exchange_files if os.path.exists(os.path.join(bob_dir, f))]
kfinal_path = os.path.join(bob_dir, "K_final.bin")
if existing and os.path.exists(kfinal_path):
    print("Fichiers d'échange déjà présents (aucune régénération) :")
    for f in existing:
        print(" -", f)
    resp = input("Supprimer ces fichiers pour un nouvel échange ? (o/n) : ").strip().lower()
    if resp == "o":
        for f in existing:
            os.remove(os.path.join(bob_dir, f))
        print("Fichiers supprimés. Relancez le script.")
        exit(0)

# --- Génération ou chargement des clés RSA de Bob ---
if not os.path.exists(os.path.join(bob_dir, "bob_rsa_private.pem")):
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(bob_dir, "bob_rsa_private.pem"), "wb") as f:
        f.write(rsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(os.path.join(bob_dir, "bob_rsa_public.pem"), "wb") as f:
        f.write(rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open(os.path.join(bob_dir, "bob_rsa_private.pem"), "rb") as f:
        rsa_private = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(bob_dir, "bob_rsa_public.pem"), "wb") as f:
        f.write(rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# --- Génération ou chargement des clés Kyber simplifié de Bob ---
if not os.path.exists(os.path.join(bob_dir, "bob_kyber_sk.bin")):
    pk, sk = simple_kyber512.keygen()
    with open(os.path.join(bob_dir, "bob_kyber_pk.bin"), "wb") as f:
        f.write(pk)
    with open(os.path.join(bob_dir, "bob_kyber_sk.bin"), "wb") as f:
        f.write(sk)
else:
    with open(os.path.join(bob_dir, "bob_kyber_pk.bin"), "rb") as f:
        pk = f.read()
    with open(os.path.join(bob_dir, "bob_kyber_sk.bin"), "rb") as f:
        sk = f.read()

# Exporte toujours la clé publique de Bob dans le dossier d'Alice
export_keys_if_needed()

# --- Récupération des clés publiques d'Alice depuis le dossier Alice ---
if not (os.path.exists(os.path.join(alice_dir, "alice_rsa_public.pem")) and os.path.exists(os.path.join(alice_dir, "alice_kyber_pk.bin"))):
    missing = []
    if not os.path.exists(os.path.join(alice_dir, "alice_rsa_public.pem")):
        missing.append("alice_rsa_public.pem")
    if not os.path.exists(os.path.join(alice_dir, "alice_kyber_pk.bin")):
        missing.append("alice_kyber_pk.bin")
    print("Les clés publiques d'Alice sont manquantes dans le dossier de Bob :", ", ".join(missing))
    exit(1)

with open(os.path.join(alice_dir, "alice_rsa_public.pem"), "rb") as f:
    alice_rsa_public = serialization.load_pem_public_key(f.read())
with open(os.path.join(alice_dir, "alice_kyber_pk.bin"), "rb") as f:
    alice_kyber_pk = f.read()

# --- Encapsulation vers Alice (uniquement si fichiers n'existent pas déjà) ---
if not (os.path.exists(os.path.join(bob_dir, "C_RSA_to_alice.bin")) and os.path.exists(os.path.join(bob_dir, "C_Kyber_to_alice.bin"))):
    K_RSA_to_alice = os.urandom(32)
    C_RSA_to_alice = alice_rsa_public.encrypt(
        K_RSA_to_alice,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(os.path.join(bob_dir, "C_RSA_to_alice.bin"), "wb") as f:
        f.write(C_RSA_to_alice)
    C_Kyber_to_alice, K_Kyber_to_alice = simple_kyber512.encapsulate(alice_kyber_pk)
    with open(os.path.join(bob_dir, "C_Kyber_to_alice.bin"), "wb") as f:
        f.write(C_Kyber_to_alice)
    with open(os.path.join(bob_dir, "K_RSA_to_alice.bin"), "wb") as f:
        f.write(K_RSA_to_alice)
    with open(os.path.join(bob_dir, "K_Kyber_to_alice.bin"), "wb") as f:
        f.write(K_Kyber_to_alice)
    print("Clés envoyées à Alice : K_RSA_to_alice, K_Kyber_to_alice")
else:
    with open(os.path.join(bob_dir, "K_RSA_to_alice.bin"), "rb") as f:
        K_RSA_to_alice = f.read()
    with open(os.path.join(bob_dir, "K_Kyber_to_alice.bin"), "rb") as f:
        K_Kyber_to_alice = f.read()

print("K_RSA_to_alice :", K_RSA_to_alice.hex())
print("K_Kyber_to_alice :", K_Kyber_to_alice.hex())

# --- Recherche des fichiers d'échange dans les deux dossiers ---
required_files = [
    "C_RSA_to_alice.bin", "C_Kyber_to_alice.bin", "K_RSA_to_alice.bin", "K_Kyber_to_alice.bin",
    "C_RSA_to_bob.bin", "C_Kyber_to_bob.bin", "K_RSA_to_bob.bin", "K_Kyber_to_bob.bin"
]
all_present = all(
    file_exists_anywhere(f, bob_dir, alice_dir)
    for f in required_files
)

if all_present:
    K_RSA_to_alice = read_anywhere("K_RSA_to_alice.bin", bob_dir, alice_dir)
    K_Kyber_to_alice = read_anywhere("K_Kyber_to_alice.bin", bob_dir, alice_dir)
    K_RSA_to_bob = read_anywhere("K_RSA_to_bob.bin", bob_dir, alice_dir)
    K_Kyber_to_bob = read_anywhere("K_Kyber_to_bob.bin", bob_dir, alice_dir)
    print("K_RSA_to_alice :", K_RSA_to_alice.hex())
    print("K_Kyber_to_alice :", K_Kyber_to_alice.hex())
    print("K_RSA_to_bob :", K_RSA_to_bob.hex())
    print("K_Kyber_to_bob :", K_Kyber_to_bob.hex())
    try:
        KDF = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"KEM_RSA+Kyber",
        )
        K_final = KDF.derive(
            K_RSA_to_alice + K_Kyber_to_alice + K_RSA_to_bob + K_Kyber_to_bob
        )
        print("K_final :", K_final.hex())
        with open(os.path.join(bob_dir, "K_final.bin"), "wb") as f:
            f.write(K_final)
        if os.path.exists(os.path.join(bob_dir, "message_aesgcm_from_alice.bin")):
            with open(os.path.join(bob_dir, "message_aesgcm_from_alice.bin"), "rb") as f:
                nonce = f.read(12)
                ciphertext = f.read()
            aesgcm = AESGCM(K_final)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            print("Message reçu d'Alice :", plaintext.decode())
    except Exception as e:
        print("Erreur lors du calcul de la KDF ou du déchiffrement :", e)
else:
    print("Tous les fichiers d'échange nécessaires sont présents pour calculer la KDF.")

# --- Vérification de la présence des encapsulations de Alice ---
has_alice_encaps = (
    os.path.exists(os.path.join(bob_dir, "C_RSA_to_bob.bin")) and
    os.path.exists(os.path.join(bob_dir, "C_Kyber_to_bob.bin"))
)
has_pub_alice = (
    os.path.exists(os.path.join(alice_dir, "alice_rsa_public.pem")) and
    os.path.exists(os.path.join(alice_dir, "alice_kyber_pk.bin"))
)
has_my_encaps = (
    os.path.exists(os.path.join(bob_dir, "C_RSA_to_alice.bin")) and
    os.path.exists(os.path.join(bob_dir, "C_Kyber_to_alice.bin"))
)
has_my_keys = (
    os.path.exists(os.path.join(bob_dir, "K_RSA_to_alice.bin")) and
    os.path.exists(os.path.join(bob_dir, "K_Kyber_to_alice.bin"))
)

if not all_present:
    if has_pub_alice and has_alice_encaps and has_my_encaps and has_my_keys:
        with open(os.path.join(bob_dir, "C_RSA_to_bob.bin"), "rb") as f:
            C_RSA_from_alice = f.read()
        with open(os.path.join(bob_dir, "C_Kyber_to_bob.bin"), "rb") as f:
            C_Kyber_from_alice = f.read()
        with open(os.path.join(bob_dir, "K_RSA_to_alice.bin"), "rb") as f:
            K_RSA_to_alice = f.read()
        with open(os.path.join(bob_dir, "K_Kyber_to_alice.bin"), "rb") as f:
            K_Kyber_to_alice = f.read()
        K_RSA_from_alice = rsa_private.decrypt(
            C_RSA_from_alice,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        K_Kyber_from_alice = simple_kyber512.decapsulate(C_Kyber_from_alice, sk)
        print("K_RSA_from_alice :", K_RSA_from_alice.hex())
        print("K_Kyber_from_alice :", K_Kyber_from_alice.hex())
        if (K_RSA_to_alice and K_Kyber_to_alice and K_RSA_from_alice and K_Kyber_from_alice):
            KDF = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"KEM_RSA+Kyber",
            )
            K_final = KDF.derive(
                K_RSA_from_alice + K_Kyber_from_alice + K_RSA_to_alice + K_Kyber_to_alice
            )
            print("K_final :", K_final.hex())
            with open(os.path.join(bob_dir, "K_final.bin"), "wb") as f:
                f.write(K_final)
        else:
            print("KDF non calculé : toutes les clés nécessaires ne sont pas présentes.")
        if os.path.exists(os.path.join(bob_dir, "message_aesgcm_from_alice.bin")):
            with open(os.path.join(bob_dir, "message_aesgcm_from_alice.bin"), "rb") as f:
                nonce = f.read(12)
                ciphertext = f.read()
            aesgcm = AESGCM(K_final)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            print("Message reçu d'Alice :", plaintext.decode())
        else:
            print("message_aesgcm_from_alice.bin introuvable dans le dossier de Bob.")
