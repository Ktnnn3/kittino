#!/usr/bin/env python3

import argparse # for building CLI (command-line interfaces)
from pathlib import Path
import hashlib
import json
import shutil
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore

import requests
from rapidfuzz import process

from huggingface_hub import snapshot_download

import yaml



# path to kittino project -> create "vault" folder from home directory
VAULT_DIR = Path.home() / ".kittino" / "vault"

def load_hf_trusted_publishers():
    path = Path.home() / ".kittino" / "trusted_publishers" / "huggingface.yaml"
    if not path.exists():
        print(f"{YELLOW}[!] Warning: No huggingface.yaml found — trust list will be empty.{RESET}")
        return []
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("trusted_publishers", [])

# Load trusted publishers once at startup
HF_TRUSTED_PUBLISHERS = load_hf_trusted_publishers()

# ANSI color codes for formatted CLI output
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"



def init_registry():
    subdirs = ["models", "provenance", "signatures"]
    for sub in subdirs:
        path = VAULT_DIR / sub
        path.mkdir(parents=True, exist_ok=True)
        print(f"[✓] Created directory: {path}")
    print("\nKittino vault initialized successfully!")

def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def sign_provenance(name, version):
    private_key_path = Path.home() / ".kittino" / "keys" / "private_key.pem"
    if not private_key_path.exists():
        print(f"{YELLOW}[!] No private key found. Skipping signing.{RESET}")
        return

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    safe_name = safe_filename(name)
    prov_path = VAULT_DIR / "provenance" / f"{safe_name}@{version}.json"
    #prov_path = VAULT_DIR / "provenance" / f"{name}@{version}.json"
    with open(prov_path, "rb") as f:
        prov_bytes = f.read()

    signature = private_key.sign(prov_bytes)

    sig_path = VAULT_DIR / "signatures" / f"{safe_name}@{version}.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"[✓] Signed provenance → {sig_path.name}")
    
def publish_model(model_path, name, version):
    # Auto-generate key if missing
    private_key_path = Path.home() / ".kittino" / "keys" / "private_key.pem"
    if not private_key_path.exists():
        print(f"{YELLOW}[!] No private key found. Generating new signing key...{RESET}")
        generate_keys()
    else:
        print(f"[✓] Found existing private key.")
    model_path = Path(model_path)
    if not model_path.exists():
        print(f"{RED}[x] Model file not found.{RESET}")
        return

    # 1️⃣ Check if same name@version already published
    safe_name = safe_filename(name)
    prov_path = VAULT_DIR / "provenance" / f"{safe_name}@{version}.json"
    if prov_path.exists():
        print(f"{YELLOW}[!] This model {name}@{version} has already been published.{RESET}")
        return

    # 2️⃣ Compute hash of the model file
    model_hash = sha256sum(model_path)

    # 3️⃣ Check if same hash was previously published
    existing_entry = provenance_exists_for_same_hash(model_hash)

    dest_path = VAULT_DIR / "models" / model_hash

    # 4️⃣ Only copy model file if not already stored
    if not dest_path.exists():
        shutil.copy2(model_path, dest_path)
        print(f"[+] Model stored as: {dest_path.name}")
    else:
        print(f"[=] Model file already stored (hash matched): {dest_path.name}")

    # 5️⃣ Prevent if identical hash was already published under another version
    if existing_entry:
        existing_name, existing_version = existing_entry
        print(f"{RED}[x] Identical model hash was already published as {existing_name}@{existing_version}.")
        print(f"{RED}Cannot re-publish same model under different version.{RESET}")
        return


    # 6️⃣ Build provenance metadata
    provenance = {
        "name": name,
        "version": version,
        "hash": model_hash,
        "original_filename": model_path.name,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    with open(prov_path, "w") as f:
        json.dump(provenance, f, indent=2)

    print(f"[+] Provenance written to: {prov_path.name}")
    sign_provenance(name, version)
    print(f"[✓] Publish complete!{RESET}")



def verify_model(name, version):
    provenance_path = VAULT_DIR / "provenance" / f"{name}@{version}.json"
    if not provenance_path.exists():
        print(f"{RED}[x] Model file not found.{RESET}")
        return

    with open(provenance_path, "rb") as f:
        prov_bytes = f.read()
        provenance = json.loads(prov_bytes)

    expected_hash = provenance["hash"]
    model_path = VAULT_DIR / "models" / expected_hash

    integrity_ok = False
    if not model_path.exists():
        print(f"{RED}[x] Model file not found in vault.{RESET}")
        return  # 🛑 Don't proceed if model is missing

    actual_hash = sha256sum(model_path)
    if actual_hash != expected_hash:
        print(f"{RED}[x] Hash mismatch: model may be altered{RESET}")
    else:
        print(f"[✓] Model integrity verified: no tampering or changes detected.")

    sig_path = VAULT_DIR / "signatures" / f"{name}@{version}.sig"
    public_key_path = Path.home() / ".kittino" / "keys" / "public_key.pem"

    if sig_path.exists() and public_key_path.exists():
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        with open(sig_path, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(signature, prov_bytes)
            print(f"[✓] Signature is valid")
        except Exception:
            print(f"{RED}[x] Signature verification failed! Provenance may be untrusted.{RESET}")
    else:
        print(f"{YELLOW}[!] No signature or public key found. Skipping authenticity check.{RESET}")

    

def generate_keys():
    keys_dir = Path.home() / ".kittino" / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key_path = keys_dir / "private_key.pem"
    public_key_path = keys_dir / "public_key.pem"

    if private_key_path.exists():
        print("[!] Keys already exist. Aborting.")
        return

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[✓] Signing keys generated and saved to ~/.kittino/keys/")
    
def audit_model(name, version):
    # ANSI color codes
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    print(f"🔍 Auditing {name}@{version}...")
    provenance_path = VAULT_DIR / "provenance" / f"{name}@{version}.json"
    if not provenance_path.exists():
        print(f"{RED}[x] Provenance file not found.{RESET}")
        return

    with open(provenance_path, "rb") as f:
        prov_bytes = f.read()
        provenance = json.loads(prov_bytes)

    issues_found = False

    # Check required fields
    required_fields = ["hash", "created_at"]
    for field in required_fields:
        if field not in provenance:
            print(f"{RED}[x] Missing required field in provenance: {field}{RESET}")
            issues_found = True
        else:
            print(f"[✓] {field} present in provenance")

    # Check model existence and hash
    expected_hash = provenance.get("hash")
    model_path = VAULT_DIR / "models" / expected_hash
    # print(f"DEBUG: model_path = {model_path}")
    if not model_path.exists():
        print(f"{RED}[x] Model file missing{RESET}")
        issues_found = True
    else:
        actual_hash = sha256sum(model_path)
        if actual_hash != expected_hash:
            print(f"{RED}[x] Hash mismatch: model may be altered{RESET}")
            issues_found = True
        else:
            print(f"[✓] Model hash matches provenance")

        # Check for risky extensions
        original_filename = provenance.get("original_filename", "").lower()
        ext = Path(original_filename).suffix.lower()

        if ext in [".pkl", ".pt", ".joblib"]:
            print(f"{YELLOW}[!] Model format is potentially unsafe: {ext}{RESET}")
            issues_found = True
        else:
            print(f"[✓] Model format appears safe: {ext}")

    # Signature verification
    sig_path = VAULT_DIR / "signatures" / f"{name}@{version}.sig"
    public_key_path = Path.home() / ".kittino" / "keys" / "public_key.pem"
    if sig_path.exists() and public_key_path.exists():
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        with open(sig_path, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(signature, prov_bytes)
            print(f"[✓] Signature is valid")
        except Exception:
            print(f"{RED}[x] Signature verification failed!{RESET}")
            issues_found = True
    else:
        print(f"{YELLOW}[!] Signature or public key missing{RESET}")
        issues_found = True

    if not issues_found:
        print(f"\033[92m[✓] Audit complete: no critical issues found.{RESET}")
    else:
        print(f"{YELLOW}[!] Audit complete: issues were found.{RESET}")
        
def list_models():
    provenance_dir = VAULT_DIR / "provenance"
    if not provenance_dir.exists():
        print(f"{YELLOW}[!] Provenance directory not found. Have you initialized the vault?{RESET}")
        return

    entries = sorted(provenance_dir.glob("*.json"))
    if not entries:
        print(f"{YELLOW}[!] No models found in the vault.{RESET}")
        return

    print(f"[✓] Listing all published models:\n")

    for prov_file in entries:
        try:
            with open(prov_file, "r") as f:
                data = json.load(f)
            name = data.get("name", "unknown")
            version = data.get("version", "unknown")
            created = data.get("created_at", "N/A")
            print(f"  [✓] {name}@{version}  |  created_at: {created}")
        except Exception as e:
            print(f"{RED}[x] Failed to read {prov_file.name}: {e}{RESET}")
            
def model_exists_on_hf(model_id):
    url = f"https://huggingface.co/api/models/{model_id}"
    r = requests.get(url)
    return r.status_code == 200

def suggest_models_on_hf(query):
    search_url = f"https://huggingface.co/api/models?search={query}"
    r = requests.get(search_url)
    if r.status_code != 200:
        return []
    model_ids = [model['modelId'] for model in r.json()]
    matches = process.extract(query, model_ids, limit=3, score_cutoff=70)
    return matches

def download_and_store_model(model_id):
    try:
        # Download full model snapshot to cache directory
        local_dir = snapshot_download(repo_id=model_id, repo_type="model")

        # Archive downloaded folder into one file (for consistent storage)
        archive_path = shutil.make_archive(base_name=local_dir, format='zip', root_dir=local_dir)
        archive_path = Path(archive_path)
        
        # Generate hash like publish_model()
        model_hash = sha256sum(archive_path)
        dest_path = VAULT_DIR / "models" / model_hash
        shutil.copy2(archive_path, dest_path)
        print(f"[+] Model stored as: {dest_path.name}")

        # Build provenance
        provenance = {
            "name": model_id,
            "version": "hf-latest",
            "hash": model_hash,
            "original_filename": archive_path.name,
            "source": "huggingface",
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        
        safe_id = safe_filename(model_id)

        prov_path = VAULT_DIR / "provenance" / f"{safe_id}@hf-latest.json"
        with open(prov_path, "w") as f:
            json.dump(provenance, f, indent=2)

        print(f"[+] Provenance written to: {prov_path.name}")
        sign_provenance(model_id, "hf-latest")
        print(f"[✓] Download complete and securely stored!{RESET}")

    except Exception as e:
        print(f"{RED}[x] Failed to download and store model: {e}{RESET}")

def safe_filename(model_id):
    return model_id.replace("/", "__")

def provenance_exists_for_same_hash(model_hash):
    provenance_dir = VAULT_DIR / "provenance"
    if not provenance_dir.exists():
        return None

    for prov_file in provenance_dir.glob("*.json"):
        try:
            with open(prov_file, "r") as f:
                data = json.load(f)
            if data.get("hash") == model_hash:
                return data.get("name"), data.get("version")
        except:
            continue
    return None



def main():
    parser = argparse.ArgumentParser(prog="kittino", description="Kittino: Local AI model package manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize the local Kittino vault")
    #subparsers.add_parser("keygen", help="Generate a signing keypair")
    subparsers.add_parser("list", help="List all published models in the vault")
    install_parser = subparsers.add_parser("install", help="Install a model from Hugging Face")


    publish_parser = subparsers.add_parser("publish", help="Publish a new model")
    publish_parser.add_argument("model_path", help="Path to the model file")
    publish_parser.add_argument("--name", required=True, help="Model name")
    publish_parser.add_argument("--version", required=True, help="Model version")

    verify_parser = subparsers.add_parser("verify", help="Verify model integrity and signature")
    verify_parser.add_argument("--name", required=True, help="Model name")
    verify_parser.add_argument("--version", required=True, help="Model version")
    
    audit_parser = subparsers.add_parser("audit", help="Audit a model for potential risks")
    audit_parser.add_argument("--name", required=True, help="Model name")
    audit_parser.add_argument("--version", required=True, help="Model version")
    
    install_parser.add_argument("model_id", help="Model ID (e.g. openai/whisper-large-v3-turbo)")


    args = parser.parse_args()

    if args.command == "init":
        init_registry()
    elif args.command == "publish":
        publish_model(args.model_path, args.name, args.version)
    elif args.command == "verify":
        verify_model(args.name, args.version)
    #elif args.command == "keygen":
        #generate_keys()
    elif args.command == "audit":
        audit_model(args.name, args.version)
    elif args.command == "list":
        list_models()
    elif args.command == "install":
        model_id = args.model_id
        org = model_id.split('/')[0]

        # First: namespace fuzzy matching
        namespace_match = process.extractOne(org, HF_TRUSTED_PUBLISHERS, score_cutoff=80)
        if namespace_match and org not in HF_TRUSTED_PUBLISHERS:
            print(f"{YELLOW}[!] Publisher '{org}' may be a typo.{RESET}")
            print(f"Did you mean publisher: '{namespace_match[0]}'? (confidence: {namespace_match[1]:.1f}%)")

        # Then: full model ID check
        if not model_exists_on_hf(model_id):
            print(f"{RED}[x] Model '{model_id}' not found on Hugging Face.{RESET}")
            suggestions = suggest_models_on_hf(model_id)
            if suggestions:
                print(f"{YELLOW}Did you mean:{RESET}")
                for match in suggestions:
                    print(f"  - {match[0]}  (confidence: {match[1]:.1f}%)")
            else:
                print(f"{YELLOW}No similar models found.{RESET}")
            return

        # After successful model existence check
        if org not in TRUSTED_PUBLISHERS:
            print(f"{YELLOW}[!] Warning: '{org}' is not in your trusted publishers list.{RESET}")
            print("You may be installing from an untrusted source.")
        else:
            print(f"{GREEN}[✓] Model exists and trusted publisher detected: '{org}'{RESET}")

        print(f"{GREEN}[✓] Downloading model '{model_id}'...{RESET}")
        download_and_store_model(model_id)


    else:
        parser.print_help()


if __name__ == "__main__":
    main()
