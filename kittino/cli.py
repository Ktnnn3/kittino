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
from rapidfuzz.fuzz import ratio


from huggingface_hub import snapshot_download

import yaml


# Blocklist of dangerous model file extensions
DANGEROUS_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".h5"}

TRUSTED_HF_PATH = Path.home() / ".kittino" / "trusted_publishers" / "huggingface.yaml"
TRUSTED_LOCAL_PATH = Path.home() / ".kittino" / "trusted_publishers" / "kittino_registry.yaml"

# path to kittino project -> create "vault" folder from home directory
VAULT_DIR = Path.home() / ".kittino" / "vault"

def load_trusted_list(hf=False):
    path = TRUSTED_HF_PATH if hf else TRUSTED_LOCAL_PATH
    if not path.exists():
        return []
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return data.get("trusted_publishers", [])

def save_trusted_list(publishers, hf=False):
    path = TRUSTED_HF_PATH if hf else TRUSTED_LOCAL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump({"trusted_publishers": sorted(set(publishers))}, f)

def add_trusted_publisher(name, hf=False):
    trusted = load_trusted_list(hf)
    if name in trusted:
        print(f"[!] Publisher '{name}' is already trusted.")
    else:
        trusted.append(name)
        save_trusted_list(trusted, hf)
        print(f"[+] Added trusted publisher: {name}")

def remove_trusted_publisher(name, hf=False):
    trusted = load_trusted_list(hf)
    if name not in trusted:
        print(f"[!] Publisher '{name}' not found in trust list.")
    else:
        trusted.remove(name)
        save_trusted_list(trusted, hf)
        print(f"[-] Removed publisher: {name}")

def list_trusted_publishers():
    local = load_trusted_list(hf=False)
    hf = load_trusted_list(hf=True)
    print("\nTrusted Local Publishers:")
    for p in local:
        print(f"  - {p}")
    print("\nTrusted Hugging Face Publishers:")
    for p in hf:
        print(f"  - {p}")


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
    
    # Trusted publisher files
    trust_dir = Path.home() / ".kittino" / "trusted_publishers"
    trust_dir.mkdir(parents=True, exist_ok=True)

    for fname in ["kittino_registry.yaml", "huggingface.yaml"]:
        fpath = trust_dir / fname
        if not fpath.exists():
            with open(fpath, "w") as f:
                yaml.dump({"trusted_publishers": []}, f)
            print(f"[✓] Initialized: {fpath.name}")
        else:
            print(f"[=] Already exists: {fpath.name}")

    print(f"\n{GREEN}Kittino vault initialized successfully!{RESET}")

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
    
def publish_model(model_path, name, version, publisher):
    # Auto-generate key if missing
    private_key_path = Path.home() / ".kittino" / "keys" / "private_key.pem"
    if not private_key_path.exists():
        print(f"{YELLOW}[!] No private key found. Generating new signing key...{RESET}")
        generate_keys()
    else:
        print(f"[✓] Found existing private key.")

    model_path = Path(model_path)

    # ❗ Reject dangerous formats to prevent code execution
    if model_path.suffix.lower() in DANGEROUS_EXTENSIONS:
        print(f"{RED}[x] Rejected: Model format '{model_path.suffix}' is unsafe for publishing due to code execution risk.{RESET}")
        print(f"{YELLOW}[!] Please convert it to a safer format like .pt, .onnx, or .bin.{RESET}")
        return

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

    # 6️⃣ Load public key to store in provenance
    public_key_path = Path.home() / ".kittino" / "keys" / "public_key.pem"
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    # 7️⃣ Build provenance metadata
    provenance = {
        "name": name,
        "version": version,
        "hash": model_hash,
        "original_filename": model_path.name,
        "publisher": publisher,
        "publisher_key": public_key_bytes,
        "signed_by": publisher,
        "signature_created_at": datetime.utcnow().isoformat() + "Z",
        "attack_detected_count": 0,
        "download_count": 0,
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
        print(f"{RED}[x] Provenance file not found.{RESET}")
        return

    with open(provenance_path, "rb") as f:
        prov_bytes = f.read()
        provenance = json.loads(prov_bytes)

    if provenance.get("source") == "huggingface":
        print(f"{GREEN}[✓] This model was installed from Hugging Face (source: huggingface).{RESET}")
        print(f"{YELLOW}[!] Verify not applicable for external models.{RESET}")
        return

    expected_hash = provenance["hash"]
    model_path = VAULT_DIR / "models" / expected_hash
    if not model_path.exists():
        print(f"{RED}[x] Model file not found in vault.{RESET}")
        return

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
    print(f"🔍 Auditing {name}@{version}...")
    provenance_path = VAULT_DIR / "provenance" / f"{name}@{version}.json"

    if not provenance_path.exists():
        print(f"{RED}[x] Provenance file not found.{RESET}")
        return

    with open(provenance_path, "rb") as f:
        prov_bytes = f.read()
        provenance = json.loads(prov_bytes)

    if provenance.get("source") == "huggingface":
        print(f"{GREEN}[✓] This model was installed from Hugging Face (source: huggingface).{RESET}")
        print(f"{YELLOW}[!] Audit not applicable for external models.{RESET}")
        return

    publisher = provenance.get("publisher", "unknown")
    print(f"[✓] Publisher: {publisher}")

    # Load trust list and check if publisher is trusted
    trusted_publishers = load_trusted_list(hf=False)
    if publisher in trusted_publishers:
        print(f"[✓] Publisher is trusted")
    else:
        print(f"{YELLOW}[!] Publisher is not in trusted list{RESET}")

    issues_found = False

    # Validate fields
    required_fields = ["hash", "created_at", "signature_created_at"]
    for field in required_fields:
        if field not in provenance:
            print(f"{RED}[x] Missing required field in provenance: {field}{RESET}")
            issues_found = True
        else:
            print(f"[✓] {field} present in provenance")

    # Check model file integrity
    expected_hash = provenance.get("hash")
    model_path = VAULT_DIR / "models" / expected_hash

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
            print(f"{RED}[x] Signature verification failed! Provenance may be untrusted.{RESET}")
            issues_found = True
    else:
        print(f"{YELLOW}[!] Signature or public key not found. Skipping authenticity check.{RESET}")
        issues_found = True
        
    print(f"[✓] Download count: {provenance.get('download_count', 0)}")


    if issues_found:
        provenance["attack_detected_count"] = provenance.get("attack_detected_count", 0) + 1
        with open(provenance_path, "w") as f:
            json.dump(provenance, f, indent=2)
        print(f"{YELLOW}[!] attack_detected_count incremented to {provenance['attack_detected_count']}{RESET}")
        print(f"{YELLOW}[!] Audit complete: issues were found.{RESET}")
    else:
        print(f"[✓] the number of this model got attacked : {provenance.get('attack_detected_count', 0)}")
        print(f"{GREEN}[✓] Audit complete: no critical issues found.{RESET}")
        
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
            source = data.get("source", "local")
            if source == "huggingface":
                print(f"  [✓] {name}@{version} (source: huggingface) | created_at: {created}")
            else:
                print(f"  [✓] {name}@{version} | created_at: {created} | downloads: {data.get('download_count', 0)}")
        except Exception as e:
            print(f"{RED}[x] Failed to read {prov_file.name}: {e}{RESET}")
            
def model_exists_on_hf(model_id):
    url = f"https://huggingface.co/api/models/{model_id}"
    r = requests.get(url)
    return r.status_code == 200

def suggest_models_on_hf(query):
    if "/" in query:
        org, _ = query.split("/", 1)
        search_url = f"https://huggingface.co/api/models?author={org}"
    else:
        search_url = f"https://huggingface.co/api/models?search={query}"

    try:
        r = requests.get(search_url)
        if r.status_code != 200:
            return []
        model_ids = [model["modelId"] for model in r.json()]
        matches = process.extract(query, model_ids, limit=5, score_cutoff=70)
        return matches
    except Exception:
        return []


def download_and_store_model(model_id):
    try:
        # Download full model snapshot to cache directory
        # ✅ Define destination directory (same as install_model_kittino)
        dest_dir = Path.cwd() / "installed_models" / safe_filename(model_id)
        dest_dir.mkdir(parents=True, exist_ok=True)

        # ✅ Download model directly to dest_dir (no cache)
        local_dir = snapshot_download(
            repo_id=model_id,
            repo_type="model",
            local_dir=dest_dir,              # <- download into installed_models/
            local_dir_use_symlinks=False     # <- use real files, not symlinks
        )
        
        print(f"[✓] Model downloaded from Hugging Face: {local_dir}")
        
        # Check for risky files and warn user
        risky_files = [f for f in Path(local_dir).rglob("*") if f.suffix.lower() in DANGEROUS_EXTENSIONS]
        if risky_files:
            print(f"{YELLOW}[!] WARNING: This Hugging Face model contains potentially unsafe files:")
            for rf in risky_files:
                print(f"    ⚠️  {rf.relative_to(local_dir)}")
            print(f"    These formats can execute code during loading (e.g., via pickle.load).")
            print(f"    Only use this model if you fully trust the source.{RESET}")


        # Save provenance only
        provenance = {
            "name": model_id,
            "version": "hf-latest",
            "source": "huggingface",
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        
        safe_id = safe_filename(model_id)
        prov_path = VAULT_DIR / "provenance" / f"{safe_id}@hf-latest.json"

        with open(prov_path, "w") as f:
            json.dump(provenance, f, indent=2)

        print(f"[✓] Entry recorded in provenance (source: huggingface): {prov_path.name}")
        print(f"[✓] Download complete!{RESET}")

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


def install_model_kittino(name, version):
    safe_name = safe_filename(name)
    prov_path = VAULT_DIR / "provenance" / f"{safe_name}@{version}.json"

    if not prov_path.exists():
        print(f"{RED}[x] Model {name}@{version} not found in registry.{RESET}")

        # Try to suggest similar model@version from local registry
        provenance_dir = VAULT_DIR / "provenance"
        all_ids = []
        for prov_file in provenance_dir.glob("*.json"):
            try:
                base = prov_file.stem.replace("__", "/")  # undo safe_filename
                all_ids.append(base)
            except:
                continue

        full_name = f"{name}@{version}"
        suggestions = process.extract(full_name, all_ids, limit=3, score_cutoff=70)
        if suggestions:
            print(f"{YELLOW}Did you mean:{RESET}")
            for match in suggestions:
                print(f"  - {match[0]}  (confidence: {match[1]:.1f}%)")
        else:
            print(f"{YELLOW}No similar models found in registry.{RESET}")

        return

    with open(prov_path, "r") as f:
        provenance = json.load(f)

    download_count = provenance.get("download_count", 0)

    # 🔍 Check if another model has > 2x downloads
    provenance_dir = VAULT_DIR / "provenance"
    all_models = []

    for prov_file in provenance_dir.glob("*.json"):
        try:
            with open(prov_file, "r") as f:
                other = json.load(f)
                full_name_version = f"{other.get('name', '')}@{other.get('version', '')}"
                all_models.append((full_name_version, other.get("download_count", 0)))
        except Exception:
            continue

    best_match = None
    for full_name_version, other_downloads in all_models:
        if full_name_version != f"{name}@{version}":
            score = ratio(f"{name}@{version}", full_name_version)
            if score > 75 and download_count * 2 < other_downloads:
                best_match = (full_name_version, other_downloads)
                break

    if best_match:
        print(f"{YELLOW}[?] Warning: '{name}@{version}' has only {download_count} downloads.{RESET}")
        print(f"{YELLOW}Did you mean: '{best_match[0]}'? ({best_match[1]} downloads){RESET}")
        answer = input("Type 'yes' to continue with low-download model, or 'no' to cancel: ").strip().lower()
        if answer != "yes":
            print(f"{RED}[x] Installation cancelled by user.{RESET}")
            return

    if provenance.get("source") == "huggingface":
        print(f"{YELLOW}[!] This model is from Hugging Face. Use 'kittino install-hf' instead.{RESET}")
        return

    trusted_publishers = load_trusted_list(hf=False)
    publisher = provenance.get("publisher", "unknown")
    if publisher not in trusted_publishers:
        print(f"{YELLOW}[!] Publisher '{publisher}' is not trusted. Proceed with caution.{RESET}")
    else:
        print(f"{GREEN}[\u2713] Publisher '{publisher}' is trusted.{RESET}")

    model_hash = provenance["hash"]
    src_model_path = VAULT_DIR / "models" / model_hash
    if not src_model_path.exists():
        print(f"{RED}[x] Model file not found in vault.{RESET}")
        return

    dest_dir = Path.cwd() / "installed_models"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / provenance["original_filename"]
    shutil.copy2(src_model_path, dest_path)

    print(f"{GREEN}[\u2713] Model installed to: {dest_path}{RESET}")

    # Update download count
    provenance["download_count"] = download_count + 1
    with open(prov_path, "w") as f:
        json.dump(provenance, f, indent=2)

    print(f"[✓] Download count updated to {provenance['download_count']}")


def main():
    parser = argparse.ArgumentParser(prog="kittino", description="Kittino: Local AI model package manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize the local Kittino vault")
    #subparsers.add_parser("keygen", help="Generate a signing keypair")
    subparsers.add_parser("list", help="List all published models in the vault")

    publish_parser = subparsers.add_parser("publish", help="Publish a new model")
    publish_parser.add_argument("model_path", help="Path to the model file")
    publish_parser.add_argument("--name", required=True, help="Model name")
    publish_parser.add_argument("--version", required=True, help="Model version")
    publish_parser.add_argument("--publisher", required=True, help="Publisher name")


    verify_parser = subparsers.add_parser("verify", help="Verify model integrity and signature")
    verify_parser.add_argument("--name", required=True, help="Model name")
    verify_parser.add_argument("--version", required=True, help="Model version")
    
    audit_parser = subparsers.add_parser("audit", help="Audit a model for potential risks")
    audit_parser.add_argument("--name", required=True, help="Model name")
    audit_parser.add_argument("--version", required=True, help="Model version")
    
    install_parser = subparsers.add_parser("install", help="Install a model from local Kittino registry")
    install_parser.add_argument("--name", required=True, help="Model name")
    install_parser.add_argument("--version", required=True, help="Model version")


    install_hf_parser = subparsers.add_parser("install-hf", help="Install a model from Hugging Face")
    install_hf_parser.add_argument("model_id", help="Model ID (e.g. openai/whisper-large-v3-turbo)")
    
    trust_parser = subparsers.add_parser("trust", help="Manage local trusted publishers")
    trust_parser.add_argument("name", nargs="?", help="Publisher name to add")
    trust_parser.add_argument("--remove", help="Publisher to remove")
    trust_parser.add_argument("--list", action="store_true", help="List trusted publishers")

    trust_hf_parser = subparsers.add_parser("trust-hf", help="Manage Hugging Face trusted publishers")
    trust_hf_parser.add_argument("name", nargs="?", help="HF publisher name to add")
    trust_hf_parser.add_argument("--remove", help="HF publisher to remove")




    args = parser.parse_args()

    if args.command == "init":
        init_registry()
    elif args.command == "publish":
        publish_model(args.model_path, args.name, args.version, args.publisher)
    elif args.command == "verify":
        verify_model(args.name, args.version)
    #elif args.command == "keygen":
        #generate_keys()
    elif args.command == "audit":
        audit_model(args.name, args.version)
    elif args.command == "list":
        list_models()
    elif args.command == "install-hf":
        model_id = args.model_id
        org = model_id.split('/')[0]

        trusted_hf_publishers = load_trusted_list(hf=True)
        namespace_match = process.extractOne(org, trusted_hf_publishers, score_cutoff=80)
        if namespace_match and org not in trusted_hf_publishers:
            print(f"{YELLOW}[!] Publisher '{org}' may be a typo.{RESET}")
            print(f"Did you mean publisher: '{namespace_match[0]}'? (confidence: {namespace_match[1]:.1f}%)")

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

        if org not in trusted_hf_publishers:
            print(f"{YELLOW}[!] Warning: '{org}' is not in your trusted publishers list.{RESET}")
            print("You may be installing from an untrusted source.")
        else:
            print(f"{GREEN}[✓] Model exists and trusted publisher detected: '{org}'{RESET}")

        # ✅ Cross-org suspicious download check
        try:
            api_url = f"https://huggingface.co/api/models/{model_id}"
            resp = requests.get(api_url)
            if resp.status_code == 200:
                model_info = resp.json()
                current_downloads = model_info.get("downloads", 0)

                # Only warn if current model has suspiciously low downloads
                if current_downloads < 100:
                    similar_candidates = []
                    for trusted_org in trusted_hf_publishers:
                        if trusted_org == org:
                            continue
                        trusted_org_url = f"https://huggingface.co/api/models?author={trusted_org}"
                        r = requests.get(trusted_org_url)
                        if r.status_code != 200:
                            continue
                        for m in r.json():
                            name = m.get("modelId", "")
                            downloads = m.get("downloads", 0)
                            if downloads > current_downloads * 2:
                                score = ratio(model_id, name)
                                if score > 75:
                                    similar_candidates.append((name, downloads, score))

                    if similar_candidates:
                        best = sorted(similar_candidates, key=lambda x: -x[1])[0]
                        print(f"{YELLOW}[?] Warning: '{model_id}' has only {current_downloads} downloads.{RESET}")
                        print(f"{YELLOW}Did you mean: '{best[0]}'? ({best[1]} downloads){RESET}")
                        answer = input("Type 'yes' to continue with low-download model, or 'no' to cancel: ").strip().lower()
                        if answer != "yes":
                            print(f"{RED}[x] Installation cancelled by user.{RESET}")
                            return
        except Exception as e:
            print(f"{YELLOW}[!] Skipping cross-org download check due to error: {e}{RESET}")

        print(f"{GREEN}[✓] Downloading model '{model_id}'...{RESET}")
        download_and_store_model(model_id)

    elif args.command == "install":
        install_model_kittino(args.name, args.version)

    elif args.command == "trust":
        if args.list:
            list_trusted_publishers()
        elif args.remove:
            remove_trusted_publisher(args.remove, hf=False)
        elif args.name:
            add_trusted_publisher(args.name, hf=False)
        else:
            print("[x] Please specify a publisher name or use --list/--remove")

    elif args.command == "trust-hf":
        if args.remove:
            remove_trusted_publisher(args.remove, hf=True)
        elif args.name:
            add_trusted_publisher(args.name, hf=True)
        else:
            print("[x] Please specify a publisher name or use --remove")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
