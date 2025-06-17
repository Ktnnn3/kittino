# 🐾 Kittino

**Kittino** is a local-only CLI tool to securely manage AI/ML models. It lets you publish, sign, verify, audit, and list models with cryptographic integrity and provenance tracking.

---

## 📦 Installation

```bash
pip install -r requirements.txt
```
required 
- cryptography>=41.0.0 
- requests>=2.31.0 
- rapidfuzz>=3.5.2 
- huggingface_hub>=0.23.0

# Kittino - AI Model Package Manager

## 🔧 Usage

1. **Initialize vault**
    ```bash
    kittino init
    ```
    to create the vault structure.

2. **Generate signing keys**
    ```bash
    kittino keygen
    ```
    generate public and private key.

3. **Publish a model**
    ```bash
    kittino publish model.pt --name mymodel --version 1.0
    ```
    - Model is hashed (SHA-256), stored, and provenance metadata is generated and signed.
    - If identical model hash exists, Kittino allows versioned re-publishing but warns about duplicates.

4. **Verify model integrity & signature**
    ```bash
    kittino verify --name mymodel --version 1.0
    ```
    - Verifies file hash consistency.
    - Verifies provenance signature authenticity.

5. **Audit model for security risks**
    ```bash
    kittino audit --name mymodel --version 1.0
    ```
    - Checks file existence.
    - Checks hash consistency.
    - Checks provenance integrity.
    - Verifies signature.
    - Warns on risky formats.

6. **Install model directly from Hugging Face**
    ```bash
    kittino install namespace/AI-model
    ```
    e.g. kittino install openai/whisper-large-v3-turbo
    - Fully downloads and secures model snapshot.
    - Fuzzy matches publisher names for safety.
    - Signs downloaded provenance automatically.


7. **List all models**
    ```bash
    kittino list
    ```
    list all registered model by scanning provenance files.

---

## 🧪 Tests

- `./test_script/test_verify.sh`
- `./test_script/test_audit.sh`

---

## 📁 Vault Structure

```plaintext
~/.kittino/
├── keys/
├── vault/
│   ├── models/  
│   ├── provenance/ 
│   └── signatures/
