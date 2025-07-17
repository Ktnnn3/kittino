# Kittino - Secure AI Model Registry & CLI Tool

**Kittino** is a secure, AI model package manager and registry that lets users manage AI/ML models with many actions securely. It also supports downloading from Hugging Face with typo detection, download heuristics, and trust validation to mitigate supply chain attacks.

---

## Features

- **Secure local publishing** of models with digital signature (Ed25519)
- **Provenance metadata** for every model: who published it, when, hash, and signature
- **Model verification** to detect tampering or hash mismatch
- **Audit** to detect signs of model misuse or trust violations
- **Trust system** for local and Hugging Face publishers
- **Local + Hugging Face install support** with typo-suggestion & warning on suspicious downloads
- Blocklist of dangerous formats (.pkl, .h5, etc.)
- **Download counter** and **attack counter** for each model
- Suggest alternative models with higher trust or download count

# Kittino - AI Model Package Manager

## Installation

    git clone https://github.com/yourname/kittino.git
    cd kittino
    pip install -r requirements.txt
    python3 kittino.py init

required 
- cryptography>=41.0.0 
- requests>=2.31.0 
- rapidfuzz>=3.5.2 
- huggingface_hub>=0.23.0


You may also want to add an alias for convenience
    
    alias kittino="python3 /full/path/to/kittino.py"

## Usage

1. **Initialize vault**
    ```bash
    kittino init
    ```
    to create the vault structure.

2. **Generate signing keys and Publish a model**
    ```bash
    kittino publish model.pt --name my-model --version 1.0.0 --publisher alice
    ```
    - replace "model.pt" with the path for your model.
    - --name : name of the model to publish.
    - --version : version to publish.
    - --publisher : name of publish for publishing.

3. **List All Published Models**
    ```bash
    kittino list
    ```
    list all published model.

4. **Install Model (from local registry)**
    ```bash
    kittino install --name my-model --version 1.0.0
    ```
    - --name : name of the model to install.
    - --version : version to install.

5. **Install Model from Hugging Face**
    ```bash
    kittino install-hf openai/whisper-large
    ```
    - openai/whisper-large is just example of namespace/AI-model-name from Hugging Face.

6. **Verify Integrity & Signature**
    ```bash
    kittino verify --name my-model --version 1.0.0
    ```
    Checks: Hash integrity, Signature validity

7. **Audit Model**
    ```bash
    kittino audit --name my-model --version 1.0.0
    ```
    Checks: File tampering, Signature, Publisher trust, Required fields, Logs detected attacks

---

## Trust Management
Add Trusted Publisher (local or HuggingFace)
    
    kittino trust alice
    kittino trust-hf openai

Remove or List

    kittino trust --remove alice
    kittino trust --list

---

## 📁 Vault Structure

```plaintext
~/.kittino/
├── vault/
│   ├── models/           # Stored model binaries
│   ├── provenance/       # Metadata files (signed)
│   └── signatures/       # Digital signatures
├── keys/                 # Ed25519 private/public keys
└── trusted_publishers/   # Local & HuggingFace trust lists

