# 🐾 Kittino

**Kittino** is a local-only CLI tool to securely manage AI/ML models. It lets you publish, sign, verify, audit, and list models with cryptographic integrity and provenance tracking — all without the cloud.

---

## 📦 Installation

```bash
pip install -r requirements.txt

```

# Kittino - AI Model Package Manager

## 🔧 Usage

1. **Initialize vault**
    ```bash
    kittino init
    ```

2. **Generate signing keys**
    ```bash
    kittino keygen
    ```

3. **Publish a model**
    ```bash
    kittino publish model.pt --name mymodel --version 1.0
    ```

4. **Verify model integrity & signature**
    ```bash
    kittino verify --name mymodel --version 1.0
    ```

5. **Audit model for security risks**
    ```bash
    kittino audit --name mymodel --version 1.0
    ```

6. **List all models**
    ```bash
    kittino list
    ```

---

## 🔍 Audit Checks

- Provenance fields (`hash`, `created_at`)
- File integrity via SHA-256
- Signature validation
- Risky formats: `.pt`, `.pkl`, `.joblib`

---

## 🧪 Tests

- `./test_verify.sh`
- `./test_audit.sh`

---

## 📁 Vault Structure

```plaintext
~/.kittino/
├── keys/
├── vault/
│   ├── models/
│   ├── provenance/
│   └── signatures/
