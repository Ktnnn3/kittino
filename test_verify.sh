#!/bin/bash
set -e

echo "🔍 Running Kittino verification tests..."

NAME="test3"
VERSION="3.0"
MODEL_FILE="$NAME.pt"
PROV_PATH="$HOME/.kittino/vault/provenance/$NAME@$VERSION.json"
SIG_PATH="$HOME/.kittino/vault/signatures/$NAME@$VERSION.sig"

echo -e "\n[1] ✅ Clean baseline"
echo "fake model" > "$MODEL_FILE"
python3 kittino/cli.py publish "$MODEL_FILE" --name "$NAME" --version "$VERSION"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION"

HASH=$(jq -r '.hash' "$PROV_PATH")
MODEL_PATH="$HOME/.kittino/vault/models/$HASH"

echo -e "\n[2] ❌ Modify model file (hash mismatch)"
echo "tampered content" >> "$MODEL_PATH"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
cp "$MODEL_FILE" "$MODEL_PATH"

echo -e "\n[3] ❌ Corrupt signature"
cp "$SIG_PATH" "$SIG_PATH.bak"
echo "invalidsig" >> "$SIG_PATH"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
mv "$SIG_PATH.bak" "$SIG_PATH"

echo -e "\n[4] ❌ Modify both model & signature"
echo "malicious" >> "$MODEL_PATH"
cp "$SIG_PATH" "$SIG_PATH.bak"
echo "malicioussig" >> "$SIG_PATH"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
cp "$MODEL_FILE" "$MODEL_PATH"
mv "$SIG_PATH.bak" "$SIG_PATH"

echo -e "\n[5] ⚠️  Delete signature"
mv "$SIG_PATH" "$SIG_PATH.bak"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
mv "$SIG_PATH.bak" "$SIG_PATH"

echo -e "\n[6] ❌ Delete provenance file"
mv "$PROV_PATH" "$PROV_PATH.bak"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
mv "$PROV_PATH.bak" "$PROV_PATH"

echo -e "\n[7] ❌ Delete model file"
mv "$MODEL_PATH" "$MODEL_PATH.bak"
python3 kittino/cli.py verify --name "$NAME" --version "$VERSION" || true
mv "$MODEL_PATH.bak" "$MODEL_PATH"

echo -e "\n✅ All verification test cases completed."

# Cleanup
echo -e "\n🧹 Cleaning up verify test artifacts..."
rm -f "$MODEL_PATH" "$PROV_PATH" "$SIG_PATH" "$MODEL_FILE"
echo "[✓] Done."
