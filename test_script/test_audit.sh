#!/bin/bash
set -e

NAME="test4"
VERSION="4.0"
MODEL_FILE="$NAME.pt"
PROV_PATH="$HOME/.kittino/vault/provenance/$NAME@$VERSION.json"
SIG_PATH="$HOME/.kittino/vault/signatures/$NAME@$VERSION.sig"

echo -e "\n🔍 Running Kittino audit tests..."

echo -e "\n[0] ✅ Clean setup"
echo "fake model content" > "$MODEL_FILE"
python3 kittino/cli.py publish "$MODEL_FILE" --name "$NAME" --version "$VERSION" --publisher "$NAME"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION"

HASH=$(jq -r '.hash' "$PROV_PATH")
MODEL_PATH="$HOME/.kittino/vault/models/$HASH"

echo -e "\n[1] ❌ Model file missing"
mv "$MODEL_PATH" "$MODEL_PATH.bak"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
mv "$MODEL_PATH.bak" "$MODEL_PATH"

echo -e "\n[2] ❌ Hash mismatch"
echo "tamper" >> "$MODEL_PATH"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
cp "$MODEL_FILE" "$MODEL_PATH"

echo -e "\n[3] ❌ Missing created_at in provenance"
cp "$PROV_PATH" "$PROV_PATH.bak"
jq 'del(.created_at)' "$PROV_PATH.bak" > "$PROV_PATH"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
mv "$PROV_PATH.bak" "$PROV_PATH"

echo -e "\n[4] ❌ Corrupted signature"
cp "$SIG_PATH" "$SIG_PATH.bak"
echo "corrupt" >> "$SIG_PATH"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
mv "$SIG_PATH.bak" "$SIG_PATH"

echo -e "\n[5] ⚠️  Signature missing"
mv "$SIG_PATH" "$SIG_PATH.bak"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
mv "$SIG_PATH.bak" "$SIG_PATH"

echo -e "\n[6] ⚠️  Unsafe format (simulate .pkl)"
mv "$MODEL_PATH" "$MODEL_PATH.pkl"
ln -s "$MODEL_PATH.pkl" "$MODEL_PATH"
python3 kittino/cli.py audit --name "$NAME" --version "$VERSION" || true
rm "$MODEL_PATH"
mv "$MODEL_PATH.pkl" "$MODEL_PATH"

echo -e "\n✅ All audit test cases completed."

# Cleanup
echo -e "\n🧹 Cleaning up audit test artifacts..."
rm -f "$MODEL_PATH" "$PROV_PATH" "$SIG_PATH" "$MODEL_FILE"
echo "[✓] Done."
