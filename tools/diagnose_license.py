#!/usr/bin/env python3
"""
Diagnostic script to debug license signature verification.
Run this on the SentriKat server to diagnose why signature fails.
"""
import json
import base64
import sys
import os

# Add parent dir to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def diagnose_license(license_input):
    """Step-by-step diagnosis of license verification."""
    print("=" * 60)
    print("LICENSE DIAGNOSTIC")
    print("=" * 60)

    # Step 1: Clean input
    cleaned = license_input.strip()
    for prefix in ['SENTRIKAT_LICENSE=', 'sentrikat_license=', 'export SENTRIKAT_LICENSE=']:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):].strip()
            print(f"\n[1] Stripped prefix: '{prefix}'")
            break

    # Remove quotes
    if (cleaned.startswith('"') and cleaned.endswith('"')) or \
       (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
        print("[1] Stripped surrounding quotes")

    # Handle JSON
    if cleaned.startswith('{'):
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                for key in ['sentrikat_license', 'signed_license', 'license_key', 'license']:
                    if key in data and isinstance(data[key], str) and '.' in data[key]:
                        cleaned = data[key].strip()
                        print(f"[1] Extracted from JSON field: '{key}'")
                        break
        except Exception:
            pass

    # Remove whitespace
    cleaned = ''.join(cleaned.split())

    print(f"\n[2] Cleaned license string length: {len(cleaned)}")
    print(f"[2] First 50 chars: {cleaned[:50]}...")
    print(f"[2] Last 20 chars: ...{cleaned[-20:]}")

    # Step 2: Split
    parts = cleaned.split('.')
    print(f"\n[3] Split on '.': {len(parts)} parts")
    if len(parts) != 2:
        print(f"[3] ERROR: Expected 2 parts, got {len(parts)}")
        if len(parts) > 2:
            print(f"[3] Part lengths: {[len(p) for p in parts]}")
        return

    payload_b64, signature_b64 = parts
    print(f"[3] Payload base64 length: {len(payload_b64)}")
    print(f"[3] Signature base64 length: {len(signature_b64)}")
    print(f"[3] Payload has '=' padding: {'=' in payload_b64}")
    print(f"[3] Signature has '=' padding: {'=' in signature_b64}")

    # Step 3: Decode payload
    try:
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload_json = payload_bytes.decode('utf-8')
        payload = json.loads(payload_json)
        print(f"\n[4] Payload decoded successfully!")
        print(f"[4] Payload JSON ({len(payload_json)} bytes):")
        print(json.dumps(payload, indent=2))
    except Exception as e:
        print(f"\n[4] ERROR decoding payload: {e}")
        return

    # Step 3b: Check if re-serialized payload matches
    re_serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    re_serialized_bytes = re_serialized.encode('utf-8')
    print(f"\n[5] Re-serialized payload matches original bytes: {re_serialized_bytes == payload_bytes}")
    if re_serialized_bytes != payload_bytes:
        print(f"[5] Original bytes length: {len(payload_bytes)}")
        print(f"[5] Re-serialized length: {len(re_serialized_bytes)}")
        print(f"[5] Original first 100: {payload_bytes[:100]}")
        print(f"[5] Re-ser  first 100: {re_serialized_bytes[:100]}")
        # Find first difference
        for i in range(min(len(payload_bytes), len(re_serialized_bytes))):
            if payload_bytes[i] != re_serialized_bytes[i]:
                print(f"[5] First diff at byte {i}: original={payload_bytes[i]:02x} vs re-serialized={re_serialized_bytes[i]:02x}")
                print(f"[5] Context: ...{payload_bytes[max(0,i-10):i+10]}...")
                break

    # Step 4: Decode signature
    try:
        sig_padded = signature_b64 + '=' * (-len(signature_b64) % 4)
        signature = base64.urlsafe_b64decode(sig_padded)
        print(f"\n[6] Signature decoded: {len(signature)} bytes")
        print(f"[6] Signature hex (first 32 bytes): {signature[:32].hex()}")
    except Exception as e:
        print(f"\n[6] ERROR decoding signature: {e}")
        return

    # Step 5: Load public key
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend

        # Try to import from app
        try:
            from app.licensing import get_license_public_key, _DEFAULT_PUBLIC_KEY
            pem = get_license_public_key()
            print(f"\n[7] Public key loaded via get_license_public_key()")
            print(f"[7] Key source: {'env/file' if pem != _DEFAULT_PUBLIC_KEY else 'embedded default'}")
        except Exception:
            # Fallback - read key from licensing.py manually
            pem = None
            key_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     'tools', '.license_keys', 'public_key.pem')
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    pem = f.read().strip()
                print(f"\n[7] Public key loaded from: {key_file}")

            if not pem:
                print(f"\n[7] Could not load public key from app module or file")
                print(f"[7] Trying embedded default...")
                # We'd need to extract it from the source file
                return

        # Parse key
        public_key = serialization.load_pem_public_key(
            pem.encode(),
            backend=default_backend()
        )
        key_size = public_key.key_size
        print(f"[7] Public key size: {key_size} bits")
        print(f"[7] Expected signature size for RSA-{key_size}: {key_size // 8} bytes")
        print(f"[7] Actual signature size: {len(signature)} bytes")

        if len(signature) != key_size // 8:
            print(f"[7] WARNING: Signature size mismatch! Key is {key_size}-bit but signature is {len(signature)*8}-bit")
            print(f"[7] This means the license was signed with a DIFFERENT key size.")

    except ImportError:
        print(f"\n[7] cryptography module not available. Cannot verify signature.")
        print(f"[7] Signature size: {len(signature)} bytes = {len(signature)*8}-bit key")
        return

    # Step 6: Try verification
    print(f"\n[8] Attempting signature verification...")

    # Try 1: Verify against raw payload_bytes (what we do now)
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"[8] SUCCESS: Signature valid against raw payload bytes!")
        return
    except Exception as e:
        print(f"[8] FAILED against raw payload bytes: {e}")

    # Try 2: Verify against re-serialized payload
    try:
        public_key.verify(
            signature,
            re_serialized_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"[8] SUCCESS: Signature valid against re-serialized payload!")
        print(f"[8] FIX: The server signs the re-serialized form, not the raw bytes")
        return
    except Exception as e:
        print(f"[8] FAILED against re-serialized payload: {e}")

    # Try 3: Maybe PSS padding?
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO
            ),
            hashes.SHA256()
        )
        print(f"[8] SUCCESS: Signature valid with PSS padding!")
        return
    except Exception as e:
        print(f"[8] FAILED with PSS padding: {e}")

    # Try 4: SHA512?
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        print(f"[8] SUCCESS: Signature valid with SHA512!")
        return
    except Exception as e:
        print(f"[8] FAILED with SHA512: {e}")

    print(f"\n[9] ALL VERIFICATION ATTEMPTS FAILED")
    print(f"[9] Most likely cause: PUBLIC KEY MISMATCH")
    print(f"[9] The embedded public key does not match the private key that signed this license.")
    print(f"[9] Verify the public key matches: check license server's /app/keys/license_public.pem")
    print(f"[9]")
    print(f"[9] Public key PEM (first 3 lines):")
    for line in pem.strip().split('\n')[:3]:
        print(f"[9]   {line}")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # License string passed as argument
        license_input = sys.argv[1]
    else:
        # Read from stdin
        print("Paste your license string (then press Enter, then Ctrl+D):")
        license_input = sys.stdin.read()

    diagnose_license(license_input)
