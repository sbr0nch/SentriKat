# SentriKat License Tools

Tools for generating SentriKat Professional licenses.

## Setup

```bash
pip install cryptography
```

## First Time: Generate Keys

```bash
cd tools/
python generate_license.py --generate-keys
```

This creates `.license_keys/` directory with:
- `private_key.pem` - **KEEP SECRET!** Never share or commit this.
- `public_key.pem` - Embed in `app/licensing.py`

## Generate License

```bash
# Professional license (1 year)
python generate_license.py \
  --customer "Acme Corp" \
  --email "admin@acme.com" \
  --edition professional \
  --expires 2027-01-15

# Perpetual license (no expiration)
python generate_license.py \
  --customer "Acme Corp" \
  --email "admin@acme.com" \
  --edition professional

# With custom limits
python generate_license.py \
  --customer "Small Biz" \
  --email "admin@small.com" \
  --edition professional \
  --expires 2027-01-15 \
  --max-users 25
```

## Development License

For testing without generating keys, use:
```
SENTRIKAT-DEV-PROFESSIONAL
```

**Do not use in production!**
