# Offline Agent Signing (H-4)

SentriKat agents verify a **detached minisign signature** before accepting
an auto-update. Checksum-only trust assumes the update server itself is
uncompromised — signature verification lets us tolerate a full server
compromise without shipping a trojanized agent to every endpoint.

This document is the release-engineer runbook for producing and rotating
signing keys.

## Threat model

- **In scope:** an attacker who gains write access to the SentriKat
  release server, compromises a CDN mirror, or mounts a TLS MITM with a
  mis-issued certificate.
- **Out of scope:** an attacker who has physical access to the signing
  hardware token. Key handling procedures below are how we reduce that
  likelihood.

## Generating the signing key (first-time setup)

Perform this on a clean offline workstation. The private key never
leaves the hardware token.

```bash
# Install minisign
apt-get install minisign   # debian/ubuntu
brew install minisign      # macOS

# Generate the keypair
minisign -G -p sentrikat-agent.pub -s /mnt/ykey/sentrikat-agent.key

# Copy the PUBLIC key content (one base64 line) and paste it into:
#   agents/sentrikat-agent-linux.sh     (SENTRIKAT_MINISIGN_PUBKEY)
#   agents/sentrikat-agent-macos.sh     (same constant)
#   agents/sentrikat-agent-windows.ps1  ($SentrikatMinisignPubkey)
```

The pubkey must be embedded at build time. **Do not** fetch it from the
server at runtime — that defeats the purpose.

## Signing a release

```bash
cd agents/
minisign -S -s /mnt/ykey/sentrikat-agent.key -m sentrikat-agent-linux.sh

# Produces sentrikat-agent-linux.sh.minisig next to the script.
# Upload BOTH files to the release bucket.
```

The agent downloads ``<download_url>.minisig`` alongside the script and
verifies locally before the atomic install step.

## Key rotation

1. Ship a new agent release signed by the **old** key that embeds the
   **new** public key.
2. Wait for fleet rollout to exceed 90% (monitor via the agents dashboard).
3. Rotate: destroy the old private key, start signing future releases
   with the new key.
4. Agents still on the pre-rotation version continue to validate against
   the old pubkey until they auto-update.

Never flip the pubkey in a single release — the fleet would reject the
update because the signature was produced with the new key but the
embedded pubkey is still the old one.

## Disabling verification during development

Set ``SENTRIKAT_AGENT_SKIP_SIG_VERIFY=1`` in the agent's environment.
Never set this in production. The auto-update log emits a ``WARN`` when
verification is skipped, which is trivial to grep for in ops dashboards.

## Related audit findings

- **H-4** (CRITICAL-grade supply-chain risk): previous releases relied
  only on a server-provided SHA256 checksum. A single server compromise
  could therefore trojanize the entire fleet with a matching checksum.
