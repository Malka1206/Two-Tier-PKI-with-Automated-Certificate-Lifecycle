# Threat model

This document describes what the PKI protects, what can go wrong, and how the project responds. It is derived from the project [README](../README.md). For the structure of the system, see [`architecture.md`](architecture.md).

## 1. Scope and trust zones

| Zone | Contents | Trust assumption |
|---|---|---|
| **Offline zone (air-gapped)** | Root CA | Never connected to a network. Used only to sign the Intermediate CA certificate and the root CRL. |
| **Online zone** | Intermediate CA, OCSP responder, CRL distribution, Nginx | Reachable, therefore exposed. Compromise of this zone must not compromise the trust anchor. |
| **End entities** | Server, client and code-signing certificates (90 days) | Each holds its own private key. Compromise affects only that entity. |

## 2. Assets

| Asset | Why it matters |
|---|---|
| Root CA private key | Compromise breaks trust for the entire PKI. |
| Intermediate CA private key | Allows an attacker to issue valid certificates. |
| CA database and CRL integrity | Tampering could hide revocations or revoke valid certificates. |
| Leaf private keys | Allow impersonation of a single server or user. |

## 3. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Theft of the root key | Root is **offline**, key is encrypted with AES-256 and a passphrase, stored on removable media, used only to sign the intermediate and the root CRL. |
| Theft of the intermediate key | Dedicated user, permissions `0400`, runs in an isolated container, `pathlen:0` and name constraints limit the damage. Can be revoked by the root. |
| Passphrase leakage | Passphrases are read from files or environment variables, never from command-line arguments (no exposure in shell history or `ps`). |
| Mis-issuance outside the intended domain | Name constraints on the intermediate. |
| Certificate misuse (e.g. client cert as server cert) | Distinct `extendedKeyUsage` per profile, enforced by verification. |
| Use of a compromised leaf certificate | Revocation through CRL (and OCSP), plus short 90-day validity. |
| Predictable serial numbers | Random serials (`-rand_serial`). |
| Stale revocation data | Realistic `nextUpdate`, scheduled CRL regeneration. |
| Secrets committed to Git | `.gitignore`, keys generated at runtime, CI builds a throwaway PKI. |

### How the mitigations are verified

The test suite checks the technical mitigations (see the README, section 10):

| Mitigation | Test |
|---|---|
| Distinct `extendedKeyUsage` per profile | A client certificate used as a server certificate fails verification. |
| Name constraints on the intermediate | A certificate with a name outside the constraint fails verification. |
| Short validity | An expired certificate fails verification. |
| Integrity of certificates | A tampered certificate fails verification. |
| Revocation (CRL) | A revoked certificate fails `-crl_check_all`, the CRL contains the revoked serial after `gen-crl`, and Nginx rejects a revoked client certificate. |
| Revocation (OCSP) | The responder answers `revoked` for a revoked certificate and `unknown` for a serial the CA never issued. |
| No secrets in Git | CI builds a fresh PKI from scratch on every run. |

## 4. Key compromise procedures

### Leaf key compromised

1. Revoke the certificate (`pki-tool revoke`).
2. Regenerate and publish the CRL (`pki-tool gen-crl`).
3. Issue a new certificate with a new key.

### Intermediate key compromised

1. Bring the root online in a controlled environment.
2. Revoke the intermediate and publish a new root CRL.
3. Create a new intermediate.
4. Re-issue all leaf certificates.

Clients keep the same trust anchor.

### Root key compromised

The trust anchor is lost. Build a new PKI with a new root key and redistribute the new root certificate to every client and server.

## 5. Limitations

This is an **educational project**, not a production CA. Known limitations:

- No HSM: keys are protected by file permissions and passphrases only.
- A single intermediate issues all profiles. Production PKIs separate TLS and code-signing hierarchies so that a compromise of one does not affect the other.
- Nginx enforces CRL only. It cannot validate client certificates through OCSP.
- The OCSP responder is `openssl ocsp`, which is single-threaded and meant for demonstration.
- No audit logging, no multi-person key ceremony, no formal CP/CPS.
- CRL distribution relies on plain HTTP (standard for CRL/OCSP, but not highly available here).
- The "offline" root is simulated on the same machine. The documented procedure describes how it would be handled on an air-gapped system.

## 6. References

- [RFC 5280: X.509 Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 6960: Online Certificate Status Protocol (OCSP)](https://datatracker.ietf.org/doc/html/rfc6960)
- [OpenSSL `ca`, `x509v3_config` and `ocsp` documentation](https://www.openssl.org/docs/)
- [Nginx `ngx_http_ssl_module`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)

> **Disclaimer:** This project is for learning and demonstration purposes. Do not use it to run a production certificate authority.
