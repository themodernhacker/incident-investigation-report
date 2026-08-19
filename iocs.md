# Indicators of Compromise, INC-2026-0819-001

Scannable IOC reference for the 2026-08-19 intrusion against `web-prod-01`.
Times are UTC. "Source rule" is the Wazuh rule that observed the indicator.

## Network

| Indicator | Type | First seen | Context | Source rule |
|-----------|------|-----------|---------|:-----------:|
| 172.19.0.1 | Source IPv4 | 22:19:56 | Origin of the brute force and the interactive session | 100102, 100104, 100105, 100110, 100151 |
| 203.0.113.10 | Remote IPv4 | 22:20:20 | Payload host in the download attempts (TEST-NET-3, reserved for documentation, non-routable) | 100108 |
| http://203.0.113.10/x.sh | URL | 22:20:20 | `wget` target, second-stage script | 100108 |
| http://203.0.113.10/payload | URL | 22:20:21 | `curl` target, second-stage payload | 100108 |

## Credentials

| Indicator | Type | First seen | Context | Source rule |
|-----------|------|-----------|---------|:-----------:|
| root / hunter2 | Valid credential | 22:20:11 | The guess that succeeded, used for the interactive session | 100103, 100105 |
| root / {admin, password, 123456, 12345, root, toor, qwerty, letmein, changeme, 000000} | Attempted credentials | 22:19:56 | Brute-force wordlist, all failed | 100102, 100104 |

## Host artifacts

| Indicator | Type | First seen | Context | Source rule |
|-----------|------|-----------|---------|:-----------:|
| /tmp/x.sh | File path | 22:20:20 | Intended local drop path for the `wget` payload (no write occurred) | 100108 |
| /tmp/p | File path | 22:20:21 | Intended local drop path for the `curl` payload (no write occurred) | 100108 |
| 84b2d6cd4479 | Cowrie session ID | 22:20:12 | The interactive shell where all post-compromise commands ran | 100151, 100108, 100106 |

## Target

| Indicator | Type | Context |
|-----------|------|---------|
| web-prod-01 | Hostname | Honeypot identity presented to the attacker |
| 172.19.0.2:2222 | Asset / port | Cowrie SSH honeypot listener |

## Notes

- No file hashes are listed: no payload was ever retrieved, so nothing was
  written to disk to hash. The download attempts (100108) fired on the commands
  themselves; no `cowrie.session.file_download` (100109) followed.
- The source address is an RFC 1918 Docker bridge gateway because the attack was
  launched from the lab host. On a live estate this field would carry the real
  routable source and would be the primary pivot for hunting the actor elsewhere.
