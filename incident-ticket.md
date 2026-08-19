# Incident Ticket INC-2026-0819-001

| Field | Value |
|-------|-------|
| **Ticket ID** | INC-2026-0819-001 |
| **Opened** | 2026-08-19 22:20 UTC |
| **Severity** | High |
| **Priority** | P2 |
| **Status** | Closed, resolved (controlled lab exercise) |
| **Detected by** | Wazuh rule 100105 *SSH login after brute-force burst* and rule 100151 *post-compromise recon*, both level 12 |
| **Affected asset** | `web-prod-01`, SSH honeypot at 172.19.0.2:2222 |
| **Source** | 172.19.0.1 (single source) |

## Summary

Between 22:19:56 and 22:20:23 UTC a single source (172.19.0.1) brute-forced the
`root` account on `web-prod-01` over SSH, succeeded on the 11th attempt with
`root/hunter2`, then opened an interactive shell and ran host-discovery commands
followed by two remote-payload download attempts. Wazuh detected the full chain
end to end and escalated the post-login recon to a level 12 page. No file was
retrieved (the payload host is a non-routable documentation address).

## Key IOCs

| Indicator | Type | Note |
|-----------|------|------|
| 172.19.0.1 | Source IP | brute force + interactive session |
| root / hunter2 | Credential | the guess that succeeded |
| http://203.0.113.10/x.sh | URL | `wget` target (no download completed) |
| http://203.0.113.10/payload | URL | `curl` target (no download completed) |

Full list: [`iocs.md`](iocs.md).

## Disposition

Confirmed intrusion against the honeypot, produced by a controlled purple-team
attack run on my own lab (not a live production compromise). `web-prod-01` is a
Cowrie SSH honeypot, so there was no real host or real data at risk. The value
here is the detection-to-investigation workflow, exercised against real fired
alerts. Full write-up: [`incident-report.md`](incident-report.md).
