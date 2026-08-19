# Incident Investigation Report

A worked **SOC incident investigation**: the document an analyst files after the
alerts fire. It takes a real, freshly captured intrusion against an SSH honeypot
and writes it up as one unified incident, structured on the **NIST SP 800-61**
incident-response lifecycle.

This is the companion to [`honeypot-siem`](https://github.com/themodernhacker/honeypot-siem).
That project is the detection-engineering half: it builds, tunes, and tests the
Wazuh rules. **This** project is the other half of the SOC job: it consumes the
alerts those rules produce and turns them into an investigation a shift lead,
manager, or auditor could read and trust. Same lab, same rules, different
deliverable.

> **Lab framing, stated honestly:** the target `web-prod-01` is a Cowrie SSH
> honeypot and the attack was a controlled purple-team run on my own machine, so
> the real-world impact was nil. That framing is kept explicit in the report's
> impact section; the analysis itself is built entirely from real fired alerts and
> real log lines, nothing invented.

## The incident

On 2026-08-19, a single source brute-forced the `root` account over SSH, succeeded
with `root/hunter2`, ran a host-discovery sweep, and attempted two remote payload
downloads, all in 27 seconds. Wazuh raised two level 12 alerts (the top of the
deployed ruleset): account takeover, then post-compromise reconnaissance.

## How to read this repo

| File | What it is |
|------|-----------|
| [`incident-ticket.md`](incident-ticket.md) | The short-form ticket, what gets filed first |
| [`incident-report.md`](incident-report.md) | The full investigation (main artifact), NIST SP 800-61 structure |
| [`iocs.md`](iocs.md) | Clean, scannable indicator table |
| [`evidence/timeline.md`](evidence/timeline.md) | Correlated event timeline, every row tied to a fired rule |
| [`evidence/raw-logs/`](evidence/raw-logs/) | Trimmed raw `cowrie.json` for this run |
| [`evidence/screenshots/`](evidence/screenshots/) | Wazuh alert exhibits for this run |

Start with the ticket for the 30-second version, then the report for the full
investigation.

## Relationship to `honeypot-siem`

Where this report references a detection rule (100104, 100105, 100151, and so on)
or an ATT&CK mapping, the authoritative definition lives in the detection project,
not here. This report links to it rather than restating it:

- Rules and MITRE mapping: [honeypot-siem/docs/MITRE-MAPPING.md](https://github.com/themodernhacker/honeypot-siem/blob/main/docs/MITRE-MAPPING.md)
- Detection tuning and known limitations: [honeypot-siem/docs/writeup-tuning.md](https://github.com/themodernhacker/honeypot-siem/blob/main/docs/writeup-tuning.md)

---

_Companion lab project for educational/defensive security use against my own
infrastructure only._
