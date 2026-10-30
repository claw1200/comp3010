# Indicators of Compromise – CW1 (2017-06-27 Pushdo infection)

Source capture: `COMP3010CW1.pcap`, SHA256 `aa8bd9280b943db2e729b921de58d5fd37c4f8c76d1aa9996e9e5b44bcf7a7a3`.
URLs and domains are edited (`[.]`) so they can't be clicked by accident.

## Affected host
| Field | Value | Evidence |
|---|---|---|
| IP | 192.168.1.96 | All alerts; frame 213 |
| MAC | 00:15:c5:de:c7:3b (Intel OUI) | DHCP frame 213 |
| Hostname | FlashGordon-PC | DHCP option 12, frame 213 |
| OS hint | Windows 7 (UA `Windows NT 6.1`) | frames 298, 313 |

## File hashes
| File | Size (bytes) | SHA256 | MD5 | Source URL |
|---|---|---|---|---|
| gerv.gun (PE32) | 241,664 | `0931537889c35226d00ed26962ecacb140521394279eb2ade7e9d2afcf1a7272` | `1568dafae63eebce20987dd6205704e5` | http://matied[.]com/gerv.gun |
| trow.exe (PE32; VirusTotal name: **Pedals.exe** – not present in the binary's strings/version info, so likely an in-the-wild submission name) | 330,752 | `94a0a09ee6a21526ac34d41eabf4ba603e9a30c26e6a1dc072ff45749dfb1fe1` | `fb75d4f81be51074bb4147e781e5b402` | http://lounge-haarstudio[.]nl/oud/trow.exe |
| wp.exe (PE32) | 307,712 | `79d503165d32176842fe386d96c04fb70f6ce1c8a485837957849297e625ea48` | `4da48f6423d5f7d75de281a674c2e620` | http://vantagepointtechnologies[.]com/wp.exe |
| t64.bin (data) | 3,162,369 | `9875dac23b48fe6a52681b113be524a18c503df9b16081be73390ea18614ca68` | `69e5e0a17f197cae3723adfc5f894d49` | http://rts21[.]co[.]jp/img/t64.bin |
| initial .js dropper | – | **Not recovered** (delivered before capture start; not found on VirusTotal) | – | Reported OSINT name: `DOC0978043-2017.6.doc.js` |

## Network indicators
| Type | Indicator | Role | Confidence |
|---|---|---|---|
| Domain | matied[.]com | Stage-1 payload host | High |
| Domain | centler[.]at | Post-infection callback (POST /auth/...) | High |
| IP | 119.28.70.207 | Hosts both matied[.]com and centler[.]at | High |
| Domain / IP | lounge-haarstudio[.]nl / 145.131.10.21 | trow.exe download (likely compromised site) | Medium |
| Domain / IP | vantagepointtechnologies[.]com / 143.95.151.192 | wp.exe download; Snort Kazy alert (likely compromised site) | Medium |
| Domain / IP | rts21[.]co[.]jp / 59.106.164.230 | t64.bin download (likely compromised site) | Medium |
| URL pattern | `/auth/ajax/<digits>/?min=data`, `/auth/min/<digits>/` | Callback URI structure | Medium |
| Behaviour | Many `POST /` with encrypted body, UA `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` to hundreds of hosts within seconds | Pushdo check-in pattern | High |
| Behaviour | Outbound TCP/25 from a workstation to many external MTAs | Spam module | High |
| User-Agent | `Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)` | Script-based downloader | High |
| Sinkhole IPs | 144.217.254.90, 193.166.255.171, 212.61.180.100 | Researcher sinkholes contacted (confirms infection; not attacker infra) | Medium |

**Do not block-list blindly.** Most of the 302 hosts in the POST burst are legitimate websites used as decoys, and the download hosts look like compromised legitimate sites. Block the high-confidence attacker infrastructure (119.28.70.207, matied[.]com, centler[.]at) and alert on the behaviour patterns rather than on every contacted domain.

## MITRE ATT&CK mapping (interpretation)
| Technique | ID | Evidence |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | OSINT: malspam zip with .js (inferred, not in pcap) |
| User Execution: Malicious File | T1204.002 | .js run by user → WinHttp request |
| Command and Scripting Interpreter (sub-technique unknown – .007 JavaScript only if the OSINT is right) | T1059 | WinHttp.WinHttpRequest UA shows a script/program, not which language |
| Ingress Tool Transfer | T1105 | gerv.gun, trow.exe, wp.exe, t64.bin downloads |
| Masquerading: Masquerade File Type | T1036.008 | PE served as `.gun`; `.bin` payload |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP POST C2 |
| Encrypted Channel | T1573 | Encrypted POST bodies |
| Resource Hijacking (host used to send spam) | T1496 | Outbound SMTP to 155 MTAs |
