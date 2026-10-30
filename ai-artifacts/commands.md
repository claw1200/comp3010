# Reproducible Commands – CW1

All tshark commands are prefixed with `TZ=UTC` because tshark prints local time by default (BST would show 14:38 instead of 13:38 UTC).

## 0. Integrity of the evidence
```bash
shasum -a 256 COMP3010CW1.pcap
# aa8bd9280b943db2e729b921de58d5fd37c4f8c76d1aa9996e9e5b44bcf7a7a3
```

## 1. Capture scope (screenshots 01–03)
```bash
capinfos COMP3010CW1.pcap                         # start/end time, packet count
tshark -r COMP3010CW1.pcap -q -z io,phs            # protocol hierarchy
tshark -r COMP3010CW1.pcap -q -z conv,ip           # IPv4 conversations
```
GUI equivalents: Statistics → Capture File Properties / Protocol Hierarchy / Conversations.

## 2. IDS alert triage (screenshots 04–05)
```bash
# Snort: count alerts by [gid:sid:rev] signature
grep -o '^\[\*\*\] \[[0-9:]*\] [^[]*' CW1Snort.txt | sed 's/^\[\*\*\] //' | sort | uniq -c | sort -rn
# Suricata: signature is the line after each "Count:" header
awk '/^Count:/{getline; print}' CW1Suricata.txt | sort | uniq -c | sort -rn
# Same PE-download event in both tools (shows the Suricata clock offset)
grep -A2 'FILE-EXECUTABLE' CW1Snort.txt | head -4
grep -A2 'PE EXE or DLL'   CW1Suricata.txt | head -4
# Destinations and time window of the Pushdo alerts
grep -A2 'Pushdo' CW1Snort.txt | grep -oE '[0-9.]+:[0-9]+ -> [0-9.]+:[0-9]+' | awk '{print $3}' | sed 's/:.*//' | sort -u | wc -l
grep -A2 'Pushdo' CW1Snort.txt | grep -oE '^[0-9/]+-[0-9:.]+' | sort | sed -n '1p;$p'
```

## 3. Infected host identity (screenshots 06–07)
```bash
TZ=UTC tshark -r COMP3010CW1.pcap -Y dhcp -V | grep -E 'Client MAC|Host Name|Client IP|Requested IP'
# Wireshark filters: dhcp     eth.addr == 00:15:c5:de:c7:3b
# Validation – look for any other hostname source (NBNS, LLMNR, SMTP EHLO, raw strings):
tshark -r COMP3010CW1.pcap -Y 'nbns or llmnr or dhcp' -T fields -e nbns.name -e dns.qry.name -e dhcp.option.hostname | sort | uniq -c | sort -rn | head
tshark -r COMP3010CW1.pcap -Y 'frame matches "(?i)flashgordon"' -T fields -e frame.number -e _ws.col.Protocol
```
Result: hostname only appears in DHCP option 12 (frames 213, 221).

## 4. Infection chain (screenshots 08–10)
```bash
# All HTTP requests except the POST / burst, with host/URI/UA
TZ=UTC tshark -r COMP3010CW1.pcap -Y 'http.request && !(http.request.method=="POST" && http.request.uri=="/")' \
  -T fields -e frame.number -e frame.time -e ip.dst -e http.request.method -e http.host -e http.request.uri -e http.user_agent
# DNS resolutions for the key domains
TZ=UTC tshark -r COMP3010CW1.pcap -Y 'dns.flags.response==1 && dns.qry.name matches "matied|centler|haarstudio|vantagepoint|rts21"' \
  -T fields -e frame.number -e frame.time -e dns.qry.name -e dns.a
```
Wireshark: `dns.qry.name == "matied.com"`; Follow → HTTP Stream on frame 6 (WinHttp UA, `MZ` header).
Note: add an `http.host` column because name resolution labels 119.28.70.207 as `centler.at` even for the matied.com request.

## 5. File extraction and hashing (screenshots 11–16)
```bash
mkdir -p evidence/http_objects
tshark -r COMP3010CW1.pcap --export-objects http,evidence/http_objects
cd evidence/http_objects
for f in *; do head -c2 "$f" | grep -q MZ && { shasum -a 256 "$f"; file "$f"; }; done   # find PE files by MZ magic
shasum -a 256 t64.bin; file t64.bin                                                    # "data" – not a PE
```
Hashes were then searched on VirusTotal (hash lookup only – files were **not** uploaded).
`evidence/http_objects/` is git-ignored: it contains live malware.

## 6. Post-infection behaviour (screenshots 17–20)
```bash
# POST burst: count, distinct hosts, duration
TZ=UTC tshark -r COMP3010CW1.pcap -Y 'http.request.method=="POST" && http.request.uri=="/"' -T fields -e frame.time_epoch -e http.host \
  | awk '{n++; h[$2]=1; if(!s||$1<s)s=$1; if($1>e)e=$1} END{print n" requests, "length(h)" hosts, "e-s" s"}'
# .ru lookups
TZ=UTC tshark -r COMP3010CW1.pcap -Y 'dns.qry.name matches "\\.ru$" && dns.flags.response==0' -T fields -e frame.number -e frame.time -e dns.qry.name
# Outbound SMTP sessions
tshark -r COMP3010CW1.pcap -Y 'tcp.dstport==25 && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst | sort | uniq -c | wc -l
tshark -r COMP3010CW1.pcap -Y smtp -T fields -e ip.src -e _ws.col.Info | head
```
Wireshark: Statistics → I/O Graphs (10 s interval) with a second graph using `http.request.method == "POST"`; filter `http.request.method == "POST" && http.request.uri == "/"`; Statistics → HTTP → Requests.

## 7. Results summary
| Check | Result |
|---|---|
| POST burst | 637 requests, 302 hosts, 41 s (13:44:01–13:44:42 UTC) |
| SMTP | 475 SYNs to 155 external mail servers |
| Pushdo alerts | Snort 498 (202 dest IPs), Suricata 823 (292 dest IPs), all within the burst window |
| Suricata clock | +10h36m vs packet time (13:38:34 → 2017-06-28 00:14:33) |
