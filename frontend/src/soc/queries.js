export const LANGS = [
  { k: "sentinel", label: "Microsoft Sentinel", sub: "KQL" },
  { k: "defender", label: "Microsoft Defender", sub: "Advanced Hunting" },
  { k: "splunk", label: "Splunk", sub: "SPL" },
  { k: "qradar", label: "QRadar", sub: "AQL" },
  { k: "rapid7", label: "Rapid7", sub: "LEQL" },
  { k: "crowdstrike", label: "CrowdStrike NG-SIEM", sub: "CQL" },
  { k: "s1", label: "SentinelOne", sub: "PowerQuery" },
];

const iso = (d) => d.toISOString().slice(0, 19) + "Z";
const spl = (d) => { const p = (n) => String(n).padStart(2, "0"); return `${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`; };
const aql = (d) => d.toISOString().slice(0, 16).replace("T", " ");
const R = (s, e) => ({ s, e, kql: `between (datetime(${iso(s)}) .. datetime(${iso(e)}))`, spl: `earliest="${spl(s)}" latest="${spl(e)}"`, aql: `START '${aql(s)}' STOP '${aql(e)}'`, label: `${aql(s)} – ${aql(e)} UTC` });

const PATH = {
  sentinel: "Microsoft Sentinel › Logs",
  defender: "security.microsoft.com › Hunting › Advanced hunting",
  splunk: "Search & Reporting (times are UTC)",
  qradar: "Log Activity › Advanced Search (AQL)",
  rapid7: "InsightIDR › Log Search › Advanced mode",
  crowdstrike: "Falcon › Next-Gen SIEM › Log search",
  s1: "Singularity › Event Search › PowerQuery",
};
const SET = {
  sentinel: "Log Analytics workspace", defender: "Advanced Hunting tables", splunk: "index=* (narrow to your indexes)",
  qradar: "Events", crowdstrike: "Repository: search-all", s1: "Deep Visibility events",
};

function K(kind, v, r) {
  const q = {
    signin: () => ({
      sentinel: `SigninLogs\n| where TimeGenerated between (datetime(${iso(r.e)}) - 7d .. datetime(${iso(r.e)}))\n| where UserPrincipalName has "${v}"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ResultDescription\n| union (SecurityEvent | where TimeGenerated > datetime(${iso(r.e)}) - 7d | where EventID in (4624, 4625) and TargetUserName has "${v}" | project TimeGenerated, TargetUserName, IpAddress, LogonType, EventID)\n| order by TimeGenerated desc`,
      defender: `IdentityLogonEvents\n| where Timestamp > datetime(${iso(r.e)}) - 7d\n| where AccountName =~ "${v}" or AccountUpn has "${v}"\n| project Timestamp, AccountUpn, DeviceName, IPAddress, ActionType, LogonType, FailureReason\n| order by Timestamp desc`,
      splunk: `index=* (user="${v}" OR Account_Name="${v}") (EventCode=4624 OR EventCode=4625 OR sourcetype=*signin*) earliest=-7d\n| table _time, user, src_ip, EventCode, Logon_Type, action\n| sort - _time`,
      qradar: `SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS evtime, username, sourceip, QIDNAME(qid) AS event\nFROM events\nWHERE username ILIKE '%${v}%' AND (QIDNAME(qid) ILIKE '%logon%' OR QIDNAME(qid) ILIKE '%login%')\nORDER BY starttime DESC LAST 7 DAYS`,
      rapid7: `where(destination_user ICONTAINS "${v}" OR user ICONTAINS "${v}")\ngroupby(source_ip, result)`,
      crowdstrike: `#event_simpleName=/^(UserLogon|UserLogonFailed2)$/\n| UserName=/${v}/i\n| table([@timestamp, ComputerName, UserName, LogonType, RemoteAddressIP4, #event_simpleName])`,
      s1: `event.type in ('Login', 'Logout') and event.login.userName contains:anycase '${v}'\n| columns event.time, endpoint.name, event.login.userName, src.endpoint.ip.address, event.login.loginIsSuccessful\n| sort -event.time`,
    }),
    extip: () => ({
      sentinel: `union isfuzzy=true CommonSecurityLog, SigninLogs, DeviceNetworkEvents, SecurityEvent\n| where TimeGenerated ${r.kql}\n| where * has "${v}"\n| summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by Type\n| order by Events desc`,
      defender: `DeviceNetworkEvents\n| where Timestamp ${r.kql}\n| where RemoteIP == "${v}"\n| summarize Connections=count(), First=min(Timestamp), Last=max(Timestamp) by DeviceName, LocalIP, RemotePort, InitiatingProcessFileName`,
      splunk: `index=* "${v}" ${r.spl}\n| stats count min(_time) as first max(_time) as last by sourcetype, src_ip, dest_port, action\n| convert ctime(first) ctime(last)`,
      qradar: `SELECT sourceip, destinationip, destinationport, LOGSOURCENAME(logsourceid) AS logsource, COUNT(*) AS events\nFROM events\nWHERE sourceip = '${v}' OR destinationip = '${v}'\nGROUP BY sourceip, destinationip, destinationport, logsourceid\n${r.aql}`,
      rapid7: `where(source_address = "${v}" OR destination_address = "${v}")\ngroupby(source_address, destination_port)`,
      crowdstrike: `RemoteAddressIP4="${v}" OR LocalAddressIP4="${v}" OR source.ip="${v}" OR destination.ip="${v}"\n| groupBy([#event_simpleName, ComputerName], function=count())`,
      s1: `dst.ip.address = '${v}' or src.ip.address = '${v}'\n| group count = count() by endpoint.name, src.process.name, dst.port.number`,
    }),
    process: () => ({
      sentinel: `SecurityEvent\n| where TimeGenerated ${r.kql}\n| where Computer has "${v}"\n| where EventID == 4688\n| project TimeGenerated, Account, ParentProcessName, NewProcessName, CommandLine\n| order by TimeGenerated asc`,
      defender: `DeviceProcessEvents\n| where Timestamp ${r.kql}\n| where DeviceName startswith "${v}"\n| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256\n| order by Timestamp asc`,
      splunk: `index=* (host="${v}" OR ComputerName="${v}*") (EventCode=4688 OR EventCode=1) ${r.spl}\n| table _time, user, ParentImage, Image, CommandLine\n| sort _time`,
      qradar: `SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS evtime, username, "Parent Process Name", "Process Name", "Process CommandLine"\nFROM events\nWHERE "Machine Name" ILIKE '%${v}%'\nORDER BY starttime ASC\n${r.aql}`,
      rapid7: `where(hostname ICONTAINS "${v}")\ngroupby(parent_process.name, process.name)`,
      crowdstrike: `#event_simpleName=ProcessRollup2 ComputerName=/${v}/i\n| table([@timestamp, UserName, ParentBaseFileName, FileName, CommandLine])`,
      s1: `endpoint.name contains:anycase '${v}' and event.type = 'Process Creation'\n| columns event.time, src.process.user, src.process.parent.name, src.process.name, src.process.cmdline\n| sort event.time`,
    }),
    domain: () => ({
      sentinel: `union isfuzzy=true DnsEvents, DeviceNetworkEvents, CommonSecurityLog\n| where TimeGenerated > datetime(${iso(r.e)}) - 7d\n| where Name has "${v}" or RemoteUrl has "${v}" or RequestURL has "${v}"\n| summarize Hits=count(), First=min(TimeGenerated) by Computer, DeviceName, SourceIP`,
      defender: `DeviceNetworkEvents\n| where Timestamp > datetime(${iso(r.e)}) - 7d\n| where RemoteUrl has "${v}"\n| summarize Hits=count(), First=min(Timestamp) by DeviceName, InitiatingProcessFileName`,
      splunk: `index=* (query="*${v}*" OR url="*${v}*" OR dest="*${v}*") earliest=-7d\n| stats count by src, user, host`,
      qradar: `SELECT sourceip, username, COUNT(*) AS hits\nFROM events\nWHERE URL ILIKE '%${v}%' OR "DNS Query" ILIKE '%${v}%'\nGROUP BY sourceip, username LAST 7 DAYS`,
      rapid7: `where(query ICONTAINS "${v}")\ngroupby(asset)`,
      crowdstrike: `#event_simpleName=DnsRequest DomainName=/${v.replace(/\./g, "\\.")}/i\n| groupBy([ComputerName], function=count())`,
      s1: `event.dns.request contains:anycase '${v}' or url.address contains:anycase '${v}'\n| group hits = count() by endpoint.name`,
    }),
    hash: () => {
      const md5 = v.length === 32;
      return {
        sentinel: `union isfuzzy=true DeviceFileEvents, DeviceProcessEvents, SecurityAlert\n| where TimeGenerated > datetime(${iso(r.e)}) - 30d\n| where ${md5 ? "MD5" : "SHA256"} =~ "${v}" or Entities has "${v}"\n| summarize Hits=count(), Devices=dcount(DeviceName) by Type`,
        defender: `DeviceFileEvents\n| where Timestamp > datetime(${iso(r.e)}) - 30d\n| where ${md5 ? "MD5" : "SHA256"} == "${v}"\n| summarize Devices=dcount(DeviceName), First=min(Timestamp), Last=max(Timestamp) by FileName, FolderPath`,
        splunk: `index=* "${v}" earliest=-30d\n| stats count dc(host) as hosts values(host) as host_list by sourcetype`,
        qradar: `SELECT LOGSOURCENAME(logsourceid) AS logsource, sourceip, COUNT(*) AS hits\nFROM events\nWHERE "${md5 ? "MD5 Hash" : "SHA256 Hash"}" = '${v}' OR UTF8(payload) ILIKE '%${v}%'\nGROUP BY logsourceid, sourceip LAST 30 DAYS`,
        rapid7: `where("${v}")\ngroupby(hostname)`,
        crowdstrike: `${md5 ? "MD5HashData" : "SHA256HashData"}="${v}"\n| groupBy([ComputerName, FileName], function=count())`,
        s1: `tgt.file.${md5 ? "md5" : "sha256"} = '${v}' or src.process.image.${md5 ? "md5" : "sha256"} = '${v}'\n| group hits = count() by endpoint.name`,
      };
    },
    net: () => ({
      sentinel: `CommonSecurityLog\n| where TimeGenerated ${r.kql}\n| where SourceIP == "${v}"\n| summarize Connections=count(), Sent=sum(SentBytes), Received=sum(ReceivedBytes) by DestinationIP, DestinationPort, DeviceAction\n| order by Connections desc`,
      defender: `DeviceNetworkEvents\n| where Timestamp ${r.kql}\n| where LocalIP == "${v}"\n| summarize Connections=count() by RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName\n| order by Connections desc`,
      splunk: `index=* (src_ip="${v}" OR src="${v}") ${r.spl}\n| stats count sum(bytes_out) as sent sum(bytes_in) as received by dest_ip, dest_port, action\n| sort - count`,
      qradar: `SELECT destinationip, destinationport, SUM(sourcebytes) AS sent, SUM(destinationbytes) AS received, COUNT(*) AS flows\nFROM flows\nWHERE sourceip = '${v}'\nGROUP BY destinationip, destinationport\n${r.aql}`,
      rapid7: `where(source_address = "${v}")\ngroupby(destination_address, destination_port)`,
      crowdstrike: `#event_simpleName=NetworkConnectIP4 LocalAddressIP4="${v}"\n| groupBy([RemoteAddressIP4, RemotePort], function=count())`,
      s1: `src.ip.address = '${v}' and event.category = 'ip'\n| group conns = count() by dst.ip.address, dst.port.number`,
    }),
    children: () => ({
      sentinel: `SecurityEvent\n| where TimeGenerated ${r.kql}\n| where EventID == 4688\n| where ParentProcessName endswith "${v}"\n| summarize Count=count() by Computer, NewProcessName, CommandLine`,
      defender: `DeviceProcessEvents\n| where Timestamp ${r.kql}\n| where InitiatingProcessFileName =~ "${v}"\n| summarize Count=count() by DeviceName, FileName, ProcessCommandLine`,
      splunk: `index=* (ParentImage="*\\\\${v}" OR parent_process_name="${v}") ${r.spl}\n| stats count by host, Image, CommandLine`,
      qradar: `SELECT "Machine Name", "Process Name", "Process CommandLine", COUNT(*) AS hits\nFROM events\nWHERE "Parent Process Name" ILIKE '%${v}'\nGROUP BY "Machine Name", "Process Name", "Process CommandLine"\n${r.aql}`,
      rapid7: `where(parent_process.name ICONTAINS "${v}")\ngroupby(hostname, process.name)`,
      crowdstrike: `#event_simpleName=ProcessRollup2 ParentBaseFileName=/^${v.replace(/\./g, "\\.")}$/i\n| groupBy([ComputerName, FileName, CommandLine], function=count())`,
      s1: `src.process.parent.name = '${v}' and event.type = 'Process Creation'\n| group hits = count() by endpoint.name, src.process.name, src.process.cmdline`,
    }),
  };
  return q[kind]();
}

function hunt(t, host, r) {
  const h = t.hunt;
  const ex = host ? host : "";
  const list = (h.t || []).map((x) => `"${x.replace(/\\/g, "\\\\")}"`).join(", ");
  const rx = (h.t || []).map((x) => x.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")).join("|");
  if (h.k === "fail" || h.k === "ok") {
    const ok = h.k === "ok";
    return {
      sentinel: `SecurityEvent\n| where TimeGenerated > datetime(${iso(r.e)}) - 7d\n| where EventID == ${ok ? 4624 : 4625}${ok ? " and LogonType in (3, 10)" : ""}\n${ex ? `| where Computer !has "${ex}"\n` : ""}| summarize Count=count() by Computer, TargetUserName, IpAddress\n${ok ? "" : "| where Count > 10\n"}| order by Count desc`,
      defender: `DeviceLogonEvents\n| where Timestamp > datetime(${iso(r.e)}) - 7d\n| where ActionType == "${ok ? "LogonSuccess" : "LogonFailed"}"${ok ? ' and LogonType in ("RemoteInteractive", "Network")' : ""}\n${ex ? `| where DeviceName !startswith "${ex}"\n` : ""}| summarize Count=count() by DeviceName, AccountName, RemoteIP\n${ok ? "" : "| where Count > 10\n"}| order by Count desc`,
      splunk: `index=* EventCode=${ok ? 4624 : 4625}${ok ? " (Logon_Type=3 OR Logon_Type=10)" : ""}${ex ? ` NOT host="${ex}"` : ""} earliest=-7d\n| stats count by host, user, src_ip${ok ? "" : "\n| where count > 10"}\n| sort - count`,
      qradar: `SELECT "Machine Name", username, sourceip, COUNT(*) AS hits\nFROM events\nWHERE QIDNAME(qid) ILIKE '%${ok ? "success" : "fail"}%logon%'${ex ? ` AND "Machine Name" NOT ILIKE '%${ex}%'` : ""}\nGROUP BY "Machine Name", username, sourceip${ok ? "" : "\nHAVING hits > 10"}\nLAST 7 DAYS`,
      rapid7: `where(result = "${ok ? "SUCCESS" : "FAILED_BAD_PASSWORD"}"${ex ? ` AND hostname != "${ex}"` : ""})\ngroupby(hostname, destination_user)`,
      crowdstrike: `#event_simpleName=${ok ? "UserLogon" : "UserLogonFailed2"}${ex ? ` ComputerName!=/${ex}/i` : ""}\n| groupBy([ComputerName, UserName, RemoteAddressIP4], function=count())${ok ? "" : "\n| _count > 10"}`,
      s1: `event.type = 'Login' and event.login.loginIsSuccessful = ${ok}${ex ? ` and endpoint.name != '${ex}'` : ""}\n| group hits = count() by endpoint.name, event.login.userName${ok ? "" : "\n| filter hits > 10"}`,
    };
  }
  if (h.k === "port") {
    const ports = h.t.join(", ");
    return {
      sentinel: `CommonSecurityLog\n| where TimeGenerated > datetime(${iso(r.e)}) - 7d\n| where DestinationPort in (${ports})\n| summarize Connections=count() by SourceIP, DestinationIP, DestinationPort, DeviceAction`,
      defender: `DeviceNetworkEvents\n| where Timestamp > datetime(${iso(r.e)}) - 7d\n| where RemotePort in (${ports})\n${ex ? `| where DeviceName !startswith "${ex}"\n` : ""}| summarize Connections=count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      splunk: `index=* (${h.t.map((p) => `dest_port=${p}`).join(" OR ")})${ex ? ` NOT host="${ex}"` : ""} earliest=-7d\n| stats count by src_ip, dest_ip, dest_port, action`,
      qradar: `SELECT sourceip, destinationip, destinationport, COUNT(*) AS flows\nFROM flows\nWHERE destinationport IN (${ports})\nGROUP BY sourceip, destinationip, destinationport LAST 7 DAYS`,
      rapid7: `where(destination_port IN [${ports}])\ngroupby(source_address, destination_address)`,
      crowdstrike: `#event_simpleName=NetworkConnectIP4 RemotePort=/^(${h.t.join("|")})$/${ex ? ` ComputerName!=/${ex}/i` : ""}\n| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count())`,
      s1: `dst.port.number in (${ports})${ex ? ` and endpoint.name != '${ex}'` : ""}\n| group conns = count() by endpoint.name, dst.ip.address, dst.port.number, src.process.name`,
    };
  }
  return {
    sentinel: `SecurityEvent\n| where TimeGenerated > datetime(${iso(r.e)}) - 7d\n| where EventID == 4688\n| where CommandLine has_any (${list})\n${ex ? `| where Computer !has "${ex}"\n` : ""}| summarize Hits=count(), Example=any(CommandLine) by Computer, Account`,
    defender: `DeviceProcessEvents\n| where Timestamp > datetime(${iso(r.e)}) - 7d\n| where ProcessCommandLine has_any (${list})\n${ex ? `| where DeviceName !startswith "${ex}"\n` : ""}| summarize Hits=count(), Example=any(ProcessCommandLine) by DeviceName, AccountName`,
    splunk: `index=* (EventCode=4688 OR EventCode=1) (${h.t.map((x) => `CommandLine="*${x.replace(/\\/g, "\\\\")}*"`).join(" OR ")})${ex ? ` NOT host="${ex}"` : ""} earliest=-7d\n| stats count values(CommandLine) as cmds by host, user`,
    qradar: `SELECT "Machine Name", username, COUNT(*) AS hits\nFROM events\nWHERE ${h.t.map((x) => `"Process CommandLine" ILIKE '%${x}%'`).join(" OR ")}\nGROUP BY "Machine Name", username LAST 7 DAYS`,
    rapid7: `where(${h.t.map((x) => `process.cmd_line ICONTAINS "${x.replace(/\\/g, "\\\\")}"`).join(" OR ")})\ngroupby(hostname)`,
    crowdstrike: `#event_simpleName=ProcessRollup2 CommandLine=/(${rx})/i${ex ? ` ComputerName!=/${ex}/i` : ""}\n| groupBy([ComputerName, UserName], function=count())`,
    s1: `event.type = 'Process Creation' and src.process.cmdline matches:anycase '(${rx.replace(/'/g, "")})'${ex ? ` and endpoint.name != '${ex}'` : ""}\n| group hits = count() by endpoint.name, src.process.user`,
  };
}

const R7SET = { signin: "Asset Authentication", extip: "Firewall Activity", process: "Process Start Event", domain: "DNS Query", hash: "Process Start Event", net: "Firewall Activity", children: "Process Start Event", hunt: "Process Start Event" };

export function buildQueries(an, lang) {
  const now = new Date();
  const s = an.window ? an.window.start : new Date(now - 864e5);
  const e = an.window ? an.window.end : now;
  const pad = R(new Date(s - 36e5), new Date(+e + 36e5));
  const center = an.timeline[0]?.ts || s;
  const tenMin = R(new Date(center - 6e5), new Date(+center + 6e5));
  const out = [];
  const add = (kind, basis, title, why, q, range) => out.push({
    id: `${kind}-${basis}`, basis, title, why, query: q[lang],
    run: { set: lang === "rapid7" ? `Log set: ${R7SET[kind]}` : SET[lang], range, path: PATH[lang] },
  });
  an.users.slice(0, 3).forEach((u) => add("signin", `User · ${u}`, `Sign-in history for ${u}`, "Shows whether the account logged in from unusual IPs or failed repeatedly.", K("signin", u, pad), "Last 7 days"));
  an.ips.external.slice(0, 4).forEach((ip) => add("extip", `External IP · ${ip}`, `All activity for ${ip}`, "Finds every log source that saw this IP, not just the one that alerted.", K("extip", ip, pad), pad.label));
  an.hosts.slice(0, 3).forEach((h) => add("process", `Host · ${h}`, `Process activity on ${h} ±10 min`, "Shows what ran on the host right before and after the alert.", K("process", h, tenMin), tenMin.label));
  an.domains.slice(0, 3).forEach((d) => add("domain", `Domain · ${d}`, `Who else contacted ${d}`, "Checks whether other hosts reached the same domain.", K("domain", d, pad), "Last 7 days"));
  an.hashes.slice(0, 3).forEach((h) => add("hash", `${h.type} · ${h.value.slice(0, 12)}…`, "Hash prevalence (30 days)", "Shows how many devices have seen this file.", K("hash", h.value, pad), "Last 30 days"));
  an.ips.internal.slice(0, 3).forEach((ip) => add("net", `Internal IP · ${ip}`, `Network activity from ${ip}`, "Lists every destination this internal IP talked to in the window.", K("net", ip, pad), pad.label));
  an.parents.slice(0, 3).forEach((p) => add("children", `Parent · ${p}`, `Children of ${p}`, "Shows what this parent process launched, to spot unusual child processes.", K("children", p, pad), pad.label));
  an.techniques.forEach((t) => add("hunt", `MITRE · ${t.id}`, `Hunt: ${t.name} on other hosts`, `Looks for the same ${t.tactic.toLowerCase()} pattern elsewhere in the estate.`, hunt(t, an.hosts[0], pad), "Last 7 days"));
  return out;
}
