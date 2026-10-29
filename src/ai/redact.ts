// Replaces client name, usernames, internal hostnames and internal IPs with tokens
// (CLIENT_1, USER_1, HOST_1, INTIP_1) before text goes to an AI provider. The mapping lives
// only in this object, for one request, and is used to put the real values back afterwards.

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class Redactor {
  private map = new Map<string, string>(); // token -> real
  private counters: Record<string, number> = {};
  private rules: { re: RegExp; token: string }[] = [];

  constructor(input: { client?: string; users?: string[]; hosts?: string[]; internalIps?: string[]; extra?: string[] }) {
    const add = (kind: string, value: string | undefined) => {
      const v = value?.trim();
      if (!v || v.length < 2) return;
      if ([...this.map.values()].some((x) => x.toLowerCase() === v.toLowerCase())) return;
      const n = (this.counters[kind] = (this.counters[kind] ?? 0) + 1);
      const token = `${kind}_${n}`;
      this.map.set(token, v);
      // Whole-value match, case-insensitive. IPs must not match inside a longer IP.
      const re = kind === "INTIP" ? new RegExp(`(?<![\\d.])${escapeRe(v)}(?![\\d])`, "g") : new RegExp(`(?<![\\w-])${escapeRe(v)}(?![\\w-])`, "gi");
      this.rules.push({ re, token });
    };
    add("CLIENT", input.client);
    for (const x of input.extra ?? []) add("CLIENT", x);
    for (const u of input.users ?? []) {
      add("USER", u);
      // Also cover the local part of UPNs and DOMAIN\user forms.
      const local = u.includes("@") ? u.split("@")[0] : u.includes("\\") ? u.split("\\").pop() : undefined;
      if (local && local.length >= 3) add("USER", local);
    }
    for (const h of input.hosts ?? []) add("HOST", h);
    for (const ip of input.internalIps ?? []) add("INTIP", ip);
    // Longest values first so "HL-WS-FIN07.corp" is replaced before "HL-WS-FIN07".
    this.rules.sort((a, b) => (this.map.get(b.token)?.length ?? 0) - (this.map.get(a.token)?.length ?? 0));
  }

  redact(text: string): string {
    return this.rules.reduce((t, r) => t.replace(r.re, r.token), text ?? "");
  }

  restore(text: string): string {
    return (text ?? "").replace(/\b(CLIENT|USER|HOST|INTIP)_(\d+)\b/g, (m) => this.map.get(m) ?? m);
  }

  get tokens(): string[] { return [...this.map.keys()]; }
  get size(): number { return this.map.size; }
}
