// Creates (or resets) an admin account.
//   npm run create-admin -- --username <name> [--display "Full Name"]
// The password is asked for interactively and never stored in shell history or code.
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { prisma } from "../db.js";
import { hashPassword, passwordOk, passwordRules } from "./password.js";
import { audit } from "../lib/audit.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

function askHidden(question: string): Promise<string> {
  let muted = false;
  const out = new Writable({ write(chunk, _enc, cb) { if (!muted) process.stdout.write(chunk); cb(); } });
  const rl = createInterface({ input: process.stdin, output: out, terminal: true });
  return new Promise((resolve) => {
    rl.question(question, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
    muted = true;
  });
}

async function main() {
  const username = arg("username")?.trim().toLowerCase();
  if (!username || !/^[a-z0-9._-]{2,64}$/.test(username)) {
    console.error('Usage: npm run create-admin -- --username <name> [--display "Full Name"]\n(letters, digits, dot, dash, underscore)');
    process.exit(1);
  }
  const displayName = arg("display")?.trim() || username;
  const pw = await askHidden(`Password for ${username} (${passwordRules}): `);
  if (!passwordOk(pw)) { console.error(`Password must be ${passwordRules}.`); process.exit(1); }
  const pw2 = await askHidden("Type it again: ");
  if (pw !== pw2) { console.error("Passwords don't match."); process.exit(1); }

  const passwordHash = await hashPassword(pw);
  const existing = await prisma.user.findUnique({ where: { username } });
  const user = existing
    ? await prisma.user.update({ where: { id: existing.id }, data: { passwordHash, role: "admin", active: true, displayName: arg("display") ? displayName : existing.displayName } })
    : await prisma.user.create({ data: { username, displayName, passwordHash, role: "admin" } });
  await audit(null, existing ? "user.admin_reset_cli" : "user.admin_created_cli", user.username, { role: "admin" }, user.id);
  console.log(`${existing ? "Updated" : "Created"} admin "${user.username}". Sign in at the app URL.`);
  await prisma.$disconnect();
}

main().catch(async (e) => { console.error((e as Error).message); await prisma.$disconnect(); process.exit(1); });
