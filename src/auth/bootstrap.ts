// Creates the accounts named in the environment at startup, so a host whose disk is wiped on
// every restart (e.g. Render's free plan) still has an admin and an analyst to sign in with.
//   ADMIN_USERNAME / ADMIN_PASSWORD      -> role admin
//   ANALYST_USERNAME / ANALYST_PASSWORD  -> role analyst
// A missing account is created; an existing one is re-enabled, given that role, and its
// password is reset only when it no longer matches. Passwords are never logged.
import { prisma } from "../db.js";
import { config } from "../config.js";
import { logger } from "../lib/logger.js";
import { audit } from "../lib/audit.js";
import { hashPassword, passwordOk, passwordRules, verifyPassword } from "./password.js";

type Account = { role: "admin" | "analyst"; username?: string; password?: string; display?: string };

export async function bootstrapAccounts() {
  const accounts: Account[] = [
    { role: "admin", username: config.ADMIN_USERNAME, password: config.ADMIN_PASSWORD, display: config.ADMIN_DISPLAY_NAME },
    { role: "analyst", username: config.ANALYST_USERNAME, password: config.ANALYST_PASSWORD, display: config.ANALYST_DISPLAY_NAME },
  ];
  for (const a of accounts) {
    if (!a.username && !a.password) continue;
    const username = a.username?.trim().toLowerCase() ?? "";
    if (!/^[a-z0-9._-]{2,64}$/.test(username) || !passwordOk(a.password)) {
      logger.warn(`${a.role.toUpperCase()}_USERNAME / ${a.role.toUpperCase()}_PASSWORD skipped: username must be letters, digits, dot, dash or underscore and the password ${passwordRules}`);
      continue;
    }
    const existing = await prisma.user.findUnique({ where: { username } });
    if (!existing) {
      const user = await prisma.user.create({ data: { username, displayName: a.display?.trim() || username, passwordHash: await hashPassword(a.password), role: a.role } });
      await audit(null, "user.created_env", user.username, { role: a.role }, user.id);
      logger.info(`Created ${a.role} account "${username}" from the environment`);
      continue;
    }
    const data: { role: string; active: boolean; passwordHash?: string } = { role: a.role, active: true };
    if (!(await verifyPassword(a.password, existing.passwordHash))) data.passwordHash = await hashPassword(a.password);
    await prisma.user.update({ where: { id: existing.id }, data });
  }
}
