import session from "express-session";
import { prisma } from "../db.js";

/** express-session store backed by the Session table, so sessions survive restarts. */
export class PrismaSessionStore extends session.Store {
  private timer: NodeJS.Timeout;

  constructor(private ttlMs: number) {
    super();
    // Remove expired sessions every 15 minutes.
    this.timer = setInterval(() => { void prisma.session.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => {}); }, 15 * 60e3);
    this.timer.unref();
  }

  private expiry(sess: session.SessionData) {
    const e = sess.cookie?.expires;
    return e ? new Date(e) : new Date(Date.now() + this.ttlMs);
  }

  override get(sid: string, cb: (err: unknown, s?: session.SessionData | null) => void) {
    prisma.session.findUnique({ where: { sid } })
      .then((row) => {
        if (!row || row.expiresAt < new Date()) return cb(null, null);
        cb(null, JSON.parse(row.data) as session.SessionData);
      })
      .catch((e) => cb(e));
  }

  override set(sid: string, sess: session.SessionData, cb?: (err?: unknown) => void) {
    const data = JSON.stringify(sess);
    const expiresAt = this.expiry(sess);
    prisma.session.upsert({ where: { sid }, create: { sid, data, expiresAt }, update: { data, expiresAt } })
      .then(() => cb?.())
      .catch((e) => cb?.(e));
  }

  override destroy(sid: string, cb?: (err?: unknown) => void) {
    prisma.session.deleteMany({ where: { sid } }).then(() => cb?.()).catch((e) => cb?.(e));
  }

  override touch(sid: string, sess: session.SessionData, cb?: (err?: unknown) => void) {
    prisma.session.updateMany({ where: { sid }, data: { expiresAt: this.expiry(sess) } }).then(() => cb?.()).catch((e) => cb?.(e));
  }

  close() { clearInterval(this.timer); }
}
