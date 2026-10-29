import bcrypt from "bcryptjs";
import { randomBytes } from "node:crypto";

// bcrypt, cost 12 (pure-JS bcryptjs: no native build needed on Windows).
const COST = 12;

export const hashPassword = (pw: string) => bcrypt.hash(pw, COST);
export const verifyPassword = (pw: string, hash: string) => bcrypt.compare(pw, hash);

// Real hash of a random value, compared against when the username doesn't exist, so a wrong
// username takes as long as a wrong password (no username probing by timing).
let dummy: Promise<string> | undefined;
export const dummyHash = () => (dummy ??= hashPassword(randomBytes(24).toString("hex")));

export const passwordRules = "at least 12 characters";
export const passwordOk = (pw: unknown): pw is string => typeof pw === "string" && pw.length >= 12 && pw.length <= 200;
