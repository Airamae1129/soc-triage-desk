// npm run dev: build the frontend into /public the first time only (later runs reuse it).
// Run `npm run build:ui` after changing frontend code, or use `npm run dev:ui` for hot reload.
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

if (existsSync("public/index.html")) process.exit(0);
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
if (!existsSync("frontend/node_modules")) {
  console.log("Installing frontend packages (first run only)…");
  // The frontend's lockfile is yarn.lock; run the pinned yarn through npx (nothing to install globally).
  const i = spawnSync("npx", ["--yes", "yarn@1.22.22", "install", "--frozen-lockfile", "--ignore-engines"], { cwd: "frontend", stdio: "inherit", shell: process.platform === "win32" });
  if (i.status) process.exit(i.status);
}
console.log("Building the frontend into /public (first run only)…");
const r = spawnSync(npm, ["--prefix", "frontend", "run", "build:public"], { stdio: "inherit", shell: process.platform === "win32" });
process.exit(r.status ?? 1);
