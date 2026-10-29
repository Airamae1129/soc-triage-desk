import { execSync } from "node:child_process";
import { rmSync } from "node:fs";
import path from "node:path";

// Fresh test database for every run.
export default function setup() {
  const root = path.resolve(import.meta.dirname, "..");
  for (const f of ["prisma/test.db", "prisma/test.db-journal"]) rmSync(path.join(root, f), { force: true });
  execSync("npx prisma db push --skip-generate --accept-data-loss", {
    cwd: root,
    stdio: "pipe",
    env: { ...process.env, DATABASE_URL: "file:./test.db" },
  });
  return () => {
    for (const f of ["prisma/test.db", "prisma/test.db-journal"]) rmSync(path.join(root, f), { force: true });
  };
}
