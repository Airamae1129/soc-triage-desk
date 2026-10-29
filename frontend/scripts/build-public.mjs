// Builds the React app straight into ../public, where the Express server serves it.
// INLINE_RUNTIME_CHUNK=false keeps every script in a file, so the server's strict CSP
// (script-src 'self', no inline scripts) can stay strict.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const r = spawnSync("npx", ["craco", "build"], {
  cwd: path.resolve(here, ".."),
  stdio: "inherit",
  shell: process.platform === "win32",
  env: {
    ...process.env,
    BUILD_PATH: path.resolve(here, "../../public"),
    INLINE_RUNTIME_CHUNK: "false",
    GENERATE_SOURCEMAP: "false",
    DISABLE_EMERGENT_OVERLAY: "true",
    DISABLE_ESLINT_PLUGIN: "true",
  },
});
process.exit(r.status ?? 1);
