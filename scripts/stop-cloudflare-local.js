import fs from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const pidFile = path.join(rootDir, ".cloudflare-local.pids");
const tunnelUrlFile = path.join(rootDir, ".cloudflare-tunnel-url");
const generatedConfigFile = path.join(rootDir, ".cloudflare-tunnel-config.yml");

function isRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function killPid(pid, signal) {
  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
}

if (!fs.existsSync(pidFile)) {
  console.log("Không tìm thấy PID file. Tool có thể đã tắt rồi.");
  process.exit(0);
}

const pids = fs
  .readFileSync(pidFile, "utf8")
  .split("\n")
  .map((line) => Number(line.trim()))
  .filter(Boolean);

for (const pid of pids) {
  killPid(pid, "SIGINT");
}

await new Promise((resolve) => setTimeout(resolve, 1200));

for (const pid of pids) {
  if (isRunning(pid)) {
    killPid(pid, "SIGTERM");
  }
}

await new Promise((resolve) => setTimeout(resolve, 800));

for (const pid of pids) {
  if (isRunning(pid)) {
    killPid(pid, "SIGKILL");
  }
}

for (const file of [pidFile, tunnelUrlFile, generatedConfigFile]) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    // Best effort cleanup.
  }
}

console.log("Đã tắt local server và Cloudflare Tunnel của tool.");
