import fs from "node:fs";
import os from "node:os";
import { spawn } from "node:child_process";
import path from "node:path";
import net from "node:net";

const rootDir = process.cwd();
const signedDir = path.join(rootDir, "signed");
const tunnelUrlFile = path.join(rootDir, ".cloudflare-tunnel-url");
const generatedConfigFile = path.join(rootDir, ".cloudflare-tunnel-config.yml");
const pidFile = path.join(rootDir, ".cloudflare-local.pids");
const homeConfigFile = path.join(os.homedir(), ".cloudflared", "config.yml");
const mode = process.env.CLOUDFLARE_TUNNEL_MODE || "named";
const children = new Set();

try {
  fs.rmSync(tunnelUrlFile, { force: true });
  fs.rmSync(generatedConfigFile, { force: true });
  fs.rmSync(pidFile, { force: true });
  fs.rmSync(signedDir, { recursive: true, force: true });
  fs.mkdirSync(signedDir, { recursive: true });
} catch {
  // Best effort cleanup.
}

function start(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: rootDir,
    env: options.env || process.env,
    stdio: options.stdio || ["ignore", "pipe", "pipe"]
  });
  children.add(child);
  child.on("exit", () => children.delete(child));
  return child;
}

function checkPortAvailable(targetPort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", (error) => {
      if (error.code === "EADDRINUSE") {
        resolve(false);
        return;
      }
      reject(error);
    });
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(Number(targetPort), "::");
  });
}

async function findAvailablePort() {
  if (process.env.PORT) {
    if (await checkPortAvailable(process.env.PORT)) {
      return String(process.env.PORT);
    }

    console.error(`Port ${process.env.PORT} đang bận.`);
    process.exit(1);
  }

  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      server.close(() => resolve(String(address.port)));
    });
    server.listen(0, "127.0.0.1");
  });
}

const port = await findAvailablePort();

function pipe(prefix, stream, onText) {
  stream.on("data", (chunk) => {
    const text = chunk.toString();
    process.stdout.write(text);
    onText?.(text);
  });
}

const server = start("node", ["server.js"], {
  env: {
    ...process.env,
    PORT: port,
    TUNNEL_URL_FILE: tunnelUrlFile
  }
});

function writePidFile() {
  const pids = [process.pid, ...[...children].map((child) => child.pid)].filter(Boolean);
  fs.writeFileSync(pidFile, `${pids.join("\n")}\n`);
}

writePidFile();
process.stdout.write(`Local server port: ${port}\n`);

pipe("", server.stdout);
pipe("", server.stderr);

server.on("exit", (code) => {
  if (code !== 0 && code !== null) {
    process.exitCode = code;
  }
  shutdown();
});

function readNamedTunnelConfig() {
  if (!fs.existsSync(homeConfigFile)) return null;

  const config = fs.readFileSync(homeConfigFile, "utf8");
  const hostname = config.match(/hostname:\s*([^\s]+)/)?.[1];
  const tunnel = config.match(/^tunnel:\s*([^\s]+)/m)?.[1];
  const credentialsFile = config.match(/^credentials-file:\s*(.+)$/m)?.[1]?.trim();

  if (!hostname || !tunnel || !credentialsFile) return null;

  return {
    hostname,
    tunnel,
    credentialsFile,
    url: `https://${hostname}`
  };
}

function writeNamedTunnelConfig(config) {
  const body = `tunnel: ${config.tunnel}
credentials-file: ${config.credentialsFile}

ingress:
  - hostname: ${config.hostname}
    service: http://127.0.0.1:${port}
  - service: http_status:404
`;

  fs.writeFileSync(generatedConfigFile, body);
  fs.writeFileSync(tunnelUrlFile, `${config.url}\n`);
  process.stdout.write(`\nCloudflare URL for OTA: ${config.url}\n\n`);
}

const namedConfig = mode === "named" ? readNamedTunnelConfig() : null;
if (namedConfig) {
  writeNamedTunnelConfig(namedConfig);
}

let tunnelRestartTimer = null;

function startTunnel() {
  const tunnel = namedConfig
    ? start("cloudflared", [
        "tunnel",
        "--config",
        generatedConfigFile,
        "--edge-ip-version",
        "4",
        "--protocol",
        "http2",
        "run"
      ])
    : start("cloudflared", [
        "tunnel",
        "--edge-ip-version",
        "4",
        "--protocol",
        "http2",
        "--url",
        `http://127.0.0.1:${port}`
      ]);

  pipe("", tunnel.stdout, captureTunnelUrl);
  pipe("", tunnel.stderr, captureTunnelUrl);
  tunnel.on("exit", (code) => {
    if (shuttingDown) return;
    process.stdout.write(`cloudflared exited with code ${code ?? "unknown"}. Restarting in 3s...\n`);
    tunnelRestartTimer = setTimeout(() => {
      tunnelRestartTimer = null;
      startTunnel();
    }, 3000);
  });
  writePidFile();
}

startTunnel();

function captureTunnelUrl(text) {
  const match = text.match(/https:\/\/[a-z0-9.-]+/i);
  if (!match) return;

  const url = match[0];
  fs.writeFileSync(tunnelUrlFile, `${url}\n`);
  process.stdout.write(`\nCloudflare URL for OTA: ${url}\n\n`);
}

let shuttingDown = false;
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  if (tunnelRestartTimer) {
    clearTimeout(tunnelRestartTimer);
  }

  for (const child of children) {
    child.kill("SIGINT");
  }
  try {
    fs.rmSync(tunnelUrlFile, { force: true });
    fs.rmSync(generatedConfigFile, { force: true });
    fs.rmSync(pidFile, { force: true });
  } catch {
    // Best effort cleanup.
  }
}

process.on("SIGINT", () => {
  shutdown();
});
process.on("SIGTERM", () => {
  shutdown();
});
