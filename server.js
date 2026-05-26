import crypto from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import express from "express";
import multer from "multer";
import QRCode from "qrcode";

const app = express();
const port = Number(process.env.PORT || 3000);
const signedDir = path.join(process.cwd(), "signed");
const chunkDir = path.join(os.tmpdir(), "resign-ipa-chunks");
const tunnelUrlFile = process.env.TUNNEL_URL_FILE ? path.resolve(process.env.TUNNEL_URL_FILE) : null;
const upload = multer({
  dest: path.join(os.tmpdir(), "resign-ipa-uploads"),
  limits: {
    fileSize: 1024 * 1024 * 1024
  }
});
const chunkUpload = multer({
  dest: path.join(os.tmpdir(), "resign-ipa-upload-chunks"),
  limits: {
    fileSize: 16 * 1024 * 1024
  }
});

app.use(
  express.static(path.join(process.cwd(), "public"), {
    etag: false,
    lastModified: false,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
  })
);

await fs.mkdir(signedDir, { recursive: true });
await fs.mkdir(chunkDir, { recursive: true });

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env || process.env
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }

      const error = new Error(`${command} ${args.join(" ")} failed with code ${code}\n${stderr || stdout}`);
      error.stdout = stdout;
      error.stderr = stderr;
      reject(error);
    });
  });
}

async function plistBuddy(plistPath, command) {
  const result = await run("/usr/libexec/PlistBuddy", ["-c", command, plistPath]);
  return result.stdout.trim();
}

async function plistValueOrDefault(plistPath, command, fallback = "") {
  try {
    return await plistBuddy(plistPath, command);
  } catch {
    return fallback;
  }
}

async function setPlistValue(plistPath, key, value) {
  try {
    await run("/usr/libexec/PlistBuddy", ["-c", `Set :${key} ${value}`, plistPath]);
  } catch {
    await run("/usr/libexec/PlistBuddy", ["-c", `Add :${key} string ${value}`, plistPath]);
  }
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function findOpenSsl() {
  const candidates = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"];
  for (const candidate of candidates) {
    if (await pathExists(candidate)) return candidate;
  }

  try {
    const result = await run("/usr/bin/which", ["openssl"]);
    return result.stdout.trim();
  } catch {
    return null;
  }
}

async function importP12IntoKeychain(p12Path, keychainPath, password, workDir) {
  async function securityImport(filePath, filePassword) {
    await run("/usr/bin/security", [
      "import",
      filePath,
      "-k",
      keychainPath,
      "-P",
      filePassword || "",
      "-T",
      "/usr/bin/codesign",
      "-T",
      "/usr/bin/security"
    ]);
  }

  async function importLegacyP12(originalError) {
    const openssl = await findOpenSsl();
    if (!openssl) {
      throw new Error("Không import được file .p12 và không tìm thấy OpenSSL để thử chuyển định dạng.");
    }

    const pemPath = path.join(workDir, "certificate.pem");
    const convertedP12Path = path.join(workDir, "certificate-legacy.p12");
    const convertedPassword = crypto.randomBytes(18).toString("hex");

    try {
      await run(openssl, [
        "pkcs12",
        "-in",
        p12Path,
        "-nodes",
        "-legacy",
        "-passin",
        `pass:${password || ""}`,
        "-out",
        pemPath
      ]);
      await run(openssl, [
        "pkcs12",
        "-export",
        "-legacy",
        "-in",
        pemPath,
        "-out",
        convertedP12Path,
        "-passout",
        `pass:${convertedPassword}`
      ]);
      await securityImport(convertedP12Path, convertedPassword);
    } catch (fallbackError) {
      const details =
        fallbackError.stderr || fallbackError.stdout || originalError?.stderr || originalError?.stdout || "";
      const hint = details.includes("Mac verify error") || details.includes("invalid password")
        ? "Mật khẩu .p12 có thể không đúng."
        : "File được chọn có thể không phải PKCS#12 hợp lệ hoặc không chứa private key.";
      throw new Error(`Không import được file .p12. ${hint}`);
    }
  }

  try {
    await securityImport(p12Path, password);
    return { retryLegacyImport: () => importLegacyP12() };
  } catch (firstError) {
    await importLegacyP12(firstError);
    return { retryLegacyImport: async () => {} };
  }
}

async function findAppBundle(payloadDir) {
  const entries = await fs.readdir(payloadDir, { withFileTypes: true });
  const app = entries.find((entry) => entry.isDirectory() && entry.name.endsWith(".app"));
  if (!app) {
    throw new Error("Không tìm thấy thư mục .app trong Payload của IPA.");
  }
  return path.join(payloadDir, app.name);
}

async function listNestedBundles(appDir) {
  const nested = [];

  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (!entry.isDirectory()) {
        if (entry.name.endsWith(".dylib")) {
          nested.push(fullPath);
        }
        continue;
      }

      if (
        entry.name.endsWith(".app") ||
        entry.name.endsWith(".appex") ||
        entry.name.endsWith(".framework")
      ) {
        nested.push(fullPath);
        if (entry.name.endsWith(".framework")) continue;
      }

      await walk(fullPath);
    }
  }

  const candidates = ["Frameworks", "PlugIns", "Watch", "Extensions"].map((name) => path.join(appDir, name));
  for (const candidate of candidates) {
    if (await pathExists(candidate)) {
      await walk(candidate);
    }
  }

  return nested.sort((a, b) => b.length - a.length);
}

async function extractEntitlements(profilePlist, outPath, teamId, bundleId) {
  await run("/usr/libexec/PlistBuddy", ["-x", "-c", "Print :Entitlements", profilePlist]).then((result) =>
    fs.writeFile(outPath, result.stdout)
  );

  if (bundleId) {
    await setPlistValue(outPath, "application-identifier", `${teamId}.${bundleId}`);
    await setPlistValue(outPath, "com.apple.developer.team-identifier", teamId);

    try {
      await run("/usr/libexec/PlistBuddy", ["-c", "Delete :keychain-access-groups", outPath]);
      await run("/usr/libexec/PlistBuddy", ["-c", "Add :keychain-access-groups array", outPath]);
      await run("/usr/libexec/PlistBuddy", ["-c", `Add :keychain-access-groups:0 string ${teamId}.${bundleId}`, outPath]);
    } catch {
      // Some profiles do not contain keychain groups. The entitlement is optional.
    }
  }
}

function normalizeFingerprint(value) {
  return String(value).replaceAll(":", "").trim().toUpperCase();
}

async function getProvisionCertificateFingerprints(profilePlist, workDir) {
  const fingerprints = [];
  const openssl = await findOpenSsl();
  if (!openssl) return fingerprints;

  for (let index = 0; index < 50; index += 1) {
    const extracted = await run("/usr/bin/plutil", [
      "-extract",
      `DeveloperCertificates.${index}`,
      "raw",
      "-o",
      "-",
      profilePlist
    ]).catch(() => null);
    if (!extracted) break;

    const certificatePath = path.join(workDir, `provision-cert-${index}.cer`);
    await fs.writeFile(certificatePath, Buffer.from(extracted.stdout.trim(), "base64"));
    const fingerprintResult = await run(openssl, [
      "x509",
      "-inform",
      "DER",
      "-in",
      certificatePath,
      "-noout",
      "-fingerprint",
      "-sha1"
    ]).catch(() => null);
    if (!fingerprintResult) continue;

    const match = fingerprintResult.stdout.match(/Fingerprint=([A-F0-9:]+)/i);
    if (match) {
      fingerprints.push(normalizeFingerprint(match[1]));
    }
  }

  return fingerprints;
}

async function validateProvisionForSigning({ profilePlist, workDir, identity }) {
  const profileCerts = await getProvisionCertificateFingerprints(profilePlist, workDir);
  const identityHash = normalizeFingerprint(identity.hash);
  if (profileCerts.length && !profileCerts.includes(identityHash)) {
    throw new Error(
      [
        "Provisioning profile không chứa certificate đang dùng để ký.",
        `P12 certificate SHA1: ${identityHash}`,
        `Profile certificates SHA1: ${profileCerts.join(", ")}`
      ].join("\n")
    );
  }
}

function parseIdentity(findIdentityOutput) {
  const line = findIdentityOutput.split("\n").find((item) => /\)\s+[A-F0-9]{40}\s+".+"/.test(item));

  if (!line) return null;

  const match = line.match(/\)\s+([A-F0-9]{40})\s+"(.+)"/);
  if (!match) return null;
  return { hash: match[1], name: match[2] };
}

async function describeImportedP12(keychainPath, identityOutput) {
  const certificates = await run("/usr/bin/security", ["find-certificate", "-a", "-p", keychainPath]).catch(
    (error) => error
  );
  const keys = await run("/usr/bin/security", ["dump-keychain", keychainPath]).catch((error) => error);
  const certificateText = (certificates.stdout || certificates.stderr || "").trim();
  const keyText = (keys.stdout || keys.stderr || "").trim();
  const identityText = identityOutput.trim() || "Không có identity codesigning hợp lệ trong keychain tạm.";

  return [
    "Không tìm thấy signing identity hợp lệ trong file .p12.",
    "File .p12 phải chứa certificate Apple Development/Distribution kèm private key.",
    "",
    "security find-identity:",
    identityText,
    "",
    "certificate/key debug:",
    [certificateText, keyText].filter(Boolean).join("\n") || "Không đọc được certificate/private key từ .p12."
  ].join("\n");
}

function parseKeychainList(output) {
  return output
    .split("\n")
    .map((line) => line.trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

async function getUserKeychainList() {
  const result = await run("/usr/bin/security", ["list-keychains", "-d", "user"]);
  return parseKeychainList(result.stdout);
}

async function setUserKeychainList(keychains) {
  await run("/usr/bin/security", ["list-keychains", "-d", "user", "-s", ...keychains]);
}

async function useOnlyKeychain(keychainPath) {
  const original = await getUserKeychainList();
  await setUserKeychainList([keychainPath]);
  return original;
}

async function addKeychainToSearchList(keychainPath) {
  const original = await getUserKeychainList();
  const next = [keychainPath, ...original.filter((item) => item !== keychainPath)];
  await setUserKeychainList(next);
  return original;
}

async function signBundle(bundlePath, identity, entitlementsPath, keychainPath) {
  const extension = path.extname(bundlePath);
  const args = [
    "--force",
    "--sign",
    identity.hash,
    "--timestamp=none"
  ];

  if (identity.keychainPath) {
    args.push("--keychain", identity.keychainPath);
  }

  if (extension === ".app" || extension === ".appex") {
    args.push("--entitlements", entitlementsPath);
  }

  args.push(bundlePath);
  try {
    await run("/usr/bin/codesign", args);
  } catch (error) {
    if ((error.stderr || error.message).includes("no identity found")) {
      throw new Error(`codesign không tìm thấy identity "${identity.name}".`);
    }
    if ((error.stderr || error.message).includes("ambiguous")) {
      throw new Error(`codesign thấy nhiều identity trùng "${identity.name}". Hãy xóa certificate trùng trong login keychain hoặc thử ký lại sau khi restart tool.`);
    }
    throw error;
  }
}

async function cleanupKeychain(keychainPath) {
  try {
    await run("/usr/bin/security", ["delete-keychain", keychainPath]);
  } catch {
    // Best effort cleanup.
  }
}

function escapeXml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function buildManifest({ ipaUrl, bundleId, bundleVersion, title }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${escapeXml(ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${escapeXml(bundleId)}</string>
        <key>bundle-version</key>
        <string>${escapeXml(bundleVersion || "1.0")}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>${escapeXml(title || "Signed App")}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
}

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, "");
  }

  if (tunnelUrlFile && fsSync.existsSync(tunnelUrlFile)) {
    const tunnelUrl = fsSync.readFileSync(tunnelUrlFile, "utf8").trim();
    if (tunnelUrl.startsWith("https://")) {
      return tunnelUrl.replace(/\/$/, "");
    }
  }

  const protocol = req.get("x-forwarded-proto") || req.protocol;
  return `${protocol}://${req.get("host")}`;
}

async function saveSignedResult(result) {
  const id = crypto.randomUUID();
  const targetDir = path.join(signedDir, id);
  const ipaPath = path.join(targetDir, result.outputName);
  const metadataPath = path.join(targetDir, "metadata.json");

  await fs.mkdir(targetDir, { recursive: true });
  await fs.copyFile(result.outputPath, ipaPath);
  await fs.writeFile(
    metadataPath,
    JSON.stringify(
      {
        id,
        fileName: result.outputName,
        bundleId: result.bundleId,
        bundleVersion: result.bundleVersion,
        title: result.title,
        identityName: result.identityName,
        p12IdentityName: result.p12IdentityName,
        signingIdentityName: result.signingIdentityName,
        signingIdentitySource: result.signingIdentitySource,
        createdAt: new Date().toISOString()
      },
      null,
      2
    )
  );

  return { id, targetDir, ipaPath };
}

async function readSignedMetadata(id) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;

  try {
    const metadata = await fs.readFile(path.join(signedDir, id, "metadata.json"), "utf8");
    return JSON.parse(metadata);
  } catch {
    return null;
  }
}

function isSafeUploadId(value) {
  return /^[0-9a-f-]{36}$/i.test(String(value || ""));
}

function isSafeFileName(value) {
  return typeof value === "string" && value.length > 0 && value === path.basename(value);
}

async function buildSignPayload(req, result, saved) {
  const baseUrl = getBaseUrl(req);
  const downloadUrl = `${baseUrl}/download/${saved.id}`;
  const manifestUrl = `${baseUrl}/manifest/${saved.id}.plist`;
  const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
  const qrDataUrl = await QRCode.toDataURL(installUrl, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 280
  });

  return {
    id: saved.id,
    fileName: result.outputName,
    bundleId: result.bundleId,
    bundleVersion: result.bundleVersion,
    title: result.title,
    identityName: result.identityName,
    p12IdentityName: result.p12IdentityName,
    signingIdentityName: result.signingIdentityName,
    signingIdentitySource: result.signingIdentitySource,
    downloadUrl,
    manifestUrl,
    installUrl,
    qrDataUrl,
    httpsRequired: !manifestUrl.startsWith("https://"),
    localhostUrl: /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/.test(baseUrl)
  };
}

async function assembleChunkedIpa(uploadId, totalChunks, originalName) {
  if (!isSafeUploadId(uploadId)) {
    throw new Error("Upload ID không hợp lệ.");
  }
  if (!isSafeFileName(originalName)) {
    throw new Error("Tên file IPA không hợp lệ.");
  }

  const total = Number(totalChunks);
  if (!Number.isInteger(total) || total < 1 || total > 1000) {
    throw new Error("Số lượng chunk không hợp lệ.");
  }

  const uploadDir = path.join(chunkDir, uploadId);
  const assembledPath = path.join(os.tmpdir(), "resign-ipa-uploads", `${uploadId}.ipa`);
  await fs.mkdir(path.dirname(assembledPath), { recursive: true });
  await fs.rm(assembledPath, { force: true });

  const output = fsSync.createWriteStream(assembledPath);
  try {
    for (let index = 0; index < total; index += 1) {
      const chunkPath = path.join(uploadDir, `${index}.part`);
      if (!(await pathExists(chunkPath))) {
        throw new Error(`Thiếu chunk ${index + 1}/${total}.`);
      }
      await new Promise((resolve, reject) => {
        const input = fsSync.createReadStream(chunkPath);
        input.on("error", reject);
        input.on("end", resolve);
        input.pipe(output, { end: false });
      });
    }
  } finally {
    await new Promise((resolve) => output.end(resolve));
  }

  return {
    path: assembledPath,
    originalname: originalName
  };
}

async function validateSigningInputs({ p12, provision, password }) {
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "resign-validate-"));
  const keychainPassword = crypto.randomBytes(18).toString("hex");
  const keychainPath = path.join(workDir, "signing.keychain-db");
  const profilePlist = path.join(workDir, "profile.plist");
  let originalKeychains = null;

  try {
    await run("/usr/bin/security", ["create-keychain", "-p", keychainPassword, keychainPath]);
    await run("/usr/bin/security", ["set-keychain-settings", "-lut", "21600", keychainPath]);
    await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
    const p12Import = await importP12IntoKeychain(p12.path, keychainPath, password || "", workDir);
    originalKeychains = await addKeychainToSearchList(keychainPath);
    await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
    await run("/usr/bin/security", [
      "set-key-partition-list",
      "-S",
      "apple-tool:,apple:",
      "-s",
      "-k",
      keychainPassword,
      keychainPath
    ]);

    const cms = await run("/usr/bin/security", ["cms", "-D", "-i", provision.path]);
    await fs.writeFile(profilePlist, cms.stdout);

    const identityResult = await run("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning", keychainPath]);
    let identity = parseIdentity(identityResult.stdout);
    if (!identity) {
      await p12Import.retryLegacyImport();
      await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
      await run("/usr/bin/security", [
        "set-key-partition-list",
        "-S",
        "apple-tool:,apple:",
        "-s",
        "-k",
        keychainPassword,
        keychainPath
      ]);
      const legacyIdentityResult = await run("/usr/bin/security", [
        "find-identity",
        "-v",
        "-p",
        "codesigning",
        keychainPath
      ]);
      identity = parseIdentity(legacyIdentityResult.stdout);
      if (!identity) {
        throw new Error(await describeImportedP12(keychainPath, legacyIdentityResult.stdout || identityResult.stdout));
      }
    }

    identity = { ...identity, keychainPath };
    await validateProvisionForSigning({ profilePlist, workDir, identity });

    return {
      ok: true,
      identityName: identity.name,
      identityHash: normalizeFingerprint(identity.hash)
    };
  } finally {
    if (originalKeychains) {
      await setUserKeychainList(originalKeychains).catch(() => {});
    }
    await cleanupKeychain(keychainPath);
    await fs.rm(workDir, { recursive: true, force: true });
  }
}

async function resignIpa({ ipa, p12, provision, password, removeEmbedded, bundleId, bundleName }) {
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "resign-ipa-"));
  const keychainPassword = crypto.randomBytes(18).toString("hex");
  const keychainPath = path.join(workDir, "signing.keychain-db");
  let originalKeychains = null;

  try {
    const unzipDir = path.join(workDir, "unzip");
    const profilePlist = path.join(workDir, "profile.plist");
    const entitlementsPath = path.join(workDir, "entitlements.plist");
    const outDir = path.join(workDir, "out");
    await fs.mkdir(unzipDir, { recursive: true });
    await fs.mkdir(outDir, { recursive: true });

    await run("/usr/bin/security", ["create-keychain", "-p", keychainPassword, keychainPath]);
    await run("/usr/bin/security", ["set-keychain-settings", "-lut", "21600", keychainPath]);
    await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
    const p12Import = await importP12IntoKeychain(p12.path, keychainPath, password || "", workDir);
    originalKeychains = await addKeychainToSearchList(keychainPath);
    await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
    await run("/usr/bin/security", [
      "set-key-partition-list",
      "-S",
      "apple-tool:,apple:",
      "-s",
      "-k",
      keychainPassword,
      keychainPath
    ]);

    const cms = await run("/usr/bin/security", ["cms", "-D", "-i", provision.path]);
    await fs.writeFile(profilePlist, cms.stdout);
    const teamId = await plistBuddy(profilePlist, "Print :TeamIdentifier:0");

    const identityResult = await run("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning", keychainPath]);
    let identity = parseIdentity(identityResult.stdout);
    if (!identity) {
      await p12Import.retryLegacyImport();
      await run("/usr/bin/security", ["unlock-keychain", "-p", keychainPassword, keychainPath]);
      await run("/usr/bin/security", [
        "set-key-partition-list",
        "-S",
        "apple-tool:,apple:",
        "-s",
        "-k",
        keychainPassword,
        keychainPath
      ]);
      const legacyIdentityResult = await run("/usr/bin/security", [
        "find-identity",
        "-v",
        "-p",
        "codesigning",
        keychainPath
      ]);
      identity = parseIdentity(legacyIdentityResult.stdout);
      if (!identity) {
        throw new Error(await describeImportedP12(keychainPath, legacyIdentityResult.stdout || identityResult.stdout));
      }
    }
    identity = { ...identity, keychainPath };

    await extractEntitlements(profilePlist, entitlementsPath, teamId, bundleId);

    await run("/usr/bin/unzip", ["-q", ipa.path, "-d", unzipDir]);
    const payloadDir = path.join(unzipDir, "Payload");
    const appDir = await findAppBundle(payloadDir);
    const infoPlist = path.join(appDir, "Info.plist");

    if (bundleId) {
      await setPlistValue(infoPlist, "CFBundleIdentifier", bundleId);
    }
    if (bundleName) {
      await setPlistValue(infoPlist, "CFBundleDisplayName", bundleName);
      await setPlistValue(infoPlist, "CFBundleName", bundleName);
    }

    const finalBundleId = await plistValueOrDefault(infoPlist, "Print :CFBundleIdentifier", bundleId);
    const finalBundleName =
      (await plistValueOrDefault(infoPlist, "Print :CFBundleDisplayName")) ||
      (await plistValueOrDefault(infoPlist, "Print :CFBundleName")) ||
      path.parse(ipa.originalname).name;
    const bundleVersion =
      (await plistValueOrDefault(infoPlist, "Print :CFBundleShortVersionString")) ||
      (await plistValueOrDefault(infoPlist, "Print :CFBundleVersion")) ||
      "1.0";

    await validateProvisionForSigning({
      profilePlist,
      workDir,
      identity
    });

    const embeddedProfile = path.join(appDir, "embedded.mobileprovision");
    await fs.rm(embeddedProfile, { force: true });
    if (!removeEmbedded) {
      await fs.copyFile(provision.path, embeddedProfile);
    }

    const nestedBundles = await listNestedBundles(appDir);
    for (const nested of nestedBundles) {
      await signBundle(nested, identity, entitlementsPath, keychainPath);
    }
    await signBundle(appDir, identity, entitlementsPath, keychainPath);

    const outputName = `${path.parse(ipa.originalname).name}-signed.ipa`;
    const outputPath = path.join(outDir, outputName);
    await run("/usr/bin/zip", ["-qry", outputPath, "Payload"], { cwd: unzipDir });

    return {
      workDir,
      outputPath,
      outputName,
      identityName: identity.name,
      p12IdentityName: identity.name,
      signingIdentityName: identity.name,
      signingIdentitySource: "p12",
      bundleId: finalBundleId,
      bundleVersion,
      title: finalBundleName
    };
  } catch (error) {
    if (originalKeychains) {
      await setUserKeychainList(originalKeychains).catch(() => {});
    }
    await cleanupKeychain(keychainPath);
    await fs.rm(workDir, { recursive: true, force: true });
    throw error;
  } finally {
    if (originalKeychains) {
      await setUserKeychainList(originalKeychains).catch(() => {});
    }
  }
}

app.post(
  "/api/sign",
  upload.fields([
    { name: "ipa", maxCount: 1 },
    { name: "p12", maxCount: 1 },
    { name: "provision", maxCount: 1 }
  ]),
  async (req, res) => {
    let result;
    try {
      const ipa = req.files?.ipa?.[0];
      const p12 = req.files?.p12?.[0];
      const provision = req.files?.provision?.[0];

      if (!ipa || !p12 || !provision) {
        res.status(400).json({ error: "Cần chọn đủ file .ipa, .p12 và .mobileprovision." });
        return;
      }

      result = await resignIpa({
        ipa,
        p12,
        provision,
        password: String(req.body.p12Password || ""),
        removeEmbedded: req.body.removeEmbedded === "true",
        bundleId: String(req.body.bundleId || "").trim(),
        bundleName: String(req.body.bundleName || "").trim()
      });

      const saved = await saveSignedResult(result);
      const payload = await buildSignPayload(req, result, saved);

      await cleanupKeychain(path.join(result.workDir, "signing.keychain-db"));
      await fs.rm(result.workDir, { recursive: true, force: true });

      res.json(payload);
    } catch (error) {
      if (result?.workDir) {
        await cleanupKeychain(path.join(result.workDir, "signing.keychain-db"));
        await fs.rm(result.workDir, { recursive: true, force: true });
      }
      res.status(500).json({
        error: error.message.replaceAll(process.cwd(), ".")
      });
    } finally {
      const uploaded = Object.values(req.files || {}).flat();
      await Promise.all(uploaded.map((file) => fs.rm(file.path, { force: true })));
    }
  }
);

app.post(
  "/api/validate-signing",
  upload.fields([
    { name: "p12", maxCount: 1 },
    { name: "provision", maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const p12 = req.files?.p12?.[0];
      const provision = req.files?.provision?.[0];

      if (!p12 || !provision) {
        res.status(400).json({ error: "Cần chọn đủ file .p12 và .mobileprovision." });
        return;
      }

      const result = await validateSigningInputs({
        p12,
        provision,
        password: String(req.body.p12Password || "")
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({
        error: error.message.replaceAll(process.cwd(), ".")
      });
    } finally {
      const uploaded = Object.values(req.files || {}).flat();
      await Promise.all(uploaded.map((file) => fs.rm(file.path, { force: true })));
    }
  }
);

app.post("/api/upload-chunk", chunkUpload.single("chunk"), async (req, res) => {
  try {
    const uploadId = String(req.body.uploadId || "");
    const index = Number(req.body.index);
    const totalChunks = Number(req.body.totalChunks);

    if (!req.file) {
      res.status(400).json({ error: "Thiếu chunk upload." });
      return;
    }
    if (!isSafeUploadId(uploadId)) {
      res.status(400).json({ error: "Upload ID không hợp lệ." });
      return;
    }
    if (!Number.isInteger(index) || index < 0 || !Number.isInteger(totalChunks) || index >= totalChunks) {
      res.status(400).json({ error: "Index chunk không hợp lệ." });
      return;
    }

    const uploadDir = path.join(chunkDir, uploadId);
    await fs.mkdir(uploadDir, { recursive: true });
    await fs.rename(req.file.path, path.join(uploadDir, `${index}.part`));
    res.json({ ok: true, index });
  } catch (error) {
    if (req.file?.path) {
      await fs.rm(req.file.path, { force: true });
    }
    res.status(500).json({ error: error.message });
  }
});

app.post(
  "/api/sign-chunked",
  upload.fields([
    { name: "p12", maxCount: 1 },
    { name: "provision", maxCount: 1 }
  ]),
  async (req, res) => {
    let result;
    let assembledIpa;
    const uploadId = String(req.body.uploadId || "");

    try {
      const p12 = req.files?.p12?.[0];
      const provision = req.files?.provision?.[0];

      if (!p12 || !provision) {
        res.status(400).json({ error: "Cần chọn đủ file .p12 và .mobileprovision." });
        return;
      }

      assembledIpa = await assembleChunkedIpa(
        uploadId,
        req.body.totalChunks,
        String(req.body.ipaName || "app.ipa")
      );

      result = await resignIpa({
        ipa: assembledIpa,
        p12,
        provision,
        password: String(req.body.p12Password || ""),
        removeEmbedded: req.body.removeEmbedded === "true",
        bundleId: String(req.body.bundleId || "").trim(),
        bundleName: String(req.body.bundleName || "").trim()
      });

      const saved = await saveSignedResult(result);
      const payload = await buildSignPayload(req, result, saved);

      await cleanupKeychain(path.join(result.workDir, "signing.keychain-db"));
      await fs.rm(result.workDir, { recursive: true, force: true });

      res.json(payload);
    } catch (error) {
      if (result?.workDir) {
        await cleanupKeychain(path.join(result.workDir, "signing.keychain-db"));
        await fs.rm(result.workDir, { recursive: true, force: true });
      }
      res.status(500).json({
        error: error.message.replaceAll(process.cwd(), ".")
      });
    } finally {
      const uploaded = Object.values(req.files || {}).flat();
      await Promise.all(uploaded.map((file) => fs.rm(file.path, { force: true })));
      if (assembledIpa?.path) {
        await fs.rm(assembledIpa.path, { force: true });
      }
      if (isSafeUploadId(uploadId)) {
        await fs.rm(path.join(chunkDir, uploadId), { recursive: true, force: true });
      }
    }
  }
);

app.get("/download/:id", async (req, res) => {
  const metadata = await readSignedMetadata(req.params.id);
  if (!metadata) {
    res.status(404).send("Không tìm thấy IPA đã ký.");
    return;
  }

  const ipaPath = path.join(signedDir, metadata.id, metadata.fileName);
  res.download(ipaPath, metadata.fileName);
});

app.get("/manifest/:id.plist", async (req, res) => {
  const metadata = await readSignedMetadata(req.params.id);
  if (!metadata) {
    res.status(404).send("Không tìm thấy manifest.");
    return;
  }

  const baseUrl = getBaseUrl(req);
  const ipaUrl = `${baseUrl}/download/${metadata.id}`;
  const manifest = buildManifest({
    ipaUrl,
    bundleId: metadata.bundleId,
    bundleVersion: metadata.bundleVersion,
    title: metadata.title
  });

  res.type("application/xml").send(manifest);
});

app.listen(port, () => {
  console.log(`IPA signing tool is running at http://localhost:${port}`);
});
