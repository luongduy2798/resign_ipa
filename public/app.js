const form = document.querySelector("#signForm");
const dropZone = document.querySelector("#dropZone");
const ipaInput = document.querySelector("#ipaInput");
const ipaLabel = document.querySelector("#ipaLabel");
const p12Input = document.querySelector("#p12Input");
const provisionInput = document.querySelector("#provisionInput");
const p12Name = document.querySelector("#p12Name");
const provisionName = document.querySelector("#provisionName");
const p12Password = document.querySelector("#p12Password");
const submitButton = document.querySelector("#submitButton");
const buttonText = document.querySelector("#buttonText");
const statusText = document.querySelector("#status");
const resultPanel = document.querySelector("#resultPanel");
const qrImage = document.querySelector("#qrImage");
const resultTitle = document.querySelector("#resultTitle");
const resultMeta = document.querySelector("#resultMeta");
const installLink = document.querySelector("#installLink");
const downloadLink = document.querySelector("#downloadLink");
const otaNote = document.querySelector("#otaNote");

function fileName(input, fallback) {
  return input.files?.[0]?.name || fallback;
}

function setValidity(container, valid) {
  container.classList.toggle("valid", valid);
  container.classList.toggle("invalid", !valid);
}

function refreshState() {
  ipaLabel.textContent = fileName(ipaInput, "Kéo thả file .ipa vào đây hoặc nhấp để chọn file .ipa");
  p12Name.textContent = fileName(p12Input, "Chọn file .p12");
  provisionName.textContent = fileName(provisionInput, "Chọn file .mobileprovision");

  setValidity(document.querySelector('[data-field="p12"]'), Boolean(p12Input.files?.length));
  setValidity(document.querySelector('[data-field="provision"]'), Boolean(provisionInput.files?.length));
  setValidity(p12Password.closest(".text-field"), p12Password.value.length > 0);
}

function setStatus(message, type = "") {
  statusText.textContent = message;
  statusText.className = `status ${type}`.trim();
}

function showResult(payload) {
  resultPanel.hidden = false;
  qrImage.src = payload.qrDataUrl;
  resultTitle.textContent = payload.title || payload.fileName || "IPA đã ký";
  resultMeta.textContent = [payload.bundleId, payload.bundleVersion].filter(Boolean).join(" · ");
  installLink.href = payload.installUrl;
  downloadLink.href = payload.downloadUrl;
  const notes = ["Quét QR bằng Camera hoặc mở link Cài OTA trong Safari trên iPhone."];
  if (payload.localhostUrl) {
    notes.push("Không dùng localhost khi quét từ iPhone; hãy mở tool bằng IP LAN của máy Mac hoặc đặt PUBLIC_BASE_URL.");
  }
  if (payload.httpsRequired) {
    notes.push("OTA trên iPhone thường yêu cầu manifest và IPA qua HTTPS.");
  }
  otaNote.textContent = notes.join(" ");
}

function assignFile(input, file) {
  const transfer = new DataTransfer();
  transfer.items.add(file);
  input.files = transfer.files;
  refreshState();
}

async function parseJsonResponse(response, fallbackMessage) {
  if (response.ok) {
    return response.json();
  }

  const payload = await response.json().catch(() => ({}));
  throw new Error(payload.error || fallbackMessage);
}

async function signDirect(data) {
  const response = await fetch("/api/sign", {
    method: "POST",
    body: data
  });
  return parseJsonResponse(response, "Ký IPA thất bại.");
}

async function signChunked(data) {
  const ipa = ipaInput.files[0];
  const uploadId = crypto.randomUUID();
  const chunkSize = 8 * 1024 * 1024;
  const totalChunks = Math.ceil(ipa.size / chunkSize);

  for (let index = 0; index < totalChunks; index += 1) {
    const start = index * chunkSize;
    const chunk = ipa.slice(start, Math.min(start + chunkSize, ipa.size));
    const chunkData = new FormData();
    chunkData.set("uploadId", uploadId);
    chunkData.set("index", String(index));
    chunkData.set("totalChunks", String(totalChunks));
    chunkData.set("chunk", chunk, `${ipa.name}.part${index}`);

    setStatus(`Đang upload IPA qua Cloudflare: ${index + 1}/${totalChunks}`);
    const response = await fetch("/api/upload-chunk", {
      method: "POST",
      body: chunkData
    });
    await parseJsonResponse(response, "Upload chunk thất bại.");
  }

  const finalData = new FormData();
  finalData.set("uploadId", uploadId);
  finalData.set("totalChunks", String(totalChunks));
  finalData.set("ipaName", ipa.name);
  finalData.set("p12", data.get("p12"));
  finalData.set("provision", data.get("provision"));
  finalData.set("p12Password", data.get("p12Password") || "");
  finalData.set("removeEmbedded", data.get("removeEmbedded") || "false");
  finalData.set("bundleId", data.get("bundleId") || "");
  finalData.set("bundleName", data.get("bundleName") || "");

  setStatus("Đang ghép file và ký IPA.");
  const response = await fetch("/api/sign-chunked", {
    method: "POST",
    body: finalData
  });
  return parseJsonResponse(response, "Ký IPA thất bại.");
}

function isCloudflareAccess() {
  return (
    location.protocol === "https:" &&
    (location.hostname.endsWith(".trycloudflare.com") || location.hostname === "macmini.chillix.me")
  );
}

document.querySelectorAll("[data-target]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelector(`#${button.dataset.target}`).click();
  });
});

[ipaInput, p12Input, provisionInput, p12Password].forEach((field) => {
  field.addEventListener("change", refreshState);
  field.addEventListener("input", refreshState);
});

dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("dragging");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragging");
});

dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
  const file = [...event.dataTransfer.files].find((item) => item.name.toLowerCase().endsWith(".ipa"));
  if (file) {
    assignFile(ipaInput, file);
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  refreshState();

  if (!ipaInput.files.length || !p12Input.files.length || !provisionInput.files.length) {
    setStatus("Cần chọn đủ file .ipa, .p12 và .mobileprovision.", "error");
    return;
  }

  submitButton.disabled = true;
  buttonText.textContent = "Đang ký...";
  resultPanel.hidden = true;
  setStatus("Đang xử lý. File IPA lớn có thể mất vài phút.");

  try {
    const data = new FormData(form);
    data.set("removeEmbedded", document.querySelector("#removeEmbedded").checked ? "true" : "false");

    const shouldChunk = isCloudflareAccess() && ipaInput.files[0].size > 50 * 1024 * 1024;
    const payload = shouldChunk ? await signChunked(data) : await signDirect(data);
    showResult(payload);
    setStatus("Ký IPA xong. Quét QR bằng iPhone để cài OTA.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    submitButton.disabled = false;
    buttonText.textContent = "Sign";
  }
});

refreshState();
