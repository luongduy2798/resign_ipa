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

    const response = await fetch("/api/sign", {
      method: "POST",
      body: data
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || "Ký IPA thất bại.");
    }

    const payload = await response.json();
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
