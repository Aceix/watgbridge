let token = "";
let csrfToken = "";
let currentChatId = "";
let latestID = 0;
const MESSAGE_PAGE_LIMIT = 50;
const UPDATE_PAGE_LIMIT = 100;

const tg = window.Telegram?.WebApp;
if (tg) {
  tg.ready();
  tg.expand();
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (csrfToken && (options.method === "POST" || options.method === "DELETE")) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "request failed");
  }
  return data;
}

async function login() {
  const initData = tg?.initData || "";
  const result = await api("/miniapp/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ init_data: initData }),
  });
  token = result.token;
  csrfToken = result.csrf_token;
}

async function loadChats() {
  const data = await api("/miniapp/api/chats");
  const list = document.getElementById("chatList");
  list.innerHTML = "";
  for (const chat of data.chats) {
    const li = document.createElement("li");
    li.textContent = chat.name;
    li.onclick = async () => {
      currentChatId = chat.wa_chat_id;
      document.querySelectorAll("#chatList li").forEach((node) => node.classList.remove("active"));
      li.classList.add("active");
      document.getElementById("chatTitle").textContent = chat.name;
      await loadMessages();
    };
    list.appendChild(li);
  }
}

async function loadMessages() {
  if (!currentChatId) return;
  const data = await api(`/miniapp/api/messages?chat_id=${encodeURIComponent(currentChatId)}&limit=${MESSAGE_PAGE_LIMIT}`);
  const list = document.getElementById("messageList");
  list.innerHTML = "";
  const messages = [...data.messages].reverse();
  for (const msg of messages) {
    const div = document.createElement("div");
    div.className = `msg ${msg.direction === "out" ? "out" : "in"}`;
    div.textContent = `${msg.sender_name || "Unknown"}: ${msg.text || ""}`;
    list.appendChild(div);
    latestID = Math.max(latestID, msg.id || 0);
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (!currentChatId) return;
  const input = document.getElementById("messageInput");
  const text = input.value.trim();
  if (!text) return;
  await api("/miniapp/api/messages/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ wa_chat_id: currentChatId, text }),
  });
  input.value = "";
  await loadMessages();
}

async function uploadMedia(event) {
  event.preventDefault();
  if (!currentChatId) return;
  const fileInput = document.getElementById("fileInput");
  if (!fileInput.files.length) return;
  const caption = document.getElementById("captionInput").value;
  const formData = new FormData();
  formData.set("wa_chat_id", currentChatId);
  formData.set("caption", caption);
  formData.set("file", fileInput.files[0]);
  await api("/miniapp/api/messages/upload", {
    method: "POST",
    body: formData,
  });
  fileInput.value = "";
  document.getElementById("captionInput").value = "";
  await loadMessages();
}

async function pollUpdates() {
  if (!currentChatId || !latestID) return;
  const data = await api(`/miniapp/api/updates?since=${latestID}&limit=${UPDATE_PAGE_LIMIT}`);
  latestID = data.latest_id || latestID;
  if ((data.messages || []).some((m) => m.wa_chat_id === currentChatId)) {
    await loadMessages();
  }
}

async function boot() {
  await login();
  await loadChats();
  document.getElementById("sendForm").addEventListener("submit", sendMessage);
  document.getElementById("uploadForm").addEventListener("submit", uploadMedia);
  document.getElementById("refreshBtn").addEventListener("click", async () => {
    await loadChats();
    await loadMessages();
  });
  setInterval(pollUpdates, 5000);
}

boot().catch((err) => {
  alert(err.message);
});
