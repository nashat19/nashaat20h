const form = document.getElementById("scan-form");
const targetInput = document.getElementById("target");
const typeSelect = document.getElementById("type");
const log = document.getElementById("log");
const counter = document.getElementById("counter");
const history = document.getElementById("history");
const filters = document.getElementById("filters");
const refresh = document.getElementById("refresh");

let activeCategories = new Set();
let total = 0;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function addEntry(data) {
  total += 1;
  counter.textContent = String(total);
  const row = el("div", `entry ${data.severity}`);
  row.append(el("span", "sev", data.severity));
  const body = el("div");
  body.append(el("div", "", data.title));
  if (data.url) {
    const link = el("a", "", data.url);
    link.href = data.url;
    link.target = "_blank";
    link.rel = "noopener";
    body.append(link);
  }
  row.append(body);
  row.append(el("span", "prov", data.provider));
  log.prepend(row);
}

function addNote(text, cls) {
  const row = el("div", `entry ${cls || "info"}`);
  row.append(el("span", "sev", "note"));
  row.append(el("div", "", text));
  row.append(el("span", "prov", ""));
  log.prepend(row);
}

async function loadProviders() {
  const response = await fetch("/api/providers");
  const providers = await response.json();
  const categories = [...new Set(providers.map((p) => p.category))].sort();
  filters.innerHTML = "";
  for (const category of categories) {
    const chip = el("span", "chip", category);
    chip.onclick = () => {
      if (activeCategories.has(category)) {
        activeCategories.delete(category);
        chip.classList.remove("on");
      } else {
        activeCategories.add(category);
        chip.classList.add("on");
      }
    };
    filters.append(chip);
  }
}

async function loadHistory() {
  const response = await fetch("/api/scans?limit=25");
  const scans = await response.json();
  history.innerHTML = "";
  for (const scan of scans) {
    const item = el("div", "item");
    item.append(el("span", "", scan.target));
    const status = el("span", `status ${scan.status}`, scan.status);
    item.append(status);
    item.onclick = () => {
      targetInput.value = scan.target;
      typeSelect.value = scan.target_type;
    };
    history.append(item);
  }
}

function stream(scanId) {
  const source = new EventSource(`/api/stream/${scanId}`);
  source.addEventListener("finding", (event) => addEntry(JSON.parse(event.data)));
  source.addEventListener("provider_skipped", (event) => {
    const data = JSON.parse(event.data);
    addNote(`skipped ${data.provider} — ${data.reason}`, "info");
  });
  source.addEventListener("provider_done", (event) => {
    const data = JSON.parse(event.data);
    if (!data.ok) addNote(`${data.provider} failed — ${data.error}`, "high");
  });
  source.addEventListener("finished", () => {
    source.close();
    addNote("scan finished", "low");
    loadHistory();
  });
  source.onerror = () => source.close();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;
  log.innerHTML = "";
  total = 0;
  counter.textContent = "0";
  addNote(`scanning ${target}`, "low");

  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      type: typeSelect.value,
      categories: [...activeCategories],
    }),
  });
  if (!response.ok) {
    addNote(`error: ${response.status}`, "high");
    return;
  }
  const { id } = await response.json();
  stream(id);
});

refresh.addEventListener("click", loadHistory);

loadProviders();
loadHistory();
