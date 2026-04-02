// ── State ──
let ws = null;
let eventCount = 0;
let feedCount = 0;
let currentFilter = "all";
const credentials = new Map();
const sessions = new Map();
const attackers = new Map();
const markers = new Map();

// ── Map ──
const map = L.map("map", {
  center: [30, 0],
  zoom: 2,
  zoomControl: false,
  attributionControl: false,
});

L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
  maxZoom: 18,
}).addTo(map);

// ── Helpers ──
function esc(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatTime(ts) {
  if (!ts) return "--";
  return new Date(ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function timeAgo(ts) {
  if (!ts) return "--";
  const diff = (Date.now() - new Date(ts).getTime()) / 1000;
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatDuration(sec) {
  if (!sec && sec !== 0) return "";
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}m ${s}s`;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.") || ip === "127.0.0.1";
}

// Unique key for dedup: must match eventid + ip + specific payload
function eventFingerprint(e) {
  let fp = `${e.eventid}|${e.src_ip}`;
  if (e.username) fp += `|${e.username}:${e.password}`;
  if (e.input) fp += `|${e.input}`;
  if (e.version) fp += `|${e.version}`;
  return fp;
}

// ── WebSocket ──
function connectWs() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${protocol}//${location.host}/ws`);

  ws.onopen = () => {
    const el = document.getElementById("wsStatus");
    el.classList.add("connected");
    el.querySelector(".ws-label").textContent = "Connected";
  };

  ws.onclose = () => {
    const el = document.getElementById("wsStatus");
    el.classList.remove("connected");
    el.querySelector(".ws-label").textContent = "Reconnecting...";
    setTimeout(connectWs, 3000);
  };

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    switch (msg.type) {
      case "event": handleEvent(msg.data); break;
      case "stats": updateStats(msg.data); break;
      case "attacker_update": updateAttacker(msg.data); break;
    }
  };
}

// ── Event Handling ──
function handleEvent(event) {
  eventCount++;
  document.getElementById("lastEventTime").textContent = timeAgo(event.timestamp);

  processEventForSession(event);
  addToFeed(event);

  if (event.eventid === "cowrie.login.failed" || event.eventid === "cowrie.login.success") {
    const key = `${event.username}:${event.password}`;
    credentials.set(key, (credentials.get(key) || 0) + 1);
    renderCredentials();
  }

  renderSessions();

  if (event._geo && event._geo.lat !== 0 && !isPrivateIp(event.src_ip)) {
    addMapMarker(event.src_ip, event._geo);
  }
}

function processEventForSession(event) {
  if (!event.session) return;

  if (!sessions.has(event.session)) {
    sessions.set(event.session, {
      ip: event.src_ip,
      time: event.timestamp,
      loginSuccess: false,
      loginAttempts: [],
      commands: [],
      clientVersion: null,
      duration: null,
      geo: null,
    });
  }

  const s = sessions.get(event.session);

  if (event.eventid === "cowrie.login.failed") {
    s.loginAttempts.push({ user: event.username, pass: event.password, success: false });
  } else if (event.eventid === "cowrie.login.success") {
    s.loginAttempts.push({ user: event.username, pass: event.password, success: true });
    s.loginSuccess = true;
  } else if (event.eventid === "cowrie.command.input" || event.eventid === "cowrie.command.failed") {
    s.commands.push(event.input);
  } else if (event.eventid === "cowrie.client.version") {
    s.clientVersion = event.version;
  } else if (event.eventid === "cowrie.session.closed") {
    s.duration = event.duration;
  }

  if (event._geo && event._geo.lat !== 0 && !isPrivateIp(event.src_ip)) {
    s.geo = event._geo;
  }
}

// ── Feed ──
// Skip these entirely (pure noise, no useful info)
const FEED_SKIP = new Set([
  "cowrie.client.kex",
  "cowrie.session.params",
  "cowrie.client.var",
  "cowrie.log.closed",
  "cowrie.client.size",
  "cowrie.session.file_upload",
  "cowrie.direct-tcpip.request",
  "cowrie.direct-tcpip.data",
]);

// Last event tracking for dedup
let _prevFP = null;
let _prevCount = 1;
let _prevEl = null;

function addToFeed(event) {
  if (FEED_SKIP.has(event.eventid)) return;

  const feed = document.getElementById("liveFeed");
  if (feed.querySelector(".feed-empty")) feed.innerHTML = "";

  const fp = eventFingerprint(event);

  // Dedup only truly identical events (same type + ip + payload)
  if (_prevFP === fp) {
    _prevCount++;
    if (_prevEl) {
      let badge = _prevEl.querySelector(".ev-repeat");
      if (!badge) {
        badge = document.createElement("span");
        badge.className = "ev-repeat";
        _prevEl.querySelector(".ev-head").appendChild(badge);
      }
      badge.textContent = `x${_prevCount}`;
    }
    return;
  }

  _prevFP = fp;
  _prevCount = 1;
  feedCount++;

  const div = document.createElement("div");
  div.className = "ev";
  div.dataset.cat = getEventCategory(event.eventid);
  div.dataset.severity = getEventSeverity(event);

  if (currentFilter !== "all" && div.dataset.cat !== currentFilter) {
    div.classList.add("hidden");
  }

  const time = formatTime(event.timestamp);
  const { tag, tagClass } = getEventTag(event.eventid);
  const detail = formatEventDetail(event);

  // Only show geo for public IPs, skip "LAN, Local" noise
  const showGeo = event._geo && event._geo.city && !isPrivateIp(event.src_ip);
  const geoText = showGeo ? `${event._geo.city}, ${event._geo.country}` : "";

  div.innerHTML = `
    <div class="ev-time">${time}</div>
    <div class="ev-body">
      <div class="ev-head">
        <span class="ev-tag ${tagClass}">${tag}</span>
        ${event.src_ip ? `<span class="ev-ip">${esc(event.src_ip)}</span>` : ""}
        ${geoText ? `<span class="ev-geo">${esc(geoText)}</span>` : ""}
      </div>
      ${detail ? `<div class="ev-detail">${detail}</div>` : ""}
    </div>
  `;

  _prevEl = div;
  feed.insertBefore(div, feed.firstChild);

  document.getElementById("eventCount").textContent = feedCount;

  while (feed.children.length > 200) {
    feed.removeChild(feed.lastChild);
  }
}

function getEventCategory(eventid) {
  if (eventid.includes("login")) return "auth";
  if (eventid.includes("command")) return "cmd";
  if (eventid.includes("download")) return "cmd";
  if (eventid.includes("session") || eventid.includes("client")) return "conn";
  return "conn";
}

function getEventSeverity(event) {
  if (event.eventid === "cowrie.login.success") return "critical";
  if (event.eventid === "cowrie.session.file_download") return "critical";
  if (event.eventid === "cowrie.login.failed") return "warning";
  if (event.eventid === "cowrie.command.input") return "info";
  if (event.eventid === "cowrie.session.connect") return "info";
  return "low";
}

function getEventTag(eventid) {
  const tags = {
    "cowrie.login.failed":         { tag: "AUTH FAIL", tagClass: "auth-fail" },
    "cowrie.login.success":        { tag: "AUTH OK",   tagClass: "auth-ok" },
    "cowrie.command.input":        { tag: "COMMAND",   tagClass: "cmd" },
    "cowrie.command.failed":       { tag: "CMD FAIL",  tagClass: "cmd" },
    "cowrie.session.connect":      { tag: "CONNECT",   tagClass: "connect" },
    "cowrie.session.closed":       { tag: "CLOSED",    tagClass: "disconnect" },
    "cowrie.session.file_download":{ tag: "DOWNLOAD",  tagClass: "download" },
    "cowrie.client.version":       { tag: "CLIENT",    tagClass: "client" },
  };
  return tags[eventid] || { tag: eventid.split(".").pop().toUpperCase(), tagClass: "client" };
}

function formatEventDetail(event) {
  switch (event.eventid) {
    case "cowrie.login.failed":
      return `Tried <code>${esc(event.username)}</code> : <code>${esc(event.password)}</code>`;
    case "cowrie.login.success":
      return `Logged in as <code>${esc(event.username)}</code> : <code>${esc(event.password)}</code>`;
    case "cowrie.command.input":
    case "cowrie.command.failed":
      return `<span class="ev-cmd">${esc(event.input)}</span>`;
    case "cowrie.session.connect":
      return null; // no extra detail needed, tag + IP is enough
    case "cowrie.session.closed":
      return event.duration ? `Session: ${formatDuration(event.duration)}` : null;
    case "cowrie.session.file_download":
      return `<code>${esc(event.url)}</code>`;
    case "cowrie.client.version":
      return `<code>${esc(event.version)}</code>`;
    default:
      return event.message ? esc(event.message) : null;
  }
}

function setFilter(filter) {
  currentFilter = filter;
  document.querySelectorAll(".fbtn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.filter === filter);
  });
  document.querySelectorAll(".ev").forEach(ev => {
    ev.classList.toggle("hidden", filter !== "all" && ev.dataset.cat !== filter);
  });
}

// ── Stats ──
function updateStats(stats) {
  document.getElementById("statConnections").textContent = stats.totalConnections;
  document.getElementById("statUniqueIps").textContent = stats.uniqueIps;
  document.getElementById("statCredentials").textContent = stats.credentialsCaptured;
  document.getElementById("statSessions").textContent = stats.sessionsCount;
  document.getElementById("statCommands").textContent = stats.commandsExecuted;
  document.getElementById("statDownloads").textContent = stats.filesDownloaded;
}

// ── Credentials ──
function renderCredentials() {
  const container = document.getElementById("credList");
  const sorted = [...credentials.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);

  if (sorted.length === 0) {
    container.innerHTML = '<div class="empty-hint">Waiting for login attempts...</div>';
    return;
  }

  const maxCount = sorted[0][1];
  document.getElementById("credCount").textContent = `${credentials.size} pairs`;

  container.innerHTML = sorted.map(([key, count]) => {
    const idx = key.indexOf(":");
    const user = key.substring(0, idx);
    const pass = key.substring(idx + 1);
    const pct = Math.max(5, (count / maxCount) * 100);

    return `<div class="cred-row">
      <div class="cred-pair">
        <span class="cred-user">${esc(user)}</span>
        <span class="cred-sep">:</span>
        <span class="cred-pass">${esc(pass)}</span>
      </div>
      <span class="cred-count">${count}</span>
      <div class="cred-bar-wrap"><div class="cred-bar" style="width:${pct}%"></div></div>
    </div>`;
  }).join("");
}

// ── Sessions ──
function renderSessions() {
  const container = document.getElementById("sessionsList");
  const sorted = [...sessions.entries()].reverse().slice(0, 50);

  document.getElementById("sessionCount").textContent = sessions.size;

  if (sorted.length === 0) {
    container.innerHTML = '<div class="empty-hint">No sessions recorded yet</div>';
    return;
  }

  container.innerHTML = sorted.map(([id, s]) => {
    const badgeClass = s.loginSuccess ? "authed" : "rejected";
    const badgeText = s.loginSuccess ? "authenticated" : "rejected";
    const time = formatTime(s.time);
    const durationText = s.duration ? formatDuration(s.duration) : "";

    // Only show geo for public IPs
    const geoText = (s.geo && !isPrivateIp(s.ip))
      ? `${s.geo.city || ""}, ${s.geo.country || ""}`.replace(/^, /, "")
      : "";

    const attemptCount = s.loginAttempts.length;
    const cmdCount = s.commands.length;

    // Build timeline for expanded view
    let timeline = "";
    if (s.clientVersion) {
      timeline += `<div class="sess-tl"><span class="sess-tl-icon info">~</span><span class="sess-tl-text">${esc(s.clientVersion)}</span></div>`;
    }
    for (const a of s.loginAttempts) {
      const icon = a.success
        ? '<span class="sess-tl-icon ok">+</span>'
        : '<span class="sess-tl-icon fail">x</span>';
      timeline += `<div class="sess-tl">${icon}<span class="sess-tl-text"><span class="hl-user">${esc(a.user)}</span> : <span class="hl-pass">${esc(a.pass)}</span>${a.success ? " - success" : ""}</span></div>`;
    }
    for (const c of s.commands) {
      timeline += `<div class="sess-tl"><span class="sess-tl-icon cmd">$</span><span class="sess-tl-text"><span class="hl-cmd">${esc(c)}</span></span></div>`;
    }
    if (s.duration != null) {
      timeline += `<div class="sess-tl"><span class="sess-tl-icon info">-</span><span class="sess-tl-text">Disconnected after ${formatDuration(s.duration)}</span></div>`;
    }

    return `<div class="sess" onclick="this.classList.toggle('expanded')">
      <div class="sess-top">
        <span class="sess-ip">${esc(s.ip)}</span>
        <span class="sess-badge ${badgeClass}">${badgeText}</span>
        ${geoText ? `<span class="sess-geo">${esc(geoText)}</span>` : ""}
        <span class="sess-time">${time}</span>
      </div>
      <div class="sess-summary">
        <span>${attemptCount} attempt${attemptCount !== 1 ? "s" : ""}</span>
        <span>${cmdCount} cmd${cmdCount !== 1 ? "s" : ""}</span>
        ${durationText ? `<span>${durationText}</span>` : ""}
      </div>
      ${timeline ? `<div class="sess-detail">${timeline}</div>` : ""}
    </div>`;
  }).join("");
}

// ── Attackers ──
function updateAttacker(data) {
  // Remove any temp placeholder with matching attackType when real data arrives
  for (const [k, v] of attackers) {
    if (v._temp && v.attackType === data.attackType) {
      attackers.delete(k);
      break;
    }
  }

  if (data.status === "destroying") {
    attackers.delete(data.vmid);
  } else {
    attackers.set(data.vmid, data);
  }
  renderAttackers();
}

function getRunningMessage(type) {
  return {
    scan: "Scanning ports with nmap...",
    bruteforce: "Spraying SSH credentials...",
    manual: "Container idle - 30 min session",
    infiltration: "Logging in & running commands...",
    sshflood: "Sending mass TCP connections...",
    credstuffing: "Exhausting 1800+ credential combos...",
  }[type] || "Attack in progress";
}

function renderAttackers() {
  const container = document.getElementById("attackersList");

  if (attackers.size === 0) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = [...attackers.values()].map(a => {
    const elapsed = a.createdAt ? timeAgo(a.createdAt) : "";
    const typeLabel = { scan: "Port Scan", bruteforce: "Brute Force", manual: "Manual Shell", infiltration: "Infiltration", sshflood: "SSH Flood", credstuffing: "Cred Stuffing" }[a.attackType] || a.attackType;
    const statusMsg = {
      creating: "Cloning template & starting container...",
      running: getRunningMessage(a.attackType),
      finished: "Completed - auto-destroying soon",
      destroying: "Destroying container...",
    }[a.status] || a.status;

    const steps = [];
    if (a.status === "creating") {
      steps.push({ cls: "step-done", text: "Clone" });
      steps.push({ cls: "step-active", text: "Setup" });
      steps.push({ cls: "step-pending", text: "Start" });
      steps.push({ cls: "step-pending", text: "Attack" });
    } else if (a.status === "running") {
      steps.push({ cls: "step-done", text: "Clone" });
      steps.push({ cls: "step-done", text: "Setup" });
      steps.push({ cls: "step-done", text: "Start" });
      steps.push({ cls: "step-active", text: "Attack" });
    } else if (a.status === "finished") {
      steps.push({ cls: "step-done", text: "Clone" });
      steps.push({ cls: "step-done", text: "Setup" });
      steps.push({ cls: "step-done", text: "Start" });
      steps.push({ cls: "step-done", text: "Done" });
    } else {
      steps.push({ cls: "step-done", text: "Clone" });
      steps.push({ cls: "step-done", text: "Setup" });
      steps.push({ cls: "step-done", text: "Start" });
      steps.push({ cls: "step-done", text: "Done" });
    }

    const stepsHtml = steps.map(s =>
      `<div class="atk-step ${s.cls}">${s.text}</div>`
    ).join("");

    return `<div class="atk-card" data-type="${esc(a.attackType)}">
      <div class="atk-card-head">
        <span class="atk-dot ${a.status}"></span>
        <span class="atk-card-type">${typeLabel}</span>
        <span class="atk-card-elapsed">${elapsed}</span>
        <button class="atk-kill" onclick="event.stopPropagation(); destroyAttacker(${a.vmid})">kill</button>
      </div>
      <div class="atk-card-info">
        <span class="atk-card-name">${esc(a.name)}</span>
        ${a.ip ? `<span class="atk-card-ip">${a.ip}</span>` : ""}
      </div>
      <div class="atk-card-status">${statusMsg}</div>
      <div class="atk-steps">${stepsHtml}</div>
    </div>`;
  }).join("");
}

// Refresh elapsed times
setInterval(() => {
  if (attackers.size > 0) renderAttackers();
}, 5000);

// ── Attack Launcher ──
async function launchAttack(type) {
  const btn = event.target.closest(".sim-btn");
  btn.disabled = true;
  btn.classList.add("launching");

  // Show immediate placeholder
  const tempId = Date.now();
  attackers.set(tempId, {
    vmid: tempId,
    name: `atk-${type}-...`,
    attackType: type,
    status: "creating",
    createdAt: new Date().toISOString(),
    ip: "",
    _temp: true,
  });
  renderAttackers();

  try {
    const res = await fetch(`/api/attack/${type}`, { method: "POST" });
    const data = await res.json();

    if (data.error) {
      attackers.delete(tempId);
      renderAttackers();
      alert("Error: " + data.error);
    } else {
      // Replace temp with real data
      attackers.delete(tempId);
      attackers.set(data.vmid, data);
      renderAttackers();
    }
  } catch (err) {
    attackers.delete(tempId);
    renderAttackers();
    alert("Failed to launch: " + err.message);
  } finally {
    btn.classList.remove("launching");
    setTimeout(() => { btn.disabled = false; }, 3000);
  }
}

async function destroyAttacker(vmid) {
  try {
    await fetch(`/api/attack/${vmid}`, { method: "DELETE" });
  } catch (err) {
    alert("Failed to destroy: " + err.message);
  }
}

// ── Map ──
function addMapMarker(ip, geo) {
  if (isPrivateIp(ip)) return;

  if (markers.has(ip)) {
    const m = markers.get(ip);
    m.count++;
    m.marker.setRadius(Math.min(5 + m.count * 2, 25));
    m.marker.bindPopup(`<b>${ip}</b><br>${geo.city || "?"}, ${geo.country || "?"}<br>${m.count} events`);
    return;
  }

  const marker = L.circleMarker([geo.lat, geo.lon], {
    radius: 5,
    fillColor: "#f59e0b",
    color: "#f59e0b",
    weight: 1.5,
    opacity: 0.9,
    fillOpacity: 0.4,
  }).addTo(map);

  marker.bindPopup(`<b>${ip}</b><br>${geo.city || "?"}, ${geo.country || "?"}<br>${geo.isp || ""}`);
  markers.set(ip, { marker, count: 1 });

  document.getElementById("geoCount").textContent = `${markers.size} source${markers.size !== 1 ? "s" : ""}`;
}

// ── Initial Data ──
async function loadInitialData() {
  try {
    const [events, creds, sessionData, stats, atkData] = await Promise.all([
      fetch("/api/events").then(r => r.json()),
      fetch("/api/credentials").then(r => r.json()),
      fetch("/api/sessions").then(r => r.json()),
      fetch("/api/stats").then(r => r.json()),
      fetch("/api/attackers").then(r => r.json()),
    ]);

    updateStats(stats);

    // Seed sessions from API
    sessionData.forEach(s => {
      sessions.set(s.session, {
        ip: s.src_ip,
        time: s.startTime,
        loginSuccess: s.loginSuccess > 0,
        loginAttempts: [],
        commands: [],
        clientVersion: null,
        duration: null,
        geo: null,
      });
    });

    // Process events oldest-first to fill sessions + feed
    const oldest = [...events].reverse();
    oldest.forEach(e => {
      eventCount++;
      processEventForSession(e);
      addToFeed(e);
    });

    if (events.length > 0) {
      document.getElementById("lastEventTime").textContent = timeAgo(events[0].timestamp);
    }

    // Credentials from API (authoritative counts)
    creds.forEach(c => {
      credentials.set(`${c.username}:${c.password}`, c.count);
    });
    renderCredentials();
    renderSessions();

    // Active attackers (persist across refresh)
    atkData.forEach(a => attackers.set(a.vmid, a));
    renderAttackers();

    // Geo markers
    const geoData = await fetch("/api/geo").then(r => r.json());
    geoData.forEach(g => {
      if (g.lat && g.lon && !isPrivateIp(g.ip)) {
        addMapMarker(g.ip, { lat: g.lat, lon: g.lon, country: g.country, city: g.city, isp: "" });
        const m = markers.get(g.ip);
        if (m) m.count = g.count;
      }
    });
  } catch (err) {
    console.error("Failed to load initial data:", err);
  }
}

// ── Reset ──
let _resetPending = false;
async function resetAll() {
  const btn = document.querySelector(".reset-btn");
  if (!_resetPending) {
    _resetPending = true;
    btn.textContent = "Confirm?";
    btn.classList.add("confirming");
    setTimeout(() => {
      if (_resetPending) {
        _resetPending = false;
        btn.textContent = "Clear data";
        btn.classList.remove("confirming");
      }
    }, 3000);
    return;
  }

  _resetPending = false;
  btn.textContent = "Resetting...";
  btn.disabled = true;

  try {
    await fetch("/api/reset", { method: "POST" });

    // Clear client state
    eventCount = 0;
    feedCount = 0;
    _prevFP = null;
    _prevCount = 1;
    _prevEl = null;
    credentials.clear();
    sessions.clear();
    markers.forEach(m => map.removeLayer(m.marker));
    markers.clear();

    // Reset UI
    document.getElementById("liveFeed").innerHTML = `
      <div class="feed-empty">
        <span>No events yet</span>
        <span class="feed-empty-hint">Simulate an attack to start monitoring</span>
      </div>`;
    document.getElementById("credList").innerHTML = '<div class="empty-hint">Waiting for login attempts...</div>';
    document.getElementById("sessionsList").innerHTML = '<div class="empty-hint">No sessions recorded yet</div>';
    document.getElementById("eventCount").textContent = "0";
    document.getElementById("credCount").textContent = "0";
    document.getElementById("sessionCount").textContent = "0";
    document.getElementById("geoCount").textContent = "0 sources";
    document.getElementById("lastEventTime").textContent = "--";

    // Zero all stat cards
    updateStats({ totalConnections: 0, uniqueIps: 0, credentialsCaptured: 0, sessionsCount: 0, commandsExecuted: 0, filesDownloaded: 0 });
  } catch (err) {
    alert("Reset failed: " + err.message);
  } finally {
    btn.textContent = "Clear data";
    btn.classList.remove("confirming");
    btn.disabled = false;
  }
}

// ── Init ──
loadInitialData().then(() => connectWs());
