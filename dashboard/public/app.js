// ── State ──
let ws = null;
let eventCount = 0;
let feedCount = 0;
let currentFilter = "all";
let currentSvcFilter = null;
let currentView = "monitor";
const credentials = new Map();
const sessions = new Map();
const attackers = new Map();
const markers = new Map();
const narrativeWindow = []; // { event, ts } for last 2 minutes

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
      case "terminal-output": handleTerminalOutput(msg.data); break;
    }
  };
}

// ── Event Handling ──
function handleEvent(event) {
  eventCount++;
  document.getElementById("lastEventTime").textContent = timeAgo(event.timestamp);

  processEventForSession(event);
  addToFeed(event);
  updateNarrative(event);

  if (event.eventid && event.eventid.includes("login") && event.username) {
    const key = `${event.username}:${event.password || ""}`;
    credentials.set(key, (credentials.get(key) || 0) + 1);
    renderCredentials();
  }

  renderSessions();

  if (event._geo && event._geo.lat !== 0) {
    addMapMarker(event.src_ip, event._geo);
  }
}

function processEventForSession(event) {
  if (!event.session) return;

  if (!sessions.has(event.session)) {
    sessions.set(event.session, {
      ip: event.src_ip,
      time: event.timestamp,
      service: event._service || "ssh",
      loginSuccess: false,
      loginAttempts: [],
      commands: [],
      clientVersion: null,
      duration: null,
      geo: null,
    });
  }

  const s = sessions.get(event.session);
  if (event._service) s.service = event._service;

  const eid = event.eventid || "";
  if (eid.includes("login.failed") || eid.includes("login.attempt")) {
    if (event.username) s.loginAttempts.push({ user: event.username, pass: event.password || "", success: false });
  } else if (eid.includes("login.success")) {
    if (event.username) s.loginAttempts.push({ user: event.username, pass: event.password || "", success: true });
    s.loginSuccess = true;
  } else if (eid.includes("command.input") || eid.includes("command.failed")) {
    if (event.input) s.commands.push(event.input);
  } else if (eid === "cowrie.client.version") {
    s.clientVersion = event.version;
  } else if (eid.includes("session.closed")) {
    s.duration = event.duration;
  }

  if (event._geo && event._geo.lat !== 0) {
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

  const svc = event._service || "ssh";
  const div = document.createElement("div");
  div.className = "ev";
  div.dataset.cat = getEventCategory(event.eventid);
  div.dataset.svc = svc;
  div.dataset.severity = getEventSeverity(event);

  const catHidden = currentFilter !== "all" && div.dataset.cat !== currentFilter;
  const svcHidden = currentSvcFilter && div.dataset.svc !== currentSvcFilter;
  if (catHidden || svcHidden) div.classList.add("hidden");

  const time = formatTime(event.timestamp);
  const { tag, tagClass } = getEventTag(event.eventid);
  const detail = formatEventDetail(event);

  // Show geo if available (skip LAN/Local placeholder)
  const showGeo = event._geo && event._geo.city && event._geo.city !== "LAN";
  const geoText = showGeo ? `${event._geo.city}, ${event._geo.country}` : "";

  const svcBadge = svc !== "ssh" ? `<span class="ev-svc ev-svc--${svc}">${svc.toUpperCase()}</span>` : "";

  div.innerHTML = `
    <div class="ev-time">${time}</div>
    <div class="ev-body">
      <div class="ev-head">
        ${svcBadge}
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
  if (!eventid) return "conn";
  if (eventid.includes("login")) return "auth";
  if (eventid.includes("command") || eventid.includes("probe")) return "cmd";
  if (eventid.includes("download") || eventid.includes("file")) return "cmd";
  if (eventid.includes("xmlrpc")) return "cmd";
  if (eventid.includes("session") || eventid.includes("client") || eventid.includes("negotiate")) return "conn";
  if (eventid.includes("request") || eventid.includes("share")) return "cmd";
  return "conn";
}

function getEventSeverity(event) {
  const eid = event.eventid || "";
  if (eid.includes("login.success")) return "critical";
  if (eid.includes("file_download") || eid.includes("file.download")) return "critical";
  if (eid.includes("login.failed") || eid.includes("login.attempt")) return "warning";
  if (eid.includes("probe")) return "warning";
  if (eid.includes("command") || eid.includes("request")) return "info";
  if (eid.includes("session.connect")) return "info";
  return "low";
}

function getEventTag(eventid) {
  const tags = {
    "cowrie.login.failed":         { tag: "Failed Login",     tagClass: "auth-fail" },
    "cowrie.login.success":        { tag: "Login Success",    tagClass: "auth-ok" },
    "cowrie.command.input":        { tag: "Command",          tagClass: "cmd" },
    "cowrie.command.failed":       { tag: "Bad Command",      tagClass: "cmd" },
    "cowrie.session.connect":      { tag: "Connected",        tagClass: "connect" },
    "cowrie.session.closed":       { tag: "Disconnected",     tagClass: "disconnect" },
    "cowrie.session.file_download":{ tag: "File Stolen",      tagClass: "download" },
    "cowrie.client.version":       { tag: "Fingerprint",      tagClass: "client" },
    // HTTP
    "http.login.attempt":          { tag: "Login Attempt",    tagClass: "auth-fail" },
    "http.request":                { tag: "Web Request",      tagClass: "client" },
    "http.probe":                  { tag: "Scanning",         tagClass: "cmd" },
    "http.xmlrpc":                 { tag: "API Attack",       tagClass: "cmd" },
    // FTP
    "ftp.login.attempt":           { tag: "Login Attempt",    tagClass: "auth-fail" },
    "ftp.login.success":           { tag: "Login Success",    tagClass: "auth-ok" },
    "ftp.login.failed":            { tag: "Failed Login",     tagClass: "auth-fail" },
    "ftp.session.connect":         { tag: "Connected",        tagClass: "connect" },
    "ftp.session.closed":          { tag: "Disconnected",     tagClass: "disconnect" },
    "ftp.file.download":           { tag: "File Stolen",      tagClass: "download" },
    "ftp.file.upload":             { tag: "File Uploaded",    tagClass: "download" },
    "ftp.command.input":           { tag: "Command",          tagClass: "cmd" },
    // SMB
    "smb.login.attempt":           { tag: "Login Attempt",    tagClass: "auth-fail" },
    "smb.session.connect":         { tag: "Connected",        tagClass: "connect" },
    "smb.session.closed":          { tag: "Disconnected",     tagClass: "disconnect" },
    "smb.negotiate":               { tag: "Handshake",        tagClass: "client" },
    "smb.share.enum":              { tag: "Share Scan",       tagClass: "cmd" },
    "smb.share.access":            { tag: "Share Access",     tagClass: "download" },
  };
  return tags[eventid] || { tag: (eventid || "UNKNOWN").split(".").pop().toUpperCase(), tagClass: "client" };
}

// Context for common probed paths
const PROBE_CONTEXT = {
  "/.env": "server configuration secrets",
  "/wp-config.php": "WordPress database credentials",
  "/wp-config.php.bak": "WordPress config backup",
  "/phpmyadmin": "database admin panel (phpMyAdmin)",
  "/wp-admin": "WordPress admin dashboard",
  "/.git": "source code repository",
  "/.git/config": "Git repository config",
  "/backup": "server backup files",
  "/wp-content/debug.log": "WordPress error logs",
  "/xmlrpc.php": "WordPress remote API",
  "/readme.html": "WordPress version info",
  "/license.txt": "WordPress version info",
  "/wp-json": "WordPress REST API",
  "/wp-cron.php": "WordPress scheduled tasks",
  "/wp-includes": "WordPress core files",
};

// Context for common attacker commands
const CMD_CONTEXT = {
  "cat /etc/passwd": "reading system user list",
  "cat /etc/shadow": "stealing password hashes",
  "uname -a": "identifying the OS version",
  "id": "checking user privileges",
  "whoami": "checking current user",
  "pwd": "checking current directory",
  "ls": "listing directory contents",
  "ifconfig": "checking network config",
  "ip addr": "checking network interfaces",
  "netstat": "listing open network ports",
  "ps aux": "listing running processes",
  "w": "checking who is logged in",
  "last": "checking login history",
  "history": "reading command history",
  "crontab": "checking scheduled tasks",
};

function formatEventDetail(event) {
  const eid = event.eventid || "";

  // Login events (all protocols)
  if (eid.includes("login.failed") || eid.includes("login.attempt")) {
    if (event.username) {
      const domain = event.domain ? `${esc(event.domain)}\\` : "";
      return `Tried to log in as <code>${domain}${esc(event.username)}</code> with password <code>${esc(event.password || "(empty)")}</code>`;
    }
    return event.message ? esc(event.message) : null;
  }
  if (eid.includes("login.success")) {
    if (event.username) return `Successfully logged in as <code>${esc(event.username)}</code> with password <code>${esc(event.password || "")}</code>`;
    return event.message ? esc(event.message) : null;
  }

  // Commands - add context for known commands
  if (eid.includes("command.input") || eid.includes("command.failed")) {
    if (!event.input) return null;
    const input = event.input.trim();
    const cmdBase = input.split(" ")[0].split("/").pop();
    let context = CMD_CONTEXT[input];
    if (!context) {
      for (const [pattern, desc] of Object.entries(CMD_CONTEXT)) {
        if (input.startsWith(pattern)) { context = desc; break; }
      }
    }
    if (!context && (input.startsWith("wget ") || input.startsWith("curl "))) context = "downloading a file from the internet";
    if (!context && input.startsWith("chmod ")) context = "changing file permissions";
    if (!context && input.startsWith("rm ")) context = "deleting files";
    if (!context && input.startsWith("cd ")) context = "navigating directories";
    const contextHtml = context ? `<span class="ev-cmd-context">${esc(context)}</span>` : "";
    return `<span class="ev-cmd">${esc(input)}</span>${contextHtml}`;
  }

  // Session events
  if (eid.includes("session.connect")) return null;
  if (eid.includes("session.closed")) return event.duration ? `Session lasted ${formatDuration(event.duration)}` : null;

  // File events
  if (eid.includes("file_download") || eid.includes("file.download")) {
    const file = event.url || event.filename || "unknown file";
    return `Attacker downloaded <code>${esc(file)}</code>`;
  }
  if (eid.includes("file.upload")) return event.filename ? `Attacker uploaded <code>${esc(event.filename)}</code>` : null;

  // HTTP probe - explain what they're looking for
  if (eid === "http.probe") {
    const path = event.path || "/";
    const context = PROBE_CONTEXT[path];
    if (context) return `Looking for <code>${esc(path)}</code> - ${esc(context)}`;
    return `Probing <code>${esc(path)}</code> for vulnerabilities`;
  }

  // HTTP request
  if (eid === "http.request") {
    const method = event.method || "GET";
    const path = event.path || "/";
    if (path === "/" || path === "/index.html") return "Visited the website homepage";
    if (path.includes("wp-login")) return "Accessed the WordPress login page";
    return `Requested <code>${esc(method)} ${esc(path)}</code>`;
  }

  // HTTP XMLRPC
  if (eid === "http.xmlrpc") {
    const method = event.post_body && event.post_body.includes("methodName") ? event.post_body.match(/<methodName>(.+?)<\/methodName>/)?.[1] || "?" : "?";
    return `Exploiting WordPress remote API - method <code>${esc(method)}</code>`;
  }

  // SMB
  if (eid === "smb.negotiate") return event.protocol ? `Initiated SMB connection (${esc(event.protocol)})` : "Initiated SMB connection";
  if (eid === "smb.share.access") return event.share ? `Trying to access shared folder: <code>${esc(event.share)}</code>` : "Accessing network share";
  if (eid === "smb.share.enum") return event.share ? `Enumerated shared folder: <code>${esc(event.share)}</code>` : "Scanning for shared folders on the network";

  // Client version
  if (eid === "cowrie.client.version") return event.version ? `Attacker tool: <code>${esc(event.version)}</code>` : null;

  return event.message ? esc(event.message) : null;
}

function setFilter(filter) {
  currentFilter = filter;
  currentSvcFilter = null;
  document.querySelectorAll(".fbtn:not(.fbtn-svc)").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.filter === filter);
  });
  document.querySelectorAll(".fbtn-svc").forEach(btn => btn.classList.remove("active"));
  applyFilters();
}

function setSvcFilter(svc) {
  if (currentSvcFilter === svc) {
    currentSvcFilter = null;
  } else {
    currentSvcFilter = svc;
  }
  document.querySelectorAll(".fbtn-svc").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.svc === currentSvcFilter);
  });
  applyFilters();
}

function applyFilters() {
  document.querySelectorAll(".ev").forEach(ev => {
    const catOk = currentFilter === "all" || ev.dataset.cat === currentFilter;
    const svcOk = !currentSvcFilter || ev.dataset.svc === currentSvcFilter;
    ev.classList.toggle("hidden", !catOk || !svcOk);
  });
}

// ── Stats ──
function updateStats(stats) {
  document.getElementById("statConnections").textContent = stats.totalConnections || 0;
  document.getElementById("statUniqueIps").textContent = stats.uniqueIps || 0;
  document.getElementById("statCredentials").textContent = stats.credentialsCaptured || 0;
  document.getElementById("statSessions").textContent = stats.sessionsCount || 0;
  document.getElementById("statCommands").textContent = stats.commandsExecuted || 0;
  document.getElementById("statDownloads").textContent = stats.filesDownloaded || 0;
  document.getElementById("statHttp").textContent = stats.httpRequests || 0;
  document.getElementById("statFtp").textContent = stats.ftpSessions || 0;
  document.getElementById("statSmb").textContent = stats.smbSessions || 0;
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

    const geoText = (s.geo && s.geo.city && s.geo.city !== "LAN")
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

    const svcTag = s.service && s.service !== "ssh" ? `<span class="ev-svc ev-svc--${s.service}">${s.service.toUpperCase()}</span>` : "";

    return `<div class="sess" onclick="this.classList.toggle('expanded')">
      <div class="sess-top">
        ${svcTag}
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

// Detailed attack descriptions for each type
const ATTACK_INFO = {
  scan: {
    desc: "Discovers open ports and identifies running services on the target machine",
    steps: [
      "Scanning ports 21, 22, 23, 80, 445, 2222, 2223, 8080",
      "Detecting service versions (nmap -sV)",
      "Running vulnerability detection scripts (nmap -sC)",
    ],
    target: "All services",
  },
  bruteforce: {
    desc: "Tries common username/password combinations to break into SSH",
    steps: [
      "Testing 6 usernames (root, admin, user, test, ubuntu, pi)",
      "Against 10 common passwords each (60 combinations)",
      "4 parallel threads via hydra",
    ],
    target: "SSH (port 2222)",
  },
  infiltration: {
    desc: "Logs into the server and simulates a real attacker stealing data",
    steps: [
      "Login as root via SSH with known credentials",
      "Recon: whoami, uname -a (identify the system)",
      "Exfiltration: cat /etc/passwd, /etc/shadow (steal accounts)",
      "Deploy malware: wget backdoor.sh + chmod +x",
      "Lateral movement: try admin:admin on SSH",
    ],
    target: "SSH (port 2222)",
  },
  sshflood: {
    desc: "Floods the SSH port with 160 rapid connections to overwhelm the server",
    steps: [
      "Wave 1: 60 simultaneous TCP connections",
      "Wave 2: 60 more connections after 3s",
      "Wave 3: 40 final connections",
    ],
    target: "SSH (port 2222)",
  },
  credstuffing: {
    desc: "Massive credential stuffing with 1800+ username/password combinations",
    steps: [
      "25 common usernames (root, admin, deploy, backup...)",
      "70+ passwords from leaked databases",
      "2 parallel threads, 10s timeout per attempt",
    ],
    target: "SSH (port 2222)",
  },
  webscan: {
    desc: "Scans the web server for WordPress vulnerabilities and sensitive files",
    steps: [
      "Nikto vulnerability scanner against HTTP",
      "Probing: .env, wp-config.php, phpmyadmin, .git...",
      "Brute-forcing WordPress login (4 users x 5 passwords)",
      "Testing XML-RPC API for exploits",
    ],
    target: "HTTP/WordPress (port 80)",
  },
  ftpbrute: {
    desc: "Brute-forces FTP credentials then tries to steal files",
    steps: [
      "Hydra: 8 usernames x 8 passwords (64 combinations)",
      "Testing anonymous FTP access",
      "Browsing server files if login succeeds",
      "Downloading sensitive files (.env.bak, backup.sql)",
    ],
    target: "FTP (port 21)",
  },
  telnetbrute: {
    desc: "Brute-forces Telnet login with common credentials",
    steps: [
      "Hydra: 5 usernames x 6 passwords (30 combinations)",
      "Manual Telnet connection probe via netcat",
    ],
    target: "Telnet (port 23)",
  },
  smbenum: {
    desc: "Enumerates Windows network shares and tries to access shared files",
    steps: [
      "Null session enumeration (no credentials)",
      "Testing common creds: admin, administrator, guest",
      "Accessing DOCUMENTS and BACKUP shares",
      "Nmap SMB scripts (OS discovery, share enum)",
    ],
    target: "SMB (port 445)",
  },
  manual: {
    desc: "Interactive shell with all attack tools available for 30 minutes",
    steps: [
      "Tools: nmap, hydra, nikto, netcat, sshpass, curl, smbclient",
      "Targets: SSH:2222, Telnet:23, HTTP:80, FTP:21, SMB:445",
    ],
    target: "All services",
  },
};

function getRunningMessage(type) {
  const info = ATTACK_INFO[type];
  return info ? info.desc : "Attack in progress";
}

function renderAttackers() {
  const container = document.getElementById("attackersList");
  const countEl = document.getElementById("attackerCount");
  if (countEl) countEl.textContent = attackers.size;

  if (attackers.size === 0) {
    container.innerHTML = '<div class="empty-hint">No active attackers</div>';
    return;
  }

  container.innerHTML = [...attackers.values()].map(a => {
    const elapsed = a.createdAt ? timeAgo(a.createdAt) : "";
    const typeLabel = { scan: "Port Scan", bruteforce: "Brute Force", manual: "Manual Shell", infiltration: "Infiltration", sshflood: "SSH Flood", credstuffing: "Cred Stuffing", webscan: "Web Scan", ftpbrute: "FTP Brute", telnetbrute: "Telnet Brute", smbenum: "SMB Enum" }[a.attackType] || a.attackType;
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

    const info = ATTACK_INFO[a.attackType];
    const stepsDetail = info && (a.status === "running" || a.status === "creating")
      ? `<div class="atk-detail">
          <div class="atk-detail-target">Target: ${esc(info.target)}</div>
          ${info.steps.map(s => `<div class="atk-detail-step">${esc(s)}</div>`).join("")}
        </div>`
      : "";

    const termBtn = a.attackType === "manual" && a.status === "running"
      ? `<button class="atk-term-btn" onclick="event.stopPropagation(); openTerminal(${a.vmid})">Open Shell</button>`
      : "";

    // SSH connection info for manual containers
    let sshInfo = "";
    if (a.attackType === "manual" && a.ip && a.status === "running") {
      const sshCmd = `ssh root@${a.ip}`;
      sshInfo = `<div class="atk-ssh-info">
        <div class="atk-ssh-label">SSH Access</div>
        <div class="atk-ssh-cmd" onclick="event.stopPropagation(); navigator.clipboard.writeText('${sshCmd}'); this.classList.add('copied'); setTimeout(() => this.classList.remove('copied'), 1500);">
          <code>${esc(sshCmd)}</code>
          <span class="atk-ssh-copy">copy</span>
        </div>
        <div class="atk-ssh-pass">Password: <code>${esc(a.sshPassword || "attacker")}</code></div>
      </div>`;
    }

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
      ${termBtn}
      ${sshInfo}
      ${stepsDetail}
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
  if (!geo || !geo.lat || geo.city === "LAN") return;

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
      if (g.lat && g.lon && g.city !== "LAN") {
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
    narrativeWindow.length = 0;

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
    document.getElementById("narrativeSection").style.display = "none";
    document.getElementById("narrativeContent").innerHTML = "";

    // Zero all stat cards
    updateStats({ totalConnections: 0, uniqueIps: 0, credentialsCaptured: 0, sessionsCount: 0, commandsExecuted: 0, filesDownloaded: 0, httpRequests: 0, ftpSessions: 0, smbSessions: 0 });
  } catch (err) {
    alert("Reset failed: " + err.message);
  } finally {
    btn.textContent = "Clear data";
    btn.classList.remove("confirming");
    btn.disabled = false;
  }
}

// ── Narrative Engine ──
// Tracks recent events and displays human-readable attack summaries

const NARRATIVE_TTL = 120000; // 2 minute window

function updateNarrative(event) {
  const now = Date.now();
  narrativeWindow.push({ event, ts: now });
  while (narrativeWindow.length > 0 && now - narrativeWindow[0].ts > NARRATIVE_TTL) {
    narrativeWindow.shift();
  }
  renderNarrative();
}

function renderNarrative() {
  const section = document.getElementById("narrativeSection");
  const content = document.getElementById("narrativeContent");
  if (narrativeWindow.length < 3) { section.style.display = "none"; return; }

  const patterns = detectNarrativePatterns();
  if (patterns.length === 0) { section.style.display = "none"; return; }

  section.style.display = "";
  content.innerHTML = patterns.map(p => `
    <div class="narr-item narr-${p.severity}">
      <span class="narr-icon">${p.icon}</span>
      <div class="narr-text">
        <strong>${esc(p.title)}</strong>
        <span>${esc(p.description)}</span>
      </div>
      <span class="narr-badge">${p.count} events</span>
    </div>
  `).join("");
}

function detectNarrativePatterns() {
  const patterns = [];
  const byIp = new Map();

  for (const { event } of narrativeWindow) {
    const ip = event.src_ip || "unknown";
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(event);
  }

  for (const [ip, events] of byIp) {
    const loginAttempts = events.filter(e => e.eventid && (e.eventid.includes("login.failed") || e.eventid.includes("login.attempt")));
    const loginSuccess = events.filter(e => e.eventid && e.eventid.includes("login.success"));
    const commands = events.filter(e => e.eventid && e.eventid.includes("command.input"));
    const probes = events.filter(e => e.eventid === "http.probe");
    const connections = events.filter(e => e.eventid && e.eventid.includes("session.connect"));

    const geoEvt = events.find(e => e._geo && e._geo.city && e._geo.city !== "LAN");
    const location = geoEvt ? `${geoEvt._geo.city}, ${geoEvt._geo.country}` : "";
    const from = location ? ` from ${location}` : "";
    const svc = events[0]?._service || "ssh";
    const svcLabel = { ssh: "SSH server", telnet: "Telnet server", http: "the web server (WordPress)", ftp: "the FTP server", smb: "network file shares (SMB)" }[svc] || svc;

    // Intrusion: login + commands = highest priority
    if (loginSuccess.length > 0 && commands.length > 0) {
      patterns.push({
        severity: "critical",
        icon: "\u{1F6A8}",
        title: "Intrusion in progress",
        description: `An attacker${from} broke into ${svcLabel} and is running commands on the system`,
        count: commands.length,
      });
      continue;
    }

    // Login success without commands yet
    if (loginSuccess.length > 0 && commands.length === 0) {
      patterns.push({
        severity: "critical",
        icon: "\u{26A0}\u{FE0F}",
        title: "Attacker logged in",
        description: `Someone${from} successfully authenticated to ${svcLabel}`,
        count: loginSuccess.length,
      });
      continue;
    }

    // Brute force: 5+ login attempts
    if (loginAttempts.length >= 5) {
      patterns.push({
        severity: "warning",
        icon: "\u{1F510}",
        title: "Brute force attack",
        description: `${loginAttempts.length} password guesses targeting ${svcLabel}${from}`,
        count: loginAttempts.length,
      });
    }

    // Vulnerability scanning: 3+ probes
    if (probes.length >= 3) {
      patterns.push({
        severity: "info",
        icon: "\u{1F50D}",
        title: "Vulnerability scanning",
        description: `Attacker${from} is searching for sensitive files and known exploits on the web server`,
        count: probes.length,
      });
    }

    // Connection flood: 10+ connections, not brute force
    if (connections.length >= 10 && loginAttempts.length < 5) {
      patterns.push({
        severity: "warning",
        icon: "\u{1F300}",
        title: "Connection flood",
        description: `${connections.length} rapid connections${from} - possible denial of service`,
        count: connections.length,
      });
    }
  }

  const sevOrder = { critical: 0, warning: 1, info: 2 };
  patterns.sort((a, b) => (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3));
  return patterns.slice(0, 3);
}

// Refresh narrative every 10s to expire old patterns
setInterval(() => {
  if (narrativeWindow.length > 0) {
    const now = Date.now();
    while (narrativeWindow.length > 0 && now - narrativeWindow[0].ts > NARRATIVE_TTL) {
      narrativeWindow.shift();
    }
    renderNarrative();
  }
}, 10000);

// ── Terminal ──
let termVmid = null;
let termBusy = false;
const termHistory = [];
let termHistoryIdx = -1;

function openTerminal(vmid) {
  termVmid = vmid;
  termBusy = false;
  termHistoryIdx = -1;
  const overlay = document.getElementById("termOverlay");
  const output = document.getElementById("termOutput");
  const input = document.getElementById("termInput");
  document.getElementById("termVmid").textContent = `CT ${vmid}`;

  // Reset output to welcome message
  output.innerHTML = `
    <div class="term-welcome">
      <span class="term-welcome-line">Connected to attacker container CT ${vmid}</span>
      <span class="term-welcome-line">Target: 10.30.30.10 (SSH:2222 HTTP:80 FTP:21 SMB:445 Telnet:23)</span>
      <span class="term-welcome-line">Tools: nmap, hydra, nikto, curl, smbclient, sshpass, netcat</span>
      <span class="term-welcome-line term-hint">All commands run inside the attacker container. The honeypot captures everything.</span>
    </div>`;

  overlay.style.display = "flex";
  input.value = "";
  input.disabled = false;
  input.focus();
}

function closeTerminal() {
  document.getElementById("termOverlay").style.display = "none";
  termVmid = null;
  termBusy = false;
}

function handleTermKey(e) {
  if (e.key === "Enter" && !termBusy) {
    const input = document.getElementById("termInput");
    const cmd = input.value.trim();
    if (!cmd) return;

    // History
    termHistory.push(cmd);
    termHistoryIdx = termHistory.length;

    sendTermCmd(cmd);
    input.value = "";
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    if (termHistory.length === 0) return;
    termHistoryIdx = Math.max(0, termHistoryIdx - 1);
    document.getElementById("termInput").value = termHistory[termHistoryIdx] || "";
  } else if (e.key === "ArrowDown") {
    e.preventDefault();
    termHistoryIdx = Math.min(termHistory.length, termHistoryIdx + 1);
    document.getElementById("termInput").value = termHistory[termHistoryIdx] || "";
  } else if (e.key === "Escape") {
    closeTerminal();
  }
}

function sendTermCmd(cmd) {
  if (!ws || ws.readyState !== 1 || !termVmid) return;

  termBusy = true;
  document.getElementById("termInput").disabled = true;

  const output = document.getElementById("termOutput");

  // Show command line
  const cmdDiv = document.createElement("div");
  cmdDiv.className = "term-cmd-line";
  cmdDiv.innerHTML = `<span class="term-cmd-prompt">root@attacker:~#</span> <span class="term-cmd-text">${esc(cmd)}</span>`;
  output.appendChild(cmdDiv);

  // Show "running..." indicator
  const runDiv = document.createElement("div");
  runDiv.className = "term-cmd-running";
  runDiv.id = "termRunning";
  runDiv.textContent = "Running...";
  output.appendChild(runDiv);
  output.scrollTop = output.scrollHeight;

  // Create output container for streaming
  const outDiv = document.createElement("div");
  outDiv.className = "term-cmd-output";
  outDiv.id = "termCurrentOutput";
  output.insertBefore(outDiv, runDiv);

  // Send command via WebSocket
  ws.send(JSON.stringify({ type: "terminal-cmd", vmid: termVmid, cmd }));
}

function handleTerminalOutput(data) {
  if (data.vmid !== termVmid) return;

  const output = document.getElementById("termOutput");
  const outDiv = document.getElementById("termCurrentOutput");
  const runDiv = document.getElementById("termRunning");

  if (data.output && outDiv) {
    outDiv.textContent += data.output;
    output.scrollTop = output.scrollHeight;
  }

  if (data.done) {
    // Remove running indicator
    if (runDiv) runDiv.remove();

    // Show error if any
    if (data.error) {
      const errDiv = document.createElement("div");
      errDiv.className = "term-cmd-output term-cmd-error";
      errDiv.textContent = data.error;
      output.appendChild(errDiv);
    }

    // Clear current output ID so next command gets its own container
    if (outDiv) outDiv.removeAttribute("id");

    termBusy = false;
    const input = document.getElementById("termInput");
    input.disabled = false;
    input.focus();
    output.scrollTop = output.scrollHeight;
  }
}

// Close terminal on overlay click (not panel click)
document.getElementById("termOverlay")?.addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeTerminal();
});

// ── View Switching ──
function switchView(view) {
  currentView = view;
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById(view === "monitor" ? "viewMonitor" : "viewAttacker").classList.add("active");
  document.querySelectorAll(".nav-tab").forEach(t => t.classList.toggle("active", t.dataset.view === view));

  // Leaflet needs a nudge after being hidden
  if (view === "monitor") {
    setTimeout(() => map.invalidateSize(), 100);
  }
}

// ── Init ──
loadInitialData().then(() => connectWs());
