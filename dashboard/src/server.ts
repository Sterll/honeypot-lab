import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import path from "path";
import type { WebSocket } from "ws";
import { initDatabase, insertEvent, getEvents, getStats, getCredentials, getSessions, getSessionCommands, getGeoData, resetData } from "./db";
import { LogWatcher } from "./log-watcher";
import { lookupGeoIp } from "./geoip";
import { spawnAttacker, destroyAttacker, getActiveAttackers, setAttackerUpdateCallback, execInContainer, ProxmoxError } from "./proxmox";
import type { HoneypotEvent, WsMessage, WsIncoming, AttackType } from "./types";

// Disable TLS verification for Proxmox self-signed certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const PORT = 3080;
const HOST = "0.0.0.0";

// Init DB
const db = initDatabase();
console.log("[server] Database initialized");

// WebSocket clients
const wsClients = new Set<WebSocket>();

function broadcast(msg: WsMessage): void {
  const payload = JSON.stringify(msg);
  for (const client of wsClients) {
    if (client.readyState === 1) {
      client.send(payload);
    }
  }
}

// Broadcast attacker status changes (finished, etc.)
setAttackerUpdateCallback((attacker) => {
  broadcast({ type: "attacker_update", data: attacker as unknown as HoneypotEvent });
});

// Log watcher (all honeypot services)
const watcher = new LogWatcher();
watcher.on("event", async (event: HoneypotEvent) => {
  // Store in DB
  insertEvent(event);

  // Lookup GeoIP
  const geo = await lookupGeoIp(event.src_ip);

  // Broadcast to all WS clients
  broadcast({ type: "event", data: { ...event, _geo: geo } as unknown as HoneypotEvent });

  // Periodically send stats update
  broadcast({ type: "stats", data: getStats() as unknown as HoneypotEvent });
});

// Fastify server
const app = Fastify({ logger: false });

app.register(fastifyStatic, {
  root: path.join(__dirname, "..", "public"),
  prefix: "/",
});

app.register(fastifyWebsocket);

app.register(async function (fastify) {
  fastify.get("/ws", { websocket: true }, (socket) => {
    wsClients.add(socket);
    console.log(`[ws] Client connected (${wsClients.size} total)`);

    // Send initial stats
    socket.send(JSON.stringify({ type: "stats", data: getStats() }));

    // Send active attackers
    for (const attacker of getActiveAttackers()) {
      socket.send(JSON.stringify({ type: "attacker_update", data: attacker }));
    }

    socket.on("message", (raw: Buffer | string) => {
      try {
        const msg: WsIncoming = JSON.parse(typeof raw === "string" ? raw : raw.toString());
        if (msg.type === "terminal-cmd" && msg.vmid && msg.cmd) {
          console.log(`[terminal] CMD in CT ${msg.vmid}: ${msg.cmd}`);
          execInContainer(
            msg.vmid,
            msg.cmd,
            (output) => {
              socket.send(JSON.stringify({ type: "terminal-output", data: { vmid: msg.vmid, output } }));
            },
            (error) => {
              socket.send(JSON.stringify({ type: "terminal-output", data: { vmid: msg.vmid, output: "", done: true, error } }));
            }
          );
        }
      } catch { /* ignore invalid messages */ }
    });

    socket.on("close", () => {
      wsClients.delete(socket);
      console.log(`[ws] Client disconnected (${wsClients.size} total)`);
    });
  });
});

// REST API
app.get("/api/events", async (req) => {
  const { limit = "100", offset = "0" } = req.query as Record<string, string>;
  return getEvents(parseInt(limit), parseInt(offset));
});

app.get("/api/stats", async () => {
  return getStats();
});

app.get("/api/credentials", async () => {
  return getCredentials();
});

app.get("/api/sessions", async () => {
  return getSessions();
});

app.get("/api/sessions/:id/commands", async (req) => {
  const { id } = req.params as { id: string };
  return getSessionCommands(id);
});

app.get("/api/geo", async () => {
  return getGeoData();
});

app.get("/api/attackers", async () => {
  return getActiveAttackers();
});

app.post("/api/attack/:type", async (req, reply) => {
  const { type } = req.params as { type: string };
  const validTypes: AttackType[] = ["scan", "bruteforce", "manual", "infiltration", "sshflood", "credstuffing", "webscan", "ftpbrute", "telnetbrute", "smbenum"];
  if (!validTypes.includes(type as AttackType)) {
    return reply.code(400).send({ error: `Invalid attack type: ${type}` });
  }
  try {
    const attacker = await spawnAttacker(type as AttackType);
    broadcast({ type: "attacker_update", data: attacker as unknown as HoneypotEvent });
    return attacker;
  } catch (err) {
    const message = err instanceof ProxmoxError ? err.message : "Failed to spawn attacker";
    console.error(`[api] POST /api/attack/${type} failed: ${message}`);
    return reply.code(500).send({ error: message });
  }
});

app.post("/api/reset", async (_req, reply) => {
  try {
    resetData();
    broadcast({ type: "stats", data: getStats() as unknown as HoneypotEvent });
    return { ok: true };
  } catch (err) {
    console.error("[api] POST /api/reset failed:", err);
    return reply.code(500).send({ error: "Failed to reset data" });
  }
});

app.delete("/api/attack/:vmid", async (req, reply) => {
  const { vmid } = req.params as { vmid: string };
  const id = parseInt(vmid);
  if (isNaN(id) || id < 950 || id > 999) {
    return reply.code(400).send({ error: `Invalid VMID: ${vmid}` });
  }
  try {
    await destroyAttacker(id);
    broadcast({
      type: "attacker_update",
      data: { vmid: id, status: "destroying" } as unknown as HoneypotEvent,
    });
    return { ok: true };
  } catch (err) {
    const message = err instanceof ProxmoxError ? err.message : "Failed to destroy attacker";
    console.error(`[api] DELETE /api/attack/${vmid} failed: ${message}`);
    return reply.code(500).send({ error: message });
  }
});

// Catch-all: redirect unknown routes to /
app.setNotFoundHandler((req, reply) => {
  if (!req.url.startsWith("/api/") && !req.url.startsWith("/ws")) {
    reply.redirect("/");
  } else {
    reply.code(404).send({ error: "Not found" });
  }
});

// Start
async function main() {
  await app.listen({ port: PORT, host: HOST });
  console.log(`[server] Dashboard running at http://${HOST}:${PORT}`);

  watcher.start();
  console.log("[server] Log watcher started (ssh, telnet, http, ftp, smb)");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
