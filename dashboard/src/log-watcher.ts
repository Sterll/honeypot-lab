import { EventEmitter } from "events";
import { Client } from "ssh2";
import type { HoneypotEvent, ServiceType } from "./types";

const HONEYPOT_HOST = "10.30.30.10";
const HONEYPOT_SSH_PORT = 22222;

interface LogSource {
  service: ServiceType;
  path: string;
}

const LOG_SOURCES: LogSource[] = [
  { service: "ssh", path: "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" },
  { service: "http", path: "/var/log/honeypot/http.json" },
  { service: "ftp", path: "/var/log/honeypot/ftp.json" },
  { service: "smb", path: "/var/log/honeypot/smb.json" },
];

/**
 * Determine service type from Cowrie eventid.
 * Cowrie logs both SSH and Telnet; the protocol field or dst_port distinguishes them.
 */
function resolveCowrieService(event: HoneypotEvent): ServiceType {
  if (event.protocol === "telnet" || event.dst_port === 2223 || event.dst_port === 23) {
    return "telnet";
  }
  return "ssh";
}

export class LogWatcher extends EventEmitter {
  private sshClient: Client | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private buffers = new Map<string, string>();

  start(): void {
    this.connect();
  }

  private connect(): void {
    if (this.sshClient) {
      try { this.sshClient.end(); } catch {}
    }

    this.sshClient = new Client();

    this.sshClient.on("ready", () => {
      console.log("[log-watcher] SSH connected to honeypot");

      // Build a single tail command that follows all log files
      const paths = LOG_SOURCES.map((s) => s.path).join(" ");
      // tail -F will output headers like "==> /path/to/file <==" when switching files
      const cmd = `tail -n 50 -F ${paths} 2>/dev/null`;

      this.sshClient!.exec(cmd, (err, stream) => {
        if (err) {
          console.error("[log-watcher] exec error:", err.message);
          this.scheduleReconnect();
          return;
        }

        console.log("[log-watcher] Tailing:", LOG_SOURCES.map((s) => s.service).join(", "));

        let currentSource: LogSource = LOG_SOURCES[0];
        let buffer = "";

        stream.on("data", (data: Buffer) => {
          buffer += data.toString();
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            // Check for tail's file header: ==> /path/to/file <==
            const headerMatch = line.match(/^==> (.+) <==$/);
            if (headerMatch) {
              const filePath = headerMatch[1];
              const source = LOG_SOURCES.find((s) => s.path === filePath);
              if (source) currentSource = source;
              continue;
            }

            if (!line.trim()) continue;

            try {
              const event = JSON.parse(line) as HoneypotEvent;

              // Tag with service
              if (currentSource.service === "ssh") {
                // Cowrie handles both SSH and Telnet
                event._service = resolveCowrieService(event);
              } else {
                event._service = currentSource.service;
              }

              this.emit("event", event);
            } catch {
              // Skip malformed lines
            }
          }
        });

        stream.on("close", () => {
          console.log("[log-watcher] Stream closed");
          this.scheduleReconnect();
        });

        stream.stderr.on("data", (data: Buffer) => {
          const msg = data.toString().trim();
          if (msg && !msg.includes("No such file")) {
            console.error("[log-watcher] stderr:", msg);
          }
        });
      });
    });

    this.sshClient.on("error", (err) => {
      console.error("[log-watcher] SSH error:", err.message);
      this.scheduleReconnect();
    });

    this.sshClient.on("close", () => {
      this.scheduleReconnect();
    });

    console.log("[log-watcher] Connecting to honeypot...");
    this.sshClient.connect({
      host: HONEYPOT_HOST,
      port: HONEYPOT_SSH_PORT,
      username: "root",
      privateKey: require("fs").readFileSync("/root/.ssh/id_ed25519", "utf8"),
      readyTimeout: 10000,
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    console.log("[log-watcher] Reconnecting in 5s...");
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 5000);
  }

  stop(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.sshClient) {
      this.sshClient.end();
      this.sshClient = null;
    }
  }
}
