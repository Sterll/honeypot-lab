import { EventEmitter } from "events";
import { Client } from "ssh2";
import type { CowrieEvent } from "./types";

const HONEYPOT_HOST = "10.30.30.10";
const HONEYPOT_SSH_PORT = 22222;
const COWRIE_LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json";

export class CowrieWatcher extends EventEmitter {
  private sshClient: Client | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private buffer = "";

  start(): void {
    this.connect();
  }

  private connect(): void {
    if (this.sshClient) {
      try { this.sshClient.end(); } catch {}
    }

    this.sshClient = new Client();

    this.sshClient.on("ready", () => {
      console.log("[cowrie-watcher] SSH connected to honeypot");

      console.log("[cowrie-watcher] Executing tail command...");
      this.sshClient!.exec(`tail -n 50 -f ${COWRIE_LOG_PATH}`, (err, stream) => {
        if (err) {
          console.error("[cowrie-watcher] exec error:", err.message);
          this.scheduleReconnect();
          return;
        }

        console.log("[cowrie-watcher] Stream opened, waiting for data...");

        stream.on("data", (data: Buffer) => {
          const chunk = data.toString();
          console.log(`[cowrie-watcher] Received ${chunk.length} bytes`);
          this.buffer += chunk;
          const lines = this.buffer.split("\n");
          this.buffer = lines.pop() || "";

          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const event = JSON.parse(line) as CowrieEvent;
              this.emit("event", event);
            } catch {
              // Skip malformed lines
            }
          }
        });

        stream.on("close", () => {
          console.log("[cowrie-watcher] Stream closed");
          this.scheduleReconnect();
        });

        stream.stderr.on("data", (data: Buffer) => {
          const msg = data.toString().trim();
          if (msg && !msg.includes("No such file")) {
            console.error("[cowrie-watcher] stderr:", msg);
          }
        });
      });
    });

    this.sshClient.on("error", (err) => {
      console.error("[cowrie-watcher] SSH error:", err.message);
      this.scheduleReconnect();
    });

    this.sshClient.on("close", () => {
      this.scheduleReconnect();
    });

    console.log("[cowrie-watcher] Connecting to honeypot...");
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
    console.log("[cowrie-watcher] Reconnecting in 5s...");
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
