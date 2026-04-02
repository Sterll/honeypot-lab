import Database from "better-sqlite3";
import path from "path";
import type { HoneypotEvent, DashboardStats, GeoInfo } from "./types";

const DB_PATH = path.join(__dirname, "..", "honeypot.db");

let db: Database.Database;

export function initDatabase(): Database.Database {
  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      eventid TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      session TEXT,
      src_ip TEXT,
      src_port INTEGER,
      dst_port INTEGER,
      service TEXT DEFAULT 'ssh',
      message TEXT,
      username TEXT,
      password TEXT,
      command TEXT,
      duration REAL,
      url TEXT,
      shasum TEXT,
      ssh_version TEXT,
      hassh TEXT,
      raw JSON NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
    CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
  `);

  // Migration: add service column if missing (existing DBs)
  try {
    db.exec(`ALTER TABLE events ADD COLUMN service TEXT DEFAULT 'ssh'`);
  } catch {
    // Column already exists
  }

  db.exec(`CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS geoip_cache (
      ip TEXT PRIMARY KEY,
      country TEXT,
      country_code TEXT,
      city TEXT,
      lat REAL,
      lon REAL,
      isp TEXT,
      org TEXT,
      cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  return db;
}

export function insertEvent(event: HoneypotEvent): void {
  try {
    const stmt = db.prepare(`
      INSERT INTO events (eventid, timestamp, session, src_ip, src_port, dst_port, service, message, username, password, command, duration, url, shasum, ssh_version, hassh, raw)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const e = event as unknown as Record<string, unknown>;
    const str = (key: string): string | null => {
      const v = e[key];
      if (v === undefined || v === null) return null;
      if (typeof v === "string") return v;
      return String(v);
    };
    const num = (key: string): number | null => {
      const v = e[key];
      if (v === undefined || v === null) return null;
      return typeof v === "number" ? v : null;
    };

    stmt.run(
      str("eventid"),
      str("timestamp"),
      str("session"),
      str("src_ip"),
      num("src_port"),
      num("dst_port"),
      str("_service") || "ssh",
      str("message"),
      str("username"),
      str("password"),
      str("input"),
      num("duration"),
      str("url"),
      str("shasum"),
      str("version"),
      str("hassh"),
      JSON.stringify(event)
    );
  } catch (err) {
    console.error("[db] Failed to insert event:", (err as Error).message);
  }
}

export function getEvents(limit = 100, offset = 0, service?: string): HoneypotEvent[] {
  if (service) {
    const rows = db.prepare(`
      SELECT raw FROM events WHERE service = ? ORDER BY id DESC LIMIT ? OFFSET ?
    `).all(service, limit, offset) as { raw: string }[];
    return rows.map((r) => JSON.parse(r.raw));
  }
  const rows = db.prepare(`
    SELECT raw FROM events ORDER BY id DESC LIMIT ? OFFSET ?
  `).all(limit, offset) as { raw: string }[];
  return rows.map((r) => JSON.parse(r.raw));
}

export function getStats(): DashboardStats {
  const row = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM events WHERE eventid LIKE '%.session.connect') as totalConnections,
      (SELECT COUNT(DISTINCT src_ip) FROM events) as uniqueIps,
      (SELECT COUNT(*) FROM events WHERE eventid LIKE '%.login.%') as credentialsCaptured,
      (SELECT COUNT(DISTINCT session) FROM events WHERE eventid LIKE '%.session.connect') as sessionsCount,
      (SELECT COUNT(*) FROM events WHERE eventid IN ('cowrie.command.input', 'ftp.command.input')) as commandsExecuted,
      (SELECT COUNT(*) FROM events WHERE eventid = 'cowrie.session.file_download') as filesDownloaded,
      (SELECT COUNT(*) FROM events WHERE service = 'http') as httpRequests,
      (SELECT COUNT(DISTINCT session) FROM events WHERE service = 'ftp') as ftpSessions,
      (SELECT COUNT(DISTINCT session) FROM events WHERE service = 'smb') as smbSessions
  `).get() as DashboardStats;
  return row;
}

export function getCredentials(limit = 50): { username: string; password: string; count: number }[] {
  return db.prepare(`
    SELECT username, password, COUNT(*) as count
    FROM events
    WHERE eventid LIKE '%.login.%' AND username IS NOT NULL
    GROUP BY username, password
    ORDER BY count DESC
    LIMIT ?
  `).all(limit) as { username: string; password: string; count: number }[];
}

export function getSessions(): { session: string; src_ip: string; startTime: string; commandCount: number; loginSuccess: number; service: string }[] {
  return db.prepare(`
    SELECT
      e.session,
      e.src_ip,
      MIN(e.timestamp) as startTime,
      COALESCE(MAX(e.service), 'ssh') as service,
      SUM(CASE WHEN e.eventid IN ('cowrie.command.input', 'ftp.command.input') THEN 1 ELSE 0 END) as commandCount,
      SUM(CASE WHEN e.eventid LIKE '%.login.success' THEN 1 ELSE 0 END) as loginSuccess
    FROM events e
    WHERE e.session IS NOT NULL
    GROUP BY e.session
    ORDER BY startTime DESC
    LIMIT 100
  `).all() as { session: string; src_ip: string; startTime: string; commandCount: number; loginSuccess: number; service: string }[];
}

export function getSessionCommands(sessionId: string): { timestamp: string; input: string }[] {
  return db.prepare(`
    SELECT timestamp, command as input
    FROM events
    WHERE session = ? AND eventid = 'cowrie.command.input'
    ORDER BY timestamp ASC
  `).all(sessionId) as { timestamp: string; input: string }[];
}

export function cacheGeoIp(ip: string, geo: GeoInfo): void {
  db.prepare(`
    INSERT OR REPLACE INTO geoip_cache (ip, country, country_code, city, lat, lon, isp, org)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(ip, geo.country, geo.countryCode, geo.city, geo.lat, geo.lon, geo.isp, geo.org);
}

export function getCachedGeoIp(ip: string): GeoInfo | null {
  const row = db.prepare(`SELECT * FROM geoip_cache WHERE ip = ?`).get(ip) as {
    country: string; country_code: string; city: string; lat: number; lon: number; isp: string; org: string;
  } | undefined;
  if (!row) return null;
  return {
    country: row.country,
    countryCode: row.country_code,
    city: row.city,
    lat: row.lat,
    lon: row.lon,
    isp: row.isp,
    org: row.org,
  };
}

export function resetData(): void {
  db.exec("DELETE FROM events");
  db.exec("DELETE FROM geoip_cache");
  db.exec("VACUUM");
}

export function getGeoData(): { ip: string; lat: number; lon: number; country: string; city: string; count: number }[] {
  return db.prepare(`
    SELECT g.ip, g.lat, g.lon, g.country, g.city, COUNT(e.id) as count
    FROM geoip_cache g
    JOIN events e ON e.src_ip = g.ip
    GROUP BY g.ip
    ORDER BY count DESC
  `).all() as { ip: string; lat: number; lon: number; country: string; city: string; count: number }[];
}
