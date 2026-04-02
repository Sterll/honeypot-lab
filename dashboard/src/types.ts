// Generic honeypot event (all services use this shape)
export interface HoneypotEvent {
  eventid: string;
  timestamp: string;
  session: string;
  src_ip: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  message?: string;
  sensor?: string;
  // Auth fields
  username?: string;
  password?: string;
  domain?: string;
  // SSH/Telnet fields
  input?: string;
  duration?: number;
  protocol?: string;
  version?: string;
  hassh?: string;
  hasshAlgorithms?: string;
  // File fields
  url?: string;
  outfile?: string;
  shasum?: string;
  filename?: string;
  // HTTP fields
  method?: string;
  path?: string;
  user_agent?: string;
  host?: string;
  response_code?: number;
  post_body?: string;
  // Service tag (added by log-watcher)
  _service?: ServiceType;
  _geo?: unknown;
}

// Backward compat alias
export type CowrieEvent = HoneypotEvent;

export type ServiceType = "ssh" | "telnet" | "http" | "ftp" | "smb";

// GeoIP
export interface GeoInfo {
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
}

// Proxmox attacker container
export type AttackType = "scan" | "bruteforce" | "manual" | "infiltration" | "sshflood" | "credstuffing" | "webscan" | "ftpbrute" | "telnetbrute" | "smbenum";

export interface AttackerContainer {
  vmid: number;
  name: string;
  attackType: AttackType;
  status: "creating" | "running" | "finished" | "destroying";
  createdAt: string;
  ip: string;
}

// Dashboard stats
export interface DashboardStats {
  totalConnections: number;
  uniqueIps: number;
  credentialsCaptured: number;
  sessionsCount: number;
  commandsExecuted: number;
  filesDownloaded: number;
  httpRequests: number;
  ftpSessions: number;
  smbSessions: number;
}

// WebSocket message types
export interface WsMessage {
  type: "event" | "stats" | "attacker_update";
  data: CowrieEvent | DashboardStats | AttackerContainer;
}
