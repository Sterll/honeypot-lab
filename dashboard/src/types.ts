// Cowrie event types
export interface CowrieBaseEvent {
  eventid: string;
  timestamp: string;
  sensor: string;
  session: string;
  src_ip: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  message: string;
}

export interface CowrieLoginEvent extends CowrieBaseEvent {
  eventid: "cowrie.login.failed" | "cowrie.login.success";
  username: string;
  password: string;
}

export interface CowrieCommandEvent extends CowrieBaseEvent {
  eventid: "cowrie.command.input" | "cowrie.command.failed";
  input: string;
}

export interface CowrieSessionConnect extends CowrieBaseEvent {
  eventid: "cowrie.session.connect";
  protocol: string;
}

export interface CowrieSessionClosed extends CowrieBaseEvent {
  eventid: "cowrie.session.closed";
  duration: number;
}

export interface CowrieFileDownload extends CowrieBaseEvent {
  eventid: "cowrie.session.file_download";
  url: string;
  outfile: string;
  shasum: string;
}

export interface CowrieClientVersion extends CowrieBaseEvent {
  eventid: "cowrie.client.version";
  version: string;
}

export interface CowrieClientKex extends CowrieBaseEvent {
  eventid: "cowrie.client.kex";
  hassh: string;
  hasshAlgorithms: string;
}

export type CowrieEvent =
  | CowrieLoginEvent
  | CowrieCommandEvent
  | CowrieSessionConnect
  | CowrieSessionClosed
  | CowrieFileDownload
  | CowrieClientVersion
  | CowrieClientKex
  | CowrieBaseEvent;

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
export type AttackType = "scan" | "bruteforce" | "manual" | "infiltration" | "sshflood" | "credstuffing";

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
}

// WebSocket message types
export interface WsMessage {
  type: "event" | "stats" | "attacker_update";
  data: CowrieEvent | DashboardStats | AttackerContainer;
}
