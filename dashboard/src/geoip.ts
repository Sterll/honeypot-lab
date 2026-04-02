import { cacheGeoIp, getCachedGeoIp } from "./db";
import type { GeoInfo } from "./types";

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_RANGES.some((r) => r.test(ip));
}

const LOCAL_GEO: GeoInfo = {
  country: "Local",
  countryCode: "LO",
  city: "LAN",
  lat: 0,
  lon: 0,
  isp: "Private Network",
  org: "Private Network",
};

// Fake locations for demo - simulated attacker origins
const FAKE_LOCATIONS: GeoInfo[] = [
  { country: "Russia", countryCode: "RU", city: "Moscow", lat: 55.75, lon: 37.62, isp: "Rostelecom", org: "VPS Hosting" },
  { country: "China", countryCode: "CN", city: "Beijing", lat: 39.90, lon: 116.40, isp: "China Telecom", org: "Cloud Services" },
  { country: "United States", countryCode: "US", city: "New York", lat: 40.71, lon: -74.01, isp: "DigitalOcean", org: "DO-13" },
  { country: "Brazil", countryCode: "BR", city: "São Paulo", lat: -23.55, lon: -46.63, isp: "Vivo", org: "Telefonica Brasil" },
  { country: "India", countryCode: "IN", city: "Mumbai", lat: 19.08, lon: 72.88, isp: "Reliance Jio", org: "Jio Platform" },
  { country: "Germany", countryCode: "DE", city: "Frankfurt", lat: 50.11, lon: 8.68, isp: "Hetzner", org: "Hetzner Online" },
  { country: "Nigeria", countryCode: "NG", city: "Lagos", lat: 6.52, lon: 3.38, isp: "MTN Nigeria", org: "MTN Communications" },
  { country: "Iran", countryCode: "IR", city: "Tehran", lat: 35.69, lon: 51.39, isp: "Irancell", org: "MTN Irancell" },
  { country: "Romania", countryCode: "RO", city: "Bucharest", lat: 44.43, lon: 26.10, isp: "RCS & RDS", org: "Digi Romania" },
  { country: "Vietnam", countryCode: "VN", city: "Ho Chi Minh City", lat: 10.82, lon: 106.63, isp: "Viettel", org: "Viettel Group" },
  { country: "Ukraine", countryCode: "UA", city: "Kyiv", lat: 50.45, lon: 30.52, isp: "Kyivstar", org: "Kyivstar JSC" },
  { country: "South Korea", countryCode: "KR", city: "Seoul", lat: 37.57, lon: 126.98, isp: "Korea Telecom", org: "KT Corporation" },
  { country: "Netherlands", countryCode: "NL", city: "Amsterdam", lat: 52.37, lon: 4.90, isp: "LeaseWeb", org: "LeaseWeb NL" },
  { country: "Indonesia", countryCode: "ID", city: "Jakarta", lat: -6.21, lon: 106.85, isp: "Telkom Indonesia", org: "PT Telkom" },
  { country: "Argentina", countryCode: "AR", city: "Buenos Aires", lat: -34.60, lon: -58.38, isp: "Telecom Argentina", org: "Telecom AR" },
];

const HONEYPOT_SUBNET = /^10\.30\.30\.(\d+)$/;

// Deterministic fake geo for honeypot subnet IPs
const fakeGeoCache = new Map<string, GeoInfo>();

function getFakeGeo(ip: string): GeoInfo | null {
  const match = ip.match(HONEYPOT_SUBNET);
  if (!match) return null;

  const lastOctet = parseInt(match[1], 10);

  // 10.30.30.1 = user's PC -> Paris, France
  if (lastOctet === 1) {
    return {
      country: "France", countryCode: "FR", city: "Paris",
      lat: 48.86, lon: 2.35, isp: "Free SAS", org: "Free SAS",
    };
  }

  // Attacker containers (101+) -> random fake location, cached per IP
  if (fakeGeoCache.has(ip)) return fakeGeoCache.get(ip)!;
  const loc = FAKE_LOCATIONS[Math.floor(Math.random() * FAKE_LOCATIONS.length)];
  // Add slight offset so multiple attackers from same "city" don't stack
  const geo: GeoInfo = {
    ...loc,
    lat: loc.lat + (Math.random() - 0.5) * 2,
    lon: loc.lon + (Math.random() - 0.5) * 2,
  };
  fakeGeoCache.set(ip, geo);
  return geo;
}

// ip-api.com batch lookup (max 100 per request, 45 req/min)
let requestCount = 0;
let resetTime = Date.now() + 60000;

export async function lookupGeoIp(ip: string): Promise<GeoInfo> {
  // Fake geo for honeypot subnet (demo mode)
  const fake = getFakeGeo(ip);
  if (fake) return fake;

  if (isPrivateIp(ip)) return LOCAL_GEO;

  const cached = getCachedGeoIp(ip);
  if (cached) return cached;

  // Rate limiting
  if (Date.now() > resetTime) {
    requestCount = 0;
    resetTime = Date.now() + 60000;
  }
  if (requestCount >= 40) {
    return LOCAL_GEO; // skip if rate limited
  }

  try {
    requestCount++;
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon,isp,org`
    );
    const data = (await res.json()) as Record<string, unknown>;

    if (data.status === "success") {
      const geo: GeoInfo = {
        country: data.country as string,
        countryCode: data.countryCode as string,
        city: (data.city as string) || "Unknown",
        lat: data.lat as number,
        lon: data.lon as number,
        isp: (data.isp as string) || "",
        org: (data.org as string) || "",
      };
      cacheGeoIp(ip, geo);
      return geo;
    }
  } catch {
    // ignore fetch errors
  }
  return LOCAL_GEO;
}

export async function batchLookupGeoIp(ips: string[]): Promise<Map<string, GeoInfo>> {
  const results = new Map<string, GeoInfo>();
  const toLookup: string[] = [];

  for (const ip of ips) {
    const fake = getFakeGeo(ip);
    if (fake) {
      cacheGeoIp(ip, fake);
      results.set(ip, fake);
      continue;
    }
    if (isPrivateIp(ip)) {
      results.set(ip, LOCAL_GEO);
      continue;
    }
    const cached = getCachedGeoIp(ip);
    if (cached) {
      results.set(ip, cached);
      continue;
    }
    toLookup.push(ip);
  }

  if (toLookup.length === 0) return results;

  // Batch up to 100 at a time
  for (let i = 0; i < toLookup.length; i += 100) {
    const batch = toLookup.slice(i, i + 100);
    try {
      const res = await fetch("http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp,org", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batch.map((ip) => ({ query: ip }))),
      });
      interface IpApiEntry {
        status: string; query: string; country: string; countryCode: string;
        city: string; lat: number; lon: number; isp: string; org: string;
      }
      const data = (await res.json()) as IpApiEntry[];
      for (const entry of data) {
        if (entry.status === "success") {
          const geo: GeoInfo = {
            country: entry.country,
            countryCode: entry.countryCode,
            city: entry.city || "Unknown",
            lat: entry.lat,
            lon: entry.lon,
            isp: entry.isp || "",
            org: entry.org || "",
          };
          cacheGeoIp(entry.query, geo);
          results.set(entry.query, geo);
        }
      }
    } catch {
      // ignore
    }
  }

  return results;
}
