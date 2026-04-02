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

// ip-api.com batch lookup (max 100 per request, 45 req/min)
let requestCount = 0;
let resetTime = Date.now() + 60000;

export async function lookupGeoIp(ip: string): Promise<GeoInfo> {
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
