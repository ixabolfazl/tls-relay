/**
 * Domain matching, port parsing, and apex/wildcard rule helpers.
 */

/**
 * Matches a hostname against a list of domain rules, mirroring the backend Go router precedence:
 * 1. Exact match has top priority (e.g. 'example.com' or 'sub.example.com').
 * 2. Wildcard match ('*.example.com') matches any sub-level (e.g. 'sub.example.com', 'a.b.example.com').
 *    - Wildcard rule '*.example.com' NEVER matches apex 'example.com'.
 *    - Apex rule 'example.com' NEVER matches subdomain 'sub.example.com'.
 * 3. If multiple wildcard rules match, the longest suffix wins.
 */
export function matchRule(hostname, rulesList = []) {
  if (!hostname || !rulesList.length) return null;
  const host = hostname.toLowerCase().trim();

  // 1. Exact match check
  for (const rule of rulesList) {
    if (rule.domain && rule.domain.toLowerCase() === host) {
      return rule;
    }
  }

  // 2. Wildcard longest-suffix match
  let bestMatch = null;
  let bestLen = 0;

  for (const rule of rulesList) {
    if (!rule.domain || !rule.domain.startsWith('*.')) continue;
    const suffix = rule.domain.slice(2).toLowerCase(); // remove '*.'
    const dotSuffix = '.' + suffix;

    if (host.endsWith(dotSuffix) && host.length > dotSuffix.length) {
      if (suffix.length > bestLen) {
        bestLen = suffix.length;
        bestMatch = rule;
      }
    }
  }

  return bestMatch;
}

export function parsePorts(portsInput) {
  if (portsInput === undefined || portsInput === null) return null;
  if (typeof portsInput === 'string') {
    const trimmed = portsInput.trim().toLowerCase();
    if (trimmed === 'all') return 'all';
    if (trimmed === '') return null;
    const parts = trimmed.split(/[,;\s]+/).filter(Boolean);
    if (parts.length === 0) return null;
    const nums = [];
    for (const p of parts) {
      const n = parseInt(p, 10);
      if (isNaN(n) || n <= 0 || n > 65535 || String(n) !== p) {
        return null;
      }
      nums.push(n);
    }
    const unique = Array.from(new Set(nums)).sort((a, b) => a - b);
    return unique.length > 0 ? unique : null;
  }
  if (Array.isArray(portsInput)) {
    if (portsInput.length === 0) return null;
    const nums = [];
    for (const p of portsInput) {
      const n = typeof p === 'number' ? p : parseInt(p, 10);
      if (isNaN(n) || n <= 0 || n > 65535) return null;
      nums.push(n);
    }
    const unique = Array.from(new Set(nums)).sort((a, b) => a - b);
    return unique.length > 0 ? unique : null;
  }
  return null;
}

export function formatPorts(ports) {
  if (ports === 'all') {
    return 'All ports';
  }
  if (!ports || (Array.isArray(ports) && ports.length === 0)) {
    return '443';
  }
  if (Array.isArray(ports)) {
    return ports.join(', ');
  }
  return String(ports);
}

export function parseDomainTokens(text) {
  if (!text) return [];
  return text
    .split(/[\r\n,;]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

export function isValidDomainToken(token) {
  if (!token) return { valid: false, reason: 'Empty domain' };
  let clean = token.toLowerCase();
  let isWildcard = false;

  if (clean.startsWith('*.')) {
    isWildcard = true;
    clean = clean.slice(2);
  }

  if (!clean || clean.length > 253) {
    return { valid: false, reason: 'Invalid domain length' };
  }

  const labelRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  const labels = clean.split('.');
  if (labels.length < 2 && clean !== 'localhost') {
    return { valid: false, reason: 'Must contain at least two labels (e.g. domain.com)' };
  }

  for (const label of labels) {
    if (!labelRe.test(label)) {
      return { valid: false, reason: `Invalid label: "${label}"` };
    }
  }

  return { valid: true, isWildcard, cleanDomain: (isWildcard ? '*.' : '') + clean };
}

/**
 * Merges apex and wildcard counterpart rows when they share identical configurations.
 * Correctly preserves mode (direct, block, proxy) and calculates combined usage.
 */
export function mergeApexWildcard(domains = []) {
  const map = new Map(); // base domain -> { apex, wildcard }
  const mergedList = [];

  for (const d of domains) {
    const isWc = d.domain.startsWith('*.');
    const base = isWc ? d.domain.slice(2).toLowerCase() : d.domain.toLowerCase();

    if (!map.has(base)) {
      map.set(base, {});
    }
    const entry = map.get(base);
    if (isWc) {
      entry.wildcard = d;
    } else {
      entry.apex = d;
    }
  }

  const processedIds = new Set();

  for (const d of domains) {
    if (processedIds.has(d.id)) continue;

    const isWc = d.domain.startsWith('*.');
    const base = isWc ? d.domain.slice(2).toLowerCase() : d.domain.toLowerCase();
    const pair = map.get(base);

    if (pair && pair.apex && pair.wildcard) {
      const a = pair.apex;
      const w = pair.wildcard;

      const sameMode = (a.mode || 'proxy') === (w.mode || 'proxy');
      const sameGroup = (a.group_name || '') === (w.group_name || '');
      const sameEgress = String(a.use_egress_proxy) === String(w.use_egress_proxy);
      const samePorts = JSON.stringify(a.ports) === JSON.stringify(w.ports);

      if (sameMode && sameGroup && sameEgress && samePorts) {
        processedIds.add(a.id);
        processedIds.add(w.id);

        mergedList.push({
          ...a,
          domain: base,
          is_merged: true,
          mode: a.mode || 'proxy', // B4 fix: preserve actual mode
          apex_id: a.id,
          wildcard_id: w.id,
          total_bytes_sent: (a.total_bytes_sent || 0) + (w.total_bytes_sent || 0),
          total_bytes_received: (a.total_bytes_received || 0) + (w.total_bytes_received || 0),
          created_at: a.created_at < w.created_at ? a.created_at : w.created_at,
        });
        continue;
      }
    }

    processedIds.add(d.id);
    mergedList.push(d);
  }

  return mergedList;
}
