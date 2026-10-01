/**
 * Maps request log statuses to human-friendly labels, tones, and Tailwind classes.
 * Uses full literal class maps for Tailwind purge safety.
 */

const TONE_CLASSES = {
  success: 'badge-success text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  info: 'badge-info text-sky-700 dark:text-sky-400 bg-sky-500/10 border-sky-500/30',
  warning: 'badge-warning text-amber-700 dark:text-amber-400 bg-amber-500/10 border-amber-500/30',
  danger: 'badge-danger text-rose-700 dark:text-rose-400 bg-rose-500/10 border-rose-500/30',
  neutral: 'badge-neutral text-slate-700 dark:text-slate-400 bg-slate-500/10 border-slate-500/30',
};

const STATUS_DEFINITIONS = {
  // Success / Info
  resolved: { label: 'Resolved', tone: 'info' },    // DNS resolution — sky/blue
  relayed: { label: 'Relayed', tone: 'success' },   // TLS relay — emerald/green
  // Legacy statuses kept for rows already in the DB — render consistently.
  connected: { label: 'Relayed', tone: 'success' },
  closed: { label: 'Relayed', tone: 'success' },

  // Warning / Forwarding
  forwarded: { label: 'Forwarded', tone: 'warning' },
  forwarded_unauthorized: { label: 'Passthrough', tone: 'warning' },
  resolved_empty: { label: 'Empty Answer', tone: 'info' },
  redirected_https: { label: 'Redirected HTTPS', tone: 'info' },

  // Warning
  limit: { label: 'Limit Reached', tone: 'warning' },
  rejected_limit: { label: 'Rate Limited', tone: 'warning' },
  timeout: { label: 'Timed Out', tone: 'warning' },
  rejected_timeout: { label: 'Timeout', tone: 'warning' },

  // Errors / Rejections (Danger)
  error: { label: 'Error', tone: 'danger' },
  error_no_relay_ip: { label: 'No Relay IP', tone: 'danger' },
  rejected_domain: { label: 'Domain Rejected', tone: 'danger' },
  rejected_domain_blocked: { label: 'Domain Blocked', tone: 'danger' },
  rejected_direct_mode: { label: 'Direct Mode Block', tone: 'danger' },
  rejected_client_ip: { label: 'IP Rejected', tone: 'danger' },
  rejected_blacklisted: { label: 'Blacklisted', tone: 'danger' },
  rejected_not_registered: { label: 'Unregistered', tone: 'danger' },
  rejected_port: { label: 'Port Disallowed', tone: 'danger' },
  rejected_no_sni: { label: 'No SNI', tone: 'danger' },
  rejected_parse_error: { label: 'Parse Error', tone: 'danger' },
  rejected_dns: { label: 'DNS Error', tone: 'danger' },
  rejected_internal_target: { label: 'Internal Target', tone: 'danger' },
  rejected_dial: { label: 'Dial Failed', tone: 'danger' },
  rejected_replay: { label: 'Replay Rejected', tone: 'danger' },
  rejected_not_http: { label: 'Not HTTP', tone: 'danger' },
  rejected_no_host: { label: 'No Host', tone: 'danger' },
  rejected_header_too_large: { label: 'Header Too Large', tone: 'danger' },
  rejected_ip_invalid: { label: 'Invalid IP', tone: 'danger' },
  rejected_bad_sni: { label: 'Bad SNI', tone: 'danger' },
  rejected_ambiguous_host: { label: 'Ambiguous Host', tone: 'danger' },
};

export function getStatusMeta(status) {
  if (!status) {
    return {
      label: 'Unknown',
      tone: 'neutral',
      className: TONE_CLASSES.neutral,
    };
  }

  const def = STATUS_DEFINITIONS[status];
  if (def) {
    return {
      label: def.label,
      tone: def.tone,
      className: TONE_CLASSES[def.tone] || TONE_CLASSES.neutral,
    };
  }

  // Fallback for custom or unknown status
  const isRejected = status.startsWith('rejected') || status.startsWith('error');
  const tone = isRejected ? 'danger' : 'neutral';
  const label = status.replace(/^rejected_/, '').replace(/_/g, ' ');

  return {
    label: label.charAt(0).toUpperCase() + label.slice(1),
    tone,
    className: TONE_CLASSES[tone],
  };
}
