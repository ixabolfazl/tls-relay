/**
 * Maps request log statuses to human-friendly labels, tones, and Tailwind classes.
 * Uses full literal class maps for Tailwind purge safety.
 */

const TONE_CLASSES = {
  success: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20',
  info: 'bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/20',
  warning: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20',
  danger: 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20',
  neutral: 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/20',
};

const STATUS_DEFINITIONS = {
  // Success
  resolved: { label: 'Resolved', tone: 'success' },
  connected: { label: 'Connected', tone: 'success' },

  // Info
  forwarded: { label: 'Forwarded', tone: 'info' },
  forwarded_unauthorized: { label: 'Passthrough', tone: 'info' },
  resolved_empty: { label: 'Empty Answer', tone: 'info' },
  redirected_https: { label: 'Redirected HTTPS', tone: 'info' },

  // Neutral
  closed: { label: 'Closed', tone: 'neutral' },

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
