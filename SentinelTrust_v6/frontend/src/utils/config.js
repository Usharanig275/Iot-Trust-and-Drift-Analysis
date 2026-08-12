export const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
export const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';

export const TRUST_COLORS = {
  trusted:      '#22c55e',
  stable:       '#84cc16',
  suspicious:   '#f59e0b',
  high_risk:    '#f97316',
  critical:     '#ef4444',
};

export const TRUST_BG = {
  trusted:      '#052e16',
  stable:       '#1a2e05',
  suspicious:   '#451a03',
  high_risk:    '#431407',
  critical:     '#450a0a',
};

export function trustColor(score) {
  if (score >= 90) return TRUST_COLORS.trusted;
  if (score >= 70) return TRUST_COLORS.stable;
  if (score >= 50) return TRUST_COLORS.suspicious;
  if (score >= 30) return TRUST_COLORS.high_risk;
  return TRUST_COLORS.critical;
}

export function trustLabel(score) {
  if (score >= 90) return 'TRUSTED';
  if (score >= 70) return 'STABLE';
  if (score >= 50) return 'SUSPICIOUS';
  if (score >= 30) return 'HIGH RISK';
  return 'CRITICAL';
}

export const DEVICE_ICONS = {
  camera:     '📷',
  sensor:     '📡',
  router:     '🔀',
  thermostat: '🌡️',
  gateway:    '🔌',
};

export const ATTACK_TYPES = [
  { id: 'mirai',            label: 'Mirai Botnet',       icon: '🦠', color: '#dc2626' },
  { id: 'exfiltration',     label: 'Data Exfiltration',  icon: '📤', color: '#7c3aed' },
  { id: 'lateral_movement', label: 'Lateral Movement',   icon: '↔️',  color: '#d97706' },
  { id: 'port_scan',        label: 'Port Scan',          icon: '🔍', color: '#0891b2' },
];
