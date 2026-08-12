import React, { useState, useEffect, useRef } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadialBarChart, RadialBar, BarChart, Bar, Cell
} from 'recharts';
import axios from 'axios';
import {
  trustColor, trustLabel, DEVICE_ICONS, ATTACK_TYPES,
  API_BASE, TRUST_COLORS
} from '../utils/config';

// ─── Color palette ───────────────────────────────────────────────────────────
const C = {
  bg:        '#0a0f1e',
  surface:   '#0f172a',
  card:      '#111827',
  border:    '#1e2d40',
  accent:    '#06b6d4',
  accentGlow:'#0891b2',
  text:      '#e2e8f0',
  muted:     '#64748b',
  green:     '#22c55e',
  yellow:    '#f59e0b',
  orange:    '#f97316',
  red:       '#ef4444',
  purple:    '#a855f7',
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function Badge({ label, color, bg }) {
  return (
    <span style={{
      background: bg || 'rgba(6,182,212,0.15)',
      color: color || C.accent,
      border: `1px solid ${color || C.accent}33`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: 1,
    }}>{label}</span>
  );
}

function StatCard({ label, value, color, icon }) {
  return (
    <div style={{
      background: C.card,
      border: `1px solid ${C.border}`,
      borderRadius: 10,
      padding: '16px 20px',
      flex: 1,
      minWidth: 100,
    }}>
      <div style={{ color: C.muted, fontSize: 11, marginBottom: 6, letterSpacing: 1 }}>
        {icon} {label}
      </div>
      <div style={{ color: color || C.text, fontSize: 28, fontWeight: 800 }}>{value}</div>
    </div>
  );
}

// ─── Trust Score Gauge ────────────────────────────────────────────────────────
function TrustGauge({ score }) {
  const color = trustColor(score);
  const data = [{ value: score, fill: color }, { value: 100 - score, fill: '#1e293b' }];
  return (
    <div style={{ position: 'relative', width: 80, height: 80 }}>
      <RadialBarChart
        width={80} height={80}
        innerRadius={26} outerRadius={38}
        data={data} startAngle={225} endAngle={-45}
      >
        <RadialBar dataKey="value" cornerRadius={4} />
      </RadialBarChart>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ color, fontSize: 16, fontWeight: 800, lineHeight: 1 }}>
          {Math.round(score)}
        </span>
        <span style={{ color: C.muted, fontSize: 8, marginTop: 2 }}>TRUST</span>
      </div>
    </div>
  );
}

// ─── Device Card ─────────────────────────────────────────────────────────────
function DeviceCard({ device }) {
  const color = trustColor(device.trust_score);
  const label = trustLabel(device.trust_score);
  return (
    <div style={{
      background: C.card,
      border: `1px solid ${device.drift_detected ? color + '55' : C.border}`,
      borderRadius: 12,
      padding: 16,
      display: 'flex',
      alignItems: 'center',
      gap: 14,
      boxShadow: device.drift_detected ? `0 0 12px ${color}22` : 'none',
      transition: 'all 0.4s ease',
    }}>
      <TrustGauge score={device.trust_score} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ fontSize: 14 }}>{DEVICE_ICONS[device.device_type] || '📟'}</span>
          <span style={{ color: C.text, fontWeight: 700, fontSize: 13 }}>
            {device.device_id}
          </span>
          <Badge label={label} color={color} />
        </div>
        <div style={{ color: C.muted, fontSize: 11 }}>
          {device.device_type?.toUpperCase()} · {device.ip_address}
        </div>
        {device.drift_detected && (
          <div style={{
            marginTop: 6,
            color: color,
            fontSize: 10,
            padding: '2px 6px',
            background: color + '18',
            borderRadius: 4,
            display: 'inline-block',
          }}>
            ⚠ DRIFT DETECTED
          </div>
        )}
        {device.explanation && device.trust_score < 70 && (
          <div style={{
            marginTop: 6, color: C.muted, fontSize: 10,
            lineHeight: 1.4, maxWidth: 240,
          }}>
            {device.explanation}
          </div>
        )}
      </div>
      <div style={{ textAlign: 'right', minWidth: 80 }}>
        <div style={{ color: C.muted, fontSize: 10, marginBottom: 2 }}>ANOMALY</div>
        <div style={{
          background: `linear-gradient(90deg, ${C.accentGlow}22, ${color}22)`,
          borderRadius: 4, height: 6, marginBottom: 6, position: 'relative',
        }}>
          <div style={{
            background: color,
            borderRadius: 4,
            height: '100%',
            width: `${Math.round((device.anomaly_score || 0) * 100)}%`,
            transition: 'width 0.5s ease',
          }} />
        </div>
        <div style={{ color, fontSize: 11, fontWeight: 700 }}>
          {Math.round((device.anomaly_score || 0) * 100)}%
        </div>
      </div>
    </div>
  );
}

// ─── Alert Feed ───────────────────────────────────────────────────────────────
function AlertFeed({ alerts }) {
  const severityColor = { critical: C.red, high: C.orange, medium: C.yellow };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 380, overflowY: 'auto' }}>
      {alerts.length === 0 && (
        <div style={{ color: C.muted, fontSize: 13, textAlign: 'center', padding: 20 }}>
          ✅ No active alerts
        </div>
      )}
      {alerts.map((a, i) => (
        <div key={a.id || i} style={{
          background: C.surface,
          border: `1px solid ${(severityColor[a.severity] || C.border)}33`,
          borderLeft: `3px solid ${severityColor[a.severity] || C.border}`,
          borderRadius: 6,
          padding: '10px 14px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{
              color: severityColor[a.severity] || C.muted,
              fontSize: 11, fontWeight: 700, letterSpacing: 0.5
            }}>
              {a.severity?.toUpperCase()} · {a.device_id}
            </span>
            <span style={{ color: C.muted, fontSize: 10 }}>
              {a.timestamp ? new Date(a.timestamp * 1000).toLocaleTimeString() : ''}
            </span>
          </div>
          <div style={{ color: C.text, fontSize: 12 }}>{a.explanation}</div>
          {a.trust_score !== undefined && (
            <div style={{ color: C.muted, fontSize: 10, marginTop: 3 }}>
              Trust score: {a.trust_score} · Drop: {a.drop}pts
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Attack Simulator Panel ───────────────────────────────────────────────────
function AttackPanel({ devices }) {
  const [selected, setSelected] = useState('mirai');
  const [targetDevice, setTargetDevice] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);

  const triggerAttack = async () => {
    setLoading(true);
    setStatus('');
    try {
      const payload = {
        attack_type: selected,
        duration_seconds: 30,
      };
      if (targetDevice) payload.target_device_id = targetDevice;
      const res = await axios.post(`${API_BASE}/simulate/attack`, payload);
      setStatus(`✅ ${res.data.name} launched on ${res.data.target_device_id}!`);
    } catch (e) {
      setStatus(`❌ Error: ${e.message}`);
    }
    setLoading(false);
  };

  const resetAll = async () => {
    await axios.post(`${API_BASE}/simulate/reset`);
    setStatus('🔄 All devices reset to baseline');
  };

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
        {ATTACK_TYPES.map(atk => (
          <button
            key={atk.id}
            onClick={() => setSelected(atk.id)}
            style={{
              background: selected === atk.id ? atk.color + '33' : C.surface,
              border: `1px solid ${selected === atk.id ? atk.color : C.border}`,
              borderRadius: 8,
              padding: '10px 12px',
              cursor: 'pointer',
              color: selected === atk.id ? atk.color : C.muted,
              fontSize: 12,
              fontWeight: 700,
              textAlign: 'left',
              transition: 'all 0.2s',
            }}
          >
            <div style={{ fontSize: 18, marginBottom: 2 }}>{atk.icon}</div>
            {atk.label}
          </button>
        ))}
      </div>

      <select
        value={targetDevice}
        onChange={e => setTargetDevice(e.target.value)}
        style={{
          width: '100%',
          background: C.surface,
          border: `1px solid ${C.border}`,
          color: C.text,
          borderRadius: 6,
          padding: '8px 10px',
          fontSize: 12,
          marginBottom: 10,
        }}
      >
        <option value="">Auto-select target device</option>
        {devices.map(d => (
          <option key={d.device_id} value={d.device_id}>
            {DEVICE_ICONS[d.device_type]} {d.device_id} ({d.device_type})
          </option>
        ))}
      </select>

      <div style={{ display: 'flex', gap: 8 }}>
        <button
          onClick={triggerAttack}
          disabled={loading}
          style={{
            flex: 1,
            background: loading ? C.border : 'linear-gradient(135deg, #dc2626, #991b1b)',
            border: 'none',
            borderRadius: 8,
            padding: '10px 16px',
            color: '#fff',
            fontSize: 13,
            fontWeight: 700,
            cursor: loading ? 'wait' : 'pointer',
          }}
        >
          {loading ? '⚡ Launching...' : '🔴 Launch Attack'}
        </button>
        <button
          onClick={resetAll}
          style={{
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 8,
            padding: '10px 16px',
            color: C.muted,
            fontSize: 13,
            cursor: 'pointer',
          }}
        >
          ↺ Reset
        </button>
      </div>

      {status && (
        <div style={{
          marginTop: 10,
          padding: '8px 12px',
          background: status.startsWith('✅') ? '#052e16' : '#450a0a',
          borderRadius: 6,
          color: status.startsWith('✅') ? C.green : C.red,
          fontSize: 12,
        }}>
          {status}
        </div>
      )}
    </div>
  );
}

// ─── Network Topology (Simple Canvas) ────────────────────────────────────────
function NetworkTopology({ devices }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !devices.length) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    const n = devices.length;
    const cx = W / 2, cy = H / 2, r = Math.min(W, H) * 0.36;

    // Draw edges (hub-and-spoke to gateway/router)
    const hub = devices.find(d => d.device_type === 'router' || d.device_type === 'gateway') || devices[0];
    const hubIdx = devices.indexOf(hub);
    const positions = devices.map((_, i) => {
      if (i === hubIdx) return { x: cx, y: cy };
      const angle = (2 * Math.PI * i) / n - Math.PI / 2;
      return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });

    devices.forEach((_, i) => {
      if (i === hubIdx) return;
      ctx.beginPath();
      ctx.moveTo(positions[hubIdx].x, positions[hubIdx].y);
      ctx.lineTo(positions[i].x, positions[i].y);
      ctx.strokeStyle = '#1e2d4066';
      ctx.lineWidth = 1;
      ctx.stroke();
    });

    // Draw nodes
    devices.forEach((dev, i) => {
      const pos = positions[i];
      const color = trustColor(dev.trust_score || 80);

      // Glow for compromised
      if ((dev.trust_score || 100) < 50) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 22, 0, Math.PI * 2);
        ctx.fillStyle = color + '22';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = '#111827';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.fillStyle = C.text;
      ctx.font = '11px monospace';
      ctx.textAlign = 'center';
      ctx.fillText(dev.device_id?.replace('dev-', '#'), pos.x, pos.y + 4);

      ctx.fillStyle = C.muted;
      ctx.font = '9px sans-serif';
      ctx.fillText(dev.device_type || '', pos.x, pos.y + 24);
    });
  }, [devices]);

  return (
    <canvas
      ref={canvasRef}
      width={320} height={280}
      style={{ width: '100%', height: 280, borderRadius: 8 }}
    />
  );
}

// ─── Drift Heatmap ────────────────────────────────────────────────────────────
function DriftHeatmap({ devices }) {
  if (!devices.length) return null;
  const rows = devices.slice(0, 6);
  const cols = 15;

  return (
    <div>
      {rows.map(dev => (
        <div key={dev.device_id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <div style={{ color: C.muted, fontSize: 10, width: 60, textAlign: 'right', flexShrink: 0 }}>
            {dev.device_id}
          </div>
          <div style={{ display: 'flex', gap: 2, flex: 1 }}>
            {Array.from({ length: cols }).map((_, i) => {
              const simScore = (dev.trust_score || 80) + (i - cols + 1) * 1.5 + Math.random() * 3 - 1.5;
              const clipped = Math.max(0, Math.min(100, simScore));
              const alpha = (100 - clipped) / 100;
              return (
                <div
                  key={i}
                  style={{
                    flex: 1,
                    height: 16,
                    borderRadius: 2,
                    background: `rgba(239,68,68,${alpha.toFixed(2)})`,
                  }}
                  title={`t-${cols - i}: ${clipped.toFixed(0)}`}
                />
              );
            })}
          </div>
        </div>
      ))}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
        <span style={{ color: C.muted, fontSize: 9 }}>← 7.5min ago</span>
        <span style={{ color: C.muted, fontSize: 9 }}>Low Risk ←→ High Risk</span>
        <span style={{ color: C.muted, fontSize: 9 }}>now →</span>
      </div>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function Dashboard({ devices, summary, alerts, connected }) {
  const [historyData, setHistoryData] = useState([]);
  const histRef = useRef({});

  // Maintain rolling history for chart
  useEffect(() => {
    if (!devices.length) return;
    const ts = new Date().toLocaleTimeString('en', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const point = { time: ts };
    devices.forEach(d => {
      point[d.device_id] = Math.round(d.trust_score || 0);
    });
    setHistoryData(prev => [...prev.slice(-30), point]);
  }, [devices]);

  const criticalDevices = devices.filter(d => (d.trust_score || 100) < 50);
  const deviceColors = ['#06b6d4', '#a855f7', '#f59e0b', '#22c55e', '#f97316', '#ec4899', '#84cc16', '#14b8a6'];

  return (
    <div style={{
      background: C.bg,
      minHeight: '100vh',
      color: C.text,
      fontFamily: "'Inter', 'Segoe UI', sans-serif",
      padding: 0,
    }}>
      {/* Header */}
      <div style={{
        background: C.surface,
        borderBottom: `1px solid ${C.border}`,
        padding: '14px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 24 }}>🛡️</div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 800, color: C.text, letterSpacing: 0.5 }}>
              SentinelTrust
            </div>
            <div style={{ fontSize: 10, color: C.muted, letterSpacing: 1 }}>
              PREDICTIVE BEHAVIORAL TRUST ENGINE · IoT NETWORKS
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {criticalDevices.length > 0 && (
            <div style={{
              background: '#450a0a',
              border: `1px solid ${C.red}44`,
              borderRadius: 6,
              padding: '4px 12px',
              color: C.red,
              fontSize: 12,
              fontWeight: 700,
              animation: 'pulse 2s infinite',
            }}>
              🔴 {criticalDevices.length} CRITICAL DEVICE{criticalDevices.length > 1 ? 'S' : ''}
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? C.green : C.red,
              boxShadow: connected ? `0 0 8px ${C.green}` : 'none',
            }} />
            <span style={{ color: C.muted, fontSize: 12 }}>
              {connected ? 'LIVE' : 'CONNECTING...'}
            </span>
          </div>
        </div>
      </div>

      <div style={{ padding: '20px 28px' }}>
        {/* Summary Stats */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
          <StatCard label="TOTAL DEVICES" value={summary.total_devices || 0} icon="📟" color={C.accent} />
          <StatCard label="SECURE DEVICES" value={(summary.trusted || 0) + (summary.stable || 0)} icon="🔒" color={C.green} />
          <StatCard label="NOT SECURE" value={(summary.suspicious || 0) + (summary.high_risk || 0) + (summary.critical || 0)} icon="🔓" color={C.red} />
          <StatCard label="HIGH RISK / CRITICAL" value={(summary.high_risk || 0) + (summary.critical || 0)} icon="🔴" color={C.red} />
          <StatCard label="ACTIVE ALERTS" value={summary.active_alerts || 0} icon="🚨" color={C.orange} />
          <StatCard label="DRIFT DETECTED" value={summary.drift_detected || 0} icon="📈" color={C.purple} />
        </div>

        {/* Main Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 16, marginBottom: 16 }}>

          {/* Trust Score Timeline */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14, marginBottom: 16 }}>
              📈 Trust Score Timeline (All Devices)
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={historyData}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                <XAxis dataKey="time" tick={{ fill: C.muted, fontSize: 10 }} />
                <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8 }}
                  labelStyle={{ color: C.muted }}
                />
                {devices.map((d, i) => (
                  <Line
                    key={d.device_id}
                    type="monotone"
                    dataKey={d.device_id}
                    stroke={deviceColors[i % deviceColors.length]}
                    dot={false}
                    strokeWidth={2}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Attack Simulator */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14, marginBottom: 16 }}>
              ⚡ Attack Simulator
            </div>
            <AttackPanel devices={devices} />
          </div>
        </div>

        {/* Second row */}
        <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 16, marginBottom: 16 }}>
          {/* Network Topology */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14, marginBottom: 12 }}>
              🕸️ Network Topology
            </div>
            <NetworkTopology devices={devices} />
          </div>

          {/* Drift Heatmap */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14, marginBottom: 12 }}>
              🔥 Behavioral Drift Heatmap
            </div>
            <DriftHeatmap devices={devices} />

            {/* Trust distribution bar chart */}
            <div style={{ marginTop: 20 }}>
              <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>Trust Distribution</div>
              <ResponsiveContainer width="100%" height={100}>
                <BarChart data={[
                  { name: 'Trusted',   value: summary.trusted || 0,   fill: TRUST_COLORS.trusted },
                  { name: 'Stable',    value: summary.stable || 0,    fill: TRUST_COLORS.stable },
                  { name: 'Suspicious',value: summary.suspicious || 0,fill: TRUST_COLORS.suspicious },
                  { name: 'High Risk', value: summary.high_risk || 0, fill: TRUST_COLORS.high_risk },
                  { name: 'Critical',  value: summary.critical || 0,  fill: TRUST_COLORS.critical },
                ]}>
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {[C.green, '#84cc16', C.yellow, C.orange, C.red].map((c, i) => (
                      <Cell key={i} fill={c} />
                    ))}
                  </Bar>
                  <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: C.surface, border: `1px solid ${C.border}` }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Bottom row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* Device Grid */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14, marginBottom: 12 }}>
              📟 Device Trust Scores
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 400, overflowY: 'auto' }}>
              {devices
                .sort((a, b) => (a.trust_score || 0) - (b.trust_score || 0))
                .map(d => <DeviceCard key={d.device_id} device={d} />)
              }
            </div>
          </div>

          {/* Alert Feed */}
          <div style={{
            background: C.card,
            border: `1px solid ${C.border}`,
            borderRadius: 12,
            padding: '16px 20px',
          }}>
            <div style={{
              display: 'flex', justifyContent: 'space-between',
              alignItems: 'center', marginBottom: 12
            }}>
              <div style={{ color: C.text, fontWeight: 700, fontSize: 14 }}>
                🚨 Security Alert Feed
              </div>
              {alerts.length > 0 && (
                <Badge label={`${alerts.length} ALERTS`} color={C.red} />
              )}
            </div>
            <AlertFeed alerts={alerts} />
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e2d40; border-radius: 2px; }
      `}</style>
    </div>
  );
}
