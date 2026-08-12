import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line,
} from "recharts";

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";
const WS  = process.env.REACT_APP_WS_URL  || "ws://localhost:8000/ws";

const FEATURE_COLS = [
  "packet_rate","byte_entropy","protocol_tcp_ratio","dns_query_freq",
  "unique_dest_ips","avg_connection_duration","port_entropy",
  "bandwidth_mbps","new_ext_conns","tcp_flag_anomaly",
];
const FEATURE_LABELS = {
  packet_rate:"Packet Rate (pkt/s)", byte_entropy:"Byte Entropy (0-8)",
  protocol_tcp_ratio:"TCP Ratio (0-1)", dns_query_freq:"DNS Queries/30s",
  unique_dest_ips:"Unique Dest IPs", avg_connection_duration:"Avg Conn Duration (s)",
  port_entropy:"Port Entropy", bandwidth_mbps:"Bandwidth (Mbps)",
  new_ext_conns:"New Ext Connections", tcp_flag_anomaly:"TCP Flag Anomaly (0-1)",
};
const DEVICE_TYPES = ["ip_camera","temp_sensor","router","smart_hub","plc","smart_lock","gateway","actuator","other"];
const C = {
  bg:"#050d1a", surface:"#0a1628", card:"#0d1f35", border:"#1a3354",
  accent:"#00d4ff", accentDim:"#0099bb", green:"#00e676", yellow:"#ffb300",
  orange:"#ff6d00", red:"#ff1744", purple:"#d500f9", text:"#e8f4fd",
  muted:"#5a7a9a", white:"#ffffff",
};
const LEVEL_COLOR = {trusted:C.green,stable:"#76ff03",suspicious:C.yellow,high_risk:C.orange,critical:C.red};
const TRUST_LBL   = {trusted:"TRUSTED",stable:"STABLE",suspicious:"SUSPICIOUS",high_risk:"HIGH RISK",critical:"CRITICAL"};
const ATTACK_COLORS = {mirai:C.red,exfiltration:"#aa00ff",lateral_movement:C.orange,port_scan:C.accent};
const LEVEL_STYLE = {
  trusted:{bg:"#dcfce7",text:"#15803d",border:"#16a34a"},
  stable:{bg:"#ecfccb",text:"#3f6212",border:"#65a30d"},
  suspicious:{bg:"#fef9c3",text:"#92400e",border:"#d97706"},
  high_risk:{bg:"#ffedd5",text:"#9a3412",border:"#ea580c"},
  critical:{bg:"#fee2e2",text:"#991b1b",border:"#dc2626"},
};

function trustColor(s){if(s>=90)return C.green;if(s>=70)return"#76ff03";if(s>=50)return C.yellow;if(s>=30)return C.orange;return C.red;}

// ── Helper: build headers with user email for isolation ──────────────────────
function authHeaders(user) {
  const h = { "Content-Type": "application/json" };
  if (user?.email) h["X-User-Email"] = user.email;
  return h;
}
function formHeaders(user) {
  const h = {};
  if (user?.email) h["X-User-Email"] = user.email;
  return h;
}

// ── Base UI ───────────────────────────────────────────────────────────────────
const GlassCard = ({children, style={}, glow=null}) => (
  <div style={{background:"linear-gradient(135deg,rgba(13,31,53,0.95),rgba(10,22,40,0.98))",
    border:`1px solid ${glow?glow+"44":C.border}`,borderRadius:16,
    boxShadow:glow?`0 0 24px ${glow}22,0 4px 24px rgba(0,0,0,0.4)`:"0 4px 24px rgba(0,0,0,0.4)",
    padding:20,...style}}>
    {children}
  </div>
);
const Card = ({children,style={}}) => (
  <div style={{background:"#fff",border:"1px solid #e5e7eb",borderRadius:8,padding:20,boxShadow:"0 1px 3px rgba(0,0,0,0.07)",...style}}>{children}</div>
);
const Btn = ({children,onClick,color="blue",disabled=false,size="md",style={}}) => {
  const colors={blue:{bg:"#2563eb",text:"#fff"},green:{bg:"#16a34a",text:"#fff"},red:{bg:"#dc2626",text:"#fff"},gray:{bg:"#f3f4f6",text:"#374151"}};
  const c=colors[color]||colors.blue;
  const pad=size==="sm"?"5px 12px":size==="lg"?"10px 24px":"7px 16px";
  return <button onClick={onClick} disabled={disabled} style={{background:disabled?"#9ca3af":c.bg,color:c.text,border:"none",borderRadius:6,padding:pad,cursor:disabled?"not-allowed":"pointer",fontSize:13,fontWeight:600,...style}}>{children}</button>;
};
const SectionTitle = ({children}) => (
  <h2 style={{fontSize:16,fontWeight:700,color:"#111827",marginBottom:16,paddingBottom:8,borderBottom:"2px solid #e5e7eb"}}>{children}</h2>
);
const Badge = ({level}) => {
  const s=LEVEL_STYLE[level]||LEVEL_STYLE.suspicious;
  return <span style={{background:s.bg,color:s.text,border:`1px solid ${s.border}`,borderRadius:4,padding:"2px 8px",fontSize:11,fontWeight:700}}>{level?.replace("_"," ").toUpperCase()}</span>;
};
const ScoreBar = ({value}) => {
  const color=value>=70?"#16a34a":value>=50?"#d97706":"#dc2626";
  return <div style={{height:8,background:"#e5e7eb",borderRadius:4,overflow:"hidden"}}><div style={{width:`${Math.min(100,value)}%`,height:"100%",background:color,transition:"width 0.5s",borderRadius:4}}/></div>;
};
const PulseDot = ({color=C.green,size=10}) => (
  <span style={{display:"inline-block",width:size,height:size,borderRadius:"50%",background:color,boxShadow:`0 0 8px ${color}`}}/>
);
function ScoreRing({score,size=80}){
  const color=trustColor(score),r=size*0.38,circ=2*Math.PI*r,dash=(score/100)*circ;
  return(
    <div style={{position:"relative",width:size,height:size,flexShrink:0}}>
      <svg width={size} height={size} style={{transform:"rotate(-90deg)"}}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={C.border} strokeWidth={size*0.08}/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={size*0.08}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{filter:`drop-shadow(0 0 6px ${color})`,transition:"stroke-dasharray 0.8s ease"}}/>
      </svg>
      <div style={{position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center"}}>
        <span style={{color,fontSize:size*0.22,fontWeight:900,lineHeight:1}}>{Math.round(score)}</span>
        <span style={{color:C.muted,fontSize:size*0.1,letterSpacing:1}}>TRUST</span>
      </div>
    </div>
  );
}

// ── Login Input ───────────────────────────────────────────────────────────────
function LoginInput({label,value,onChange,placeholder,type="text"}){
  return(
    <div>
      <label style={{display:"block",fontSize:10,fontWeight:700,color:C.muted,letterSpacing:2,marginBottom:6}}>{label}</label>
      <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
        style={{width:"100%",padding:"11px 14px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,
          color:C.text,fontSize:13,outline:"none",fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}
        onFocus={e=>e.target.style.borderColor=C.accent} onBlur={e=>e.target.style.borderColor=C.border}/>
    </div>
  );
}

// ── Login Page ────────────────────────────────────────────────────────────────
function LoginPage({onLogin}){
  const[mode,setMode]=useState("login");
  const[role,setRole]=useState("user");
  const[form,setForm]=useState({name:"",email:"",phone:"",password:"",confirm:""});
  const[error,setError]=useState("");
  const[loading,setLoading]=useState(false);
  const[success,setSuccess]=useState("");
  const set=(k,v)=>setForm(f=>({...f,[k]:v}));

  const handleSubmit=async()=>{
    setError("");setSuccess("");setLoading(true);
    try{
      if(mode==="register"){
        if(!form.name||!form.email||!form.password){setError("Please fill all required fields");setLoading(false);return;}
        if(form.password!==form.confirm){setError("Passwords do not match");setLoading(false);return;}
        const ep=role==="user"?"/api/v1/auth/register/user":"/api/v1/auth/register/admin";
        const body=role==="user"
          ?{name:form.name,email:form.email,phone:form.phone,password:form.password}
          :{name:form.name,email:form.email,password:form.password};
        const res=await fetch(`${API}${ep}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
        const data=await res.json();
        if(data.detail){setError(data.detail);setLoading(false);return;}
        setSuccess("Account created! Please login.");setMode("login");
      }else{
        const res=await fetch(`${API}/api/v1/auth/login`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:form.email,password:form.password,role})});
        const data=await res.json();
        if(data.detail){setError(data.detail);setLoading(false);return;}
        onLogin(data);
      }
    }catch(e){setError("Server error. Make sure backend is running on port 8000.");}
    setLoading(false);
  };

  return(
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'Courier New',monospace",position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",inset:0,opacity:0.04,backgroundImage:`repeating-linear-gradient(0deg,${C.accent} 0,${C.accent} 1px,transparent 1px,transparent 40px),repeating-linear-gradient(90deg,${C.accent} 0,${C.accent} 1px,transparent 1px,transparent 40px)`}}/>
      <div style={{position:"absolute",width:500,height:500,borderRadius:"50%",background:`radial-gradient(circle,${C.accent}10 0%,transparent 70%)`,top:-150,left:-150,pointerEvents:"none"}}/>
      <div style={{width:"100%",maxWidth:440,padding:"0 20px",position:"relative"}}>
        <div style={{textAlign:"center",marginBottom:32}}>
          <div style={{fontSize:52,marginBottom:10}}>🛡️</div>
          <h1 style={{color:C.white,fontSize:28,fontWeight:900,margin:0,letterSpacing:4,textShadow:`0 0 30px ${C.accent}66`}}>
            SENTINEL<span style={{color:C.accent}}>TRUST</span>
          </h1>
          <p style={{color:C.muted,fontSize:11,letterSpacing:3,marginTop:8}}>IoT BEHAVIORAL SECURITY ENGINE</p>
        </div>
        <GlassCard glow={C.accent}>
          <div style={{display:"flex",background:C.bg,borderRadius:10,padding:4,marginBottom:20}}>
            {["user","admin"].map(r=>(
              <button key={r} onClick={()=>setRole(r)} style={{flex:1,padding:"10px 0",borderRadius:8,
                border:role===r?`1px solid ${C.accent}44`:"1px solid transparent",
                background:role===r?`linear-gradient(135deg,${C.accent}33,${C.accent}11)`:"transparent",
                color:role===r?C.accent:C.muted,fontWeight:700,fontSize:12,letterSpacing:2,
                cursor:"pointer",transition:"all 0.2s",fontFamily:"'Courier New',monospace"}}>
                {r==="user"?"👤 USER":"🔐 ADMIN"}
              </button>
            ))}
          </div>
          <div style={{display:"flex",gap:16,marginBottom:20}}>
            {["login","register"].map(m=>(
              <button key={m} onClick={()=>{setMode(m);setError("");setSuccess("");}} style={{background:"none",border:"none",cursor:"pointer",padding:"4px 0",color:mode===m?C.accent:C.muted,fontWeight:700,fontSize:13,letterSpacing:1,borderBottom:mode===m?`2px solid ${C.accent}`:"2px solid transparent",transition:"all 0.2s",fontFamily:"'Courier New',monospace"}}>
                {m.toUpperCase()}
              </button>
            ))}
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {mode==="register"&&<LoginInput label="FULL NAME *" value={form.name} onChange={v=>set("name",v)} placeholder="Enter your name"/>}
            <LoginInput label="EMAIL ADDRESS *" value={form.email} onChange={v=>set("email",v)} placeholder="Enter email" type="email"/>
            {mode==="register"&&role==="user"&&<LoginInput label="PHONE NUMBER" value={form.phone} onChange={v=>set("phone",v)} placeholder="+91 XXXXXXXXXX"/>}
            <LoginInput label="PASSWORD *" value={form.password} onChange={v=>set("password",v)} placeholder="Enter password" type="password"/>
            {mode==="register"&&<LoginInput label="CONFIRM PASSWORD *" value={form.confirm} onChange={v=>set("confirm",v)} placeholder="Repeat password" type="password"/>}
          </div>
          {error&&<div style={{marginTop:12,padding:"10px 14px",background:C.red+"22",border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12}}>❌ {error}</div>}
          {success&&<div style={{marginTop:12,padding:"10px 14px",background:C.green+"22",border:`1px solid ${C.green}44`,borderRadius:8,color:C.green,fontSize:12}}>✅ {success}</div>}
          <button onClick={handleSubmit} disabled={loading} style={{marginTop:20,width:"100%",padding:"14px 0",background:loading?C.muted:`linear-gradient(135deg,${C.accent},${C.accentDim})`,border:"none",borderRadius:10,color:C.bg,fontWeight:900,fontSize:14,letterSpacing:2,cursor:loading?"wait":"pointer",fontFamily:"'Courier New',monospace",boxShadow:loading?"none":`0 0 20px ${C.accent}44`,transition:"all 0.2s"}}>
            {loading?"PROCESSING...":(mode==="login"?"→ ENTER SYSTEM":"→ CREATE ACCOUNT")}
          </button>
        </GlassCard>
        <p style={{textAlign:"center",color:C.muted,fontSize:10,marginTop:16,letterSpacing:1}}>ZERO-TRUST IoT SECURITY ARCHITECTURE</p>
      </div>
    </div>
  );
}

// ── TrustScoreCard ────────────────────────────────────────────────────────────
const TrustScoreCard = ({result}) => {
  if(!result)return null;
  const s=LEVEL_STYLE[result.level]||LEVEL_STYLE.suspicious;
  return(
    <Card style={{border:`2px solid ${s.border}`}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16}}>
        <div>
          <div style={{fontSize:13,color:"#6b7280",marginBottom:4}}>Trust Score</div>
          <div style={{fontSize:52,fontWeight:900,color:s.border,lineHeight:1}}>{result.score}</div>
          <div style={{fontSize:11,color:"#6b7280"}}>/100</div>
        </div>
        <Badge level={result.level}/>
      </div>
      <div style={{background:"#f9fafb",borderRadius:6,padding:"10px 14px",marginBottom:16,fontSize:13,color:"#374151",lineHeight:1.6}}>{result.explanation}</div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
        {[["Behavioral Stability",result.behavioral_stability],["Policy Compliance",result.policy_compliance],["Historical Trust",result.historical_trust],["Recent Activity",result.recent_activity]].map(([label,val])=>(
          <div key={label}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:12,marginBottom:4}}><span style={{color:"#6b7280"}}>{label}</span><span style={{fontWeight:700}}>{Math.round(val||0)}</span></div>
            <ScoreBar value={val||0}/>
          </div>
        ))}
      </div>
      {result.top_risk_factors?.length>0&&(
        <div>
          <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:6}}>⚠ Drifted Features</div>
          {result.top_risk_factors.map((f,i)=>(<div key={i} style={{background:"#fef2f2",border:"1px solid #fecaca",borderRadius:4,padding:"4px 8px",fontSize:11,color:"#991b1b",marginBottom:4}}>{f}</div>))}
        </div>
      )}
      {result.feature_zscores&&Object.keys(result.feature_zscores).length>0&&(
        <details style={{marginTop:12}}>
          <summary style={{fontSize:12,fontWeight:600,color:"#4b5563",cursor:"pointer"}}>Feature Z-Scores (drift from baseline)</summary>
          <div style={{marginTop:8}}>
            {Object.entries(result.feature_zscores).sort((a,b)=>b[1]-a[1]).map(([col,z])=>(
              <div key={col} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"4px 0",borderBottom:"1px solid #f3f4f6",fontSize:12}}>
                <span style={{color:"#374151"}}>{FEATURE_LABELS[col]||col}</span>
                <span style={{fontWeight:700,color:z>2?"#dc2626":z>1?"#d97706":"#16a34a",fontFamily:"monospace"}}>{z>2?"⚠ ":""}{z.toFixed(2)}σ</span>
              </div>
            ))}
          </div>
        </details>
      )}
      <div style={{display:"flex",gap:16,marginTop:12,fontSize:11,color:"#9ca3af"}}>
        <span>Drift: {result.drift_score?.toFixed(3)}</span>
        <span>Trend: {result.trend} ({result.trend_delta>0?"+":""}{result.trend_delta})</span>
        <span>Predicted: {result.predicted_score}</span>
      </div>
    </Card>
  );
};

// ── Add Device Tab ────────────────────────────────────────────────────────────
function AddDeviceTab({user,onDeviceAdded}){
  const[form,setForm]=useState({id:"",name:"",type:"ip_camera",ip:"",description:""});
  const[status,setStatus]=useState(null);
  const set=(k,v)=>setForm(f=>({...f,[k]:v}));

  const submit=async()=>{
    if(!form.id||!form.name||!form.ip){setStatus({ok:false,msg:"Device ID, Name and IP are required."});return;}
    const res=await fetch(`${API}/api/v1/devices/register`,{method:"POST",headers:authHeaders(user),body:JSON.stringify(form)});
    const data=await res.json();
    if(data.error){setStatus({ok:false,msg:data.error});return;}
    setStatus({ok:true,msg:`Device "${form.id}" registered successfully!`});
    setForm({id:"",name:"",type:"ip_camera",ip:"",description:""});
    onDeviceAdded();
  };

  return(
    <div style={{maxWidth:520}}>
      <SectionTitle>Register New Device</SectionTitle>
      <Card>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Device ID *</label>
          <input value={form.id} onChange={e=>set("id",e.target.value)} placeholder="e.g. camera-003" style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Device Name *</label>
          <input value={form.name} onChange={e=>set("name",e.target.value)} placeholder="e.g. Lobby Camera" style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Device Type</label>
          <select value={form.type} onChange={e=>set("type",e.target.value)} style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,background:"#fff",boxSizing:"border-box"}}>
            {DEVICE_TYPES.map(t=><option key={t} value={t}>{t.replace("_"," ")}</option>)}
          </select>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>IP Address *</label>
          <input value={form.ip} onChange={e=>set("ip",e.target.value)} placeholder="e.g. 192.168.1.50" style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Description</label>
          <input value={form.description} onChange={e=>set("description",e.target.value)} placeholder="Optional notes" style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
        </div>
        <Btn onClick={submit} color="blue" size="lg">+ Register Device</Btn>
        {status&&<div style={{marginTop:12,padding:"10px 14px",borderRadius:6,fontSize:13,background:status.ok?"#dcfce7":"#fee2e2",color:status.ok?"#15803d":"#991b1b"}}>{status.msg}</div>}
      </Card>
      <div style={{marginTop:24}}>
        <SectionTitle>Expected Feature Columns</SectionTitle>
        <Card style={{padding:0,overflow:"hidden"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead><tr style={{background:"#f9fafb"}}><th style={{padding:"8px 12px",textAlign:"left",color:"#374151",fontWeight:600}}>Column</th><th style={{padding:"8px 12px",textAlign:"left",color:"#374151",fontWeight:600}}>Description</th></tr></thead>
            <tbody>{Object.entries(FEATURE_LABELS).map(([col,desc])=>(<tr key={col} style={{borderTop:"1px solid #f3f4f6"}}><td style={{padding:"7px 12px",fontFamily:"monospace",color:"#2563eb",fontWeight:600}}>{col}</td><td style={{padding:"7px 12px",color:"#6b7280"}}>{desc}</td></tr>))}</tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}

// ── Train Baseline Tab ────────────────────────────────────────────────────────
function TrainBaselineTab({user,devices}){
  const[deviceId,setDeviceId]=useState("");
  const[file,setFile]=useState(null);
  const[preview,setPreview]=useState(null);
  const[result,setResult]=useState(null);
  const[loading,setLoading]=useState(false);
  const fileRef=useRef();

  function parseCSV(text){
    const lines=text.trim().split("\n");if(lines.length<2)return[];
    const headers=lines[0].split(",").map(h=>h.trim().replace(/^"|"$/g,""));
    return lines.slice(1).map(line=>{const vals=line.split(",").map(v=>v.trim().replace(/^"|"$/g,""));const row={};headers.forEach((h,i)=>{row[h]=isNaN(vals[i])?vals[i]:parseFloat(vals[i]);});return row;});
  }

  const handleFile=e=>{
    const f=e.target.files[0];if(!f)return;setFile(f);
    const reader=new FileReader();
    reader.onload=ev=>{const text=ev.target.result;const rows=parseCSV(text);setPreview({rows:rows.slice(0,3),total:rows.length,cols:Object.keys(rows[0]||{})});};
    reader.readAsText(f);
  };

  const train=async()=>{
    if(!deviceId){alert("Select a device first");return;}
    if(!file){alert("Upload a CSV file first");return;}
    setLoading(true);setResult(null);
    const form=new FormData();form.append("file",file);
    const res=await fetch(`${API}/api/v1/devices/${deviceId}/baseline`,{method:"POST",headers:formHeaders(user),body:form});
    const data=await res.json();setResult(data);setLoading(false);
  };

  return(
    <div style={{maxWidth:640}}>
      <SectionTitle>Train Device Baseline</SectionTitle>
      <Card>
        <p style={{fontSize:13,color:"#6b7280",marginBottom:16,lineHeight:1.6}}>Upload a CSV of <strong>normal traffic</strong> for a device. The system computes mean + std per feature to establish the baseline for drift detection.</p>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Select Device</label>
          <select value={deviceId} onChange={e=>setDeviceId(e.target.value)} style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,background:"#fff",boxSizing:"border-box"}}>
            <option value="">-- choose device --</option>
            {devices.map(d=><option key={d.id} value={d.id}>{d.id} — {d.name}</option>)}
          </select>
        </div>
        <div style={{marginBottom:12}}>
          <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Upload Training CSV *</label>
          <input ref={fileRef} type="file" accept=".csv" onChange={handleFile} style={{fontSize:13,padding:"6px 0"}}/>
          <div style={{fontSize:11,color:"#9ca3af",marginTop:4}}>Min 5 rows. Required columns: {FEATURE_COLS.join(", ")}</div>
        </div>
        {preview&&(
          <div style={{background:"#f9fafb",border:"1px solid #e5e7eb",borderRadius:6,padding:"10px 14px",marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:600,color:"#374151",marginBottom:6}}>Preview — {preview.total} rows, {preview.cols.length} columns</div>
            <div style={{overflowX:"auto"}}>
              <table style={{fontSize:11,borderCollapse:"collapse"}}>
                <thead><tr>{preview.cols.slice(0,8).map(c=><th key={c} style={{padding:"3px 8px",textAlign:"left",color:"#6b7280",fontWeight:600,whiteSpace:"nowrap"}}>{c}</th>)}</tr></thead>
                <tbody>{preview.rows.map((row,i)=><tr key={i} style={{borderTop:"1px solid #f3f4f6"}}>{preview.cols.slice(0,8).map(c=><td key={c} style={{padding:"3px 8px",fontFamily:"monospace",color:"#374151"}}>{typeof row[c]==="number"?row[c].toFixed(2):row[c]}</td>)}</tr>)}</tbody>
              </table>
            </div>
          </div>
        )}
        <Btn onClick={train} color="blue" size="lg" disabled={loading}>{loading?"Training…":"Train Baseline"}</Btn>
        {result&&(
          <div style={{marginTop:16}}>
            {result.error
              ?<div style={{background:"#fee2e2",color:"#991b1b",padding:"10px 14px",borderRadius:6,fontSize:13}}>❌ {result.error}</div>
              :<div style={{background:"#dcfce7",color:"#15803d",padding:"10px 14px",borderRadius:6,fontSize:13}}>
                ✅ Baseline trained on {result.n_samples} samples for <strong>{result.device_id}</strong>
                {result.summary&&<div style={{marginTop:8}}>
                  <table style={{fontSize:11,borderCollapse:"collapse"}}>
                    <thead><tr><th style={{padding:"2px 10px",textAlign:"left"}}>Feature</th><th style={{padding:"2px 10px"}}>Mean</th><th style={{padding:"2px 10px"}}>Std Dev</th></tr></thead>
                    <tbody>{Object.entries(result.summary).map(([col,stat])=><tr key={col}><td style={{padding:"2px 10px",fontFamily:"monospace"}}>{col}</td><td style={{padding:"2px 10px",textAlign:"center",fontFamily:"monospace"}}>{stat.mean?.toFixed(3)}</td><td style={{padding:"2px 10px",textAlign:"center",fontFamily:"monospace"}}>{stat.std?.toFixed(3)}</td></tr>)}</tbody>
                  </table>
                </div>}
              </div>
            }
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Test Data Tab ─────────────────────────────────────────────────────────────
function TestDataTab({user,devices}){
  const[deviceId,setDeviceId]=useState("");
  const[mode,setMode]=useState("single");
  const[fields,setFields]=useState({});
  const[file,setFile]=useState(null);
  const[result,setResult]=useState(null);
  const[batchResult,setBatchResult]=useState(null);
  const[loading,setLoading]=useState(false);

  const scoreOne=async()=>{
    if(!deviceId){alert("Select a device");return;}
    setLoading(true);setResult(null);
    const body={};FEATURE_COLS.forEach(c=>{if(fields[c]!==""&&fields[c]!==undefined)body[c]=parseFloat(fields[c]);});
    const res=await fetch(`${API}/api/v1/devices/${deviceId}/test`,{method:"POST",headers:authHeaders(user),body:JSON.stringify(body)});
    const data=await res.json();setResult(data);setLoading(false);
  };

  const scoreCsv=async()=>{
    if(!deviceId){alert("Select a device");return;}
    if(!file){alert("Upload a CSV first");return;}
    setLoading(true);setBatchResult(null);
    const form=new FormData();form.append("file",file);
    const res=await fetch(`${API}/api/v1/devices/${deviceId}/test/csv`,{method:"POST",headers:formHeaders(user),body:form});
    const data=await res.json();setBatchResult(data);setLoading(false);
  };

  return(
    <div>
      <SectionTitle>Test Data — Drift & Trust Analysis</SectionTitle>
      <div style={{display:"grid",gridTemplateColumns:"360px 1fr",gap:20}}>
        <Card>
          <div style={{marginBottom:12}}>
            <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>Select Device</label>
            <select value={deviceId} onChange={e=>setDeviceId(e.target.value)} style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,background:"#fff",boxSizing:"border-box"}}>
              <option value="">-- choose device --</option>
              {devices.map(d=><option key={d.id} value={d.id}>{d.id} — {d.name}</option>)}
            </select>
          </div>
          <div style={{display:"flex",gap:8,marginBottom:16}}>
            <Btn onClick={()=>setMode("single")} color={mode==="single"?"blue":"gray"} size="sm">Manual Entry</Btn>
            <Btn onClick={()=>setMode("csv")} color={mode==="csv"?"blue":"gray"} size="sm">Upload CSV</Btn>
          </div>
          {mode==="single"&&(
            <>
              <div style={{fontSize:12,color:"#6b7280",marginBottom:10}}>Enter feature values for one 30s window. Leave blank to use baseline mean.</div>
              {FEATURE_COLS.map(col=>(
                <div key={col} style={{marginBottom:8}}>
                  <label style={{display:"block",fontSize:11,fontWeight:600,color:"#374151",marginBottom:3}}>{FEATURE_LABELS[col]}</label>
                  <input type="number" step="any" value={fields[col]||""} onChange={e=>setFields(f=>({...f,[col]:e.target.value}))} placeholder="leave blank = use baseline mean" style={{width:"100%",padding:"6px 8px",border:"1px solid #d1d5db",borderRadius:5,fontSize:12,boxSizing:"border-box"}}/>
                </div>
              ))}
              <Btn onClick={scoreOne} color="blue" size="lg" disabled={loading} style={{marginTop:8,width:"100%"}}>{loading?"Analyzing…":"Analyze →"}</Btn>
            </>
          )}
          {mode==="csv"&&(
            <>
              <div style={{fontSize:12,color:"#6b7280",marginBottom:10}}>Upload a CSV with test data rows. Each row = one 30s window.</div>
              <input type="file" accept=".csv" onChange={e=>setFile(e.target.files[0])} style={{fontSize:12,marginBottom:12}}/>
              <Btn onClick={scoreCsv} color="blue" size="lg" disabled={loading} style={{width:"100%"}}>{loading?"Analyzing…":"Analyze CSV →"}</Btn>
            </>
          )}
        </Card>
        <div>
          {mode==="single"&&result&&(result.error?<Card><div style={{color:"#dc2626",fontSize:13}}>❌ {result.error}</div></Card>:<TrustScoreCard result={result}/>)}
          {mode==="csv"&&batchResult&&(batchResult.error?<Card><div style={{color:"#dc2626",fontSize:13}}>❌ {batchResult.error}</div></Card>:(
            <div>
              <Card style={{marginBottom:16}}>
                <div style={{fontSize:14,fontWeight:700,color:"#111827",marginBottom:14}}>Batch Analysis — {batchResult.device_id}</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
                  {[["Rows Analyzed",batchResult.n_rows,"#2563eb"],["Avg Trust Score",batchResult.avg_score,batchResult.avg_score>=70?"#16a34a":batchResult.avg_score>=50?"#d97706":"#dc2626"],["Anomaly Rate",batchResult.anomaly_rate+"%",batchResult.anomaly_rate>20?"#dc2626":"#16a34a"],["Min Score",batchResult.min_score,"#374151"],["Max Score",batchResult.max_score,"#374151"],["Anomalies Found",batchResult.anomaly_count,batchResult.anomaly_count>0?"#dc2626":"#16a34a"]].map(([l,v,c])=>(<div key={l} style={{background:"#f9fafb",borderRadius:6,padding:"10px 12px"}}><div style={{fontSize:11,color:"#6b7280",marginBottom:4}}>{l}</div><div style={{fontSize:22,fontWeight:800,color:c}}>{v}</div></div>))}
                </div>
                <Badge level={batchResult.final_level}/>
              </Card>
              <Card style={{padding:0,overflow:"hidden"}}>
                <div style={{padding:"12px 16px",background:"#f9fafb",borderBottom:"1px solid #e5e7eb",fontSize:13,fontWeight:600,color:"#374151"}}>Per-Row Results ({batchResult.results?.length} rows)</div>
                <div style={{maxHeight:400,overflowY:"auto"}}>
                  <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                    <thead><tr style={{background:"#f9fafb",position:"sticky",top:0}}><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>#</th><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>Score</th><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>Level</th><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>Drift</th><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>Anomaly</th><th style={{padding:"8px 12px",textAlign:"left",color:"#6b7280"}}>Top Risk</th></tr></thead>
                    <tbody>{batchResult.results?.map((r,i)=><tr key={i} style={{borderTop:"1px solid #f3f4f6",background:r.anomaly_detected?"#fff7ed":"transparent"}}><td style={{padding:"7px 12px",color:"#9ca3af"}}>{i+1}</td><td style={{padding:"7px 12px",fontWeight:700,color:r.score>=70?"#16a34a":r.score>=50?"#d97706":"#dc2626",fontFamily:"monospace",fontSize:14}}>{r.score}</td><td style={{padding:"7px 12px"}}><Badge level={r.level}/></td><td style={{padding:"7px 12px",fontFamily:"monospace",color:"#374151"}}>{r.drift_score?.toFixed(3)}</td><td style={{padding:"7px 12px"}}>{r.anomaly_detected?<span style={{color:"#dc2626",fontWeight:700}}>⚠ YES</span>:<span style={{color:"#16a34a"}}>✓ No</span>}</td><td style={{padding:"7px 12px",color:"#6b7280",fontSize:11}}>{r.top_risk_factors?.[0]||"—"}</td></tr>)}</tbody>
                  </table>
                </div>
              </Card>
            </div>
          ))}
          {!result&&!batchResult&&<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:200,color:"#9ca3af",fontSize:14}}>← Enter feature values or upload a CSV to see trust analysis</div>}
        </div>
      </div>
    </div>
  );
}

// ── Dark Device Card ──────────────────────────────────────────────────────────
function DarkDeviceCard({s,onTrigger,onStop}){
  const color=trustColor(s.score);
  const[showAtk,setShowAtk]=useState(false);
  return(
    <GlassCard glow={s.anomaly_detected?color:null}>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
        <ScoreRing score={s.score} size={64}/>
        <div style={{flex:1}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
            <span style={{color:C.text,fontWeight:700,fontSize:13}}>{s.device_id}</span>
            {s.anomaly_detected&&<PulseDot color={color}/>}
          </div>
          <div style={{display:"inline-block",fontSize:9,fontWeight:900,letterSpacing:2,padding:"2px 8px",borderRadius:4,background:color+"22",color,border:`1px solid ${color}44`}}>{TRUST_LBL[s.level]||s.level}</div>
          <div style={{color:C.muted,fontSize:10,marginTop:4}}>Drift: {s.drift_score?.toFixed(3)}</div>
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:10}}>
        {[["Behavioral",s.behavioral_stability],["Policy",s.policy_compliance],["Historical",s.historical_trust],["Activity",s.recent_activity]].map(([label,val])=>(
          <div key={label}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:9,marginBottom:3}}><span style={{color:C.muted}}>{label}</span><span style={{color:C.text,fontWeight:700}}>{Math.round(val||0)}</span></div>
            <div style={{height:4,background:C.border,borderRadius:2}}><div style={{height:"100%",width:`${val||0}%`,borderRadius:2,background:`linear-gradient(90deg,${color},${color}88)`,transition:"width 0.6s"}}/></div>
          </div>
        ))}
      </div>
      <div style={{fontSize:10,color:s.anomaly_detected?color:C.muted,lineHeight:1.5,marginBottom:8}}>{s.explanation}</div>
      {s.top_risk_factors?.slice(0,2).map((f,i)=><div key={i} style={{fontSize:9,color:C.red,background:C.red+"11",border:`1px solid ${C.red}22`,borderRadius:4,padding:"2px 7px",marginBottom:3}}>▶ {f}</div>)}
      <div style={{paddingTop:10,borderTop:`1px solid ${C.border}`}}>
        <button onClick={()=>setShowAtk(!showAtk)} style={{background:"none",border:`1px solid ${C.border}`,borderRadius:6,color:C.muted,fontSize:9,cursor:"pointer",padding:"4px 10px",fontFamily:"'Courier New',monospace"}}>⚡ ATTACK SIM {showAtk?"▲":"▼"}</button>
        {showAtk&&<div style={{display:"flex",flexWrap:"wrap",gap:4,marginTop:8}}>
          {["mirai","exfiltration","lateral_movement","port_scan"].map(a=>(
            <button key={a} onClick={()=>onTrigger(s.device_id,a)} style={{background:ATTACK_COLORS[a]+"22",border:`1px solid ${ATTACK_COLORS[a]}44`,borderRadius:4,color:ATTACK_COLORS[a],fontSize:8,fontWeight:700,cursor:"pointer",padding:"3px 8px",fontFamily:"'Courier New',monospace"}}>{a.replace(/_/g," ").toUpperCase()}</button>
          ))}
          <button onClick={()=>onStop(s.device_id)} style={{background:C.green+"22",border:`1px solid ${C.green}44`,borderRadius:4,color:C.green,fontSize:8,fontWeight:700,cursor:"pointer",padding:"3px 8px"}}>■ STOP</button>
        </div>}
      </div>
    </GlassCard>
  );
}

// ── Dashboard Tab ─────────────────────────────────────────────────────────────
function DarkDashboardTab({scores,devices,historyData,onTrigger,onStop}){
  const dColors=["#00d4ff","#d500f9","#ffb300","#00e676","#ff6d00","#ff1744","#76ff03","#00bcd4"];
  const anomalyCount=scores.filter(s=>s.anomaly_detected).length;
  const secureCount=scores.filter(s=>s.score>=70).length;
  const notSecureCount=scores.filter(s=>s.score<70).length;
  const levelCounts=scores.reduce((acc,s)=>{acc[s.level]=(acc[s.level]||0)+1;return acc;},{});
  const pieData=Object.entries(levelCounts).map(([lv,c])=>({name:TRUST_LBL[lv]||lv,value:c,color:LEVEL_COLOR[lv]||C.muted}));
  const netStatus=secureCount>=scores.length*0.7?"SECURE":secureCount>=scores.length*0.5?"DEGRADED":"CRITICAL";
  return(
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
        {[{label:"TOTAL DEVICES",val:devices.length,color:C.accent,icon:"📟"},{label:"SECURE DEVICES",val:secureCount,color:C.green,icon:"🔒"},{label:"NOT SECURE",val:notSecureCount,color:notSecureCount>0?C.red:C.green,icon:"🔓"},{label:"NETWORK STATUS",val:netStatus,color:netStatus==="SECURE"?C.green:netStatus==="DEGRADED"?C.yellow:C.red,icon:"🌐"}].map(k=>(
          <GlassCard key={k.label} glow={k.color} style={{textAlign:"center",padding:"16px 12px"}}>
            <div style={{fontSize:20,marginBottom:6}}>{k.icon}</div>
            <div style={{fontSize:typeof k.val==="string"?16:30,fontWeight:900,color:k.color}}>{k.val}</div>
            <div style={{fontSize:9,color:C.muted,letterSpacing:2,marginTop:4}}>{k.label}</div>
          </GlassCard>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 280px",gap:16,marginBottom:16}}>
        <GlassCard>
          <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:12,fontWeight:700}}>◈ REAL-TIME TRUST SCORE TIMELINE</div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={historyData}>
              <defs>{scores.map((s,i)=><linearGradient key={s.device_id} id={`g${i}`} x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={dColors[i%dColors.length]} stopOpacity={0.3}/><stop offset="95%" stopColor={dColors[i%dColors.length]} stopOpacity={0}/></linearGradient>)}</defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border}/>
              <XAxis dataKey="time" tick={{fill:C.muted,fontSize:9}}/>
              <YAxis domain={[0,100]} tick={{fill:C.muted,fontSize:9}}/>
              <Tooltip contentStyle={{background:C.surface,border:`1px solid ${C.border}`,fontSize:11}} labelStyle={{color:C.muted}}/>
              {scores.map((s,i)=><Area key={s.device_id} type="monotone" dataKey={s.device_id} stroke={dColors[i%dColors.length]} fill={`url(#g${i})`} strokeWidth={2} dot={false}/>)}
            </AreaChart>
          </ResponsiveContainer>
        </GlassCard>
        <GlassCard>
          <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:12,fontWeight:700}}>◈ TRUST DISTRIBUTION</div>
          {pieData.length>0?(<><ResponsiveContainer width="100%" height={140}><PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} dataKey="value" paddingAngle={3}>{pieData.map((e,i)=><Cell key={i} fill={e.color} stroke={C.bg} strokeWidth={2}/>)}</Pie><Tooltip contentStyle={{background:C.surface,border:`1px solid ${C.border}`,fontSize:11}}/></PieChart></ResponsiveContainer><div style={{display:"flex",flexDirection:"column",gap:4}}>{pieData.map((d,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:8,fontSize:10}}><div style={{width:10,height:10,borderRadius:2,background:d.color}}/><span style={{color:C.muted,flex:1}}>{d.name}</span><span style={{color:d.color,fontWeight:700}}>{d.value}</span></div>))}</div></>)
            :<div style={{color:C.muted,fontSize:12,textAlign:"center",padding:30}}>No scored devices yet</div>}
        </GlassCard>
      </div>
      <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:12,fontWeight:700}}>◈ DEVICE TRUST MONITOR</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(310px,1fr))",gap:12}}>
        {scores.sort((a,b)=>a.score-b.score).map(s=><DarkDeviceCard key={s.device_id} s={s} onTrigger={onTrigger} onStop={onStop}/>)}
        {scores.length===0&&<GlassCard style={{gridColumn:"1/-1",textAlign:"center",padding:40}}><div style={{fontSize:32,marginBottom:12}}>📟</div><div style={{color:C.muted}}>No scored devices yet. Register a device, train baseline, then submit test data.</div></GlassCard>}
      </div>
    </div>
  );
}

// ── Network Tab ───────────────────────────────────────────────────────────────
function NetworkTab({scores}){
  const canvasRef=useRef(null);const animRef=useRef(null);const parts=useRef([]);
  useEffect(()=>{
    const canvas=canvasRef.current;if(!canvas||!scores.length)return;
    const ctx=canvas.getContext("2d");const W=canvas.offsetWidth,H=canvas.offsetHeight;
    canvas.width=W;canvas.height=H;
    const cx=W/2,cy=H/2,r=Math.min(W,H)*0.32;
    const pos=scores.map((s,i)=>{const a=(2*Math.PI*i/scores.length)-Math.PI/2;return{x:cx+r*Math.cos(a),y:cy+r*Math.sin(a),s};});
    parts.current=pos.map(p=>({x:cx,y:cy,tx:p.x,ty:p.y,prog:Math.random(),speed:0.003+Math.random()*0.003}));
    const draw=()=>{
      ctx.clearRect(0,0,W,H);
      pos.forEach(p=>{const c=trustColor(p.s.score);ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(p.x,p.y);ctx.strokeStyle=p.s.anomaly_detected?c+"88":C.border+"66";ctx.lineWidth=p.s.anomaly_detected?2:1;if(p.s.anomaly_detected){ctx.shadowBlur=8;ctx.shadowColor=c;}ctx.stroke();ctx.shadowBlur=0;});
      parts.current.forEach((p,i)=>{p.prog+=p.speed;if(p.prog>1)p.prog=0;const px=cx+(p.tx-cx)*p.prog,py=cy+(p.ty-cy)*p.prog;const c=trustColor(pos[i]?.s?.score||80);ctx.beginPath();ctx.arc(px,py,2.5,0,Math.PI*2);ctx.fillStyle=c;ctx.shadowBlur=8;ctx.shadowColor=c;ctx.fill();ctx.shadowBlur=0;});
      ctx.beginPath();ctx.arc(cx,cy,24,0,Math.PI*2);ctx.fillStyle=C.surface;ctx.shadowBlur=20;ctx.shadowColor=C.accent;ctx.fill();ctx.strokeStyle=C.accent;ctx.lineWidth=2;ctx.stroke();ctx.shadowBlur=0;ctx.fillStyle=C.accent;ctx.font="bold 10px 'Courier New'";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText("HUB",cx,cy);
      pos.forEach(p=>{const c=trustColor(p.s.score),rad=18+(p.s.anomaly_detected?4:0);if(p.s.anomaly_detected){ctx.beginPath();ctx.arc(p.x,p.y,rad+8,0,Math.PI*2);ctx.fillStyle=c+"22";ctx.fill();}ctx.beginPath();ctx.arc(p.x,p.y,rad,0,Math.PI*2);ctx.fillStyle=C.card;ctx.shadowBlur=p.s.anomaly_detected?16:6;ctx.shadowColor=c;ctx.fill();ctx.strokeStyle=c;ctx.lineWidth=2;ctx.stroke();ctx.shadowBlur=0;ctx.fillStyle=c;ctx.font="bold 11px 'Courier New'";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText(Math.round(p.s.score),p.x,p.y);ctx.fillStyle=C.muted;ctx.font="9px 'Courier New'";ctx.fillText(p.s.device_id.slice(0,8),p.x,p.y+rad+12);});
      animRef.current=requestAnimationFrame(draw);
    };draw();return()=>cancelAnimationFrame(animRef.current);
  },[scores]);
  return(
    <div>
      <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:16,fontWeight:700}}>◈ LIVE NETWORK TOPOLOGY</div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 240px",gap:16}}>
        <GlassCard style={{padding:0,overflow:"hidden"}}><canvas ref={canvasRef} style={{width:"100%",height:460,display:"block"}}/></GlassCard>
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          <GlassCard style={{padding:14}}>
            <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:10,fontWeight:700}}>LEGEND</div>
            {Object.entries(LEVEL_COLOR).map(([l,c])=>(<div key={l} style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}><div style={{width:12,height:12,borderRadius:"50%",background:c,boxShadow:`0 0 8px ${c}`}}/><span style={{fontSize:10,color:C.muted}}>{TRUST_LBL[l]}</span></div>))}
          </GlassCard>
          {scores.sort((a,b)=>a.score-b.score).map(s=>{const c=trustColor(s.score);return(<GlassCard key={s.device_id} glow={s.anomaly_detected?c:null} style={{padding:12}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:11,color:C.text,fontWeight:700}}>{s.device_id}</span><span style={{fontSize:14,fontWeight:900,color:c}}>{Math.round(s.score)}</span></div><div style={{height:4,background:C.border,borderRadius:2,marginTop:6}}><div style={{height:"100%",width:`${s.score}%`,borderRadius:2,background:c,transition:"width 0.6s"}}/></div>{s.anomaly_detected&&<div style={{fontSize:9,color:c,marginTop:4}}>⚠ ANOMALY</div>}</GlassCard>);})}
        </div>
      </div>
    </div>
  );
}

// ── Alerts Tab ────────────────────────────────────────────────────────────────
function AlertsTab({user,notifications,scores}){
  const activeAlerts=scores.filter(s=>s.anomaly_detected||s.score<60);
  return(
    <div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        <div>
          <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:12,fontWeight:700}}>◈ LIVE SECURITY ALERTS ({activeAlerts.length})</div>
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {activeAlerts.length===0?(<GlassCard style={{textAlign:"center",padding:40}}><div style={{fontSize:28,marginBottom:8}}>✅</div><div style={{color:C.green,fontSize:13}}>All devices operating normally</div></GlassCard>)
              :activeAlerts.map(s=>{const c=trustColor(s.score);return(<GlassCard key={s.device_id} glow={c} style={{padding:14}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><div style={{display:"flex",alignItems:"center",gap:8}}><PulseDot color={c}/><span style={{color:C.text,fontWeight:700,fontSize:13}}>{s.device_id}</span></div><span style={{color:c,fontSize:20,fontWeight:900}}>{Math.round(s.score)}</span></div><div style={{fontSize:11,color:c,marginBottom:8}}>{s.explanation}</div>{s.top_risk_factors?.map((f,i)=><div key={i} style={{fontSize:10,color:C.muted,padding:"2px 8px",background:C.red+"11",borderRadius:3,marginBottom:3}}>▶ {f}</div>)}</GlassCard>);})}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.accent,letterSpacing:2,marginBottom:12,fontWeight:700}}>◈ EMAIL NOTIFICATION LOG ({notifications.length})</div>
          {user?.email&&<div style={{padding:"8px 12px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,marginBottom:10,fontSize:10,color:C.muted}}>📬 Alerts sent to: <span style={{color:C.accent,fontWeight:700}}>{user.email}</span></div>}
          <div style={{display:"flex",flexDirection:"column",gap:8,maxHeight:560,overflowY:"auto"}}>
            {notifications.length===0?(<GlassCard style={{textAlign:"center",padding:40}}><div style={{fontSize:28,marginBottom:8}}>📬</div><div style={{color:C.muted,fontSize:12}}>Alerts will appear here and be emailed to {user?.email} when anomalies are detected</div></GlassCard>)
              :notifications.map(n=>{const c=trustColor(n.score);return(<GlassCard key={n.id} style={{padding:12}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}><span style={{color:C.text,fontWeight:700,fontSize:11}}>{n.device_id}</span><span style={{color:C.muted,fontSize:9}}>{n.time}</span></div><div style={{fontSize:10,color:c,marginBottom:4}}>{n.explanation}</div>{n.suspicious_ips?.length>0&&<div style={{background:C.red+"11",border:`1px solid ${C.red}22`,borderRadius:6,padding:"8px 10px",marginBottom:6}}><div style={{fontSize:9,color:C.red,fontWeight:700,marginBottom:4,letterSpacing:1}}>🔍 TRACKED IPs</div>{n.suspicious_ips.map((ip,i)=><div key={i} style={{fontFamily:"monospace",fontSize:10,color:C.red,padding:"2px 0"}}>⚡ {ip}</div>)}</div>}<div style={{fontSize:9,color:n.email_sent?C.green:C.yellow}}>{n.email_sent?"📧 Email sent to "+user?.email:"📋 Logged (configure SMTP to enable email)"}</div></GlassCard>);})}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Email Config Tab ──────────────────────────────────────────────────────────
function EmailConfigTab(){
  const[form,setForm]=useState({host:"smtp.gmail.com",port:"587",username:"",password:"",from_email:""});
  const[status,setStatus]=useState(null);
  const[configStatus,setConfigStatus]=useState(null);
  const set=(k,v)=>setForm(f=>({...f,[k]:v}));

  useEffect(()=>{
    fetch(`${API}/api/v1/notifications/email-config-status`).then(r=>r.json()).then(d=>setConfigStatus(d)).catch(()=>{});
  },[]);

  const save=async()=>{
    setStatus(null);
    const res=await fetch(`${API}/api/v1/notifications/configure-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({host:form.host,port:parseInt(form.port),username:form.username,password:form.password,from_email:form.from_email||form.username})});
    const data=await res.json();
    if(data.status==="smtp_configured"){setStatus({ok:true,msg:`SMTP configured for ${data.username}`});setConfigStatus({configured:true,username:data.username});}
    else setStatus({ok:false,msg:data.detail||"Failed to save"});
  };

  return(
    <div style={{maxWidth:560}}>
      <SectionTitle>📧 Email Alert Configuration</SectionTitle>
      <Card>
        {configStatus&&<div style={{marginBottom:16,padding:"10px 14px",borderRadius:8,background:configStatus.configured?C.green+"11":C.yellow+"11",border:`1px solid ${configStatus.configured?C.green:C.yellow}44`,fontSize:12,color:configStatus.configured?C.green:C.yellow}}>
          {configStatus.configured?`✅ SMTP active — using ${configStatus.username}`:"⚠ SMTP not configured — alerts will be logged but not emailed"}
        </div>}
        <div style={{background:"#f0f9ff",border:"1px solid #bae6fd",borderRadius:8,padding:"12px 14px",marginBottom:16,fontSize:12,color:"#0369a1"}}>
          <strong>Gmail setup:</strong> Enable 2FA → Google Account → Security → App Passwords → generate 16-char password → paste below
        </div>
        {[["SMTP Host","host","smtp.gmail.com"],["SMTP Port","port","587"],["Gmail Address","username","your@gmail.com"],["App Password (16 chars)","password","xxxx xxxx xxxx xxxx"],["From Email (optional)","from_email","leave blank = same as username"]].map(([label,key,ph])=>(
          <div key={key} style={{marginBottom:12}}>
            <label style={{display:"block",fontSize:12,fontWeight:600,color:"#374151",marginBottom:4}}>{label}</label>
            <input type={key==="password"?"password":"text"} value={form[key]} onChange={e=>set(key,e.target.value)} placeholder={ph} style={{width:"100%",padding:"8px 10px",border:"1px solid #d1d5db",borderRadius:6,fontSize:13,outline:"none",boxSizing:"border-box"}}/>
          </div>
        ))}
        <Btn onClick={save} color="blue" size="lg">💾 Save SMTP Config</Btn>
        {status&&<div style={{marginTop:12,padding:"10px 14px",borderRadius:6,fontSize:13,background:status.ok?"#dcfce7":"#fee2e2",color:status.ok?"#15803d":"#991b1b"}}>{status.msg}</div>}
        <div style={{marginTop:16,padding:"10px 14px",background:"#fffbeb",border:"1px solid #fde68a",borderRadius:6,fontSize:12,color:"#92400e"}}>
          <strong>How auto-alerts work:</strong> Once SMTP is saved, SentinelTrust checks every 30 seconds. If your device score drops below 40 or anomaly is detected, an email is automatically sent to your registered email address.
        </div>
      </Card>
    </div>
  );
}

// ── Admin Dashboard ───────────────────────────────────────────────────────────
function AdminDashboardTab(){
  const[data,setData]=useState(null);const[loading,setLoading]=useState(true);const[activeSection,setActiveSection]=useState("users");
  const load=()=>{setLoading(true);fetch(`${API}/api/v1/auth/admin/dashboard-data`).then(r=>r.json()).then(d=>{setData(d);setLoading(false);}).catch(()=>setLoading(false));};
  useEffect(()=>{load();},[]);
  const SECTIONS=[{id:"users",label:"👥 Registered Users",count:data?.summary?.total_users},{id:"devices",label:"📟 All Devices",count:data?.summary?.total_devices},{id:"baseline",label:"🧠 Baselines",count:data?.summary?.devices_with_baseline},{id:"alerts",label:"🚨 Alert History",count:data?.summary?.total_alerts}];
  return(
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div><div style={{fontSize:18,fontWeight:900,color:C.white,letterSpacing:2}}>🔐 ADMIN PANEL</div><div style={{fontSize:11,color:C.muted,marginTop:2}}>Full backend data view</div></div>
        <button onClick={load} style={{background:`linear-gradient(135deg,${C.accent}44,${C.accent}22)`,border:`1px solid ${C.accent}44`,borderRadius:8,color:C.accent,fontSize:11,fontWeight:700,cursor:"pointer",padding:"8px 16px",fontFamily:"'Courier New',monospace",letterSpacing:1}}>↻ REFRESH</button>
      </div>
      {data&&<div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>{[{label:"REGISTERED USERS",val:data.summary.total_users,color:C.accent,icon:"👥"},{label:"TOTAL DEVICES",val:data.summary.total_devices,color:C.purple,icon:"📟"},{label:"TRAINED BASELINES",val:data.summary.devices_with_baseline,color:C.green,icon:"🧠"},{label:"TOTAL ALERTS",val:data.summary.total_alerts,color:data.summary.total_alerts>0?C.red:C.green,icon:"🚨"}].map(k=>(<GlassCard key={k.label} glow={k.color} style={{textAlign:"center",padding:"16px 12px"}}><div style={{fontSize:22,marginBottom:6}}>{k.icon}</div><div style={{fontSize:32,fontWeight:900,color:k.color}}>{k.val}</div><div style={{fontSize:9,color:C.muted,letterSpacing:2,marginTop:4}}>{k.label}</div></GlassCard>))}</div>}
      <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>{SECTIONS.map(s=>(<button key={s.id} onClick={()=>setActiveSection(s.id)} style={{padding:"8px 16px",borderRadius:8,border:`1px solid ${activeSection===s.id?C.accent+"66":C.border}`,background:activeSection===s.id?C.accent+"22":"transparent",color:activeSection===s.id?C.accent:C.muted,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"'Courier New',monospace",transition:"all 0.2s"}}>{s.label}{s.count!==undefined&&<span style={{background:C.accent+"33",borderRadius:4,padding:"1px 6px",marginLeft:4,fontSize:10}}>{s.count}</span>}</button>))}</div>
      {loading&&<GlassCard style={{textAlign:"center",padding:40}}><div style={{color:C.accent,fontSize:13}}>Loading backend data...</div></GlassCard>}
      {!loading&&data&&(
        <>
          {activeSection==="users"&&<GlassCard style={{padding:0,overflow:"hidden"}}><div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,fontSize:10,color:C.accent,letterSpacing:2,fontWeight:700}}>◈ REGISTERED USERS ({data.users.length})</div>{data.users.length===0?<div style={{padding:40,textAlign:"center",color:C.muted}}>No users yet</div>:<table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr style={{background:C.surface}}>{["#","NAME","EMAIL","PHONE","JOINED"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontWeight:700,letterSpacing:1,fontSize:10}}>{h}</th>)}</tr></thead><tbody>{data.users.map((u,i)=><tr key={u.email} style={{borderTop:`1px solid ${C.border}22`,background:i%2===0?"transparent":C.surface+"44"}}><td style={{padding:"10px 14px",color:C.muted,fontSize:11}}>{i+1}</td><td style={{padding:"10px 14px",color:C.text,fontWeight:700}}>{u.name}</td><td style={{padding:"10px 14px",color:C.accent,fontFamily:"monospace"}}>{u.email}</td><td style={{padding:"10px 14px",color:C.muted,fontFamily:"monospace"}}>{u.phone}</td><td style={{padding:"10px 14px",color:C.muted,fontSize:10}}>{u.joined}</td></tr>)}</tbody></table>}</GlassCard>}
          {activeSection==="devices"&&<GlassCard style={{padding:0,overflow:"hidden"}}><div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,fontSize:10,color:C.accent,letterSpacing:2,fontWeight:700}}>◈ ALL REGISTERED DEVICES ({data.devices.length})</div>{data.devices.length===0?<div style={{padding:40,textAlign:"center",color:C.muted}}>No devices yet</div>:<table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr style={{background:C.surface}}>{["DEVICE ID","NAME","TYPE","IP","BASELINE","TESTS","OWNER","REGISTERED"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontWeight:700,letterSpacing:1,fontSize:10}}>{h}</th>)}</tr></thead><tbody>{data.devices.map((d,i)=><tr key={d.id+d.owner} style={{borderTop:`1px solid ${C.border}22`,background:i%2===0?"transparent":C.surface+"44"}}><td style={{padding:"10px 14px",color:C.accent,fontFamily:"monospace",fontWeight:700}}>{d.id}</td><td style={{padding:"10px 14px",color:C.text}}>{d.name}</td><td style={{padding:"10px 14px",color:C.muted}}>{d.type}</td><td style={{padding:"10px 14px",color:C.muted,fontFamily:"monospace"}}>{d.ip}</td><td style={{padding:"10px 14px"}}>{d.has_baseline?<span style={{color:C.green,fontWeight:700,fontSize:10}}>✓ TRAINED</span>:<span style={{color:C.yellow,fontSize:10}}>⚠ PENDING</span>}</td><td style={{padding:"10px 14px",color:C.text,fontWeight:700}}>{d.test_count}</td><td style={{padding:"10px 14px",color:C.accent,fontFamily:"monospace",fontSize:10}}>{d.owner}</td><td style={{padding:"10px 14px",color:C.muted,fontSize:10}}>{d.registered_at}</td></tr>)}</tbody></table>}</GlassCard>}
          {activeSection==="alerts"&&<GlassCard style={{padding:0,overflow:"hidden"}}><div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,fontSize:10,color:C.accent,letterSpacing:2,fontWeight:700}}>◈ ALERT HISTORY ({data.notifications.length})</div>{data.notifications.length===0?<div style={{padding:40,textAlign:"center",color:C.muted}}>No alerts yet</div>:<div style={{maxHeight:500,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}><thead style={{position:"sticky",top:0,zIndex:1}}><tr style={{background:C.surface}}>{["TIME","DEVICE","EMAIL SENT TO","SCORE","LEVEL","ATTACK TYPE","EMAIL STATUS","IPs TRACKED"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontWeight:700,letterSpacing:1,fontSize:9}}>{h}</th>)}</tr></thead><tbody>{data.notifications.map((n,i)=>{const lc=LEVEL_COLOR[n.level]||C.muted;return(<tr key={i} style={{borderTop:`1px solid ${C.border}22`,background:i%2===0?"transparent":C.surface+"44"}}><td style={{padding:"8px 14px",color:C.muted,fontSize:9,whiteSpace:"nowrap"}}>{n.sent_at}</td><td style={{padding:"8px 14px",color:C.accent,fontFamily:"monospace",fontWeight:700}}>{n.device_id}</td><td style={{padding:"8px 14px",color:C.muted,fontFamily:"monospace",fontSize:10}}>{n.to_email}</td><td style={{padding:"8px 14px",color:lc,fontWeight:900,fontSize:14}}>{n.score}</td><td style={{padding:"8px 14px"}}><span style={{background:lc+"22",color:lc,border:`1px solid ${lc}44`,borderRadius:4,padding:"2px 7px",fontSize:9,fontWeight:700}}>{n.level?.toUpperCase().replace("_"," ")}</span></td><td style={{padding:"8px 14px",color:n.attack_type?C.red:C.muted,fontSize:10}}>{n.attack_type||"auto-detected"}</td><td style={{padding:"8px 14px",fontSize:10}}>{n.email_sent?<span style={{color:C.green}}>✅ Sent</span>:<span style={{color:C.yellow}}>📋 Logged</span>}</td><td style={{padding:"8px 14px"}}>{n.suspicious_ips?.length>0?n.suspicious_ips.map((ip,j)=><div key={j} style={{fontFamily:"monospace",fontSize:9,color:C.red}}>⚡{ip}</div>):<span style={{color:C.muted,fontSize:9}}>—</span>}</td></tr>);})}</tbody></table></div>}</GlassCard>}
        </>
      )}
    </div>
  );
}

// ── Admin App — completely separate dashboard for admins ──────────────────────
function AdminApp({user,onLogout}){
  const[tab,setTab]=useState("overview");
  const[data,setData]=useState(null);
  const[loading,setLoading]=useState(true);
  const[allUsers,setAllUsers]=useState([]);
  const[showPass,setShowPass]=useState({});

  const load=async()=>{
    setLoading(true);
    try{
      const[dashRes,usersRes]=await Promise.all([
        fetch(`${API}/api/v1/auth/admin/dashboard-data`),
        fetch(`${API}/api/v1/auth/admin/users-full`),
      ]);
      const dash=await dashRes.json();
      setData(dash);
      if(usersRes.ok){const u=await usersRes.json();setAllUsers(u.users||[]);}
      else setAllUsers(dash.users||[]);
    }catch(e){console.error(e);}
    setLoading(false);
  };
  useEffect(()=>{load();},[]);

  const ADMIN_TABS=[
    {id:"overview",label:"📊 Overview"},
    {id:"credentials",label:"🔑 User Credentials"},
    {id:"devices",label:"📟 All Devices"},
    {id:"alerts",label:"🚨 Alert Log"},
  ];

  const CA={
    bg:"#03070f",surface:"#060f1c",card:"#091525",border:"#0d2040",
    accent:"#f59e0b",accentDim:"#d97706",green:"#22c55e",red:"#ef4444",
    yellow:"#f59e0b",orange:"#f97316",purple:"#a855f7",text:"#f1f5f9",
    muted:"#4a6080",white:"#ffffff",
  };

  const statCards=data?[
    {label:"REGISTERED USERS",val:data.summary.total_users,color:CA.accent,icon:"👥"},
    {label:"TOTAL DEVICES",val:data.summary.total_devices,color:CA.purple,icon:"📟"},
    {label:"TRAINED BASELINES",val:data.summary.devices_with_baseline,color:CA.green,icon:"🧠"},
    {label:"TOTAL ALERTS",val:data.summary.total_alerts,color:data.summary.total_alerts>0?CA.red:CA.green,icon:"🚨"},
  ]:[];

  const th={padding:"10px 14px",textAlign:"left",color:CA.muted,fontWeight:700,letterSpacing:1,fontSize:9,borderBottom:`1px solid ${CA.border}`};
  const td=(extra={})=>({padding:"10px 14px",fontSize:11,borderBottom:`1px solid ${CA.border}22`,...extra});

  return(
    <div style={{minHeight:"100vh",background:CA.bg,color:CA.text,fontFamily:"'Courier New',monospace"}}>
      {/* Admin Header */}
      <header style={{background:`linear-gradient(90deg,${CA.bg},${CA.surface})`,borderBottom:`1px solid ${CA.accent}44`,padding:"0 24px",position:"sticky",top:0,zIndex:100,boxShadow:`0 4px 24px rgba(0,0,0,0.6),0 0 40px ${CA.accent}08`}}>
        <div style={{maxWidth:1400,margin:"0 auto",display:"flex",alignItems:"center",height:58,gap:16}}>
          <div style={{display:"flex",alignItems:"center",gap:10,marginRight:20}}>
            <div style={{fontSize:22}}>🔐</div>
            <div>
              <div style={{fontSize:14,fontWeight:900,color:CA.white,letterSpacing:2}}>
                SENTINEL<span style={{color:CA.accent}}>TRUST</span>
                <span style={{marginLeft:10,fontSize:9,background:CA.accent+"33",border:`1px solid ${CA.accent}44`,borderRadius:4,padding:"2px 8px",color:CA.accent,letterSpacing:2}}>ADMIN</span>
              </div>
              <div style={{fontSize:8,color:CA.muted,letterSpacing:1}}>SYSTEM ADMINISTRATION PANEL</div>
            </div>
          </div>
          <nav style={{display:"flex",gap:2,flex:1}}>
            {ADMIN_TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)} style={{
                padding:"8px 16px",borderRadius:6,border:"none",cursor:"pointer",
                background:tab===t.id?`${CA.accent}22`:"transparent",
                color:tab===t.id?CA.accent:CA.muted,
                fontSize:11,fontWeight:700,letterSpacing:0.5,
                borderBottom:tab===t.id?`2px solid ${CA.accent}`:"2px solid transparent",
                transition:"all 0.2s",fontFamily:"'Courier New',monospace",
              }}>{t.label}</button>
            ))}
          </nav>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <button onClick={load} style={{background:`${CA.accent}22`,border:`1px solid ${CA.accent}44`,borderRadius:6,color:CA.accent,fontSize:10,fontWeight:700,cursor:"pointer",padding:"6px 14px",fontFamily:"'Courier New',monospace",letterSpacing:1}}>↻ REFRESH</button>
            <div style={{display:"flex",alignItems:"center",gap:8,background:CA.surface,border:`1px solid ${CA.border}`,borderRadius:8,padding:"5px 12px"}}>
              <span style={{fontSize:13}}>🔐</span>
              <div>
                <div style={{fontSize:10,fontWeight:700,color:CA.text}}>{user.name}</div>
                <div style={{fontSize:8,color:CA.muted}}>{user.email} · ADMIN</div>
              </div>
              <button onClick={onLogout} style={{marginLeft:6,background:"none",border:`1px solid ${CA.border}`,borderRadius:4,color:CA.muted,fontSize:9,cursor:"pointer",padding:"2px 7px",fontFamily:"'Courier New',monospace"}}>EXIT</button>
            </div>
          </div>
        </div>
      </header>

      <main style={{maxWidth:1400,margin:"0 auto",padding:"24px"}}>
        {loading&&(
          <div style={{textAlign:"center",padding:80}}>
            <div style={{fontSize:36,marginBottom:12,animation:"spin 1s linear infinite"}}>⚙️</div>
            <div style={{color:CA.accent,fontSize:13,letterSpacing:2}}>LOADING SYSTEM DATA...</div>
          </div>
        )}

        {!loading&&(
          <>
            {/* Overview Tab */}
            {tab==="overview"&&(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:14,marginBottom:24}}>
                  {statCards.map(k=>(
                    <div key={k.label} style={{background:`linear-gradient(135deg,${CA.card},${CA.surface})`,border:`1px solid ${k.color}33`,borderRadius:14,padding:"20px 16px",textAlign:"center",boxShadow:`0 0 20px ${k.color}11`}}>
                      <div style={{fontSize:26,marginBottom:8}}>{k.icon}</div>
                      <div style={{fontSize:34,fontWeight:900,color:k.color}}>{k.val}</div>
                      <div style={{fontSize:9,color:CA.muted,letterSpacing:2,marginTop:6}}>{k.label}</div>
                    </div>
                  ))}
                </div>

                {/* Recent Users summary */}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
                  <div style={{background:CA.card,border:`1px solid ${CA.border}`,borderRadius:12,padding:0,overflow:"hidden"}}>
                    <div style={{padding:"14px 18px",borderBottom:`1px solid ${CA.border}`,fontSize:10,color:CA.accent,letterSpacing:2,fontWeight:700}}>◈ RECENT USERS ({data?.users?.length||0})</div>
                    <table style={{width:"100%",borderCollapse:"collapse"}}>
                      <thead><tr style={{background:CA.surface}}><th style={th}>NAME</th><th style={th}>EMAIL</th><th style={th}>JOINED</th></tr></thead>
                      <tbody>{(data?.users||[]).slice(0,6).map((u,i)=>(
                        <tr key={i}><td style={td({color:CA.text,fontWeight:700})}>{u.name}</td><td style={td({color:CA.accent,fontFamily:"monospace"})}>{u.email}</td><td style={td({color:CA.muted,fontSize:9})}>{u.joined}</td></tr>
                      ))}</tbody>
                    </table>
                    {(data?.users?.length||0)>6&&<div style={{padding:"8px 18px",fontSize:10,color:CA.muted,borderTop:`1px solid ${CA.border}`}}>+{(data.users.length-6)} more — see Credentials tab</div>}
                  </div>
                  <div style={{background:CA.card,border:`1px solid ${CA.border}`,borderRadius:12,padding:0,overflow:"hidden"}}>
                    <div style={{padding:"14px 18px",borderBottom:`1px solid ${CA.border}`,fontSize:10,color:CA.accent,letterSpacing:2,fontWeight:700}}>◈ RECENT ALERTS ({data?.notifications?.length||0})</div>
                    <div style={{maxHeight:260,overflowY:"auto"}}>
                      {(data?.notifications||[]).slice(0,6).map((n,i)=>{
                        const lc=LEVEL_COLOR[n.level]||CA.muted;
                        return(
                          <div key={i} style={{padding:"10px 18px",borderBottom:`1px solid ${CA.border}22`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                            <div>
                              <span style={{color:CA.accent,fontFamily:"monospace",fontWeight:700,fontSize:11}}>{n.device_id}</span>
                              <span style={{marginLeft:8,background:lc+"22",color:lc,border:`1px solid ${lc}44`,borderRadius:4,padding:"1px 6px",fontSize:9,fontWeight:700}}>{n.level?.toUpperCase().replace("_"," ")}</span>
                            </div>
                            <div style={{textAlign:"right"}}>
                              <div style={{color:lc,fontWeight:900,fontSize:16}}>{n.score}</div>
                              <div style={{color:CA.muted,fontSize:9}}>{n.sent_at}</div>
                            </div>
                          </div>
                        );
                      })}
                      {!(data?.notifications?.length)&&<div style={{padding:30,textAlign:"center",color:CA.muted,fontSize:12}}>No alerts yet</div>}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Credentials Tab */}
            {tab==="credentials"&&(
              <div>
                <div style={{marginBottom:14,padding:"12px 16px",background:CA.card,border:`1px solid ${CA.accent}44`,borderRadius:10,fontSize:12,color:CA.accent,display:"flex",alignItems:"center",gap:10}}>
                  <span style={{fontSize:16}}>🔑</span>
                  <span>Full credentials of all registered users. Passwords shown as hashes (SHA-256). This view is only accessible to admins.</span>
                </div>
                <div style={{background:CA.card,border:`1px solid ${CA.border}`,borderRadius:12,overflow:"hidden"}}>
                  <div style={{padding:"14px 18px",borderBottom:`1px solid ${CA.border}`,fontSize:10,color:CA.accent,letterSpacing:2,fontWeight:700}}>◈ ALL REGISTERED USERS — FULL CREDENTIALS ({allUsers.length||data?.users?.length||0})</div>
                  {!(allUsers.length||data?.users?.length)?
                    <div style={{padding:40,textAlign:"center",color:CA.muted}}>No users registered yet</div>:
                    <div style={{overflowX:"auto"}}>
                      <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                        <thead>
                          <tr style={{background:CA.surface}}>
                            {["#","NAME","EMAIL","PHONE","PASSWORD HASH","ROLE","JOINED",""].map(h=><th key={h} style={th}>{h}</th>)}
                          </tr>
                        </thead>
                        <tbody>
                          {(allUsers.length?allUsers:data?.users||[]).map((u,i)=>(
                            <tr key={i} style={{background:i%2===0?"transparent":CA.surface+"55"}}>
                              <td style={td({color:CA.muted})}>{i+1}</td>
                              <td style={td({color:CA.text,fontWeight:700})}>{u.name}</td>
                              <td style={td({color:CA.accent,fontFamily:"monospace"})}>{u.email}</td>
                              <td style={td({color:CA.muted,fontFamily:"monospace"})}>{u.phone||"—"}</td>
                              <td style={td({fontFamily:"monospace",fontSize:10})}>
                                {u.password_hash?(
                                  <div style={{display:"flex",alignItems:"center",gap:6}}>
                                    <span style={{color:showPass[i]?CA.yellow:CA.muted}}>
                                      {showPass[i]?u.password_hash:`${u.password_hash.slice(0,12)}...`}
                                    </span>
                                    <button onClick={()=>setShowPass(p=>({...p,[i]:!p[i]}))}
                                      style={{background:CA.surface,border:`1px solid ${CA.border}`,borderRadius:4,color:CA.muted,fontSize:8,cursor:"pointer",padding:"2px 6px",fontFamily:"'Courier New',monospace"}}>
                                      {showPass[i]?"HIDE":"SHOW"}
                                    </button>
                                  </div>
                                ):(
                                  <span style={{color:CA.muted,fontSize:9}}>not available</span>
                                )}
                              </td>
                              <td style={td()}><span style={{background:CA.accent+"22",color:CA.accent,border:`1px solid ${CA.accent}44`,borderRadius:4,padding:"2px 8px",fontSize:9,fontWeight:700}}>USER</span></td>
                              <td style={td({color:CA.muted,fontSize:9})}>{u.joined||"—"}</td>
                              <td style={td()}>
                                <button onClick={()=>{navigator.clipboard.writeText(`Email: ${u.email}\nHash: ${u.password_hash||""}\nPhone: ${u.phone||""}`);}}
                                  style={{background:CA.surface,border:`1px solid ${CA.border}`,borderRadius:4,color:CA.muted,fontSize:8,cursor:"pointer",padding:"3px 8px",fontFamily:"'Courier New',monospace"}}>
                                  📋 COPY
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  }
                </div>
              </div>
            )}

            {/* Devices Tab */}
            {tab==="devices"&&(
              <div style={{background:CA.card,border:`1px solid ${CA.border}`,borderRadius:12,overflow:"hidden"}}>
                <div style={{padding:"14px 18px",borderBottom:`1px solid ${CA.border}`,fontSize:10,color:CA.accent,letterSpacing:2,fontWeight:700}}>◈ ALL REGISTERED DEVICES ({data?.devices?.length||0})</div>
                {!data?.devices?.length?<div style={{padding:40,textAlign:"center",color:CA.muted}}>No devices registered</div>:(
                  <div style={{overflowX:"auto"}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                      <thead><tr style={{background:CA.surface}}>{["DEVICE ID","NAME","TYPE","IP","OWNER","BASELINE","TESTS","REGISTERED"].map(h=><th key={h} style={th}>{h}</th>)}</tr></thead>
                      <tbody>{data.devices.map((d,i)=>(
                        <tr key={i} style={{background:i%2===0?"transparent":CA.surface+"55"}}>
                          <td style={td({color:CA.accent,fontFamily:"monospace",fontWeight:700})}>{d.id}</td>
                          <td style={td({color:CA.text})}>{d.name}</td>
                          <td style={td({color:CA.muted})}>{d.type}</td>
                          <td style={td({fontFamily:"monospace",color:CA.muted})}>{d.ip}</td>
                          <td style={td({color:CA.yellow,fontFamily:"monospace",fontSize:10})}>{d.owner}</td>
                          <td style={td()}>{d.has_baseline?<span style={{color:CA.green,fontWeight:700,fontSize:10}}>✓ TRAINED</span>:<span style={{color:CA.yellow,fontSize:10}}>⚠ PENDING</span>}</td>
                          <td style={td({color:CA.text,fontWeight:700})}>{d.test_count}</td>
                          <td style={td({color:CA.muted,fontSize:9})}>{d.registered_at}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Alerts Tab */}
            {tab==="alerts"&&(
              <div style={{background:CA.card,border:`1px solid ${CA.border}`,borderRadius:12,overflow:"hidden"}}>
                <div style={{padding:"14px 18px",borderBottom:`1px solid ${CA.border}`,fontSize:10,color:CA.accent,letterSpacing:2,fontWeight:700}}>◈ FULL ALERT HISTORY ({data?.notifications?.length||0})</div>
                {!data?.notifications?.length?<div style={{padding:40,textAlign:"center",color:CA.muted}}>No alerts yet</div>:(
                  <div style={{maxHeight:600,overflowY:"auto",overflowX:"auto"}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                      <thead style={{position:"sticky",top:0,zIndex:1}}><tr style={{background:CA.surface}}>{["TIME","DEVICE","SENT TO","SCORE","LEVEL","ATTACK","EMAIL","TRACKED IPs"].map(h=><th key={h} style={th}>{h}</th>)}</tr></thead>
                      <tbody>{data.notifications.map((n,i)=>{
                        const lc=LEVEL_COLOR[n.level]||CA.muted;
                        return(
                          <tr key={i} style={{background:i%2===0?"transparent":CA.surface+"55"}}>
                            <td style={td({color:CA.muted,fontSize:9,whiteSpace:"nowrap"})}>{n.sent_at}</td>
                            <td style={td({color:CA.accent,fontFamily:"monospace",fontWeight:700})}>{n.device_id}</td>
                            <td style={td({color:CA.muted,fontFamily:"monospace",fontSize:10})}>{n.to_email}</td>
                            <td style={td({color:lc,fontWeight:900,fontSize:15})}>{n.score}</td>
                            <td style={td()}><span style={{background:lc+"22",color:lc,border:`1px solid ${lc}44`,borderRadius:4,padding:"2px 6px",fontSize:9,fontWeight:700}}>{n.level?.toUpperCase().replace("_"," ")}</span></td>
                            <td style={td({color:n.attack_type?CA.red:CA.muted,fontSize:10})}>{n.attack_type||"auto"}</td>
                            <td style={td({fontSize:10})}>{n.email_sent?<span style={{color:CA.green}}>✅ Sent</span>:<span style={{color:CA.yellow}}>📋 Logged</span>}</td>
                            <td style={td()}>{n.suspicious_ips?.length>0?n.suspicious_ips.map((ip,j)=><div key={j} style={{fontFamily:"monospace",fontSize:9,color:CA.red}}>⚡{ip}</div>):<span style={{color:CA.muted,fontSize:9}}>—</span>}</td>
                          </tr>
                        );
                      })}</tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:${CA.border};border-radius:2px}`}</style>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App(){
  const[user,setUser]=useState(null);
  const[tab,setTab]=useState("dashboard");
  const[devices,setDevices]=useState([]);
  const[scores,setScores]=useState([]);
  const[wsStatus,setWsStatus]=useState("connecting");
  const[notifications,setNotifications]=useState([]);
  const[historyData,setHistoryData]=useState([]);
  const wsRef=useRef(null);
  const prevRef=useRef({});
  const alertCooldown=useRef({});  // per device: last alert time

  // All API calls pass user email in headers for isolation
  const fetchDevices=useCallback(async()=>{
    if(!user)return;
    try{const r=await fetch(`${API}/api/v1/devices/`,{headers:authHeaders(user)});const d=await r.json();setDevices(d.devices||[]);}catch{}
  },[user]);

  const fetchScores=useCallback(async()=>{
    if(!user)return;
    try{
      const r=await fetch(`${API}/api/v1/trust/scores`,{headers:authHeaders(user)});
      const d=await r.json();
      const ns=d.scores||[];
      setScores(ns);

      // Auto-notify: only send if new anomaly and cooldown passed (5 min)
      const now=Date.now();
      for(const s of ns){
        const prev=prevRef.current[s.device_id];
        const lastAlerted=alertCooldown.current[s.device_id]||0;
        const isNewAnomaly=(s.anomaly_detected||s.score<40)&&(!prev||!prev.anomaly_detected||prev.score>=40);
        const cooldownPassed=(now-lastAlerted)>5*60*1000;
        if((isNewAnomaly||cooldownPassed&&(s.anomaly_detected||s.score<40))&&(now-lastAlerted)>60000){
          alertCooldown.current[s.device_id]=now;
          // Find device IP
          const dev=devices.find(d=>d.id===s.device_id);
          fetch(`${API}/api/v1/notifications/send-alert`,{
            method:"POST",headers:{"Content-Type":"application/json"},
            body:JSON.stringify({to_email:user.email,to_name:user.name,device_id:s.device_id,score:s.score,level:s.level,explanation:s.explanation,risk_factors:s.top_risk_factors||[],attack_type:null,device_ip:dev?.ip||null})
          }).then(r=>r.json()).then(data=>{
            setNotifications(prev=>[{id:Date.now(),device_id:s.device_id,score:s.score,level:s.level,explanation:s.explanation,suspicious_ips:data.suspicious_ips||[],email_sent:data.email_sent,time:new Date().toLocaleTimeString()},...prev.slice(0,29)]);
          }).catch(()=>{});
        }
      }
      prevRef.current=Object.fromEntries(ns.map(s=>[s.device_id,s]));
    }catch{}
  },[user,devices]);

  useEffect(()=>{if(!user)return;fetchDevices();fetchScores();const p=setInterval(()=>{fetchDevices();fetchScores();},5000);return()=>clearInterval(p);},[user,fetchDevices,fetchScores]);

  // Real-time graph: push a new data point every 3 seconds using latest scores ref
  const scoresRef=useRef([]);
  useEffect(()=>{scoresRef.current=scores;},[scores]);
  useEffect(()=>{
    if(!user)return;
    const tick=()=>{
      const cur=scoresRef.current;
      if(!cur.length)return;
      const ts=new Date().toLocaleTimeString("en",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"});
      const point={time:ts};
      cur.forEach(s=>{point[s.device_id]=Math.round(s.score||0);});
      setHistoryData(prev=>{
        const last=prev[prev.length-1];
        // Always push if time changed OR scores changed
        const scoresSame=last&&cur.every(s=>last[s.device_id]===Math.round(s.score||0));
        if(last&&last.time===ts&&scoresSame)return prev;
        return[...prev.slice(-50),point];
      });
    };
    const p=setInterval(tick,3000);
    return()=>clearInterval(p);
  },[user]);

  useEffect(()=>{
    if(!user)return;
    const connect=()=>{
      try{
        const ws=new WebSocket(WS);wsRef.current=ws;
        ws.onopen=()=>setWsStatus("live");
        ws.onclose=()=>{setWsStatus("reconnecting");setTimeout(connect,4000);};
        ws.onerror=()=>setWsStatus("error");
        ws.onmessage=e=>{
          try{
            const m=JSON.parse(e.data);
            if(m.type==="trust_update"){
              setScores(m.data);
              // Also push to history immediately on WS update
              const ts=new Date().toLocaleTimeString("en",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"});
              const point={time:ts};
              m.data.forEach(s=>{point[s.device_id]=Math.round(s.score||0);});
              setHistoryData(prev=>[...prev.slice(-50),point]);
            }
          }catch{}
        };
      }catch{}
    };
    connect();return()=>wsRef.current?.close();
  },[user]);

  const triggerAttack=async(deviceId,attackType)=>{
    await fetch(`${API}/api/v1/simulator/trigger`,{method:"POST",headers:authHeaders(user),body:JSON.stringify({device_id:deviceId,attack_type:attackType})});
    const dev=devices.find(d=>d.id===deviceId);
    const sc=scores.find(s=>s.device_id===deviceId);
    fetch(`${API}/api/v1/notifications/send-alert`,{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({to_email:user.email,to_name:user.name,device_id:deviceId,score:sc?.score||10,level:"critical",explanation:`ATTACK SIMULATION: ${attackType.replace(/_/g," ").toUpperCase()} triggered on ${deviceId}`,risk_factors:sc?.top_risk_factors||[],attack_type:attackType,device_ip:dev?.ip||null})
    }).then(r=>r.json()).then(data=>{
      setNotifications(prev=>[{id:Date.now(),device_id:deviceId,score:sc?.score||10,level:"critical",explanation:`${attackType.replace(/_/g," ").toUpperCase()} attack simulated`,suspicious_ips:data.suspicious_ips||[],email_sent:data.email_sent,time:new Date().toLocaleTimeString()},...prev.slice(0,29)]);
    }).catch(()=>{});
    setTimeout(fetchScores,1000);
  };

  const stopAttack=async(deviceId)=>{
    await fetch(`${API}/api/v1/simulator/stop`,{method:"POST",headers:authHeaders(user),body:JSON.stringify({device_id:deviceId})});
    setTimeout(fetchScores,1000);
  };

  const handleLogout=()=>{
    setUser(null);setDevices([]);setScores([]);setNotifications([]);setHistoryData([]);
    prevRef.current={};alertCooldown.current={};
  };

  if(!user)return<LoginPage onLogin={setUser}/>;

  // Admin gets their own dashboard immediately — different tab set entirely
  if(user.role==="admin") return <AdminApp user={user} onLogout={handleLogout}/>;

  const criticalCount=scores.filter(s=>s.score<30).length;
  const wsColor=wsStatus==="live"?C.green:wsStatus==="reconnecting"?C.yellow:C.red;
  const TABS=[
    {id:"dashboard",label:"📊 Dashboard"},
    {id:"network",label:"🌐 Network"},
    {id:"alerts",label:`🚨 Alerts${notifications.length>0?" ("+notifications.length+")":""}`},
    {id:"add_device",label:"➕ Add Device"},
    {id:"baseline",label:"🧠 Train Baseline"},
    {id:"test_data",label:"🔬 Test Data"},
    {id:"email_config",label:"📧 Email Setup"},
  ];

  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'Courier New',monospace"}}>
      <header style={{background:"linear-gradient(90deg,#050d1a,#0a1628)",borderBottom:`1px solid ${C.border}`,padding:"0 20px",position:"sticky",top:0,zIndex:100,boxShadow:"0 4px 20px rgba(0,0,0,0.5)"}}>
        <div style={{maxWidth:1400,margin:"0 auto",display:"flex",alignItems:"center",height:54,gap:12}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginRight:16}}>
            <span style={{fontSize:20}}>🛡️</span>
            <div><div style={{fontSize:13,fontWeight:900,color:C.white,letterSpacing:2}}>SENTINEL<span style={{color:C.accent}}>TRUST</span></div><div style={{fontSize:8,color:C.muted,letterSpacing:1}}>IoT SECURITY ENGINE</div></div>
          </div>
          <nav style={{display:"flex",gap:2,flex:1,flexWrap:"wrap"}}>
            {TABS.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"7px 14px",borderRadius:6,border:"none",cursor:"pointer",background:tab===t.id?`${C.accent}22`:"transparent",color:tab===t.id?C.accent:C.muted,fontSize:11,fontWeight:700,letterSpacing:0.5,borderBottom:tab===t.id?`2px solid ${C.accent}`:"2px solid transparent",transition:"all 0.2s",fontFamily:"'Courier New',monospace"}}>{t.label}</button>)}
          </nav>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            {criticalCount>0&&<div style={{display:"flex",alignItems:"center",gap:6,background:C.red+"22",border:`1px solid ${C.red}44`,borderRadius:6,padding:"4px 8px"}}><PulseDot color={C.red} size={7}/><span style={{color:C.red,fontSize:10,fontWeight:700}}>{criticalCount} CRITICAL</span></div>}
            <div style={{display:"flex",alignItems:"center",gap:5}}><PulseDot color={wsColor} size={7}/><span style={{color:wsColor,fontSize:9,fontWeight:700}}>{wsStatus.toUpperCase()}</span></div>
            <div style={{display:"flex",alignItems:"center",gap:6,background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"4px 10px"}}>
              <span style={{fontSize:12}}>{user.role==="admin"?"🔐":"👤"}</span>
              <div><div style={{fontSize:10,fontWeight:700,color:C.text}}>{user.name}</div><div style={{fontSize:8,color:C.muted}}>{user.email}</div></div>
              <button onClick={handleLogout} style={{marginLeft:6,background:"none",border:`1px solid ${C.border}`,borderRadius:4,color:C.muted,fontSize:9,cursor:"pointer",padding:"2px 5px",fontFamily:"'Courier New',monospace"}}>EXIT</button>
            </div>
          </div>
        </div>
      </header>
      <main style={{maxWidth:1400,margin:"0 auto",padding:"20px"}}>
        {tab==="dashboard"  &&<DarkDashboardTab scores={scores} devices={devices} historyData={historyData} onTrigger={triggerAttack} onStop={stopAttack}/>}
        {tab==="network"    &&<NetworkTab scores={scores}/>}
        {tab==="alerts"     &&<AlertsTab user={user} notifications={notifications} scores={scores}/>}
        {tab==="add_device" &&<AddDeviceTab user={user} onDeviceAdded={fetchDevices}/>}
        {tab==="baseline"   &&<TrainBaselineTab user={user} devices={devices}/>}
        {tab==="test_data"  &&<TestDataTab user={user} devices={devices}/>}
        {tab==="email_config"&&<EmailConfigTab/>}
      </main>
      <style>{`@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px}input::placeholder{color:#9ca3af}select option{background:white;color:#111}`}</style>
    </div>
  );
}
