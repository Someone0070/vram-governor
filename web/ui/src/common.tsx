import React, { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import "./style.css";

export type Workload = {
  request: { id:string; adapter:string; workload_type:string; priority:number; qos?:string; disruption?:string; created_at:string; transformations?:string[] };
  status:string;
  progress?:number;
  progress_stage?:string;
  progress_node?:string;
  progress_current?:number;
  progress_total?:number;
  runtime_priority?:number;
  preemption_count?:number;
  transition_plan_ids?:string[];
  decision?:{ blocker?:string; target_id?:string; alternatives?:string[]; estimated_start?:string; estimated_end?:string; confidence?:number };
  plan?:{plan_hash:string;target_id:string;transformations?:string[];estimated_cost_cents?:number};
  output_refs?:string[];
  inline_output?:unknown;
  error?:string;
};

export async function api<T>(path:string, init:RequestInit = {}):Promise<T> {
  const csrf = sessionStorage.getItem(path.startsWith("/admin/") ? "vg_csrf_admin" : "vg_csrf_ui");
  const headers = new Headers(init.headers);
  if (csrf && init.method && init.method !== "GET") headers.set("X-CSRF-Token", csrf);
  const response = await fetch(path, {...init, credentials:"same-origin", headers});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error?.message || body.error || `Request failed (${response.status})`);
  return body as T;
}

export function Login({onReady,kind="ui"}:{onReady:()=>void;kind?:"ui"|"admin"}) {
  const [token,setToken]=useState(""); const [error,setError]=useState(""); const [checking,setChecking]=useState(true); const attempted=useRef(false);
  function acceptSession(result:{csrf_token:string}) { sessionStorage.setItem(kind==="admin"?"vg_csrf_admin":"vg_csrf_ui",result.csrf_token); setToken(""); onReady(); }
  useEffect(()=>{ if(attempted.current)return; attempted.current=true; api<{csrf_token:string}>("/auth/session",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:"",kind})}).then(acceptSession).catch(()=>setChecking(false)); },[kind]);
  async function submit(event:FormEvent) { event.preventDefault(); setError(""); try { acceptSession(await api<{csrf_token:string}>("/auth/session",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token,kind})})); } catch(e) { setError((e as Error).message); } }
  if(checking)return <div className="login"><form><div className="eyebrow">Local control plane</div><h1>Opening cockpit…</h1><p>Establishing a protected browser session.</p></form></div>;
  return <div className="login"><form onSubmit={submit}><div className="eyebrow">{kind==="admin"?"Independent administrator session":"Secure control plane"}</div><h1>{kind==="admin"?"Unlock Fleet.":"Enter the cockpit."}</h1><p>{kind==="admin"?"Enter an administrator credential. Activity and Chat cookies are intentionally ignored here.":"Use a scoped UI credential. The token is exchanged for an HTTP-only browser session and is not retained."}</p><label>{kind==="admin"?"Administrator token":"Access token"}<input type="password" value={token} onChange={e=>setToken(e.target.value)} autoComplete="current-password" required/></label><button>{kind==="admin"?"Open Fleet":"Start session"}</button>{error&&<div className="error">{error}</div>}</form></div>;
}

export function Shell({title,section,children}:{title:string;section:string;children:ReactNode}) { return <><header><a className="brand" href="/studio/"><span>VG</span> VRAM GOVERNOR</a><nav><a className={section==="chat"?"active":""} href="/chat/">Chat</a><a className={section==="studio"?"active":""} href="/studio/">Activity</a><a className={section==="admin"?"active":""} href="/admin/">Fleet</a></nav><div className="live"><i/> control online</div></header><main><div className="page-title"><div><div className="eyebrow">Unified accelerator control</div><h1>{title}</h1></div><div className="timestamp">{new Date().toLocaleString()}</div></div>{children}</main></> }

export function Status({value}:{value:string}) { return <span className={`status ${value}`}>{value.replaceAll("_"," ")}</span> }

export function usePoll<T>(path:string|null, initial:T, interval=2000) { const [data,setData]=useState(initial); const [error,setError]=useState(""); const refresh=()=>{if(!path)return;api<T>(path).then(v=>{setData(v);setError("")}).catch(e=>setError(e.message))}; useEffect(()=>{if(!path)return;refresh();const id=setInterval(refresh,interval);return()=>clearInterval(id)},[path]); return {data,error,refresh}; }
