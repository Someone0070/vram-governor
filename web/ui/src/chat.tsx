import React, { FormEvent, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Login, Shell, usePoll } from "./common";
import "./chat.css";
import "./chat-progress.css";

type ChatMessage = {role:"user"|"assistant";content:string;model?:string};
type ModelCatalog = {data:{id:string;owned_by?:string;governor?:{max_context_tokens?:number;available_context_limits?:number[];target_count?:number;resident?:boolean;lifecycle_capable?:boolean}}[]};

function modelSizeRank(id:string) {
  const match=id.match(/(?:^|[^\d])(\d+(?:\.\d+)?)\s*b(?:[^a-z]|$)/i);
  return match?Number(match[1]):Number.POSITIVE_INFINITY;
}

function Chat() {
  const [ready,setReady]=useState(false);
  const {data:models,error:modelError}=usePoll<ModelCatalog>(ready?"/v1/models":null,{data:[]},10000);
  const [model,setModel]=useState("");
  const [messages,setMessages]=useState<ChatMessage[]>([]);
  const [draft,setDraft]=useState("");
  const [contextTokens,setContextTokens]=useState(2048);
  const [maxOutput,setMaxOutput]=useState(512);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [keepTranscript,setKeepTranscript]=useState(true);
  const [switchNotice,setSwitchNotice]=useState("");
  const [placementKey,setPlacementKey]=useState(()=>`chat-${crypto.randomUUID()}`);
  const abortRef=useRef<AbortController|null>(null);
  const transcriptRef=useRef<HTMLDivElement|null>(null);
  const selectedModel=models.data.find(row=>row.id===model);
  const routeContext=selectedModel?.governor?.max_context_tokens||0;

  useEffect(()=>{
    if(!models.data.length||models.data.some(row=>row.id===model))return;
    const remembered=localStorage.getItem("vg_chat_model");
    const preferred=models.data.find(row=>row.id===remembered)?.id;
    const safest=[...models.data].sort((left,right)=>modelSizeRank(left.id)-modelSizeRank(right.id))[0]?.id;
    setModel(preferred||safest||models.data[0].id);
  },[models,model]);
  useEffect(()=>{
    if(!routeContext)return;
    const nextOutput=Math.min(maxOutput,Math.max(1,routeContext-256));
    const nextContext=Math.min(contextTokens,Math.max(256,routeContext-nextOutput));
    if(nextOutput!==maxOutput)setMaxOutput(nextOutput);
    if(nextContext!==contextTokens)setContextTokens(nextContext);
  },[routeContext,contextTokens,maxOutput]);
  useEffect(()=>{transcriptRef.current?.scrollTo({top:transcriptRef.current.scrollHeight,behavior:"smooth"})},[messages]);
  if(!ready)return <Login onReady={()=>setReady(true)}/>;

  function changeModel(nextModel:string) {
    if(nextModel===model)return;
    localStorage.setItem("vg_chat_model",nextModel);
    if(messages.length&&keepTranscript) {
      setSwitchNotice("Transcript retained. The new model will re-tokenize every message; the previous model's KV cache is not reused.");
    } else if(messages.length) {
      setMessages([]);
      setPlacementKey(`chat-${crypto.randomUUID()}`);
      setSwitchNotice("New model, new conversation. The previous transcript was cleared.");
    } else {
      setSwitchNotice("");
    }
    setModel(nextModel);
  }

  async function send(event:FormEvent) {
    event.preventDefault();
    const text=draft.trim();
    if(!text||!model||busy)return;
    if(routeContext&&contextTokens+maxOutput>routeContext){setError(`This route supports ${routeContext.toLocaleString()} total tokens; input plus maximum response is ${(contextTokens+maxOutput).toLocaleString()}.`);return}
    const next:ChatMessage[]=[...messages,{role:"user",content:text}];
    const requestMessages=next.map(({role,content})=>({role,content}));
    setDraft("");setError("");setBusy(true);setMessages([...next,{role:"assistant",content:"",model}]);
    const controller=new AbortController();abortRef.current=controller;
    let assistant="";
    try {
      const response=await fetch("/v1/chat/completions",{method:"POST",credentials:"same-origin",signal:controller.signal,headers:{"Content-Type":"application/json","X-CSRF-Token":sessionStorage.getItem("vg_csrf_ui")||""},body:JSON.stringify({model,messages:requestMessages,max_completion_tokens:maxOutput,stream:true,governor:{context_tokens:contextTokens,placement_key:placementKey,placement_policy:"sticky"}})});
      if(!response.ok){const body=await response.json().catch(()=>({}));const alternatives=body.admission?.alternatives as string[]|undefined;const detail=body.error?.message||body.error||`Request failed (${response.status})`;throw new Error(alternatives?.length&&!String(detail).includes(alternatives[0])?`${detail}: ${alternatives.join("; ")}`:detail)}
      if(!response.body)throw new Error("Streaming response unavailable");
      const reader=response.body.getReader();const decoder=new TextDecoder();let buffer="";
      while(true){const {done,value}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});const frames=buffer.split(/\r?\n\r?\n/);buffer=frames.pop()||"";for(const frame of frames){for(const line of frame.split(/\r?\n/)){if(!line.startsWith("data:"))continue;const data=line.slice(5).trim();if(!data||data==="[DONE]")continue;const chunk=JSON.parse(data);const token=chunk.choices?.[0]?.delta?.content||"";if(token){assistant+=token;setMessages([...next,{role:"assistant",content:assistant,model}])}}}}
      if(!assistant)setMessages([...next,{role:"assistant",content:"The model returned an empty response.",model}]);
    } catch(cause) {
      if((cause as Error).name!=="AbortError"){setError((cause as Error).message);setMessages(next)}
    } finally {abortRef.current=null;setBusy(false)}
  }

  function stop(){abortRef.current?.abort();setBusy(false)}
  function clear(){if(busy)stop();setMessages([]);setError("");setSwitchNotice("");setPlacementKey(`chat-${crypto.randomUUID()}`)}

  return <Shell title="Chat" section="chat">
    <section className="chat-shell">
      <aside className="chat-settings">
        <div><div className="eyebrow">Local inference</div><h2>Conversation setup</h2><p>Messages use the same scheduler, leases, budgets, and sticky placement as every agent request.</p></div>
        <label>Model<select value={model} onChange={event=>changeModel(event.target.value)} disabled={busy||models.data.length===0}>{models.data.map(row=><option key={row.id} value={row.id}>{row.id}</option>)}</select></label>
        <label className="context-policy"><span><input type="checkbox" checked={keepTranscript} onChange={event=>setKeepTranscript(event.target.checked)}/> Keep transcript when switching models</span><small>Messages stay, but each model rebuilds its own tokenization and KV cache.</small></label>
        <label>Input context budget<input type="number" min="256" max={routeContext?Math.max(256,routeContext-maxOutput):undefined} step="256" value={contextTokens} onChange={event=>setContextTokens(Math.min(Number(event.target.value),routeContext?Math.max(256,routeContext-maxOutput):Number(event.target.value)))}/></label>
        <label>Maximum response<input type="number" min="1" max={routeContext?Math.max(1,routeContext-contextTokens):8192} value={maxOutput} onChange={event=>setMaxOutput(Math.min(Number(event.target.value),routeContext?Math.max(1,routeContext-contextTokens):Number(event.target.value)))}/></label>
        <div className="chat-session"><small>{routeContext?`Route window ${routeContext.toLocaleString()} tokens · using ${(contextTokens+maxOutput).toLocaleString()}`:"Sticky session"}</small><code>{placementKey}</code></div>
        {switchNotice&&<div className="context-notice">{switchNotice}</div>}
        <button className="quiet" onClick={clear}>Clear conversation</button>{modelError&&<div className="error">{modelError}</div>}
      </aside>
      <section className="chat-panel">
        <div className={`chat-head ${busy?"loading":""}`}><div><i className={busy?"thinking":""}/><span>{busy?"Preparing model / generating":model?`${model} ready`:"No eligible chat model"}</span></div><span>{messages.length} messages</span></div>
        <div className="transcript" ref={transcriptRef}>{messages.length===0?<div className="chat-empty"><span>VG</span><h2>What do you want to run?</h2><p>This is the human chat surface. Agents should continue using the OpenAI-compatible API directly.</p></div>:messages.map((message,index)=><article className={`message ${message.role}`} key={`${message.role}-${index}`}><small>{message.role==="user"?"You":message.model||model}</small><div>{message.content||<i className="typing">•••</i>}</div></article>)}</div>
        {error&&<div className="error chat-error">{error}</div>}
        <form className="chat-composer" onSubmit={send}><textarea rows={3} value={draft} onChange={event=>setDraft(event.target.value)} onKeyDown={event=>{if(event.key==="Enter"&&(event.ctrlKey||event.metaKey))event.currentTarget.form?.requestSubmit()}} placeholder={model?"Message the model…":"Waiting for an eligible model…"} disabled={!model}/><div><span>Ctrl/⌘ + Enter to send</span>{busy?<button type="button" className="stop" onClick={stop}>Stop</button>:<button disabled={!model||!draft.trim()}>Send</button>}</div></form>
      </section>
    </section>
  </Shell>
}

createRoot(document.getElementById("root")!).render(<Chat/>);
