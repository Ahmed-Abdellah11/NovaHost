"""REST API + admin dashboard.   uvicorn nova.api:app --port 8000   (docs at /docs)"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import blocklist, config
from .service import Engine

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["engine"] = Engine()
    blocklist.sync(state["engine"].store)
    yield


app = FastAPI(title="Nova Host - AI Website Classifier", version="1.0.0", lifespan=lifespan)


def engine() -> Engine:
    return state["engine"]


def require_key(x_api_key: str = Header(default="")):
    if config.API_KEY and not hmac.compare_digest(x_api_key, config.API_KEY):
        raise HTTPException(401, "missing or invalid X-API-Key")


class DomainIn(BaseModel):
    domain: str = Field(min_length=3, max_length=300, examples=["paypal-secure-login.xyz"])


class BatchIn(BaseModel):
    domains: list[str] = Field(max_length=1000)


@app.get("/health")
def health():
    e = engine()
    return {"status": "ok", "model_version": e.clf.version, "block_threshold": round(e.clf.block_t, 3),
            "suspicious_threshold": round(e.clf.suspect_t, 3), "feed_size": len(e.feed),
            "auth_enabled": bool(config.API_KEY)}


@app.post("/classify")
def classify(body: DomainIn, record: bool = Query(False, description="also log into the DB / blocklist")):
    try:
        return engine().decide(body.domain, record=record)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/classify/batch")
def classify_batch(body: BatchIn):
    out = []
    for d in body.domains:
        try:
            out.append(engine().decide(d))
        except ValueError:
            out.append({"domain": d, "verdict": "INVALID"})
    return out


@app.get("/decisions")
def decisions(limit: int = Query(50, le=500)):
    return engine().store.recent(limit)


@app.get("/review")
def review(limit: int = Query(50, le=500)):
    """Suspicious domains waiting for an admin decision."""
    return engine().store.review_queue(limit)


@app.get("/stats")
def stats():
    return engine().store.stats()


@app.post("/allow", dependencies=[Depends(require_key)])
def allow(body: DomainIn):
    return _override(body.domain, "SAFE")


@app.post("/deny", dependencies=[Depends(require_key)])
def deny(body: DomainIn):
    return _override(body.domain, "BLOCK")


def _override(raw: str, verdict: str):
    from .features import is_valid, normalize
    d = normalize(raw)
    if not is_valid(d):
        raise HTTPException(422, "not a valid domain")
    e = engine()
    e.store.set_override(d, verdict)
    n, reloaded = blocklist.sync(e.store)
    return {"domain": d, "verdict": verdict, "blocklist_size": n, "dnsmasq_reloaded": reloaded}


@app.get("/blocklist", response_class=PlainTextResponse)
def get_blocklist():
    return "".join(f"0.0.0.0 {d}\n" for d in engine().store.blocked_domains())


DASHBOARD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nova Host - AI Website Classifier</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--mut:#667085;--bd:#e2e5ea;--ok:#1a7f4b;--warn:#b7791f;--bad:#c53030;--acc:#2b59c3}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e8ebf0;--mut:#9aa3b2;--bd:#2c3340;--ok:#4cc38a;--warn:#e0b04a;--bad:#f06a6a;--acc:#6f95ee}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 60px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}
.sub{color:var(--mut);margin-bottom:20px}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:8px;flex-wrap:wrap}input{flex:1;min-width:220px;padding:10px 12px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg);font-size:15px}
button{padding:9px 14px;border:0;border-radius:8px;background:var(--acc);color:#fff;font-size:14px;cursor:pointer}button.sec{background:transparent;color:var(--fg);border:1px solid var(--bd)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid currentColor}
.SAFE{color:var(--ok)}.SUSPICIOUS{color:var(--warn)}.BLOCK{color:var(--bad)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}.stat b{display:block;font-size:24px}.stat span{color:var(--mut);font-size:13px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);white-space:nowrap}th{color:var(--mut);font-weight:500}
#result{margin-top:12px}.mut{color:var(--mut)}
</style></head><body><main>
<h1>Nova Host - AI Website Classifier</h1><div class="sub">Live domain classification, review queue and DNS blocklist.</div>
<div class="card"><h2>Check a domain</h2><div class="row"><input id="d" placeholder="e.g. paypal-secure-login.xyz" autocomplete="off">
<button id="go">Classify</button></div><div id="result"></div></div>
<div class="card"><h2>Overview</h2><div class="stats" id="stats"></div></div>
<div class="card"><h2>Review queue <span class="mut">(suspicious, waiting for a decision)</span></h2><div class="tw"><table id="rev"></table></div></div>
<div class="card"><h2>Recent decisions</h2><div class="tw"><table id="rec"></table></div></div>
</main><script>
const $=id=>document.getElementById(id);
const el=(t,txt,cls)=>{const e=document.createElement(t);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e};
const pill=v=>el('span',v,'pill '+v);
let KEY=sessionStorage.getItem('k')||'';
async function api(p,o){const r=await fetch(p,o);if(!r.ok)throw new Error((await r.json().catch(()=>({}))).detail||r.statusText);return r.json()}
async function act(kind,domain){
  const go=async()=>api('/'+kind,{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':KEY},body:JSON.stringify({domain})});
  try{await go()}catch(e){if(String(e.message).includes('X-API-Key')){KEY=prompt('API key')||'';sessionStorage.setItem('k',KEY);try{await go()}catch(x){alert(x.message)}}else alert(e.message)}
  load()}
function table(t,rows,withAct){t.replaceChildren();const h=el('tr');['Domain','Verdict','Score','Layer','Why'].concat(withAct?['']:[]).forEach(x=>h.append(el('th',x)));t.append(h);
  rows.forEach(r=>{const tr=el('tr');tr.append(el('td',r.domain));const v=el('td');v.append(pill(r.verdict));tr.append(v);tr.append(el('td',Number(r.score).toFixed(2)));tr.append(el('td',r.layer));tr.append(el('td',(r.reasons||[]).join('; ')));
    if(withAct){const a=el('td');const ok=el('button','Allow','sec');ok.onclick=()=>act('allow',r.domain);const no=el('button','Block');no.style.marginLeft='6px';no.onclick=()=>act('deny',r.domain);a.append(ok,no);tr.append(a)}t.append(tr)});
  if(!rows.length){const tr=el('tr');tr.append(el('td','Nothing yet','mut'));t.append(tr)}}
async function load(){
  const s=await api('/stats');$('stats').replaceChildren();
  [['Domains seen',s.total],['Safe',s.by_verdict.SAFE||0],['Suspicious',s.by_verdict.SUSPICIOUS||0],['Blocked',s.by_verdict.BLOCK||0],['Active blocklist',s.blocked_now],['Admin overrides',s.overrides]]
   .forEach(([k,v])=>{const d=el('div','','stat');d.append(el('b',v),el('span',k));$('stats').append(d)});
  table($('rev'),await api('/review'),true);table($('rec'),await api('/decisions?limit=15'),false)}
async function check(){const d=$('d').value.trim();if(!d)return;const out=$('result');out.replaceChildren();
  try{const r=await api('/classify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:d})});
    out.append(pill(r.verdict),el('span','  '+r.domain+'  score '+r.score.toFixed(2)+'  (decided by: '+r.layer+')'));
    if(r.reasons.length)out.append(el('div','Why: '+r.reasons.join('; '),'mut'))}catch(e){out.append(el('span',e.message,'BLOCK'))}}
$('go').onclick=check;$('d').addEventListener('keydown',e=>{if(e.key==='Enter')check()});load();setInterval(load,5000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return DASHBOARD
