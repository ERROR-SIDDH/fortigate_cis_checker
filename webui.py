"""
webui.py
--------
Tiny local web page: scan the FortiGate (read token), then Apply / Undo
the fix for each failed check (write token). Binds to 127.0.0.1 only.

    export FGT_API_TOKEN=<read-only token>
    export FGT_WRITE_TOKEN=<read-write token>
    python3 webui.py --host <firewall-ip> --insecure
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from connector import FortiGateAPIClient
from fixer import FIXES, FortiGateWriter, can_undo
from rules import ALL_RULES, RuleContext

PAGE = r"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>FortiGate CIS Console</title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--ink:#141a2a;--mute:#667089;--line:#e3e7f0;--brand:#5b5bf0;--ok:#12a150;--bad:#e5484d;--warn:#d98a00;--err:#7a5af8;--shadow:0 1px 2px #0001,0 8px 24px #1a237e0d}
@media(prefers-color-scheme:dark){:root{--bg:#0d111c;--card:#151b2b;--ink:#e8ecf7;--mute:#8d97b3;--line:#232b42;--brand:#8b8bff;--ok:#3ccf7a;--bad:#ff6b70;--warn:#f5b73d;--err:#a78bfa;--shadow:0 1px 2px #0006,0 8px 24px #0004}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif}
header{background:linear-gradient(120deg,#3b3bd6,#7b4dff 60%,#c04dff);color:#fff;padding:28px 20px 90px}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}header .wrap{display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap}
h1{margin:0;font-size:22px;letter-spacing:-.01em}header p{margin:2px 0 0;opacity:.8;font-size:13px}
.btn{border:0;border-radius:10px;padding:9px 16px;font:600 13px inherit;font-family:inherit;cursor:pointer;transition:.15s;display:inline-flex;gap:8px;align-items:center}
.btn:hover{transform:translateY(-1px)}.btn:disabled{opacity:.6;cursor:wait;transform:none}
.btn.ghost{background:#fff2;color:#fff;backdrop-filter:blur(6px)}.btn.apply{background:var(--brand);color:#fff}.btn.undo{background:transparent;color:var(--mute);box-shadow:inset 0 0 0 1px var(--line)}
main{margin-top:-64px;padding-bottom:60px}
.card{background:var(--card);border-radius:16px;box-shadow:var(--shadow);padding:22px}
.summary{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.ring{--p:0;width:116px;height:116px;border-radius:50%;background:conic-gradient(var(--ok) calc(var(--p)*1%),var(--line) 0);display:grid;place-items:center;transition:--p .8s;flex:none}
.ring>div{width:92px;height:92px;border-radius:50%;background:var(--card);display:grid;place-items:center;font:700 24px inherit;font-family:inherit}
.stats{display:flex;gap:10px;flex-wrap:wrap}.stat{min-width:92px;padding:10px 14px;border-radius:12px;background:var(--bg)}
.stat b{display:block;font-size:22px}.stat span{font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
.filters{display:flex;gap:8px;margin:22px 0 12px;flex-wrap:wrap}.chip{border:1px solid var(--line);background:var(--card);color:var(--mute);border-radius:99px;padding:5px 14px;font:600 13px inherit;font-family:inherit;cursor:pointer}
.chip.on{background:var(--brand);border-color:var(--brand);color:#fff}
.row{background:var(--card);border-radius:14px;box-shadow:var(--shadow);margin-bottom:10px;overflow:hidden;animation:rise .4s both}
.head{display:flex;gap:14px;align-items:center;padding:14px 18px;cursor:pointer}.head:hover{background:var(--bg)}
.id{font:600 12px ui-monospace,monospace;color:var(--mute);width:40px}.title{flex:1;font-weight:600}
.lvl{font-size:11px;color:var(--mute);border:1px solid var(--line);border-radius:6px;padding:1px 6px}
.badge{font:700 11px inherit;font-family:inherit;letter-spacing:.06em;border-radius:99px;padding:3px 10px;color:#fff}
.PASS{background:var(--ok)}.FAIL{background:var(--bad)}.WARN{background:var(--warn)}.ERROR{background:var(--err)}
.body{display:none;padding:0 18px 18px 72px;border-top:1px solid var(--line)}.row.open .body{display:block}
.kv{margin:12px 0 4px;font-size:13px}.kv span{color:var(--mute);display:inline-block;width:72px}
pre{background:#0d111c;color:#cfe1ff;border-radius:10px;padding:12px;font-size:12px;overflow:auto;margin:10px 0}
.actions{display:flex;gap:8px;margin-top:8px}
.spin{width:14px;height:14px;border:2px solid #fff6;border-top-color:#fff;border-radius:50%;animation:rot .7s linear infinite}
.undo .spin{border-color:var(--line);border-top-color:var(--mute)}
@keyframes rot{to{transform:rotate(360deg)}}@keyframes rise{from{opacity:0;transform:translateY(8px)}}
/* scanning */
#scan{display:none;text-align:center;padding:34px 10px}.radar{width:120px;height:120px;margin:0 auto 18px;border-radius:50%;border:2px solid var(--line);position:relative;overflow:hidden;
background:repeating-radial-gradient(circle,transparent 0 19px,var(--line) 20px)}
.radar:after{content:"";position:absolute;inset:0;background:conic-gradient(from 0deg,transparent 0 270deg,var(--brand));animation:rot 1.4s linear infinite;border-radius:50%;opacity:.55}
.bar{height:6px;border-radius:9px;background:var(--line);max-width:360px;margin:14px auto;overflow:hidden}.bar i{display:block;height:100%;width:40%;background:var(--brand);border-radius:9px;animation:slide 1.2s ease-in-out infinite}
@keyframes slide{from{margin-left:-40%}to{margin-left:100%}}
.sk{height:56px;border-radius:14px;margin-bottom:10px;background:linear-gradient(90deg,var(--card) 25%,var(--line) 50%,var(--card) 75%);background-size:200% 100%;animation:sh 1.2s infinite}
@keyframes sh{to{background-position:-200% 0}}
#toast{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:8px}.t{background:var(--ink);color:var(--bg);padding:10px 16px;border-radius:10px;box-shadow:var(--shadow);animation:rise .3s;max-width:360px;font-size:13px}.t.bad{background:var(--bad);color:#fff}
</style>
<header><div class=wrap><div><h1>FortiGate CIS Console</h1><p id=target></p></div>
<button class="btn ghost" id=rescan>&#8635; Rescan</button></div></header>
<main class=wrap>
<div class=card id=scan><div class=radar></div><b id=phase>Connecting to the firewall…</b><div class=bar><i></i></div><p style="color:var(--mute);margin:0">Reading configuration, read-only</p></div>
<div id=skel></div>
<div id=results style="display:none">
<div class="card summary"><div class=ring id=ring><div id=pct>0%</div></div><div class=stats id=stats></div></div>
<div class=filters id=filters></div><div id=list></div></div>
</main><div id=toast></div>
<script>
const $=id=>document.getElementById(id);let DATA=[],FILTER='ALL';
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const toast=(m,bad)=>{const t=el('div','t'+(bad?' bad':''),m);$('toast').append(t);setTimeout(()=>t.remove(),4500)};
const phases=['Connecting to the firewall…','Reading admin & password policy…','Inspecting interfaces & SNMP…','Checking logging & policies…','Scoring results…'];
async function scan(){
  $('rescan').disabled=true;$('results').style.display='none';$('scan').style.display='block';
  $('skel').replaceChildren(...[...Array(6)].map(()=>el('div','sk')));
  let i=0;const iv=setInterval(()=>{$('phase').textContent=phases[Math.min(++i,phases.length-1)]},1100);
  try{
    const [r]=await Promise.all([fetch('/api/scan'),new Promise(r=>setTimeout(r,1800))]);
    if(!r.ok)throw new Error(await r.text());
    const j=await r.json();DATA=j.results;$('target').textContent=j.target+' · scanned '+new Date().toLocaleTimeString();render();
  }catch(e){toast('Scan failed: '+e.message,1)}
  clearInterval(iv);$('scan').style.display='none';$('skel').replaceChildren();$('rescan').disabled=false;
}
function render(){
  const n=s=>DATA.filter(r=>r.status===s).length,pass=n('PASS'),pct=Math.round(100*pass/DATA.length);
  $('results').style.display='block';$('pct').textContent=pct+'%';$('ring').style.setProperty('--p',pct);
  $('stats').replaceChildren(...[['PASS','Passed'],['FAIL','Failed'],['WARN','Warnings'],['ERROR','Errors']].map(([k,l])=>{const d=el('div','stat');d.append(el('b','',n(k)),el('span','',l));return d}));
  $('filters').replaceChildren(...['ALL','FAIL','WARN','PASS','ERROR'].map(f=>{const b=el('button','chip'+(f===FILTER?' on':''),f==='ALL'?'All':f[0]+f.slice(1).toLowerCase());b.onclick=()=>{FILTER=f;render()};return b}));
  $('list').replaceChildren(...DATA.filter(r=>FILTER==='ALL'||r.status===FILTER).map((r,i)=>row(r,i)));
}
function row(r,i){
  const d=el('div','row');d.style.animationDelay=i*30+'ms';
  const h=el('div','head');h.append(el('span','id',r.id),el('span','title',r.title),el('span','lvl','L'+r.level),el('span','badge '+r.status,r.status));h.onclick=()=>d.classList.toggle('open');
  const b=el('div','body');
  const kv=(k,v)=>{const p=el('div','kv');p.append(el('span','',k),document.createTextNode(v));return p};
  b.append(kv('Expected',r.expected),kv('Actual',r.actual));
  if(r.status!=='PASS'){b.append(el('pre','',r.remediation))}
  const a=el('div','actions');
  if(r.fixable&&r.status!=='PASS')a.append(btn('apply','Apply fix',r));
  if(r.undoable)a.append(btn('undo','Undo',r));
  if(a.children.length)b.append(a);d.append(h,b);return d;
}
function btn(kind,label,r){const b=el('button','btn '+kind,label);
  b.onclick=async()=>{b.disabled=true;b.prepend(el('span','spin'));
    const x=await fetch('/'+kind+'/'+r.id,{method:'POST',headers:{'X-Fixer':'1'}});const t=await x.text();
    toast(t,!x.ok);if(x.ok)scan();else{b.disabled=false;b.querySelector('.spin').remove()}};return b}
$('rescan').onclick=scan;scan();
</script>"""


def build_ctx(args) -> RuleContext:
    c = FortiGateAPIClient(args.host, os.environ["FGT_API_TOKEN"], args.port, not args.insecure, vdom=args.vdom)
    return RuleContext(backend="api", cmdb_fetch=c.cmdb, monitor_fetch=c.monitor)


def scan_json(args) -> str:
    ctx = build_ctx(args)
    out = []
    for fn in ALL_RULES:
        r = fn(ctx)
        out.append({"id": r.rule_id, "title": r.title, "status": r.status.value, "level": r.level,
                    "expected": r.expected, "actual": r.actual, "remediation": r.remediation,
                    "fixable": r.rule_id in FIXES, "undoable": can_undo(r.rule_id)})
    out.sort(key=lambda r: [int(p) for p in r["id"].split(".")])
    return json.dumps({"target": args.host, "results": out})


def make_handler(args, writer):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            if self.path == "/api/scan":
                try:
                    return self._send(200, scan_json(args), "application/json")
                except Exception as exc:
                    return self._send(502, str(exc))
            self._send(200, PAGE, "text/html")

        def do_POST(self):
            # Browsers can't add a custom header cross-site without a CORS preflight, so this blocks CSRF.
            if self.headers.get("X-Fixer") != "1":
                return self._send(403, "missing X-Fixer header")
            _, action, rid = self.path.split("/", 2)
            try:
                msg = {"apply": writer.apply, "undo": writer.undo}[action](rid)
                self._send(200, f"{rid}: {msg}")
            except Exception as exc:
                self._send(400, f"{rid}: {exc}")

        def log_message(self, fmt, *a):
            sys.stderr.write("%s\n" % (fmt % a))
    return H


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--vdom", default="root")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    p.add_argument("--listen-port", type=int, default=8080)
    args = p.parse_args()
    for var in ("FGT_API_TOKEN", "FGT_WRITE_TOKEN"):
        if not os.environ.get(var):
            sys.exit(f"ERROR: set {var}")
    writer = FortiGateWriter(args.host, os.environ["FGT_WRITE_TOKEN"], args.port, not args.insecure, args.vdom)
    print(f"Open http://127.0.0.1:{args.listen_port}")
    ThreadingHTTPServer(("127.0.0.1", args.listen_port), make_handler(args, writer)).serve_forever()


if __name__ == "__main__":
    main()
