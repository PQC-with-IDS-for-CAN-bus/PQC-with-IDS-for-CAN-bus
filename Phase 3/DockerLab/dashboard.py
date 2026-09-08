"""Read-only live view of container evidence, independent of Grafana availability."""
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from controller import read_events, rpc

PAGE = r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PQC / CAN laboratory</title>
<style>
:root{--bg:#edf3f8;--ink:#203b54;--edge:#cbd9e5;--blue:#215bb5;--green:#087769;--red:#b33940}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui}main{max-width:1250px;margin:auto;padding:28px}header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--ink);padding-bottom:18px}h1{font:600 36px/1.1 'Trebuchet MS',sans-serif;margin:8px 0}h2{font-size:18px;margin:0 0 12px}small{font:12px monospace;letter-spacing:.05em}.scope{padding:13px 18px;border-left:4px solid var(--blue);background:#dce8f4;margin:22px 0}.domains{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}article,section{background:white;border:1px solid var(--edge);border-radius:8px;padding:18px}article{cursor:pointer}article[aria-pressed=true]{border:2px solid var(--blue)}article:focus-visible{outline:3px solid var(--blue)}.state{font:12px monospace;overflow-wrap:anywhere}.ok{color:var(--green)}.bad{color:var(--red)}.layout{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}.grid{display:grid;grid-template-columns:repeat(10,1fr);gap:5px}.frame{padding:9px 0;text-align:center;background:var(--bg);border:1px solid var(--edge);font:12px monospace}.received{background:#d9eee8;color:var(--green);border-color:var(--green)}.dropped{background:#f9e2e3;color:var(--red);border-color:var(--red)}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 monospace;margin:8px 0}.events{height:330px;overflow:auto}table{border-collapse:collapse;width:100%;font:12px monospace}td{padding:7px;border-bottom:1px solid var(--edge);vertical-align:top;overflow-wrap:anywhere}td:last-child{max-width:350px}footer{margin-top:22px;font-size:13px}#connection{font:12px monospace}.wide{margin-top:18px}.hint{color:#536b81;font-size:13px}@media(max-width:800px){main{padding:16px}.domains{grid-template-columns:1fr 1fr}.layout{grid-template-columns:1fr}h1{font-size:28px}header{display:block}}
</style><main><header><div><small>PHASE 2 / FOUR ISOLATED CAN DOMAINS</small><h1>PQC handshake. Observable defenses.</h1></div><span id="connection">Connecting to evidence…</span></header>
<div class="scope"><b>Live Docker processes · Linux SocketCAN · real cryptography</b><br>Virtual CAN has no physical bitrate or arbitration measurement. Data below comes from node logs. Tier-2 vehicle IDS is not evaluated without a verified vehicle data stream.</div>
<div id="domains" class="domains"></div><div class="layout"><section><h2 id="bufferTitle">Receiver buffer</h2><p class="hint">Gray: not received · Red: injected omission · Green: accepted fragment</p><div id="frames" class="grid"></div><pre id="recovery"></pre></section><section><h2>Authentication and session</h2><pre id="session">Waiting for an execution.</pre><p class="hint">ML-DSA-44 attests the actual ECU source. HKDF derives bootstrap keys. Ascon protects attestation and session-key delivery. Only authenticated diagnostic frames can advance the replay counter.</p></section></div>
<section class="wide"><h2>Live event stream</h2><div class="events"><table><tbody id="events"></tbody></table></div></section><section class="wide"><h2>Latest completed experiment</h2><pre id="suite">No experiment has completed yet.</pre></section><footer>Run the experiment with <code>python3 lab.py run</code>. Logs are retained under <code>state/logs</code>; CSV and evidence exports under <code>state/exports</code>. Optional Grafana: <a href="http://localhost:3000">localhost:3000</a>.</footer></main>
<script>
const $=id=>document.getElementById(id),names=['Powertrain','Chassis','Body & comfort','Infotainment'];let selected=1,last=null;
const cards=names.map((name,i)=>{let c=document.createElement('article');c.tabIndex=0;c.setAttribute('role','button');let h=document.createElement('h2');h.textContent=name;let s=document.createElement('div');s.className='state';s.textContent='Waiting for readiness';c.append(h,s);c.onclick=()=>{selected=i+1;if(last)draw(last)};c.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();c.click()}};$('domains').append(c);return c});
const cells=Array.from({length:41},(_,i)=>{let e=document.createElement('div');e.className='frame';e.textContent=i;$('frames').append(e);return e});
function draw(data){last=data;cards.forEach((c,i)=>{let s=data.gateway?.domains?.[i+1];c.setAttribute('aria-pressed',String(selected===i+1));c.lastChild.textContent=s?(s.busy?'HANDSHAKE RUNNING':s.result?.status||'READY'): 'NOT READY'});let state=data.gateway?.domains?.[selected];let run=state?.run_id;let log=data.events.filter(e=>e.domain===selected&&e.run_id===run);cells.forEach(c=>c.className='frame');log.forEach(e=>{if(Number.isInteger(e.frame_idx)&&e.frame_idx>=0&&e.frame_idx<41){if(e.event==='injected_drop')cells[e.frame_idx].className='frame dropped';if(e.event==='fragment_accepted')cells[e.frame_idx].className='frame received'}});$('bufferTitle').textContent=names[selected-1]+' / receiver buffer';let r=state?.result;$('session').textContent=r?JSON.stringify({status:r.status,ascon_tag_valid:r.ascon_tag_valid,mldsa_signature_valid:r.mldsa_signature_valid,key_delivered:r.key_delivered,authenticated_diagnostics:r.diagnostic_accepted,session_id:r.session_id},null,2):state?.busy?'Handshake in progress.':'Ready; no completed handshake.';$('recovery').textContent=r?.rounds?.length?r.rounds.map(x=>`Round ${x.round}: ${x.bitmap}\n${x.requested} requested → ${x.recovered} recovered`).join('\n'):'No NACK rounds recorded.';$('events').replaceChildren();data.events.filter(e=>e.domain===selected).slice(-70).reverse().forEach(e=>{let tr=document.createElement('tr');[new Date(e.epoch_ns/1e6).toLocaleTimeString(),e.node,e.event,e.can_id||e.status||''].forEach(v=>{let td=document.createElement('td');td.textContent=v;tr.append(td)});$('events').append(tr)});$('suite').textContent=data.latest?JSON.stringify(data.latest,null,2):'No experiment has completed yet.'}
async function poll(){try{let r=await fetch('/snapshot');if(!r.ok)throw Error(r.status);draw(await r.json());$('connection').textContent='Updated '+new Date().toLocaleTimeString();}catch(e){$('connection').textContent='Evidence connection unavailable: '+e.message}setTimeout(poll,1000)}poll();
</script></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass
    def do_GET(self):
        if self.path == '/snapshot':
            try:
                gateway = rpc('gateway')
            except OSError:
                gateway = None
            path = Path('/exports/latest.json')
            events = read_events()
            # Keep current run evidence for each domain plus recent attack events.
            current = {s.get('run_id') for s in (gateway or {}).get('domains',{}).values()}
            body = json.dumps(dict(gateway=gateway, events=[e for e in events if e.get('run_id') in current],
                              latest=json.loads(path.read_text()) if path.exists() else None)).encode()
            kind='application/json'
        elif self.path in ('/','/health'):
            body,kind=PAGE.encode(),'text/html; charset=utf-8'
        else:
            self.send_error(404);return
        self.send_response(200)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
