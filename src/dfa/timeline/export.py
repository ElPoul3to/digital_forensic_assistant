"""Self-contained HTML timeline: one local file, no server, no external resources.

The page embeds the exported events as JSON and draws a stacked histogram
(drag to zoom, click a bar to select it), filter controls and a paged event
table with a detail panel showing the raw line.  Evidence never leaves the
host: the file is opened from disk.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

COLUMNS = ("event_id", "ts", "host", "user", "category", "action", "source_file", "record_ref", "summary", "raw", "ips")


def _cell(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, list):
        return [str(x) for x in v]
    return v


def rows_to_json(rows: list[dict[str, Any]], raw_chars: int = 400) -> str:
    out = []
    for r in rows:
        row = [_cell(r.get(c)) for c in COLUMNS]
        raw = row[COLUMNS.index("raw")]
        if isinstance(raw, str) and len(raw) > raw_chars:
            row[COLUMNS.index("raw")] = raw[:raw_chars] + "…"
        out.append(row)
    # "</" must not terminate the script element
    return json.dumps({"columns": list(COLUMNS), "rows": out}, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def render(case_id: str, rows: list[dict[str, Any]], *, total: int, filters: dict[str, Any], raw_chars: int = 400) -> str:
    meta = {"case": case_id, "exported": len(rows), "total": total,
            "filters": {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in filters.items() if v},
            "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}
    return (_TEMPLATE.replace("__TITLE__", html.escape(f"Timeline {case_id}"))
            .replace("__META__", json.dumps(meta).replace("</", "<\\/"))
            .replace("__DATA__", rows_to_json(rows, raw_chars)))


def write(path: Path, case_id: str, rows: list[dict[str, Any]], *, total: int, filters: dict[str, Any], raw_chars: int = 400) -> Path:
    path.write_text(render(case_id, rows, total=total, filters=filters, raw_chars=raw_chars), encoding="utf-8")
    return path


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>__TITLE__</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#ddd;--panel:#f6f6f6;--sel:#ffe9a8;--accent:#2b6cb0}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#e6e6e6;--muted:#9a9a9a;--line:#333;--panel:#1e1f22;--sel:#5a4a12;--accent:#7ab0ff}}
*{box-sizing:border-box}body{margin:0;padding:12px 16px;font:13px/1.4 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
h1{font-size:16px;margin:0 0 4px}.meta{color:var(--muted);margin-bottom:8px}
.controls{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:8px}
.controls select,.controls input,.controls button{font:inherit;padding:3px 6px;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:4px}
.controls input[type=text]{min-width:220px}
#chart{width:100%;height:180px;display:block;border:1px solid var(--line);border-radius:4px;cursor:crosshair;background:var(--panel);touch-action:none}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin:6px 0;color:var(--muted)}.legend span::before{content:"";display:inline-block;width:10px;height:10px;margin-right:4px;border-radius:2px;background:var(--c);vertical-align:-1px}
.status{margin:6px 0;color:var(--muted)}
.wrap{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}@media(min-width:1100px){.wrap{grid-template-columns:minmax(0,2fr) minmax(280px,1fr)}}
.tbl{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:3px 6px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
td.sum{white-space:normal;max-width:60vw}tr:hover td{background:var(--panel)}tr.sel td{background:var(--sel)}th{position:sticky;top:0;background:var(--bg)}
.cat{display:inline-block;padding:0 5px;border-radius:3px;color:#000;background:var(--c);font-size:11px}
#detail{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:8px;min-height:60px;position:sticky;top:8px}
#detail pre{white-space:pre-wrap;word-break:break-all;margin:6px 0 0;font-size:12px}#detail dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:2px 8px}#detail dt{color:var(--muted)}
button.more{margin:8px 0}
</style></head><body>
<h1 id="title"></h1><div class="meta" id="meta"></div>
<div class="controls">
 <select id="f_host"></select><select id="f_user"></select><select id="f_category"></select><select id="f_action"></select><select id="f_source_file"></select>
 <input type="text" id="f_text" placeholder="text filter (summary / raw, case-insensitive)">
 <select id="bucket"><option value="auto">bucket: auto</option><option value="60000">minute</option><option value="3600000">hour</option><option value="86400000">day</option></select>
 <button id="reset">reset zoom</button><button id="clear">clear filters</button>
</div>
<canvas id="chart"></canvas><div class="legend" id="legend"></div>
<div class="status" id="status"></div>
<div class="wrap"><div class="tbl"><table><thead><tr><th>time (UTC)</th><th>host</th><th>user</th><th>category / action</th><th>summary</th><th>source</th></tr></thead><tbody id="rows"></tbody></table><button class="more" id="more">show more</button></div>
<div id="detail"><span style="color:var(--muted)">Click an event to see its raw line. Drag on the chart to zoom into a time range; click a bar to select that bucket.</span></div></div>
<script id="meta-json" type="application/json">__META__</script>
<script id="data-json" type="application/json">__DATA__</script>
<script>
(function(){
const META=JSON.parse(document.getElementById('meta-json').textContent);
const DATA=JSON.parse(document.getElementById('data-json').textContent);
const C=Object.fromEntries(DATA.columns.map((c,i)=>[c,i]));
const EV=DATA.rows.map(r=>{const t=r[C.ts];return {r,t:t?Date.parse(t):NaN}});
EV.sort((a,b)=>(isNaN(a.t)?1:0)-(isNaN(b.t)?1:0)||a.t-b.t);
const PALETTE={authentication:'#e6a23c',privilege:'#e05c5c',user_management:'#c65cd6',network:'#4f9ddb',web:'#3cb371',package:'#8b8b3c',kernel:'#9aa5b1',service:'#5cc0c0',other:'#c0c0c0',process:'#f28cb1',file:'#b9a06b',registry:'#9370db',dns:'#2aa198'};
const color=c=>PALETTE[c]||('#'+((h=>{let x=0;for(const ch of h)x=(x*31+ch.charCodeAt(0))>>>0;return (x&0xffffff).toString(16).padStart(6,'0')})(c||'')));
const $=id=>document.getElementById(id);
document.title='Timeline '+META.case;$('title').textContent='Timeline: '+META.case;
$('meta').textContent=`${META.exported.toLocaleString()} of ${META.total.toLocaleString()} events exported ${META.generated}`+(Object.keys(META.filters).length?' with filters '+JSON.stringify(META.filters):'');
const F={host:'',user:'',category:'',action:'',source_file:'',text:''};let range=null,selected=null,shown=0;const PAGE=200;
for(const k of ['host','user','category','action','source_file']){const s=$('f_'+k),cnt={};for(const e of EV){const v=e.r[C[k]];if(v!=null)cnt[v]=(cnt[v]||0)+1}
 s.innerHTML=`<option value="">${k}: all</option>`+Object.entries(cnt).sort((a,b)=>b[1]-a[1]).map(([v,n])=>`<option value="${esc(v)}">${esc(v)} (${n})</option>`).join('');
 s.onchange=()=>{F[k]=s.value;redraw()}}
let tmr;$('f_text').oninput=()=>{clearTimeout(tmr);tmr=setTimeout(()=>{F.text=$('f_text').value.toLowerCase();redraw()},150)};
$('bucket').onchange=redraw;$('reset').onclick=()=>{range=null;redraw()};
$('clear').onclick=()=>{for(const k in F){F[k]='';const s=$('f_'+k);if(s)s.value=''}range=null;redraw()};
$('more').onclick=()=>{renderRows(false)};
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function pass(e,withRange){const r=e.r;for(const k of ['host','user','category','action','source_file'])if(F[k]&&r[C[k]]!==F[k])return false;
 if(F.text&&!((r[C.summary]||'').toLowerCase().includes(F.text)||(r[C.raw]||'').toLowerCase().includes(F.text)))return false;
 if(withRange&&range&&!(e.t>=range[0]&&e.t<range[1]))return false;return true}
function filtered(withRange){return EV.filter(e=>pass(e,withRange))}
function bucketMs(span){const b=$('bucket').value;if(b!=='auto')return +b;if(span<=3*3600e3)return 60e3;if(span<=14*86400e3)return 3600e3;return 86400e3}
const cv=$('chart'),ctx=cv.getContext('2d');let bars=[],x0=0,x1=1,plotL=48,plotR=8,plotT=6,plotB=22;
function drawChart(){const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
 const evs=filtered(false).filter(e=>!isNaN(e.t));if(!evs.length){bars=[];ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--muted');ctx.fillText('no timestamped events match',plotL,H/2);return}
 x0=range?range[0]:evs[0].t;x1=range?range[1]:evs[evs.length-1].t+1;const bm=bucketMs(x1-x0);x0=Math.floor(x0/bm)*bm;x1=Math.ceil(x1/bm)*bm;const n=Math.max(1,Math.round((x1-x0)/bm));
 const cats=[...new Set(evs.map(e=>e.r[C.category]||'other'))];const m=Array.from({length:n},()=>({}));let max=1;
 for(const e of evs){if(e.t<x0||e.t>=x1)continue;const i=Math.min(n-1,Math.floor((e.t-x0)/bm));const c=e.r[C.category]||'other';m[i][c]=(m[i][c]||0)+1}
 for(const b of m)max=Math.max(max,Object.values(b).reduce((a,v)=>a+v,0));
 const pw=W-plotL-plotR,ph=H-plotT-plotB,bw=pw/n;bars=[];const fg=getComputedStyle(document.body).getPropertyValue('--fg'),muted=getComputedStyle(document.body).getPropertyValue('--muted');
 ctx.strokeStyle=muted;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(plotL,plotT+ph);ctx.lineTo(plotL+pw,plotT+ph);ctx.stroke();
 ctx.fillStyle=muted;ctx.font='11px system-ui';ctx.textAlign='right';ctx.fillText(max.toLocaleString(),plotL-4,plotT+10);ctx.fillText('0',plotL-4,plotT+ph);
 for(let i=0;i<n;i++){let y=plotT+ph;const tot=Object.values(m[i]).reduce((a,v)=>a+v,0);bars.push({x:plotL+i*bw,w:bw,t0:x0+i*bm,t1:x0+(i+1)*bm,tot});
  for(const c of cats){const v=m[i][c];if(!v)continue;const h=v/max*ph;ctx.fillStyle=color(c);ctx.fillRect(plotL+i*bw+0.5,y-h,Math.max(1,bw-1),h);y-=h}
  if(selected&&selected.t0===x0+i*bm){ctx.strokeStyle=fg;ctx.strokeRect(plotL+i*bw+0.5,plotT,Math.max(1,bw-1),ph)}}
 ctx.textAlign='left';const ticks=Math.max(2,Math.floor(pw/110));for(let k=0;k<=ticks;k++){const t=x0+(x1-x0)*k/ticks,x=plotL+pw*k/ticks;ctx.fillStyle=muted;ctx.fillText(fmt(t,bm),Math.min(x,plotL+pw-90),H-6)}
 $('legend').innerHTML=cats.map(c=>`<span style="--c:${color(c)}">${esc(c)}</span>`).join('')+`<span style="--c:transparent">bucket: ${bm>=86400e3?'day':bm>=3600e3?'hour':'minute'}</span>`}
function fmt(t,bm){const d=new Date(t);const iso=d.toISOString();return bm>=86400e3?iso.slice(0,10):iso.slice(5,16).replace('T',' ')}
let drag=null;cv.onpointerdown=e=>{drag={x:e.offsetX,moved:false};cv.setPointerCapture(e.pointerId)};
cv.onpointermove=e=>{if(!drag)return;if(Math.abs(e.offsetX-drag.x)>3)drag.moved=true;if(drag.moved){drawChart();ctx.fillStyle='rgba(120,120,255,0.25)';ctx.fillRect(Math.min(drag.x,e.offsetX),plotT,Math.abs(e.offsetX-drag.x),cv.clientHeight-plotT-plotB)}};
cv.onpointerup=e=>{if(!drag)return;const a=Math.min(drag.x,e.offsetX),b=Math.max(drag.x,e.offsetX);const px2t=x=>x0+(x-plotL)/(cv.clientWidth-plotL-plotR)*(x1-x0);
 if(drag.moved){range=[px2t(a),px2t(b)];selected=null}else{const bar=bars.find(bb=>e.offsetX>=bb.x&&e.offsetX<bb.x+bb.w);if(bar){selected=(selected&&selected.t0===bar.t0)?null:bar}}
 drag=null;redraw()};
cv.ondblclick=()=>{if(selected){range=[selected.t0,selected.t1];selected=null;redraw()}};
let cur=[];function renderRows(reset){if(reset){$('rows').innerHTML='';shown=0}const tb=$('rows'),end=Math.min(cur.length,shown+PAGE);const frag=document.createDocumentFragment();
 for(let i=shown;i<end;i++){const r=cur[i].r,tr=document.createElement('tr');tr.dataset.i=i;const c=r[C.category]||'other';
  tr.innerHTML=`<td>${r[C.ts]?esc(r[C.ts]).replace('T',' ').replace('Z',''):'—'}</td><td>${esc(r[C.host]||'')}</td><td>${esc(r[C.user]||'')}</td><td><span class="cat" style="--c:${color(c)}">${esc(c)}</span> ${esc(r[C.action]||'')}</td><td class="sum">${esc(r[C.summary]||'')}</td><td>${esc(r[C.source_file]||'')} ${esc(r[C.record_ref]||'')}</td>`;
  tr.onclick=()=>{for(const x of tb.querySelectorAll('tr.sel'))x.classList.remove('sel');tr.classList.add('sel');detail(r)};frag.appendChild(tr)}
 tb.appendChild(frag);shown=end;$('more').style.display=shown<cur.length?'':'none'}
function detail(r){const d=$('detail');d.innerHTML='<dl>'+['ts','host','user','category','action','source_file','record_ref','ips','event_id'].map(k=>`<dt>${k}</dt><dd>${esc(Array.isArray(r[C[k]])?r[C[k]].join(', '):(r[C[k]]??''))}</dd>`).join('')+'</dl><pre>'+esc(r[C.raw]||r[C.summary]||'')+'</pre>'}
function redraw(){drawChart();cur=filtered(true);if(selected)cur=cur.filter(e=>e.t>=selected.t0&&e.t<selected.t1);
 $('status').textContent=`${cur.length.toLocaleString()} events`+(range?` in ${new Date(range[0]).toISOString().slice(0,16)} .. ${new Date(range[1]).toISOString().slice(0,16)}`:'')+(selected?` (bucket ${fmt(selected.t0,0)})`:'')+' — click a bar to select, drag to zoom, double-click a selected bar to zoom into it';
 renderRows(true)}
window.addEventListener('resize',drawChart);redraw();
})();
</script></body></html>
"""
