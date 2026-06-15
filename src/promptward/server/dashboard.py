"""Promptward — Claude Security Monitor  |  Enterprise dashboard."""

import logging
import socket
import webbrowser

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..common.config import get_settings
from ..common.storage import Store
from . import auth

logger = logging.getLogger("pw.dashboard")

_LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Promptward — Sign in</title><style>
body{background:#0b0e14;color:#e6e6e6;font-family:system-ui,sans-serif;
display:grid;place-items:center;height:100vh;margin:0}
.box{background:#141925;padding:32px 36px;border-radius:14px;border:1px solid #232a3a;
box-shadow:0 10px 40px rgba(0,0,0,.4);width:320px}
h1{font-size:18px;margin:0 0 4px}p{color:#8b95a7;font-size:13px;margin:0 0 18px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2a3344;
background:#0e1220;color:#fff;box-sizing:border-box;margin-bottom:12px}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#3b82f6;
color:#fff;font-weight:600;cursor:pointer}
</style></head><body><form class="box" action="/login" method="get">
<h1>Promptward</h1><p>Enter the dashboard access token.</p>
<input name="token" type="password" placeholder="Access token" autofocus>
<button type="submit">Sign in</button></form></body></html>"""

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Security Monitor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-font-smoothing:antialiased}
:root{
  --bg0:#06080e;--bg1:#0c1020;--bg2:#111827;--bg3:#162035;
  --brd:#1a2840;--brd2:#1e3050;
  --t0:#e8eeff;--t1:#7a8fb0;--t2:#344560;
  --blue:#3b82f6;--bld:#0a1e3d;
  --violet:#8b5cf6;--vld:#160d38;
  --green:#22c55e;--gld:#041e0e;
  --amber:#f59e0b;--ald:#201000;
  --red:#ef4444;--rld:#200808;
  --cyan:#06b6d4;--cld:#031820;
  --pink:#ec4899;
}
html,body{height:100%;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg0);color:var(--t0)}

/* ── TOPBAR ── */
#topbar{height:54px;background:rgba(12,16,32,.95);backdrop-filter:blur(20px);border-bottom:1px solid var(--brd);display:flex;align-items:center;padding:0 22px;gap:14px;flex-shrink:0;z-index:300;position:sticky;top:0}
.logo{display:flex;align-items:center;gap:11px}
.lm{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#fff;flex-shrink:0;box-shadow:0 0 16px rgba(139,92,246,.4)}
.lt{font-size:13px;font-weight:700;color:var(--t0);line-height:1.2}
.lt small{font-size:9px;font-weight:500;color:var(--t2);display:block;letter-spacing:.7px;text-transform:uppercase}
.sp{flex:1}
.pill{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid transparent;white-space:nowrap;transition:.2s}
.p-live{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.25)}
.p-on{background:rgba(59,130,246,.08);color:var(--blue);border-color:rgba(59,130,246,.25)}
.p-off{background:rgba(239,68,68,.08);color:var(--red);border-color:rgba(239,68,68,.25)}
.p-alert{background:rgba(239,68,68,.12);color:var(--red);border-color:rgba(239,68,68,.35);cursor:pointer;animation:alert-shake 3s infinite}
.p-alert:hover{background:rgba(239,68,68,.2)}
@keyframes alert-shake{0%,90%,100%{transform:translateX(0)}92%{transform:translateX(-3px)}94%{transform:translateX(3px)}96%{transform:translateX(-2px)}98%{transform:translateX(2px)}}
.tb-clock{font-size:12px;color:var(--t1);font-family:'Courier New',monospace;background:rgba(255,255,255,.03);padding:5px 12px;border-radius:6px;border:1px solid var(--brd);letter-spacing:.5px}
.tb-btn{padding:5px 14px;background:var(--bg3);border:1px solid var(--brd2);border-radius:6px;color:var(--t1);font-size:12px;font-weight:600;cursor:pointer;transition:.15s}
.tb-btn:hover{background:var(--bg2);color:var(--t0);border-color:var(--blue)}
.pulse-dot{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pdot 2s infinite}
@keyframes pdot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.8)}}

/* ── LAYOUT ── */
#wrap{display:flex;height:calc(100vh - 54px);overflow:hidden}

/* ── SIDEBAR ── */
#sb{width:215px;background:rgba(12,16,32,.8);backdrop-filter:blur(10px);border-right:1px solid var(--brd);display:flex;flex-direction:column;flex-shrink:0;padding-top:10px;overflow-y:auto}
.ns{padding:14px 18px 5px;font-size:9px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.12em}
.ni{display:flex;align-items:center;gap:9px;padding:9px 14px;margin:1px 8px;border-radius:8px;font-size:12px;font-weight:500;color:var(--t1);cursor:pointer;transition:.15s;user-select:none}
.ni:hover{background:rgba(255,255,255,.04);color:var(--t0)}
.ni.on{background:linear-gradient(90deg,rgba(59,130,246,.15),rgba(139,92,246,.06));color:var(--blue);border-left:2px solid var(--blue);margin-left:6px;padding-left:12px}
.ni-ic{font-size:14px;width:18px;text-align:center;flex-shrink:0;opacity:.8}
.nb{margin-left:auto;font-size:9px;font-weight:700;padding:2px 6px;border-radius:7px}
.nb-r{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.nb-b{background:rgba(59,130,246,.12);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.nb-d{background:rgba(255,255,255,.04);color:var(--t2);border:1px solid var(--brd)}
.sb-foot{margin-top:auto;padding:14px 16px;border-top:1px solid var(--brd)}
.sf{display:flex;justify-content:space-between;font-size:10px;color:var(--t2);margin-bottom:4px}
.sf b{color:var(--t1);font-weight:600}

/* ── MAIN ── */
#main{flex:1;overflow-y:auto;background:var(--bg0)}
.tab{display:none;padding:22px;animation:fi .25s}
.tab.on{display:block}
@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* ══════════════════════════════════════════════
   OVERVIEW — premium animated cards
══════════════════════════════════════════════ */
.ov-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.ov-title{font-size:18px;font-weight:700;color:var(--t0)}
.ov-sub{font-size:11px;color:var(--t2);margin-top:2px}
.ov-time-badge{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:8px;padding:6px 14px;font-size:11px;color:var(--blue);font-family:monospace}

/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:20px}
.sc{position:relative;background:linear-gradient(145deg,rgba(13,17,33,.9),rgba(10,14,28,.7));border:1px solid var(--brd);border-radius:12px;padding:18px 20px;overflow:hidden;cursor:default;transition:transform .2s,box-shadow .2s,border-color .2s}
.sc:hover{transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,.4)}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:12px 12px 0 0;transition:.3s}
.sc-bl::before{background:linear-gradient(90deg,#3b82f6,#8b5cf6)}
.sc-cy::before{background:linear-gradient(90deg,#06b6d4,#3b82f6)}
.sc-vi::before{background:linear-gradient(90deg,#8b5cf6,#ec4899)}
.sc-rd::before{background:linear-gradient(90deg,#ef4444,#f97316)}
.sc-gr::before{background:linear-gradient(90deg,#22c55e,#06b6d4)}
.sc-glow-red{box-shadow:0 0 30px rgba(239,68,68,.2),0 0 60px rgba(239,68,68,.08);border-color:rgba(239,68,68,.3);animation:glow-red 2s ease-in-out infinite}
@keyframes glow-red{0%,100%{box-shadow:0 0 20px rgba(239,68,68,.15),0 0 40px rgba(239,68,68,.06)}50%{box-shadow:0 0 35px rgba(239,68,68,.3),0 0 70px rgba(239,68,68,.12)}}
.sc-bg-icon{position:absolute;right:14px;top:50%;transform:translateY(-50%);font-size:42px;opacity:.04;pointer-events:none;user-select:none}
.sc-lbl{font-size:10px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:9px}
.sc-val{font-size:30px;font-weight:800;line-height:1;margin-bottom:5px;font-variant-numeric:tabular-nums;transition:.3s}
.sc-sub{font-size:10px;color:var(--t2);line-height:1.4}
.sc-delta{display:inline-flex;align-items:center;gap:3px;font-size:10px;font-weight:600;padding:1px 6px;border-radius:4px;margin-left:6px}
.delta-up{background:rgba(34,197,94,.12);color:var(--green)}
.delta-down{background:rgba(239,68,68,.12);color:var(--red)}
.v-wh{color:var(--t0)}.v-bl{color:var(--blue)}.v-vi{color:var(--violet)}.v-gr{color:var(--green)}.v-rd{color:var(--red)}.v-cy{color:var(--cyan)}

/* ── 2-col grid ── */
.g2{display:grid;grid-template-columns:1.45fr 1fr;gap:15px;margin-bottom:18px}

/* ── Panel ── */
.panel{background:linear-gradient(145deg,rgba(13,17,33,.95),rgba(10,14,26,.8));border:1px solid var(--brd);border-radius:12px;overflow:hidden;transition:border-color .2s}
.panel:hover{border-color:var(--brd2)}
.ph{padding:13px 18px;border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:10px}
.ph h3{font-size:12px;font-weight:700;color:var(--t0)}
.ph-sub{font-size:10px;color:var(--t2)}
.ph-sp{flex:1}
.tag{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:7px;font-size:10px;font-weight:700;border:1px solid transparent;white-space:nowrap}
.tg{background:rgba(34,197,94,.1);color:var(--green);border-color:rgba(34,197,94,.25)}
.tr{background:rgba(239,68,68,.1);color:var(--red);border-color:rgba(239,68,68,.3)}
.ta{background:rgba(245,158,11,.1);color:var(--amber);border-color:rgba(245,158,11,.25)}
.tb{background:rgba(59,130,246,.1);color:var(--blue);border-color:rgba(59,130,246,.25)}
.tv{background:rgba(139,92,246,.1);color:var(--violet);border-color:rgba(139,92,246,.25)}
.tb-sm{padding:3px 10px;background:rgba(255,255,255,.04);border:1px solid var(--brd2);border-radius:6px;color:var(--t1);font-size:11px;font-weight:600;cursor:pointer;transition:.15s}
.tb-sm:hover{background:rgba(255,255,255,.08);color:var(--t0)}

/* ── Chart ── */
.chart-wrap{padding:16px 18px;height:130px;position:relative}
.chart-svg{width:100%;height:100%}
.cl-area{fill:url(#cg);stroke:none;opacity:0;transition:opacity 1s}
.cl-area.in{opacity:1}
.cl-line{fill:none;stroke:url(#lg);stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1000;stroke-dashoffset:1000;transition:stroke-dashoffset 1.2s ease-out}
.cl-line.in{stroke-dashoffset:0}
.cl-dot{fill:var(--blue);opacity:0;transition:opacity .3s .8s}
.cl-dot.in{opacity:1}
.cl-lbl{font-size:9px;fill:var(--t2)}

/* ── Donut ── */
.donut-wrap{display:flex;align-items:center;justify-content:center;gap:20px;padding:14px 18px}
.dleg{display:flex;flex-direction:column;gap:9px}
.dl{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--t1)}
.dl-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dl b{margin-left:auto;padding-left:10px;color:var(--t0);min-width:30px;text-align:right;font-size:13px}
.dc-ring circle{transition:stroke-dasharray .8s cubic-bezier(.4,0,.2,1),stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)}

/* ── Alert Feed ── */
.af-empty{padding:18px;display:flex;align-items:center;justify-content:center;gap:8px;color:var(--green);font-size:12px;font-weight:500}
.af-row{padding:11px 18px;display:grid;grid-template-columns:90px 60px 1fr auto;gap:12px;align-items:center;border-bottom:1px solid rgba(26,40,64,.6);font-size:11px;cursor:pointer;transition:.15s;position:relative;overflow:hidden}
.af-row::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--red);opacity:0;transition:.2s}
.af-row:hover{background:rgba(239,68,68,.04)}
.af-row:hover::after{opacity:1}
.af-row:last-child{border-bottom:none}
.af-time{color:var(--t2);font-family:monospace;font-size:10px}
.af-new{animation:new-row .6s ease-out}
@keyframes new-row{from{background:rgba(239,68,68,.15);transform:translateX(-8px)}to{background:transparent;transform:none}}

/* ── Sessions Feed ── */
.sf-row{padding:9px 18px;display:grid;grid-template-columns:80px 110px 70px 1fr auto;gap:10px;align-items:center;border-bottom:1px solid rgba(26,40,64,.4);font-size:11px;cursor:pointer;transition:.15s}
.sf-row:hover{background:rgba(255,255,255,.02)}
.sf-row:last-child{border-bottom:none}
.sf-new{animation:sf-slide .5s ease-out}
@keyframes sf-slide{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}

/* ── Severity badges ── */
.sv{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:.02em;border:1px solid transparent;white-space:nowrap}
.sh{background:rgba(239,68,68,.12);color:var(--red);border-color:rgba(239,68,68,.3);animation:badge-pulse 2s infinite}
@keyframes badge-pulse{0%,100%{box-shadow:none}50%{box-shadow:0 0 8px rgba(239,68,68,.4)}}
.sm2{background:rgba(245,158,11,.1);color:var(--amber);border-color:rgba(245,158,11,.25)}
.sl{background:rgba(59,130,246,.1);color:var(--blue);border-color:rgba(59,130,246,.2)}
.sc2{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.2)}
.sp2{background:rgba(139,92,246,.1);color:var(--violet);border-color:rgba(139,92,246,.2)}
.scli{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.2)}
.mt{font-size:9px;font-family:monospace;background:rgba(6,182,212,.08);color:var(--cyan);border:1px solid rgba(6,182,212,.2);padding:1px 5px;border-radius:3px}

/* ── Risk bar ── */
.rb-wrap{display:flex;align-items:center;gap:7px}
.rb{height:4px;border-radius:2px;background:rgba(255,255,255,.06);overflow:hidden;width:72px}
.rb-fill{height:100%;border-radius:2px;transition:width .8s ease-out}
.rbc{background:linear-gradient(90deg,#ef4444,#f97316)}
.rbh{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.rbm{background:#eab308}
.rbl{background:linear-gradient(90deg,#22c55e,#06b6d4)}
.rb-num{font-size:11px;font-weight:700;font-family:monospace;width:24px;text-align:right}

/* ── Live feed ticker ── */
.ticker-wrap{background:rgba(6,182,212,.04);border:1px solid rgba(6,182,212,.12);border-radius:8px;padding:10px 16px;display:flex;align-items:center;gap:12px;margin-bottom:18px;overflow:hidden}
.ticker-lbl{font-size:10px;font-weight:700;color:var(--cyan);text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;display:flex;align-items:center;gap:6px}
.ticker-dot{width:6px;height:6px;border-radius:50%;background:var(--cyan);animation:pdot 1.5s infinite}
.ticker-text{font-size:11px;color:var(--t1);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;flex:1}
.ticker-time{font-size:10px;color:var(--t2);font-family:monospace;white-space:nowrap}

/* ── Heatmap ── */
.hm{padding:14px 18px}
.hm-labels{display:flex;justify-content:space-between;margin-bottom:6px;padding-left:28px}
.hm-label{font-size:9px;color:var(--t2)}
.hm-grid{display:grid;grid-template-columns:28px repeat(24,1fr);gap:3px}
.hm-day{font-size:9px;color:var(--t2);display:flex;align-items:center;font-family:monospace}
.hm-cell{height:13px;border-radius:2px;background:rgba(255,255,255,.03);transition:all .3s;cursor:default;position:relative}
.hm-cell:hover::after{content:attr(data-t);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1a2840;border:1px solid var(--brd2);padding:3px 8px;border-radius:4px;font-size:10px;color:var(--t0);white-space:nowrap;z-index:50;pointer-events:none}
.hm-0{background:rgba(255,255,255,.03)}
.hm-1{background:rgba(59,130,246,.2)}
.hm-2{background:rgba(59,130,246,.4)}
.hm-3{background:rgba(139,92,246,.5)}
.hm-4{background:rgba(139,92,246,.75)}
.hm-5{background:rgba(236,72,153,.85)}

/* ── 3-col ── */
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px;margin-bottom:18px}

/* ── Model usage bars ── */
.mu-row{padding:9px 18px;display:flex;align-items:center;gap:10px;border-bottom:1px solid rgba(26,40,64,.4);font-size:11px}
.mu-row:last-child{border-bottom:none}
.mu-name{color:var(--violet);font-family:monospace;font-size:10px;min-width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mu-bar{flex:1;height:5px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden}
.mu-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--violet),var(--blue));transition:width .8s ease-out}
.mu-n{font-family:monospace;font-size:10px;color:var(--t1);min-width:28px;text-align:right}

/* ── Token ring ── */
.tok-ring{display:flex;align-items:center;justify-content:center;padding:16px 18px;gap:16px}
.tok-center{text-align:center}
.tok-big{font-size:22px;font-weight:800;color:var(--t0)}
.tok-sub{font-size:9px;color:var(--t2);text-transform:uppercase;letter-spacing:.06em}
.tok-rows{display:flex;flex-direction:column;gap:8px}
.tok-row{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--t1)}
.tok-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* ══════════════════════════════════════════════
   TOAST NOTIFICATIONS
══════════════════════════════════════════════ */
#toasts{position:fixed;top:70px;right:20px;z-index:999;display:flex;flex-direction:column;gap:10px;pointer-events:none}
.toast{min-width:320px;max-width:400px;background:rgba(13,17,33,.97);backdrop-filter:blur(20px);border:1px solid rgba(239,68,68,.35);border-radius:12px;padding:14px 16px;display:flex;gap:12px;pointer-events:all;animation:toast-in .4s cubic-bezier(.21,1.02,.73,1) forwards;box-shadow:0 8px 40px rgba(0,0,0,.5),0 0 0 1px rgba(239,68,68,.1),0 0 40px rgba(239,68,68,.12);position:relative;overflow:hidden}
.toast::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--red),#f97316)}
.toast.toast-med::before{background:linear-gradient(90deg,var(--amber),#f97316)}
.toast.toast-med{border-color:rgba(245,158,11,.35);box-shadow:0 8px 40px rgba(0,0,0,.5),0 0 40px rgba(245,158,11,.1)}
.toast.out{animation:toast-out .3s ease-in forwards}
@keyframes toast-in{from{opacity:0;transform:translateX(120px) scale(.9)}to{opacity:1;transform:none}}
@keyframes toast-out{from{opacity:1;transform:none;max-height:200px}to{opacity:0;transform:translateX(80px);max-height:0;margin-bottom:0;padding:0}}
.toast-icon{font-size:20px;flex-shrink:0;margin-top:1px}
.toast-body{flex:1;min-width:0}
.toast-title{font-size:12px;font-weight:700;color:var(--t0);margin-bottom:3px;display:flex;align-items:center;gap:6px}
.toast-msg{font-size:11px;color:var(--t1);line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.toast-sub{font-size:10px;color:var(--t2);margin-top:4px;font-family:monospace}
.toast-x{position:absolute;top:10px;right:12px;background:none;border:none;color:var(--t2);font-size:16px;cursor:pointer;line-height:1;padding:2px 4px}
.toast-x:hover{color:var(--t0)}
.toast-prog{position:absolute;bottom:0;left:0;height:2px;background:rgba(239,68,68,.4);animation:toast-prog 5s linear forwards}
@keyframes toast-prog{from{width:100%}to{width:0}}

/* ══════════════════════════════════════════════
   ALERT BANNER (full-width warning)
══════════════════════════════════════════════ */
#alert-banner{display:none;background:linear-gradient(90deg,rgba(239,68,68,.12),rgba(239,68,68,.06));border:1px solid rgba(239,68,68,.3);border-radius:10px;padding:12px 18px;margin-bottom:18px;display:none;align-items:center;gap:12px;animation:fi .3s}
.ab-icon{font-size:20px;animation:icon-pulse 2s infinite}
@keyframes icon-pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.15)}}
.ab-text{flex:1;font-size:12px;color:var(--t0);font-weight:500}
.ab-text b{color:var(--red)}
.ab-close{background:none;border:none;color:var(--t2);cursor:pointer;font-size:18px;padding:0}

/* ── TABLE (other tabs) ── */
.tbar{padding:9px 14px;display:flex;align-items:center;gap:8px}
.ts{background:var(--bg0);border:1px solid var(--brd2);border-radius:6px;padding:5px 10px;font-size:12px;color:var(--t0);outline:none;min-width:180px}
.ts:focus{border-color:var(--blue)}
.ts::placeholder{color:var(--t2)}
.tsel{background:var(--bg0);border:1px solid var(--brd2);border-radius:6px;padding:5px 9px;font-size:12px;color:var(--t1);outline:none}
.tsel:focus{border-color:var(--blue)}
.tc{margin-left:auto;font-size:10px;color:var(--t2)}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{padding:7px 12px;text-align:left;font-size:9px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.07em;background:rgba(6,8,14,.6);border-bottom:1px solid var(--brd);white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(26,40,64,.35);cursor:pointer;transition:.12s}
tbody tr:hover{background:rgba(255,255,255,.025)}
tbody td{padding:8px 12px;vertical-align:middle;max-width:0}
.mono{font-family:'Courier New',monospace;color:var(--t2);font-size:11px;white-space:nowrap}
.clip{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tmd{color:var(--violet);font-family:monospace;font-size:10px;white-space:nowrap}
.num{text-align:right;font-family:monospace;font-size:11px}
.nin{color:var(--blue)}.nou{color:var(--violet)}
.ctr{text-align:center}
.emp{text-align:center;padding:36px;color:var(--t2);font-size:12px}

/* ── ENDPOINT CARDS ── */
.ep-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;padding:16px}
.epc{background:linear-gradient(145deg,rgba(13,17,33,.9),rgba(10,14,26,.7));border:1px solid var(--brd);border-radius:10px;padding:14px;cursor:pointer;transition:.2s}
.epc:hover{transform:translateY(-2px);border-color:var(--brd2);box-shadow:0 8px 24px rgba(0,0,0,.3)}
.epc-h{display:flex;align-items:center;gap:10px;margin-bottom:11px}
.epc-icon{width:34px;height:34px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.ic-lin{background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.2)}
.ic-mac{background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.2)}
.ic-win{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2)}
.ic-unk{background:rgba(255,255,255,.04);border:1px solid var(--brd)}
.epc-name{font-size:13px;font-weight:700;color:var(--t0)}
.epc-sub{font-size:10px;color:var(--t2)}
.epc-rows{display:grid;gap:5px}
.epc-row{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--t2);padding-top:5px;border-top:1px solid rgba(26,40,64,.5)}
.epc-v{color:var(--t1);font-weight:600;font-family:monospace;font-size:11px}

/* ── HUNT ── */
#hunt-q{background:var(--bg0);border:1px solid var(--brd2);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--t0);outline:none;width:100%;transition:.2s}
#hunt-q:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
#hunt-q::placeholder{color:var(--t2)}

/* ── MODAL ── */
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);backdrop-filter:blur(8px);z-index:400;overflow-y:auto;padding:20px}
.mw{max-width:860px;margin:30px auto;background:linear-gradient(145deg,rgba(13,17,33,.98),rgba(10,14,26,.95));border:1px solid var(--brd2);border-radius:14px;overflow:hidden}
.mb-top{padding:16px 20px;border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:12px}
.mb-top h3{font-size:13px;font-weight:700;color:var(--t0)}
.mx{margin-left:auto;background:none;border:none;color:var(--t2);font-size:22px;cursor:pointer;line-height:1;transition:.15s}
.mx:hover{color:var(--t0);transform:rotate(90deg)}
.mb-body{padding:20px;display:grid;gap:14px}
.mg{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
.mgc{background:rgba(6,8,14,.6);border:1px solid var(--brd);border-radius:8px;padding:10px 14px}
.mgc label{font-size:9px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.07em;display:block;margin-bottom:4px}
.mgc .mv{font-size:12px;color:var(--t0);font-weight:600;word-break:break-all}
.ms label{font-size:9px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;display:block;margin-bottom:6px}
.mp{background:rgba(6,8,14,.7);border:1px solid var(--brd);border-radius:8px;padding:12px;font-family:'Courier New',monospace;font-size:11px;color:var(--t1);max-height:180px;overflow:auto;white-space:pre-wrap;word-break:break-word;line-height:1.6}
.abox{border-radius:8px;padding:10px 14px;font-size:12px;display:flex;align-items:flex-start;gap:10px}
.abox-h{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);color:var(--red)}
.abox-m{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);color:var(--amber)}
.abox-l{background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.2);color:var(--blue)}
.abox-ic{font-size:16px;flex-shrink:0}
.abox-bd b{display:block;margin-bottom:3px}

/* scrollbar */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--brd2);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:#2a4070}

/* ── OTHER TABS ── */
#t-endpoints .panel,#t-threats .panel,#t-sessions .panel,#t-hunt .panel{background:linear-gradient(145deg,rgba(13,17,33,.95),rgba(10,14,26,.8))}
</style>
</head>
<body>

<!-- TOAST CONTAINER -->
<div id="toasts"></div>

<!-- TOPBAR -->
<div id="topbar">
  <div class="logo">
    <div class="lm">C</div>
    <div class="lt">Claude Security Monitor<small>AI AGENT OBSERVABILITY</small></div>
  </div>
  <div class="sp"></div>
  <div class="pill p-live"><span class="pulse-dot"></span>Live</div>
  <div class="pill p-on" id="px-pill">&#9679;&nbsp;Proxy</div>
  <div class="pill p-alert" id="al-pill" style="display:none" onclick="go('threats')">
    &#9888;&nbsp;<span id="al-n">0</span>&nbsp;Active Alerts
  </div>
  <div class="tb-clock">IST&nbsp;<span id="clk">--:--:--</span></div>
  <button class="tb-btn" onclick="loadAll()">&#8635;&nbsp;Refresh</button>
</div>

<div id="wrap">

<!-- SIDEBAR -->
<div id="sb">
  <div class="ns">Monitor</div>
  <div class="ni on" data-t="overview" onclick="go('overview')"><span class="ni-ic">&#9632;</span>Overview</div>
  <div class="ni" data-t="endpoints" onclick="go('endpoints')"><span class="ni-ic">&#9675;</span>Endpoints<span class="nb nb-b" id="nb-ep">0</span></div>
  <div class="ni" data-t="threats" onclick="go('threats')"><span class="ni-ic">&#9888;</span>Threats<span class="nb nb-r" id="nb-th" style="display:none">0</span></div>
  <div class="ns">Data</div>
  <div class="ni" data-t="sessions" onclick="go('sessions')"><span class="ni-ic">&#9776;</span>Sessions<span class="nb nb-d" id="nb-ss">0</span></div>
  <div class="ni" data-t="hunt" onclick="go('hunt')"><span class="ni-ic">&#9906;</span>Threat Hunt</div>
  <div class="sb-foot">
    <div class="sf"><span>Version</span><b>1.0.0</b></div>
    <div class="sf"><span>Devices</span><b id="sf-dev">—</b></div>
    <div class="sf"><span>Sessions</span><b id="sf-ss">—</b></div>
    <div class="sf"><span>Uptime</span><b id="sf-up">—</b></div>
  </div>
</div>

<!-- MAIN -->
<div id="main">

<!-- ══ OVERVIEW ══ -->
<div class="tab on" id="t-overview">

  <!-- Alert Banner -->
  <div id="alert-banner" style="display:none">
    <span class="ab-icon">&#9888;</span>
    <span class="ab-text" id="ab-text"><b>Security Alert</b> — threats detected on your network</span>
    <button class="ab-close" onclick="document.getElementById('alert-banner').style.display='none'">&#215;</button>
  </div>

  <!-- Ticker -->
  <div class="ticker-wrap">
    <div class="ticker-lbl"><span class="ticker-dot"></span>LIVE FEED</div>
    <div class="ticker-text" id="ticker-text">Waiting for activity…</div>
    <div class="ticker-time" id="ticker-time"></div>
  </div>

  <!-- Stat Cards -->
  <div class="stat-grid">
    <div class="sc sc-bl" id="sc-total">
      <div class="sc-bg-icon">&#9632;</div>
      <div class="sc-lbl">Total Sessions</div>
      <div class="sc-val v-wh" id="sv-total">—</div>
      <div class="sc-sub">all interactions logged</div>
    </div>
    <div class="sc sc-cy">
      <div class="sc-bg-icon">&#9675;</div>
      <div class="sc-lbl">Active Endpoints</div>
      <div class="sc-val v-cy" id="sv-dev">—</div>
      <div class="sc-sub">unique devices seen</div>
    </div>
    <div class="sc sc-vi">
      <div class="sc-bg-icon">&#9670;</div>
      <div class="sc-lbl">Tokens Processed</div>
      <div class="sc-val v-vi" id="sv-tok">—</div>
      <div class="sc-sub" id="sv-tok-s">in + out</div>
    </div>
    <div class="sc sc-rd" id="sc-threats">
      <div class="sc-bg-icon">&#9888;</div>
      <div class="sc-lbl">Threats Detected</div>
      <div class="sc-val v-gr" id="sv-thr">0</div>
      <div class="sc-sub" id="sv-thr-s">no alerts</div>
    </div>
    <div class="sc sc-gr">
      <div class="sc-bg-icon">&#10003;</div>
      <div class="sc-lbl">Clean Rate</div>
      <div class="sc-val v-gr" id="sv-cln">—</div>
      <div class="sc-sub">sessions without alerts</div>
    </div>
  </div>

  <!-- Chart + Donut -->
  <div class="g2">
    <div class="panel">
      <div class="ph">
        <h3>&#9650; Session Activity</h3>
        <span class="ph-sub" id="ch-sub">last 24 hours</span>
        <div class="ph-sp"></div>
        <span class="tag tb" id="ch-pk">—</span>
      </div>
      <div class="chart-wrap">
        <svg class="chart-svg" id="ch-svg" viewBox="0 0 400 92" preserveAspectRatio="none">
          <defs>
            <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#3b82f6" stop-opacity=".35"/>
              <stop offset="85%" stop-color="#8b5cf6" stop-opacity="0"/>
            </linearGradient>
            <linearGradient id="lg" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stop-color="#3b82f6"/>
              <stop offset="100%" stop-color="#8b5cf6"/>
            </linearGradient>
          </defs>
          <text x="2" y="89" class="cl-lbl">00:00</text>
          <text x="200" y="89" text-anchor="middle" class="cl-lbl">12:00</text>
          <text x="398" y="89" text-anchor="end" class="cl-lbl">23:59</text>
        </svg>
      </div>
    </div>

    <div class="panel">
      <div class="ph">
        <h3>Threat Severity</h3>
        <div class="ph-sp"></div>
        <span class="tag tg" id="dn-tag">Clean</span>
      </div>
      <div class="donut-wrap">
        <svg class="dc-ring" width="110" height="110" viewBox="0 0 110 110" style="transform:rotate(-90deg)">
          <defs>
            <linearGradient id="dg-g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#22c55e"/><stop offset="100%" stop-color="#06b6d4"/></linearGradient>
            <linearGradient id="dg-r" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ef4444"/><stop offset="100%" stop-color="#f97316"/></linearGradient>
          </defs>
          <circle cx="55" cy="55" r="38" fill="none" stroke="rgba(26,40,64,.8)" stroke-width="15"/>
          <circle cx="55" cy="55" r="38" fill="none" stroke="url(#dg-g)" stroke-width="15" stroke-dasharray="238.8" stroke-dashoffset="0" id="dc-cl"/>
          <circle cx="55" cy="55" r="38" fill="none" stroke="#3b82f6" stroke-width="15" stroke-dasharray="238.8" stroke-dashoffset="0" id="dc-lo"/>
          <circle cx="55" cy="55" r="38" fill="none" stroke="#f59e0b" stroke-width="15" stroke-dasharray="238.8" stroke-dashoffset="0" id="dc-me"/>
          <circle cx="55" cy="55" r="38" fill="none" stroke="url(#dg-r)" stroke-width="15" stroke-dasharray="238.8" stroke-dashoffset="0" id="dc-hi"/>
          <text x="55" y="50" text-anchor="middle" fill="#e8eeff" font-size="20" font-weight="800" transform="rotate(90,55,55)" id="dc-n">0</text>
          <text x="55" y="63" text-anchor="middle" fill="#344560" font-size="9" transform="rotate(90,55,55)">alerts</text>
        </svg>
        <div class="dleg">
          <div class="dl"><span class="dl-dot" style="background:linear-gradient(135deg,#22c55e,#06b6d4)"></span>Clean<b id="dl-c">—</b></div>
          <div class="dl"><span class="dl-dot" style="background:#3b82f6"></span>Low<b id="dl-l">0</b></div>
          <div class="dl"><span class="dl-dot" style="background:#f59e0b"></span>Medium<b id="dl-m">0</b></div>
          <div class="dl"><span class="dl-dot" style="background:linear-gradient(135deg,#ef4444,#f97316)"></span>High<b id="dl-h">0</b></div>
        </div>
      </div>
    </div>
  </div>

  <!-- 3-col: Recent Threats · Model Usage · Token Split -->
  <div class="g3">
    <div class="panel">
      <div class="ph"><h3>&#9888; Recent Threats</h3><div class="ph-sp"></div><span class="tag tg" id="af-tag">Clear</span><button class="tb-sm" style="margin-left:8px" onclick="go('threats')">All</button></div>
      <div id="af-body"><div class="af-empty">&#10003; No threats</div></div>
    </div>

    <div class="panel">
      <div class="ph"><h3>&#9670; Model Usage</h3><div class="ph-sp"></div><span class="tag tv" id="mu-tag">—</span></div>
      <div id="mu-body"><div class="emp" style="padding:20px">No data yet</div></div>
    </div>

    <div class="panel">
      <div class="ph"><h3>&#9650;&#9660; Token Distribution</h3></div>
      <div class="tok-ring">
        <svg width="80" height="80" viewBox="0 0 80 80" style="transform:rotate(-90deg)">
          <circle cx="40" cy="40" r="28" fill="none" stroke="rgba(26,40,64,.8)" stroke-width="12"/>
          <circle cx="40" cy="40" r="28" fill="none" stroke="#3b82f6" stroke-width="12" stroke-dasharray="175.9" stroke-dashoffset="0" id="tk-in"/>
          <circle cx="40" cy="40" r="28" fill="none" stroke="#8b5cf6" stroke-width="12" stroke-dasharray="175.9" stroke-dashoffset="0" id="tk-out"/>
        </svg>
        <div class="tok-rows">
          <div class="tok-row"><span class="tok-dot" style="background:var(--blue)"></span>Tokens In<b style="margin-left:auto;padding-left:8px;color:var(--blue);font-weight:700" id="tok-in-v">—</b></div>
          <div class="tok-row"><span class="tok-dot" style="background:var(--violet)"></span>Tokens Out<b style="margin-left:auto;padding-left:8px;color:var(--violet);font-weight:700" id="tok-out-v">—</b></div>
          <div class="tok-row" style="margin-top:4px;border-top:1px solid var(--brd);padding-top:8px"><span style="color:var(--t2)">Total</span><b style="margin-left:auto;padding-left:8px;color:var(--t0);font-weight:700" id="tok-tot-v">—</b></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Heatmap + Live Sessions -->
  <div class="g2">
    <div class="panel">
      <div class="ph"><h3>&#9635; Activity Heatmap</h3><span class="ph-sub">last 7 days by hour (IST)</span></div>
      <div class="hm">
        <div class="hm-labels" id="hm-hlabels"></div>
        <div class="hm-grid" id="hm-grid"></div>
      </div>
    </div>

    <div class="panel">
      <div class="ph"><h3>&#9654; Live Sessions</h3><span class="ph-sub" id="ls-sub">recent activity</span><div class="ph-sp"></div><button class="tb-sm" onclick="go('sessions')">All</button></div>
      <div id="ls-body"><div class="emp" style="padding:20px">Loading…</div></div>
    </div>
  </div>

</div><!-- /overview -->

<!-- ══ ENDPOINTS ══ -->
<div class="tab" id="t-endpoints">
  <div class="panel" style="margin-bottom:14px">
    <div class="ph"><h3>&#9675; Endpoints</h3><span class="ph-sub" id="ep-sub"></span><div class="ph-sp"></div><span class="tag tb" id="ep-tag">—</span></div>
    <div class="tbar">
      <input class="ts" id="ep-q" placeholder="Search device, user, OS…" oninput="renderEP()">
      <select class="tsel" id="ep-risk" onchange="renderEP()"><option value="">All risk</option><option value="crit">Critical 80+</option><option value="high">High 50+</option><option value="any">Any risk</option><option value="clean">Clean only</option></select>
      <span class="tc" id="ep-cnt"></span>
    </div>
  </div>
  <div id="ep-grid" class="ep-grid"></div>
</div>

<!-- ══ THREATS ══ -->
<div class="tab" id="t-threats">
  <div class="panel">
    <div class="ph"><h3>&#9888; Threat Intelligence</h3><span class="ph-sub">MITRE ATLAS mapped</span><div class="ph-sp"></div><span class="tag tr" id="th-tag">0 threats</span></div>
    <div class="tbar">
      <input class="ts" id="th-q" placeholder="Search threats…" oninput="renderTH()">
      <select class="tsel" id="th-sev" onchange="renderTH()"><option value="">All severity</option><option value="3">High</option><option value="2">Medium</option><option value="1">Low</option></select>
      <span class="tc" id="th-cnt"></span>
    </div>
    <table>
      <thead><tr><th>Time (IST)</th><th>Severity</th><th>MITRE</th><th>Finding</th><th>Device</th><th>User</th><th>&#8593;tok</th></tr></thead>
      <tbody id="th-body"><tr><td colspan="7" class="emp">No threats</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ SESSIONS ══ -->
<div class="tab" id="t-sessions">
  <div class="panel">
    <div class="ph"><h3>Session Log</h3><span class="ph-sub" id="ss-sub"></span></div>
    <div class="tbar">
      <input class="ts" id="ss-q" placeholder="Search…" oninput="filterSS()">
      <select class="tsel" id="ss-dev" onchange="filterSS()"><option value="">All devices</option></select>
      <select class="tsel" id="ss-src" onchange="filterSS()"><option value="">All sources</option><option value="proxy">proxy</option><option value="cli">cli</option></select>
      <select class="tsel" id="ss-al" onchange="filterSS()"><option value="">All levels</option><option value="3">High</option><option value="2">Med+</option><option value="1">Any alert</option><option value="-1">Clean</option></select>
      <span class="tc" id="ss-cnt"></span>
    </div>
    <table>
      <thead><tr><th>Time (IST)</th><th>Device</th><th>User</th><th>Src</th><th>Model</th><th style="width:34%">What user asked</th><th>Response</th><th class="num">&#8593;</th><th class="num">&#8595;</th><th>Alert</th></tr></thead>
      <tbody id="ss-body"><tr><td colspan="10" class="emp">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ══ HUNT ══ -->
<div class="tab" id="t-hunt">
  <div class="panel" style="margin-bottom:14px">
    <div class="ph"><h3>&#9906; Threat Hunt</h3><span class="ph-sub">search across all session content</span></div>
    <div style="padding:14px 16px;display:flex;gap:10px;align-items:center">
      <input id="hunt-q" placeholder="e.g.  password  ·  ignore instructions  ·  exfiltrate" oninput="runHunt()">
      <select class="tsel" id="hunt-f" onchange="runHunt()"><option value="both">Prompt + Response</option><option value="prompt">Prompt</option><option value="response">Response</option></select>
      <span class="tc" id="hunt-cnt" style="font-size:12px"></span>
    </div>
  </div>
  <div class="panel">
    <table>
      <thead><tr><th>Time (IST)</th><th>Device</th><th>User</th><th>Match in</th><th style="width:40%">Content</th><th>Model</th><th>Alert</th></tr></thead>
      <tbody id="hunt-body"><tr><td colspan="7" class="emp">Type above to search</td></tr></tbody>
    </table>
  </div>
</div>

</div><!-- /main -->
</div><!-- /wrap -->

<!-- MODAL -->
<div id="modal" onclick="if(event.target===this)cm()">
  <div class="mw">
    <div class="mb-top"><h3 id="m-title">Session Detail</h3><button class="mx" onclick="cm()">&#215;</button></div>
    <div class="mb-body" id="m-body"></div>
  </div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────────────
let rows=[], eps=[], stats={}, t0=Date.now();
let prevAlertIds=new Set(), prevTotal=0;
let tickerRows=[];

// ── IST Clock ────────────────────────────────────────────────────────────────
function tick(){const d=new Date(Date.now()+(5*60+30)*60000),p=n=>String(n).padStart(2,'0');document.getElementById('clk').textContent=p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());}
setInterval(tick,1000);tick();
setInterval(()=>{document.getElementById('sf-up').textContent=ups();},1000);
function ups(){const s=Math.floor((Date.now()-t0)/1000);if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';}

// ── Utils ─────────────────────────────────────────────────────────────────────
function ist(ts){const d=new Date(new Date(ts).getTime()+(5*60+30)*60000),p=n=>String(n).padStart(2,'0');return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(n){if(n==null)return'—';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1000)return(n/1000).toFixed(1)+'k';return String(n);}

function umsg(pj){
  try{
    const msgs=JSON.parse(pj);
    const last=[...msgs].reverse().find(m=>m.role==='user');
    if(!last)return'(no user msg)';
    const c=last.content;
    if(typeof c==='string')return c.trim();
    if(Array.isArray(c)){
      const t=c.filter(x=>x.type==='text'&&!x.text.startsWith('<system-')&&!x.text.startsWith('<user-')).map(x=>x.text.trim()).filter(Boolean).join(' ');
      return t||'(system context)';
    }
    return String(c).slice(0,200);
  }catch{return(pj||'').slice(0,120);}
}

function sm(m){if(!m)return'—';return m.replace('claude-','').replace(/-20\d{6}$/,'').replace(/-\d{8}$/,'');}
function turns(pj){try{return JSON.parse(pj).length;}catch{return 0;}}

function sevBadge(lv){
  if(lv>=3)return'<span class="sv sh">&#9660; HIGH</span>';
  if(lv==2)return'<span class="sv sm2">&#9650; MED</span>';
  if(lv==1)return'<span class="sv sl">&#9675; LOW</span>';
  return'<span class="sv sc2">&#10003;</span>';
}
function srcBadge(s){return s==='proxy'?'<span class="sv sp2">proxy</span>':'<span class="sv scli">cli</span>';}
function mitre(r){
  if(!r)return'<span class="mt">—</span>';
  const l=r.toLowerCase();
  if(l.includes('injection'))return'<span class="mt">AML.T0051</span>';
  if(l.includes('credential'))return'<span class="mt">AML.T0056</span>';
  if(l.includes('exfiltrat'))return'<span class="mt">AML.T0048</span>';
  if(l.includes('non-local'))return'<span class="mt">AML.T0002</span>';
  if(l.includes('token'))return'<span class="mt">AML.T0043</span>';
  return'<span class="mt">AML.T0000</span>';
}
function risk(ep){return Math.min(100,(ep.alerts_high||0)*35+(ep.alerts_med||0)*15+(ep.alerts_low||0)*5);}
function riskBar(r){
  const cls=r>=80?'rbc':r>=50?'rbh':r>=20?'rbm':'rbl';
  const col=r>=80?'var(--red)':r>=50?'var(--amber)':r>=20?'#eab308':'var(--green)';
  return'<div class="rb-wrap"><span class="rb-num" style="color:'+col+'">'+r+'</span><div class="rb"><div class="rb-fill '+cls+'" style="width:'+r+'%"></div></div></div>';
}
function osIcon(os){if(!os)return'ic-unk';const o=os.toLowerCase();if(o.includes('linux'))return'ic-lin';if(o.includes('mac')||o.includes('darwin'))return'ic-mac';if(o.includes('win'))return'ic-win';return'ic-unk';}
function osEmoji(os){if(!os)return'💻';const o=os.toLowerCase();if(o.includes('linux'))return'🐧';if(o.includes('mac')||o.includes('darwin'))return'🍎';if(o.includes('win'))return'🪟';return'💻';}

// ── Count-up animation ────────────────────────────────────────────────────────
function countUp(el, target, suffix='', duration=800){
  const start=parseInt(el.textContent)||0;
  if(start===target)return;
  const diff=target-start, step=16, steps=Math.max(1,Math.round(duration/step));
  let i=0;
  const t=setInterval(()=>{
    i++;
    el.textContent=Math.round(start+diff*(i/steps))+(suffix||'');
    if(i>=steps){el.textContent=target+(suffix||'');clearInterval(t);}
  },step);
}

// ── Toast notifications ───────────────────────────────────────────────────────
function showToast(title, msg, sub, level=3){
  const id='t'+Date.now();
  const cls=level>=3?'':'toast-med';
  const icon=level>=3?'🚨':level>=2?'⚠️':'ℹ️';
  const d=document.createElement('div');
  d.className='toast '+cls; d.id=id;
  d.innerHTML='<span class="toast-icon">'+icon+'</span>'
    +'<div class="toast-body">'
    +'<div class="toast-title">'+esc(title)+sevBadge(level)+'</div>'
    +'<div class="toast-msg">'+esc(msg)+'</div>'
    +'<div class="toast-sub">'+esc(sub)+'</div>'
    +'</div>'
    +'<button class="toast-x" onclick="dismissToast(\''+id+'\')">&#215;</button>'
    +'<div class="toast-prog"></div>';
  document.getElementById('toasts').appendChild(d);
  setTimeout(()=>dismissToast(id), 5200);
}
function dismissToast(id){
  const el=document.getElementById(id);
  if(!el)return;
  el.classList.add('out');
  setTimeout(()=>el.remove(), 350);
}

// ── Ticker ────────────────────────────────────────────────────────────────────
function updateTicker(){
  if(!rows.length)return;
  const r=rows[0];
  const msg=umsg(r.prompt);
  const dev=(r.device_name||r.hostname||'unknown').split('.')[0];
  document.getElementById('ticker-text').textContent=dev+' → '+msg.slice(0,120);
  document.getElementById('ticker-time').textContent=ist(r.ts).slice(11,19)+' IST';
}

// ── Nav ───────────────────────────────────────────────────────────────────────
function go(name){
  document.querySelectorAll('.ni').forEach(e=>e.classList.toggle('on',e.dataset.t===name));
  document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('on',e.id==='t-'+name));
  if(name==='endpoints')renderEP();
  if(name==='threats')renderTH();
  if(name==='sessions')filterSS();
  if(name==='hunt')runHunt();
}

// ── Load ──────────────────────────────────────────────────────────────────────
async function loadAll(){
  try{
    const [r,e,s]=await Promise.all([
      fetch('/api/logs?n=500').then(x=>x.json()),
      fetch('/api/endpoints').then(x=>x.json()),
      fetch('/api/stats').then(x=>x.json()),
    ]);

    // Detect new alerts for toast notifications
    const newAlertRows=r.filter(x=>(x.alert_level||0)>0&&!prevAlertIds.has(x.id));
    newAlertRows.forEach(a=>{
      const dev=(a.device_name||a.hostname||'unknown').split('.')[0];
      showToast('New Security Alert', a.alert_reason||'Suspicious activity', dev+' · '+ist(a.ts).slice(11,16)+' IST', a.alert_level);
      prevAlertIds.add(a.id);
    });
    r.forEach(x=>prevAlertIds.add(x.id));

    // Detect new sessions
    const newTotal=s.total_interactions||0;
    if(prevTotal>0&&newTotal>prevTotal){
      // Silently update ticker
    }
    prevTotal=newTotal;

    rows=r; eps=e; stats=s;
    render();
  }catch(ex){console.error(ex);}
}

function render(){
  renderTopBar(); renderSidebar(); renderOverview();
  const act=document.querySelector('.ni.on');
  if(act){const t=act.dataset.t;if(t==='endpoints')renderEP();if(t==='threats')renderTH();if(t==='sessions')filterSS();if(t==='hunt')runHunt();}
}

// ── Topbar ────────────────────────────────────────────────────────────────────
function renderTopBar(){
  const on=stats.proxy_running;
  const pp=document.getElementById('px-pill');
  pp.textContent=(on?'● Proxy Running':'○ Proxy Stopped');
  pp.className='pill '+(on?'p-on':'p-off');
  const total=(stats.alerts_high||0)+(stats.alerts_medium||0)+(stats.alerts_low||0);
  document.getElementById('al-n').textContent=total;
  document.getElementById('al-pill').style.display=total>0?'':'none';
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function renderSidebar(){
  const a=(stats.alerts_high||0)+(stats.alerts_medium||0)+(stats.alerts_low||0);
  const nb=document.getElementById('nb-th');
  nb.textContent=a; nb.style.display=a>0?'':'none';
  document.getElementById('nb-ss').textContent=stats.total_interactions||0;
  document.getElementById('nb-ep').textContent=stats.total_devices||0;
  document.getElementById('sf-dev').textContent=stats.total_devices||0;
  document.getElementById('sf-ss').textContent=stats.total_interactions||0;
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview(){
  const t=stats.total_interactions||0,dev=stats.total_devices||0;
  const hi=stats.alerts_high||0,med=stats.alerts_medium||0,lo=stats.alerts_low||0;
  const al=hi+med+lo,clean=Math.max(0,t-al);
  const tin=stats.total_tokens_in||0,tout=stats.total_tokens_out||0;

  // Alert banner
  const banner=document.getElementById('alert-banner');
  if(al>0){
    banner.style.display='flex';
    document.getElementById('ab-text').innerHTML='<b>'+al+' security alert'+(al>1?'s':'')+' detected</b> — '+hi+' high, '+med+' medium on your network';
  } else { banner.style.display='none'; }

  // Stat cards with count-up
  countUp(document.getElementById('sv-total'),t);
  countUp(document.getElementById('sv-dev'),dev);
  document.getElementById('sv-tok').textContent=fmt(tin+tout);
  document.getElementById('sv-tok-s').textContent=fmt(tin)+' in / '+fmt(tout)+' out';
  countUp(document.getElementById('sv-thr'),al);
  document.getElementById('sv-thr').className='sc-val '+(al>0?'v-rd':'v-gr');
  document.getElementById('sv-thr-s').textContent=al>0?hi+' high, '+med+' med, '+lo+' low':'no alerts detected';
  document.getElementById('sv-cln').textContent=t>0?Math.round(clean/t*100)+'%':'—';

  // Threat card glow
  const sc=document.getElementById('sc-threats');
  sc.classList.toggle('sc-glow-red',al>0);

  // Donut
  const circ=238.8,tot=t||1;let off=0;
  function arc(id,n){const a=(n/tot)*circ;document.getElementById(id).setAttribute('stroke-dasharray',a+' '+circ);document.getElementById(id).setAttribute('stroke-dashoffset',-off);off+=a;}
  arc('dc-cl',clean);arc('dc-lo',lo);arc('dc-me',med);arc('dc-hi',hi);
  document.getElementById('dc-n').textContent=al;
  document.getElementById('dl-c').textContent=clean;
  document.getElementById('dl-l').textContent=lo;
  document.getElementById('dl-m').textContent=med;
  document.getElementById('dl-h').textContent=hi;
  document.getElementById('dn-tag').textContent=al===0?'All Clear':al+' alerts';
  document.getElementById('dn-tag').className='tag '+(al===0?'tg':hi>0?'tr':'ta');

  // Token ring
  const tcirc=175.9,ttot=Math.max(tin+tout,1);
  const tinArc=(tin/ttot)*tcirc;
  document.getElementById('tk-in').setAttribute('stroke-dasharray',tinArc+' '+tcirc);
  document.getElementById('tk-in').setAttribute('stroke-dashoffset',0);
  document.getElementById('tk-out').setAttribute('stroke-dasharray',((tout/ttot)*tcirc)+' '+tcirc);
  document.getElementById('tk-out').setAttribute('stroke-dashoffset',-tinArc);
  document.getElementById('tok-in-v').textContent=fmt(tin);
  document.getElementById('tok-out-v').textContent=fmt(tout);
  document.getElementById('tok-tot-v').textContent=fmt(tin+tout);

  renderChart();
  renderAlertFeed();
  renderModelUsage();
  renderHeatmap();
  renderLiveSessions();
  updateTicker();
}

// ── Chart ──────────────────────────────────────────────────────────────────────
function renderChart(){
  const now=Date.now(),bkts=new Array(24).fill(0);
  rows.forEach(r=>{const h=Math.floor((now-new Date(r.ts).getTime())/3600000);if(h>=0&&h<24)bkts[23-h]++;});
  const max=Math.max(...bkts,1);
  const W=400,H=78;
  const pts=bkts.map((v,i)=>[((i/(bkts.length-1))*W).toFixed(1),(H-(v/max)*H).toFixed(1)]);
  const poly=pts.map(p=>p[0]+','+p[1]).join(' ');
  const fill='0,'+H+' '+poly+' '+W+','+H;
  const svg=document.getElementById('ch-svg');
  svg.querySelectorAll('.dyn').forEach(e=>e.remove());
  const pg=document.createElementNS('http://www.w3.org/2000/svg','polygon');
  pg.setAttribute('points',fill);pg.setAttribute('class','cl-area dyn');
  svg.insertBefore(pg,svg.firstChild.nextSibling);
  setTimeout(()=>pg.classList.add('in'),50);
  const pl=document.createElementNS('http://www.w3.org/2000/svg','polyline');
  pl.setAttribute('points',poly);pl.setAttribute('class','cl-line dyn');
  svg.appendChild(pl);
  setTimeout(()=>pl.classList.add('in'),100);
  // Peak dot
  const peakIdx=bkts.indexOf(Math.max(...bkts));
  if(peakIdx>=0){
    const [px,py]=pts[peakIdx];
    const dot=document.createElementNS('http://www.w3.org/2000/svg','circle');
    dot.setAttribute('cx',px);dot.setAttribute('cy',py);dot.setAttribute('r','3');
    dot.setAttribute('class','cl-dot dyn');
    svg.appendChild(dot);
    setTimeout(()=>dot.classList.add('in'),900);
  }
  document.getElementById('ch-pk').textContent='peak: '+Math.max(...bkts)+'/hr';
  document.getElementById('ch-sub').textContent=rows.length+' sessions · 24h';
}

// ── Alert feed ─────────────────────────────────────────────────────────────────
function renderAlertFeed(){
  const al=rows.filter(r=>(r.alert_level||0)>0).slice(0,5);
  const tag=document.getElementById('af-tag');
  if(!al.length){document.getElementById('af-body').innerHTML='<div class="af-empty">&#10003; All clear</div>';tag.textContent='Clear';tag.className='tag tg';return;}
  tag.textContent=al.length+' alert'+(al.length>1?'s':'');
  tag.className='tag '+(al.some(a=>a.alert_level>=3)?'tr':'ta');
  document.getElementById('af-body').innerHTML=al.map((r,i)=>
    '<div class="af-row" onclick="sd('+r.id+')">'
    +'<span class="af-time">'+ist(r.ts).slice(5,16)+'</span>'
    +sevBadge(r.alert_level)
    +'<span style="color:var(--t1)">'+esc(r.alert_reason||'')+'</span>'
    +'<span style="color:var(--t2);font-size:10px">'+esc((r.device_name||r.hostname||'?').split('.')[0])+'</span>'
    +'</div>'
  ).join('');
}

// ── Model usage ────────────────────────────────────────────────────────────────
function renderModelUsage(){
  const mc={};
  rows.forEach(r=>{if(r.model)mc[r.model]=(mc[r.model]||0)+1;});
  const sorted=Object.entries(mc).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxV=sorted.length?sorted[0][1]:1;
  document.getElementById('mu-tag').textContent=sorted.length+' model'+(sorted.length!==1?'s':'');
  if(!sorted.length){document.getElementById('mu-body').innerHTML='<div class="emp" style="padding:20px">No data</div>';return;}
  document.getElementById('mu-body').innerHTML=sorted.map(([m,n])=>
    '<div class="mu-row">'
    +'<span class="mu-name">'+esc(sm(m))+'</span>'
    +'<div class="mu-bar"><div class="mu-fill" style="width:'+(n/maxV*100)+'%"></div></div>'
    +'<span class="mu-n">'+n+'</span>'
    +'</div>'
  ).join('');
}

// ── Heatmap (7d × 24h IST) ─────────────────────────────────────────────────────
function renderHeatmap(){
  const now=new Date(Date.now()+(5*60+30)*60000);
  const DAYS=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  // Build buckets [day0..6][hr0..23]  day0=6 days ago
  const buckets=Array.from({length:7},()=>new Array(24).fill(0));
  rows.forEach(r=>{
    const d=new Date(new Date(r.ts).getTime()+(5*60+30)*60000);
    const dayDiff=Math.floor((now-d)/86400000);
    if(dayDiff<0||dayDiff>=7)return;
    buckets[6-dayDiff][d.getUTCHours()]++;
  });
  const maxV=Math.max(...buckets.flat(),1);
  // Hour labels
  const hlabels=document.getElementById('hm-hlabels');
  hlabels.innerHTML=[0,6,12,18,23].map(h=>'<span class="hm-label">'+String(h).padStart(2,'0')+'h</span>').join('');
  // Grid
  let html='';
  for(let d=0;d<7;d++){
    const dLabel=new Date(now.getTime()-((6-d)*86400000));
    const dayName=DAYS[dLabel.getUTCDay()];
    html+='<span class="hm-day">'+dayName+'</span>';
    for(let h=0;h<24;h++){
      const v=buckets[d][h],lvl=v===0?0:Math.ceil((v/maxV)*5);
      html+='<div class="hm-cell hm-'+lvl+'" data-t="'+dayName+' '+String(h).padStart(2,'0')+':00 · '+v+' sessions"></div>';
    }
  }
  document.getElementById('hm-grid').innerHTML=html;
}

// ── Live sessions ──────────────────────────────────────────────────────────────
function renderLiveSessions(){
  const recent=rows.slice(0,8);
  document.getElementById('ls-sub').textContent=rows.length+' total';
  if(!recent.length){document.getElementById('ls-body').innerHTML='<div class="emp" style="padding:20px">No sessions yet</div>';return;}
  document.getElementById('ls-body').innerHTML=recent.map(r=>{
    const dev=(r.device_name||r.hostname||'?').split('.')[0];
    const msg=umsg(r.prompt).slice(0,80);
    return'<div class="sf-row" onclick="sd('+r.id+')">'
      +'<span class="mono" style="font-size:10px">'+ist(r.ts).slice(11,19)+'</span>'
      +'<span style="color:var(--cyan);font-size:11px">'+esc(dev)+'</span>'
      +'<span style="color:var(--t2);font-size:10px">'+esc(sm(r.model))+'</span>'
      +'<span class="clip" style="max-width:0;font-size:11px;color:var(--t1)">'+esc(msg)+'</span>'
      +sevBadge(r.alert_level||0)
      +'</div>';
  }).join('');
}

// ── Endpoints ──────────────────────────────────────────────────────────────────
function renderEP(){
  const q=(document.getElementById('ep-q').value||'').toLowerCase();
  const rf=document.getElementById('ep-risk').value;
  const vis=eps.filter(e=>{
    if(q&&!((e.device||'').toLowerCase().includes(q)||(e.sys_user||'').toLowerCase().includes(q)||(e.os_info||'').toLowerCase().includes(q)))return false;
    const r=risk(e);
    if(rf==='crit'&&r<80)return false;
    if(rf==='high'&&r<50)return false;
    if(rf==='any'&&r===0)return false;
    if(rf==='clean'&&r>0)return false;
    return true;
  });
  document.getElementById('ep-sub').textContent=vis.length+' of '+eps.length+' endpoints';
  document.getElementById('ep-tag').textContent=vis.length+' shown';
  document.getElementById('ep-cnt').textContent=vis.length+' endpoints';
  if(!vis.length){document.getElementById('ep-grid').innerHTML='<div class="emp" style="padding:40px;text-align:center">No endpoints</div>';return;}
  document.getElementById('ep-grid').innerHTML=vis.map(e=>{
    const r=risk(e),ical=osIcon(e.os_info),alC=(e.alerts_high||0)+(e.alerts_med||0)+(e.alerts_low||0);
    return'<div class="epc" onclick="epDrill(\''+esc(e.device)+'\')">'
      +'<div class="epc-h"><div class="epc-icon '+ical+'">'+osEmoji(e.os_info)+'</div>'
      +'<div><div class="epc-name">'+esc(e.device)+'</div><div class="epc-sub">'+esc(e.sys_user||'?')+' · '+esc(e.client_ip||'—')+'</div></div>'
      +'<div style="margin-left:auto">'+sevBadge(e.alerts_high>0?3:e.alerts_med>0?2:e.alerts_low>0?1:0)+'</div></div>'
      +'<div class="epc-rows">'
      +'<div class="epc-row"><span>OS</span><span class="epc-v">'+esc((e.os_info||'Unknown').split(' ').slice(0,3).join(' '))+'</span></div>'
      +'<div class="epc-row"><span>Sessions</span><span class="epc-v" style="color:var(--blue)">'+e.sessions+'</span></div>'
      +'<div class="epc-row"><span>Tokens</span><span class="epc-v" style="color:var(--violet)">'+fmt((e.tokens_in||0)+(e.tokens_out||0))+'</span></div>'
      +'<div class="epc-row"><span>Alerts</span><span class="epc-v" style="color:'+(alC>0?'var(--red)':'var(--green)')+'">'+alC+'</span></div>'
      +'<div class="epc-row"><span>Last seen</span><span class="epc-v" style="font-size:10px">'+ist(e.last_seen).slice(0,16)+'</span></div>'
      +'<div class="epc-row"><span>Risk score</span>'+riskBar(r)+'</div>'
      +'</div></div>';
  }).join('');
}
function epDrill(dev){const s=document.getElementById('ss-dev');for(let i=0;i<s.options.length;i++){if(s.options[i].value===dev){s.selectedIndex=i;break;}}go('sessions');filterSS();}

// ── Threats ────────────────────────────────────────────────────────────────────
function renderTH(){
  const q=(document.getElementById('th-q').value||'').toLowerCase();
  const sf=parseInt(document.getElementById('th-sev').value||'0');
  const vis=rows.filter(r=>{
    if((r.alert_level||0)===0)return false;
    if(sf&&(r.alert_level||0)<sf)return false;
    if(q){const dev=(r.device_name||r.hostname||'').toLowerCase(),ar=(r.alert_reason||'').toLowerCase();if(!dev.includes(q)&&!ar.includes(q)&&!umsg(r.prompt).toLowerCase().includes(q))return false;}
    return true;
  });
  document.getElementById('th-tag').textContent=vis.length+' threat'+(vis.length!==1?'s':'');
  document.getElementById('th-tag').className='tag '+(vis.length===0?'tg':vis.some(r=>r.alert_level>=3)?'tr':'ta');
  document.getElementById('th-cnt').textContent=vis.length+' rows';
  if(!vis.length){document.getElementById('th-body').innerHTML='<tr><td colspan="7" class="emp" style="color:var(--green)">&#10003; No threats</td></tr>';return;}
  document.getElementById('th-body').innerHTML=vis.map(r=>
    '<tr onclick="sd('+r.id+')">'
    +'<td class="mono" style="font-size:10px">'+ist(r.ts).slice(0,16)+'</td>'
    +'<td>'+sevBadge(r.alert_level)+'</td>'
    +'<td>'+mitre(r.alert_reason)+'</td>'
    +'<td class="clip" style="max-width:0;color:var(--t1)">'+esc(r.alert_reason||'')+'</td>'
    +'<td class="mono" style="color:var(--cyan)">'+esc((r.device_name||r.hostname||'?').split('.')[0])+'</td>'
    +'<td class="mono">'+esc(r.sys_user||'—')+'</td>'
    +'<td class="num nin">'+(r.tokens_in??'—')+'</td>'
    +'</tr>'
  ).join('');
}

// ── Sessions ───────────────────────────────────────────────────────────────────
function buildDevSel(){
  const devs=[...new Set(rows.map(r=>r.device_name||r.hostname||'unknown').filter(Boolean))].sort();
  const s=document.getElementById('ss-dev'),cur=s.value;
  s.innerHTML='<option value="">All devices</option>'+devs.map(d=>'<option value="'+esc(d)+'">'+esc(d)+'</option>').join('');
  if(cur)for(let i=0;i<s.options.length;i++){if(s.options[i].value===cur){s.selectedIndex=i;break;}}
}
function filterSS(){
  buildDevSel();
  const q=(document.getElementById('ss-q').value||'').toLowerCase();
  const dev=document.getElementById('ss-dev').value;
  const src=document.getElementById('ss-src').value;
  const al=parseInt(document.getElementById('ss-al').value||'0');
  const vis=rows.filter(r=>{
    const dn=r.device_name||r.hostname||'unknown';
    if(dev&&dn!==dev)return false;
    if(src&&r.source!==src)return false;
    const lv=r.alert_level||0;
    if(al===-1&&lv>0)return false;
    if(al>0&&lv<al)return false;
    if(q){const m=umsg(r.prompt).toLowerCase();if(!m.includes(q)&&!(r.response||'').toLowerCase().includes(q))return false;}
    return true;
  });
  document.getElementById('ss-sub').textContent=vis.length+' interactions';
  document.getElementById('ss-cnt').textContent=vis.length+' rows';
  if(!vis.length){document.getElementById('ss-body').innerHTML='<tr><td colspan="10" class="emp">No sessions match</td></tr>';return;}
  document.getElementById('ss-body').innerHTML=vis.map(r=>{
    const dn=(r.device_name||r.hostname||'?').split('.')[0];
    return'<tr onclick="sd('+r.id+')">'
      +'<td class="mono" style="font-size:10px">'+ist(r.ts).slice(0,16)+'</td>'
      +'<td class="mono" style="color:var(--cyan)">'+esc(dn)+'</td>'
      +'<td class="mono" style="font-size:10px;color:var(--t2)">'+esc(r.sys_user||'—')+'</td>'
      +'<td>'+srcBadge(r.source)+'</td>'
      +'<td class="tmd">'+esc(sm(r.model))+'</td>'
      +'<td class="clip" style="max-width:0">'+esc(umsg(r.prompt).slice(0,120))+'</td>'
      +'<td class="clip" style="max-width:0;color:var(--t2)">'+esc((r.response||'').slice(0,80))+'</td>'
      +'<td class="num nin">'+(r.tokens_in??'—')+'</td>'
      +'<td class="num nou">'+(r.tokens_out??'—')+'</td>'
      +'<td class="ctr">'+sevBadge(r.alert_level||0)+'</td>'
      +'</tr>';
  }).join('');
}

// ── Hunt ───────────────────────────────────────────────────────────────────────
function runHunt(){
  const q=(document.getElementById('hunt-q').value||'').trim().toLowerCase();
  const f=document.getElementById('hunt-f').value;
  if(!q){document.getElementById('hunt-body').innerHTML='<tr><td colspan="7" class="emp">Type a search term above</td></tr>';document.getElementById('hunt-cnt').textContent='';return;}
  const vis=[];
  rows.forEach(r=>{
    const pm=umsg(r.prompt).toLowerCase(),rm=(r.response||'').toLowerCase();
    let where='',snippet='';
    const inP=pm.includes(q),inR=rm.includes(q);
    if(f==='prompt'&&!inP)return;
    if(f==='response'&&!inR)return;
    if(f==='both'&&!inP&&!inR)return;
    if(inP){where='prompt';const i=pm.indexOf(q);snippet=umsg(r.prompt).slice(Math.max(0,i-40),i+90);}
    else{where='response';const i=rm.indexOf(q);snippet=(r.response||'').slice(Math.max(0,i-40),i+90);}
    const re=new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'gi');
    const hi=snippet.replace(re,m=>'<mark style="background:#fbbf24;color:#000;border-radius:2px;padding:0 2px">'+esc(m)+'</mark>');
    vis.push({r,where,hi});
  });
  document.getElementById('hunt-cnt').textContent=vis.length+' match'+(vis.length!==1?'es':'');
  if(!vis.length){document.getElementById('hunt-body').innerHTML='<tr><td colspan="7" class="emp">No matches for "'+esc(q)+'"</td></tr>';return;}
  document.getElementById('hunt-body').innerHTML=vis.map(({r,where,hi})=>
    '<tr onclick="sd('+r.id+')">'
    +'<td class="mono" style="font-size:10px">'+ist(r.ts).slice(0,16)+'</td>'
    +'<td class="mono" style="color:var(--cyan)">'+esc((r.device_name||r.hostname||'?').split('.')[0])+'</td>'
    +'<td class="mono" style="font-size:10px;color:var(--t2)">'+esc(r.sys_user||'—')+'</td>'
    +'<td><span class="sv '+(where==='prompt'?'sp2':'scli')+'">'+where+'</span></td>'
    +'<td style="font-size:11px;color:var(--t1);max-width:0" class="clip">'+hi+'</td>'
    +'<td class="tmd">'+esc(sm(r.model))+'</td>'
    +'<td class="ctr">'+sevBadge(r.alert_level||0)+'</td>'
    +'</tr>'
  ).join('');
}

// ── Modal ──────────────────────────────────────────────────────────────────────
function sd(id){
  const r=rows.find(x=>x.id===id);
  if(!r)return;
  const msg=umsg(r.prompt);
  let fp=r.prompt||'';try{fp=JSON.stringify(JSON.parse(r.prompt),null,2);}catch{}
  const alHtml=r.alert_level>0
    ?'<div class="ms"><label>Security Finding</label><div class="abox abox-'+(r.alert_level>=3?'h':r.alert_level>=2?'m':'l')+'"><span class="abox-ic">&#9888;</span><div class="abox-bd"><b>'+sevBadge(r.alert_level)+' '+mitre(r.alert_reason)+'</b>'+esc(r.alert_reason||'')+'</div></div></div>':'';
  document.getElementById('m-title').textContent='Session #'+r.id+' — '+(r.device_name||r.hostname||'unknown');
  document.getElementById('m-body').innerHTML=
    '<div class="mg">'
    +mc('Time (IST)',ist(r.ts))+mc('Device',r.device_name||r.hostname||'unknown')+mc('System User',r.sys_user||'—')
    +mc('OS',r.os_info||'—')+mc('Client IP',r.client_ip||'—')+mc('Source / Model',r.source+' / '+sm(r.model))
    +mc('Tokens In / Out',(r.tokens_in||'—')+' / '+(r.tokens_out||'—'))+mc('Turns',turns(r.prompt))+mc('Alert',r.alert_level>0?['—','LOW','MEDIUM','HIGH'][r.alert_level]:'Clean')
    +'</div>'
    +alHtml
    +'<div class="ms"><label>What user asked</label><div class="mp">'+esc(msg)+'</div></div>'
    +'<div class="ms"><label>Claude Response</label><div class="mp">'+esc(r.response||'(empty)')+'</div></div>'
    +'<div class="ms"><label>User Agent</label><div class="mp" style="max-height:50px">'+esc(r.user_agent||'—')+'</div></div>';
  document.getElementById('modal').style.display='block';
}
function mc(l,v){return'<div class="mgc"><label>'+esc(l)+'</label><div class="mv">'+esc(String(v))+'</div></div>';}
function cm(){document.getElementById('modal').style.display='none';}
document.addEventListener('keydown',e=>{if(e.key==='Escape')cm();});

// ── Boot ───────────────────────────────────────────────────────────────────────
loadAll();
setInterval(loadAll,5000);
</script>
</body>
</html>"""


def _app() -> FastAPI:
    settings = get_settings()
    store    = Store(settings)
    app      = FastAPI()

    token = settings.dashboard_token

    @app.middleware("http")
    async def _gate(request: Request, call_next):
        # No token configured → only safe on loopback (enforced in run()).
        if not token or request.url.path in auth.PUBLIC_PATHS:
            return await call_next(request)
        if auth.constant_eq(auth.extract_token(request), token):
            return await call_next(request)
        # Browsers get the login page; API clients get 401.
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return HTMLResponse(_LOGIN_HTML, status_code=401)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.get("/login", response_class=HTMLResponse)
    async def login(token_q: str = Query("", alias="token")) -> HTMLResponse:
        # Validate the supplied token; on success set an HttpOnly cookie.
        if token and auth.constant_eq(token_q, token):
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(
                auth.COOKIE_NAME, token, httponly=True, samesite="lax", max_age=86400
            )
            return resp  # type: ignore[return-value]
        return HTMLResponse(_LOGIN_HTML, status_code=401)

    # Admin / compliance control plane (same token gate as the dashboard).
    from .admin import register_admin
    register_admin(app, settings)

    @app.get("/", response_class=HTMLResponse)
    async def index(_: Request) -> HTMLResponse:
        return HTMLResponse(_HTML)

    @app.get("/api/logs")
    async def api_logs(n: int = 500) -> list[dict]:
        return store.list_recent(n)

    @app.get("/api/endpoints")
    async def api_endpoints() -> list[dict]:
        return store.endpoints()

    @app.get("/api/stats")
    async def api_stats() -> dict:
        s = store.stats()
        proxy_up = False
        try:
            with socket.create_connection(
                (settings.proxy_host, settings.proxy_port), timeout=0.3
            ):
                proxy_up = True
        except OSError:
            pass
        return {**s, "proxy_running": proxy_up}

    return app


def run(port: int | None = None, open_browser: bool = True, host: str | None = None) -> None:
    logging.basicConfig(level=logging.WARNING)
    settings = get_settings()
    bind_host = host or settings.dashboard_host
    bind_port = port or settings.dashboard_port

    # Refuse to expose prompts/responses on a non-loopback interface without a token.
    if not auth.is_loopback(bind_host) and not settings.dashboard_token:
        raise SystemExit(
            f"Refusing to bind dashboard to {bind_host} without a token.\n"
            "Set PW_DASHBOARD_TOKEN (or dashboard_token in ~/.promptward/.env) "
            "before exposing the dashboard beyond localhost."
        )

    display = "127.0.0.1" if auth.is_loopback(bind_host) else bind_host
    url = f"http://{display}:{bind_port}"
    print(f"  Dashboard → {url}")
    if settings.dashboard_token:
        print("  Auth: token required (open /login or pass ?token=…).")
    if open_browser and auth.is_loopback(bind_host):
        import threading
        open_url = f"{url}/login?token={settings.dashboard_token}" if settings.dashboard_token else url
        threading.Timer(0.8, lambda: webbrowser.open(open_url)).start()
    uvicorn.run(_app(), host=bind_host, port=bind_port, log_level="warning")
