/* CFNJ Designer Coach. Static, private: data files are AES-256-GCM encrypted. Published site (kdf.json present, v2): ONE slow PBKDF2 (3,000,000 iterations, site salt) of the access code gives both the AES key and the file name, so file names never reveal a code. Local preview (no kdf.json, v1): SHA-256 file name + per-file PBKDF2. */
'use strict';
var D=null, CUR=null, PSK=null;   /* PSK: owner key material kept in memory only (never stored), used solely to open the owner's per-designer My past Sales files (pastsales.js) */
var $=function(s){return document.querySelector(s)};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function b64(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
async function sha(code){var h=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('cfnj-coach|'+code));return Array.from(new Uint8Array(h)).map(function(x){return x.toString(16).padStart(2,'0')}).join('').slice(0,24)}
async function decrypt(blob,code){var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(code),'PBKDF2',false,['deriveKey']);
  var k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(blob.salt),iterations:blob.iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(blob.iv)},k,b64(blob.ct));return JSON.parse(new TextDecoder().decode(pt))}
/* Canonical form: Unicode NFKC, lowercase, then keep ONLY a-z and 0-9. Hyphens/spaces/smart dashes/punctuation/line breaks are ignored, so "Amber-Moon-Tiger-42", "amber moon tiger 42." and "ambermoontiger42" are the same code. */
function canon(s){s=String(s==null?'':s);try{s=s.normalize('NFKC')}catch(e){}return s.toLowerCase().replace(/[^a-z0-9]/g,'')}
/* ── Remember this device (Andrew, Oct 21, 2026). After a successful unlock we store ONLY the PBKDF2 output m (32 bytes; 3,000,000
   rounds of the code with the fixed site salt in kdf.json), never the typed code, in localStorage under a key scoped to this page path.
   m gives both the file name (SHA-256(m|'|cfnj-fid')) and the AES key (SHA-256(m|'|cfnj-key')), so reopening is one fetch + one AES
   decrypt (no 3M-round PBKDF2). The site salt is fixed (pub_kdf.json), so m keeps working across republishes; a fingerprint of the salt
   is stored too, and a changed salt clears m. A rotated code -> its file is gone (404) or will not decrypt -> m is cleared and the code
   box shows. A network error never clears m (shows Retry instead). m never leaves the device. Legacy plaintext codes
   (key 'cfnj_coach_code', stored before this change) are migrated once and deleted. ── */
var LSK='cfnj_coach_key_v2|'+location.pathname.replace(/index\.html$/,''), LS_OLD='cfnj_coach_code';
function remGet(){try{var o=JSON.parse(localStorage.getItem(LSK)||'null');return o&&o.v===2&&o.m&&o.fp?o:null}catch(e){return null}}
function remSet(o){try{localStorage.setItem(LSK,JSON.stringify(o));if(navigator.storage&&navigator.storage.persist)navigator.storage.persist().catch(function(){})}catch(e){}}
function remClear(){try{localStorage.removeItem(LSK);localStorage.removeItem(LS_OLD)}catch(e){}}
function b64e(u){var s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)}
function NetErr(){var e=new Error('net');e.kind='net';return e}
var KDF=null;async function kdf(){if(KDF===null){var r;try{r=await fetch('kdf.json',{cache:'no-store'})}catch(e){throw NetErr()}
  if(r.ok)KDF=await r.json();else if(r.status===404)KDF=false;else throw NetErr()}return KDF}
function hex(u){return Array.from(u).map(function(x){return x.toString(16).padStart(2,'0')}).join('')}
async function h256(a,tag){var t=new TextEncoder().encode(tag),u=new Uint8Array(a.length+t.length);u.set(a);u.set(t,a.length);return new Uint8Array(await crypto.subtle.digest('SHA-256',u))}
async function saltFp(K){return hex(await h256(b64(K.salt),'|cfnj-salt-fp')).slice(0,16)}
async function master2(code,K){var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(code),'PBKDF2',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:b64(K.salt),iterations:K.iter,hash:'SHA-256'},base,256))}
async function openM(m){var f=hex(await h256(m,'|cfnj-fid')).slice(0,24),r;      /* throws kind: 'gone' (no such file), 'bad' (will not decrypt), 'net' */
  try{r=await fetch('d/'+f+'.json',{cache:'no-store'})}catch(e){throw NetErr()}
  if(r.status===404){var g=new Error('gone');g.kind='gone';throw g}if(!r.ok)throw NetErr();
  var blob;try{blob=await r.json()}catch(e){throw NetErr()}
  var k=await crypto.subtle.importKey('raw',await h256(m,'|cfnj-key'),{name:'AES-GCM'},false,['decrypt']),pt;
  try{pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(blob.iv)},k,b64(blob.ct))}catch(e){var b=new Error('bad');b.kind='bad';throw b}
  return JSON.parse(new TextDecoder().decode(pt))}
async function unlock(code,rem){code=canon(code);var K=await kdf();
  if(K&&K.v===2){var m=await master2(code,K),d;try{d=await openM(m)}catch(e){if(e.kind==='net')throw e;throw new Error('nf')}
    if(rem)remSet({v:2,fp:await saltFp(K),m:b64e(m),at:new Date().toISOString().slice(0,10)});else remClear();PSK={v:2,m:m};return d}
  var f=await sha(code),r;try{r=await fetch('d/'+f+'.json',{cache:'no-store'})}catch(e){throw NetErr()}if(!r.ok)throw new Error('nf');var d1=await decrypt(await r.json(),code);PSK={v:1,c:code};return d1}   /* local v1 preview: not remembered */
function opening(on,msg){var o=$('#opening');if(!o)return;o.classList.toggle('hidden',!on);if(msg)$('#openmsg').textContent=msg}
function lock(msg,retry){opening(false);$('#lock').classList.remove('hidden');$('#lockerr').textContent=msg||'';var rb=$('#retry');if(rb)rb.classList.toggle('hidden',!retry);if(!retry)$('#code').focus()}
function standalone(){return window.navigator.standalone===true||(window.matchMedia&&window.matchMedia('(display-mode: standalone)').matches)}
(function(){var h=$('#lockhint');if(h&&standalone())h.textContent='This Home Screen icon keeps its own memory: enter your code once here and it is remembered on this icon.'})();
$('#lockform').addEventListener('submit',async function(e){e.preventDefault();var c=$('#code').value.trim();if(!c)return;$('#lockerr').textContent='Opening…';var rem=!$('#remember')||$('#remember').checked;
  try{D=await unlock(c,rem);$('#code').value='';$('#lock').classList.add('hidden');start()}catch(err){$('#lockerr').textContent=err&&err.kind==='net'?'Could not reach the page. Check your connection and try again.':'That code did not work. Check it and try again.'}});
function signOut(){remClear();location.hash='';location.reload()}
$('#btnOut').onclick=signOut;(function(){var l=$('#lnkOut');if(l)l.onclick=function(e){e.preventDefault();signOut()};var rb=$('#retry');if(rb)rb.onclick=function(){location.reload()}})();
(async function init(){var q=new URLSearchParams(location.search);
  if(q.get('dev')&&/^(localhost|127\.0\.0\.1)$/.test(location.hostname)){var r=await fetch(q.get('dev'),{cache:'no-store'});D=await r.json();return start()}
  if(location.hash.indexOf('#k=')===0){var kk=decodeURIComponent(location.hash.slice(3));history.replaceState(null,'',location.pathname+location.search);opening(true,'Opening…');try{D=await unlock(kk,true);opening(false);return start()}catch(e){return lock(e&&e.kind==='net'?'Could not reach the page. Check your connection.':'That link did not work.',e&&e.kind==='net')}}
  var R=remGet();
  if(R){opening(true,'Opening…');try{var K=await kdf();if(!K||K.v!==2||R.fp!==await saltFp(K)){remClear();return lock('Please enter your code again.')}
      D=await openM(b64(R.m));PSK={v:2,m:b64(R.m)};opening(false);return start()}
    catch(e){if(e&&e.kind==='net')return lock('Could not reach the page (no connection?). This device is still remembered: tap Retry.',true);remClear();return lock('Your code has changed. Please enter your current code.')}}
  var c=null;try{c=localStorage.getItem(LS_OLD)}catch(e){}
  if(c){opening(true,'Opening… (one-time update, a few seconds)');try{D=await unlock(c,true);try{localStorage.removeItem(LS_OLD)}catch(e){}opening(false);return start()}
    catch(e){if(e&&e.kind==='net')return lock('Could not reach the page (no connection?). Tap Retry.',true);try{localStorage.removeItem(LS_OLD)}catch(e2){}}}
  lock()})();
/* ── formatting ── */
function m0(v){return v==null||isNaN(v)?'–':(v<0?'−':'')+'$'+Math.round(Math.abs(v)).toLocaleString('en-US')}
function mk(v){if(v==null||isNaN(v))return'–';var a=Math.abs(v);return(v<0?'−':'')+(a>=1e6?'$'+(a/1e6).toFixed(2)+'M':a>=1e4?'$'+Math.round(a/1e3)+'K':a>=1e3?'$'+(a/1e3).toFixed(1)+'K':'$'+Math.round(a))}
function pc(v){return v==null||isNaN(v)?'–':Math.round(v*100)+'%'}
function n0(v){return v==null?'–':Math.round(v).toLocaleString('en-US')}
/* direction-aware color: compare value to reference; band = neutral zone */
function cls(v,ref,band,lowerBetter){if(v==null||ref==null||isNaN(v)||isNaN(ref))return'neu';var d=lowerBetter?ref-v:v-ref;return d>band?'pos':d<-band?'neg':'neu'}
function toast(t){var e=$('#toast');e.textContent=t;e.classList.remove('hidden');setTimeout(function(){e.classList.add('hidden')},1800)}
function copy(t){(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){toast('Copied')},function(){toast('Select and copy the text')})}
function tile(k,v,s,c){return '<div class="tile"><div class="k">'+k+'</div><div class="v '+(c||'neu')+'">'+v+'</div>'+(s?'<div class="s">'+s+'</div>':'')+'</div>'}
function sec(id,title,html){return '<section class="sec" id="'+id+'"><h2>'+title+'</h2>'+html+'</section>'}
/* ── router ── */
function start(){if(!D||D.kind!=='owner')PSK=null;$('#btnOut').classList.remove('hidden');var so=$('#signout');if(so)so.classList.remove('hidden');ACT.setForm(D.meta.activity_form||null);ACT.syncAll(D.meta.activity_form,window.ACT_ONSYNC);$('#sub').textContent='Data as of '+D.meta.asof+' · '+D.meta.month;
  if(D.kind==='designer'){document.body.classList.add('dview');$('#nav').innerHTML='';$('#ttl').textContent='My Coaching Page';route('d/'+D.designers[0].slug)}else{window.onhashchange=function(){route(location.hash.slice(1))};route(location.hash.slice(1)||'team')}}
function nav(on){var t=[['team','Team'],['people','Designers'],['topics','Training topics'],['queue','Teams drafts'],['lib','Library'],['how','How it works']];
  $('#nav').innerHTML=t.map(function(x){return '<a href="#'+x[0]+'" class="'+(on===x[0]?'on':'')+'">'+x[1]+'</a>'}).join('')}
function route(h){window.scrollTo(0,0);var M=$('#main');
  if(h.indexOf('d/')===0){var x=D.designers.find(function(z){return z.slug===h.slice(2)})||D.designers[0];if(D.kind==='owner')nav('people');M.innerHTML=designer(x);wire(x);return}
  nav(h);M.innerHTML=h==='people'?people():h==='topics'?topics():h==='queue'?queue():h==='lib'?library():h==='how'?how():team();wireOwner();if(h!=='people'&&h!=='topics'&&h!=='queue'&&h!=='lib'&&h!=='how')adWire()}
/* personal goal helpers */
function gtxt(h){if(h.basis==='none')return'No goal shown (on leave, no leads).';var d=h.diff==null?null:Math.round(Math.abs(h.diff)*100);
  if(h.basis==='lead')return'Under '+D.meta.cfg.HIST_MIN_MONTHS+' months of history ('+h.months+'), so the lead-based goal share is used for now.';
  if(h.flag==='above')return'Flag: personal goal is '+d+'% above the lead-adjusted fair month. Your own history beats what team-typical results on your leads would give; the history goal is used.';
  if(h.flag==='below')return'Flag: personal goal is '+d+'% below the lead-adjusted fair month. Your leads would support more than your own recent average; worth a coaching look.';
  return'Within '+Math.round(D.meta.cfg.FAIR_FLAG*100)+'% of the lead-adjusted fair month (no flag).'}
/* ── designer page ── */
function designer(x){var s=x.snap,g=x.goal,n=x.notes,T=D.team,tm=T.mtd,M=D.meta,h='';
  if(D.kind==='owner')h+='<a class="back" href="#people">← All designers</a>';
  if(x.test)h+='<div class="card" style="border-left:5px solid #c47f00;background:#fff8e6"><b>🧪 TEST PAGE</b><p class="small" style="margin:6px 0 0">'+esc(x.test.label||x.name)+': a copy of '+esc(x.test.mirror||'a designer')+'\'s real page for testing. Activity entries saved here are sent to the Activity log Sheet with Designer = "'+esc(x.act_who||x.name)+'" so they are easy to filter and delete. Not counted in team totals.</p></div>';
  h+='<div class="card hero"><div class="m">'+esc(M.month)+' · day '+M.day+' of '+M.dim+' · '+M.days_left+' days left</div><h2>'+esc(x.name)+'</h2><div class="m">Personal coaching page · coach, not judge: every number compares you fairly to the team for the leads you run.</div>'+psBtn(x)+'</div>';
  h+='<div class="minis"><a href="#wins">Wins</a><a href="#close">Close this month</a><a href="#pastc">Past clients</a><a href="#inact">Former designers&#39; clients</a><a href="#activity">My activity</a><a href="#snap">Snapshot</a><a href="#goal">Goal</a><a href="#notes">Next steps</a><a href="#focus">Focus</a><a href="#week">This week</a><a href="#learn">Library</a></div>';
  h+=fuSection(x);
  /* wins first */
  h+=sec('wins','🌟 Wins & streaks','<div class="wins">'+x.wins.map(function(w){return '<div class="win"><div class="i">'+w.icon+'</div><div><b>'+esc(w.t)+'</b><span>'+esc(w.d)+'</span></div></div>'}).join('')+'</div>');
  h+=actSection(x);
  h+=nsSection(x);
  /* snapshot */
  var d9=s.dcl90,dclc=d9.band==='below'?'neg':(d9.band?'pos':'neu');
  h+=sec('snap','📊 This month snapshot','<div class="grid">'+
    tile('Sold this month',m0(s.usd),s.sales+' sale'+(s.sales!==1?'s':'')+(s.pend_n?' · '+m0(s.pend)+' pending Final':''),'neu')+
    tile('Close rate (corporate)',pc(s.rate),'Sold Final ÷ '+s.held+' held first appts · team '+pc(tm.rate),s.held>=8?cls(s.rate,tm.rate,.03):'neu')+
    tile('Lead-appt close rate',pc(s.lead_rate),s.lead_held+' logged lead appts · team '+pc(tm.lead_rate),s.lead_held>=8?cls(s.lead_rate,tm.lead_rate,.03):'neu')+
    tile('$ per first appt',m0(s.usd_per_first),'team '+m0(tm.usd_per_first),s.held>=8?cls(s.usd_per_first,tm.usd_per_first,tm.usd_per_first*.1):'neu')+
    tile('First appts held',n0(s.held),s.booked+' booked this month · team avg '+T.held_m_avg.toFixed(1),'neu')+
    tile('Leads assigned',s.opps_m+' / '+s.opps_60,'this month / last 60 days · team avg '+T.opps_m_avg.toFixed(0)+' / '+T.opps_60_avg.toFixed(0),'neu')+
    tile('Designer-created share (90 days)',pc(d9.share),d9.dcl+' of '+d9.n+' sold deals ('+pc(d9.share_usd)+' of sold $) · target 20–30% · this month '+s.dcl.dcl+' of '+s.dcl.n+' · team '+pc(T.dcl90.share)+(d9.band?'':' · too few sales to judge'),dclc)+
    tile('Last 90 days',pc(s.rate90)+' close',m0(s.usd90)+' on '+s.sales90+' sales · '+s.held90+' first appts · team '+pc(T.l90.rate),s.held90>=20?cls(s.rate90,T.l90.rate,.03):'neu')+'</div>'+
    '<p class="fine">Office sets appointments, so lead volume is never on you; these numbers are about what happens after the appointment. Colors only when the sample is big enough (8+ appts this month, 20+ over 90 days). Green ≥3 pts above team, red ≥3 pts below, black in between.</p>');
  /* goal */
  var hg=g.hist,pg=g.personal,mx=Math.max(g.fair,pg||0,g.proj,s.usd)*1.08||1,P=function(v){return Math.min(100,v/mx*100).toFixed(1)+'%'};
  var att=g.exp_td?s.usd/g.exp_td:null;
  if(M.plan)h+=goalPlanSec(x);else h+=sec('goal',(g.target!=null?'🎯 Goal tracker (October target)':'🎯 Goal tracker (personal goal)'),(g.target!=null?'<div class="card" style="border-left:5px solid #b26b00"><div class="grid g3">'+tile('October target (goal-back plan)',m0(g.target),'sold through Oct 18 '+m0(g.target_base)+' + remaining quota '+m0(g.target_quota),'neu')+tile('Gap to target',g.target_gap>0?m0(g.target_gap):'hit',(g.target_gap>0?'still to sell':'target reached')+' · sold '+m0(s.usd),g.target_gap<=0?'pos':'neu')+tile('On path now',m0(g.target_pace),'daily targets path · you are '+(s.usd>=g.target_pace?m0(s.usd-g.target_pace)+' ahead':m0(g.target_pace-s.usd)+' behind'),g.target_status||'neu')+'</div><p class="fine">Everyone tracks to the same October number: CEO Coach\'s goal-back plan, approved by Andrew. The path follows the daily targets (checkpoints Fri 10/23 and Tue 10/27). Your personal goal below is a reference.</p></div>':(g.no_target_why&&D.meta.plan?'<div class="card"><p class="small">No October target: '+esc(g.no_target_why)+'. Your personal goal is shown.</p></div>':''))+'<div class="card">'+(hg.basis==='none'?'<p class="small">'+esc(gtxt(hg))+'</p>':'<div class="grid g2" style="margin-bottom:10px">'+tile('Personal goal this month',m0(pg),hg.basis==='history'?'your '+hg.months+'-month average '+m0(hg.avg)+' × '+hg.stretch.toFixed(3)+(hg.lead.applied?' × lead flow '+hg.lead.factor.toFixed(2):''):'lead-based (under '+M.cfg.HIST_MIN_MONTHS+' months of history)','neu')+tile('Lead-adjusted fair month',m0(g.fair),'fairness check · '+(hg.diff==null?'–':(hg.diff>=0?'+':'−')+Math.round(Math.abs(hg.diff)*100)+'% vs personal goal'),'neu')+'</div>')+
    '<div class="grid g3">'+tile('Sold so far',m0(s.usd),'incl. pending Final'+(att!=null&&s.usd>0?' · '+pc(att)+' of typical':''),cls(s.usd,g.exp_td,g.exp_td*.05))+tile('Team-typical by today',m0(g.exp_td),'for your lead flow, day '+M.day,'neu')+
    tile('Projected month-end',m0(g.proj),pg!=null?'vs personal goal '+m0(pg):'vs fair month '+m0(g.fair),pg!=null?cls(g.proj,pg,pg*.05):cls(g.proj,g.fair,g.fair*.05))+'</div>'+
    '<div class="bar"><div class="proj" style="width:'+P(g.proj)+'"></div><div class="fill" style="width:'+P(s.usd)+'"></div>'+
    '<div class="mk" style="left:'+P(g.exp_td)+'"><span class="lb">by today '+mk(g.exp_td)+'</span></div>'+
    '<div class="mk bt" style="left:'+P(g.fair)+'"><span class="lb">fair month '+mk(g.fair)+'</span></div>'+
    (pg!=null?'<div class="mk" style="left:'+P(pg)+';background:#b26b00"><span class="lb" style="color:#b26b00">personal goal '+mk(pg)+'</span></div>':'')+'</div>'+
    '<div class="legend"><span><i style="background:#12263f"></i>sold</span><span><i style="background:#9fb2c9"></i>projected month-end (back-loaded curve + pipeline floor)</span><span><i style="background:#14171c"></i>team-typical markers</span><span><i style="background:#b26b00"></i>your personal goal</span></div>'+
    '<div style="margin-top:10px">'+(hg.basis==='none'?'':'<div class="kv"><span>Your average monthly sold $, last '+hg.months+' completed month'+(hg.months===1?'':'s')+' (Sold Final + Sold Designer pending Final)</span><b>'+m0(hg.avg)+'</b></div>'+
    '<div class="kv"><span>× lead-flow factor (your held first appts per 30 days, last 60: '+g.flow.toFixed(1)+', vs your own average '+(hg.lead.base==null?'–':hg.lead.base.toFixed(1))+')'+(hg.lead.applied?'':' · not applied: '+esc(hg.lead.why||'no history'))+'</span><b>'+hg.lead.factor.toFixed(2)+'</b></div>'+
    '<div class="kv"><span>× stretch '+hg.stretch.toFixed(3)+' = <b>personal goal</b>'+(hg.basis==='lead'?' (not used yet: under '+M.cfg.HIST_MIN_MONTHS+' months)':'')+'</span><b>'+m0(hg.hist_goal)+'</b></div>'+
    '<div class="kv"><span>Best / lowest month in that window</span><b>'+m0(hg.hi)+' / '+m0(hg.lo)+'</b></div>'+
    '<div class="kv"><span>Fairness check vs lead-adjusted fair month</span><b>'+m0(g.fair)+'</b></div>'+
    '<p class="fine" style="margin:4px 0 8px">'+esc(gtxt(hg))+'</p>')+
    '<div class="kv"><span>Projection parts: pipeline floor (sold + open quotes + booked appts) · month-to-date on the typical curve ('+(g.proj_curve==null?'–':m0(g.proj_curve))+') · weight on the curve '+pc(g.proj_w)+'</span><b>'+m0(g.proj_pipe)+'</b></div>'+
    '<div class="kv"><span>Your lead flow (held first appts per 30 days, last 60 days)</span><b>'+g.flow.toFixed(1)+'</b></div>'+
    '<div class="kv"><span>× team $ per held first appt (90 days, excl. designer-created)</span><b>'+m0(T.team_rate_usd)+'</b></div>'+
    '<div class="kv"><span>Designer-created part: lead production ÷ 0.75 (designer-created = 25% midpoint of the 20–30% standard)</span><b>'+m0(g.fair_dcl)+'</b></div>'+
    '<div class="kv"><span><b>Fair month expectation</b> (what a team-typical designer sells with your leads)</span><b>'+m0(g.fair)+'</b></div>'+
    '<div class="kv"><span>Team-typical by day '+M.day+' (typical months have '+pc(M.typ_share)+' sold by now)</span><b>'+m0(g.exp_td)+'</b></div>'+
    '<div class="kv"><span>Your appointments held this month at the team rate</span><b>'+m0(g.exp_held_mtd)+'</b></div>'+
    (g.goal_share==null?'':'<div class="kv"><span>Reference: lead-based share of the team month goal ('+m0(M.goal)+' = Q4 '+m0(M.q4)+' × 31/92), split by lead flow ('+pc(g.share)+')</span><b>'+m0(g.goal_share)+'</b></div>')+'</div>'+
    '<p class="fine">Projected month-end is not a straight line: sales back-load, so it blends what your month-to-date implies on the typical curve ('+pc(M.typ_share)+' of a month is usually sold by day '+M.day+') with your typical month, and never goes below sold + expected closes from your open quotes and booked appointments ('+m0(g.proj_pipe)+'). Your personal goal is your own trailing average plus a 7.5% stretch (times a lead-flow factor); the fair month shows what the leads alone would suggest.</p></div>');
  /* notes */
  var sc=n.score==null?null:Math.round(n.score),scc=sc==null?'#999':sc>=75?'#0d7a45':sc>=50?'#b26b00':'#c62828',tn=T.notes,W=M.cfg.NOTE_W;
  var nh='<div class="card"><div class="gauge"><div class="ring" style="--p:'+(sc||0)+';--c:'+scc+'"><div>'+(sc==null?'–':sc)+'</div></div><div><b>Next-step compliance</b> <span class="small">team '+Math.round(tn.score)+' · 0–100</span><div class="small">Average across your '+n.n+' open opps ('+m0(n.usd)+'). '+W.next+' pts dated next appointment in the note (date, place, time) · '+W.future+' pts not overdue · '+W.stage+' pts right stage · '+W.fresh+' pts fresh note (≤'+M.cfg.FRESH_DAYS+' days).</div></div></div>'+
    '<div class="grid" style="margin-top:12px">'+tile('Dated future appointment',pc(n.pct_next),'team '+pc(tn.pct_next),n.n>=3?cls(n.pct_next,tn.pct_next,.05):'neu')+tile('Correct stage',pc(n.pct_stage),'team '+pc(tn.pct_stage),n.n>=3?cls(n.pct_stage,tn.pct_stage,.05):'neu')+
    tile('Fresh note (≤'+M.cfg.FRESH_DAYS+'d)',pc(n.pct_fresh),'team '+pc(tn.pct_fresh),n.n>=3?cls(n.pct_fresh,tn.pct_fresh,.05):'neu')+tile('Days since update',n.med_upd==null?'–':Math.round(n.med_upd),'median · team '+Math.round(tn.med_upd),n.n>=3?cls(n.med_upd,tn.med_upd,2,true):'neu')+'</div>'+
    (n.overdue_n?'<p class="small">'+n.overdue_n+' open opp'+(n.overdue_n==1?' has':'s have')+' a next appointment date that has passed: log what happened and book the next one.</p>':'')+
    (n.dorm_n?'<p class="small">Also '+n.dorm_n+' older opps ('+m0(n.dorm_usd)+', appointment 90+ days ago): get a yes, a no, or a firm appointment, so the pipeline stays honest.</p>':'')+'</div>';
  nh+='<div class="card"><b>Opps to fix</b> <span class="small">sorted by expected value (amount × close odds for its age)</span><div style="margin-top:8px">'+
    (x.deals.length?'<div id="opps">'+x.deals.map(function(d,i){return '<div class="deal" data-ref="'+esc(d.ref)+'" data-oi="'+(d.oi!=null?d.oi:i)+'"><div class="top"><span><b>'+esc(d.name||'(no first name)')+'</b> · <span class="small">'+esc(d.stage)+' · '+esc(d.src)+'</span></span><span class="amt">'+m0(d.usd)+'</span></div>'+ctLine(d)+
      '<div class="why"><span class="chip '+(d.upd>14?'r':'')+'">'+d.upd+'d since update</span><span class="chip">appt '+d.age+'d ago</span><span class="chip">score '+d.score+'</span>'+(d.next?'<span class="chip g">next '+esc(d.next)+'</span>':'')+'</div><div class="why small">Fix: '+d.miss.map(esc).join(' · ')+'</div>'+fuBox('deal',d.ref,1)+'</div>'}).join('')+'</div>':'<p>All open opps have a dated future appointment, the right stage and a fresh note. 👏</p>')+'</div></div>';
  nh+='<div class="card"><b>The rule</b><p class="small" style="margin:6px 0">Never leave an appointment without one of three outcomes: a <b>YES</b> (signed), a <b>NO</b>, or a <b>FIRM FOLLOW-UP APPOINTMENT</b>. Only if the client refuses all three, book a firm <b>phone</b> appointment at a specific time. Work your skills until that is almost never needed.</p><b>The one-line note</b><div class="tmpl" style="margin-top:8px">'+esc(M.note_template)+'</div><p class="fine">'+esc('<Date of note> Follow scheduled <date of next appointment> in <showroom/home/phone/wherever> at <time>.')+'</p><ul class="tight small">'+M.note_checks.map(function(c){return '<li>✔︎ '+esc(c[1])+'</li>'}).join('')+'</ul></div>';
  nh+='<div class="card"><b>Where it goes (stages)</b><ul class="tight small">'+M.stage_guide.map(function(g){return '<li><b>'+esc(g.when)+'</b> → '+esc(g.stage)+'. '+esc(g.note)+'</li>'}).join('')+'</ul></div>';
  h+=sec('notes','📝 Next-step compliance',nh);
  /* focus */
  var L=D.lib,fh='';
  if(!x.focus.length)fh='<div class="card"><b>No data-driven gaps flagged right now.</b> Keep your rhythm: a yes, a no, or a firm follow-up appointment every time, with the one-line note. Pick any skill in the library to sharpen.</div>';
  x.focus.forEach(function(f,i){var S=L.skills[f.skill];fh+='<div class="card focus"><div class="small">Focus '+(i+1)+' · '+S.icon+' '+esc(S.name)+'</div><h3>'+esc(f.title)+'</h3><div class="ev">'+esc(f.evidence)+'</div>'+
    (f.deals&&f.deals.length?'<div style="margin-top:6px">'+f.deals.map(function(d){return '<div class="fdl"'+(d.ref?' data-ref="'+esc(d.ref)+'"':'')+'><span class="chip a">'+esc(d.name)+' '+m0(d.usd)+'</span>'+ctLine(d,1)+(d.ref?fuBox('deal',d.ref,1):'')+'</div>'}).join('')+'</div>':'')+
    '<div style="margin-top:8px"><b class="small">What good looks like</b><ul class="tight">'+S.good.map(function(g){return '<li>'+esc(g)+'</li>'}).join('')+'</ul></div>'+
    '<div style="margin-top:8px"><b class="small">Watch &amp; learn: short videos on exactly this</b>'+resList(f.skill,f.key)+'</div></div>'});
  h+=sec('focus','🧭 Your focus areas',fh+'<p class="fine">Detected from your ClosetWare data with simple rules (see How it works); ranked by the dollars involved. Up to 3, never a list of faults.</p>');
  /* week */
  var q=x.quiz,wh='<div class="card">'+x.actions.map(function(a,i){return '<div class="act" data-i="'+i+'"><input type="checkbox" aria-label="done"><div><div class="due">by '+esc(a.due)+'</div><div class="t"><b>'+esc(a.t)+'</b></div><div class="small">'+esc(a.d)+(a.url?' <a href="'+esc(a.url)+'" target="_blank" rel="noopener">Open</a>':'')+'</div></div></div>'}).join('')+'<p class="fine">Check-offs are saved on this device only.</p></div>';
  wh+='<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap"><b>Message from Andrew</b><span class="draft">'+esc(x.message.status)+'</span></div><div class="msg" style="margin-top:8px">'+esc(x.message.text)+'</div><div class="fine" style="margin:6px 0">'+x.message.words+' words · for Teams</div>'+(D.kind==='owner'?'<button class="btn ghost" id="cp">Copy draft</button>':'')+'</div>';
  wh+='<div class="card quiz"><b>3-minute check: '+esc(L.skills[q.skill].name)+'</b><p>'+esc(q.q)+'</p>'+q.opts.map(function(o,i){return '<button data-i="'+i+'">'+esc(o)+'</button>'}).join('')+'<div id="qa" class="small"></div><p class="small" style="margin-top:10px"><b>Reflect:</b> '+esc(q.reflect)+'</p></div>';
  h+=sec('week','✅ This week',wh);
  h+=sec('learn','🎬 Watch this week',(x.videos&&x.videos.length?'<div class="card"><p class="small" style="margin:0 0 8px">One short video for each of your focus areas, picked from your own numbers. Each one is about exactly that skill.</p><div class="vids">'+x.videos.map(function(v){return vidCard(v,v.reason,v.focus_title)}).join('')+'</div></div>':'')+'<details><summary>📚 More videos and articles by skill</summary>'+librarySkills()+'</details>');
  h+='<p class="fine">ClosetWare data, read-only, NJ only. Sold = Sold (Final) + Sold (Designer) pending Final; 17 Lowe\'s bay records excluded. Clients shown by first name with their phone and email from ClosetWare (your own clients only; tapping a number or email does not log anything).</p>';
  return h}
function vidCard(v,reason,ft){return '<a class="vid" href="'+esc(v.url)+'" target="_blank" rel="noopener noreferrer"><img loading="lazy" alt="" src="https://i.ytimg.com/vi/'+esc(v.vid)+'/mqdefault.jpg"><span class="vb">'+(ft?'<span class="vf">Focus: '+esc(ft)+'</span>':'')+'<b>'+esc(v.title)+'</b><span class="m">▶ '+esc(v.length)+' · '+esc(v.src)+(D.kind==='owner'&&v.essential?' · <span class="chip a">longer: '+esc(v.essential)+'</span>':'')+'</span><span class="why"><b>Why this helps:</b> '+esc(v.why)+'</span>'+(reason?'<span class="small">Your numbers: '+esc(reason)+'</span>':'')+'</span></a>'}
function resList(sk,key){var L=D.lib,vs=(key&&L.focus_videos&&L.focus_videos[key])||((L.videos&&L.videos[sk])||[]),vu={};vs.forEach(function(v){vu[v.url]=1});
  var a=(L.internal[sk]||[]).concat((L.resources[sk]||[]).filter(function(r){return !vu[r.url]}));
  return (vs.length?'<div class="vids">'+vs.map(function(v){return vidCard(v)}).join('')+'</div>':'')+(a.length?'<div class="small" style="margin:8px 0 2px"><b>Read / CFNJ resources</b></div>':'')+a.map(function(r){return '<div class="res"><span class="kd '+esc(r.kind)+'">'+esc(r.kind)+'</span><div>'+(r.url?'<a href="'+esc(r.url)+'" target="_blank" rel="noopener noreferrer">'+esc(r.title)+'</a>':'<b>'+esc(r.title)+'</b>')+
  '<div class="m">'+esc(r.src)+' · '+esc(r.length)+(r.status==='403'?' · <span class="chip a">link unchecked (site blocks checks)</span>':'')+'</div><div class="small">'+esc(r.why)+'</div></div></div>'}).join('')}
function librarySkills(){var L=D.lib;return Object.keys(L.skills).map(function(k){var S=L.skills[k];return '<details><summary>'+S.icon+' '+esc(S.name)+'</summary><ul class="tight">'+S.good.map(function(g){return '<li>'+esc(g)+'</li>'}).join('')+'</ul>'+resList(k)+'</details>'}).join('')}
function wire(x){var key='cfnj_coach_done_'+x.slug+'_'+D.meta.today,st={};try{st=JSON.parse(localStorage.getItem(key)||'{}')}catch(e){}
  document.querySelectorAll('.act').forEach(function(el){var i=el.dataset.i,cb=el.querySelector('input');cb.checked=!!st[i];el.classList.toggle('done',cb.checked);cb.onchange=function(){st[i]=cb.checked;el.classList.toggle('done',cb.checked);localStorage.setItem(key,JSON.stringify(st))}});
  document.querySelectorAll('.quiz button').forEach(function(b){b.onclick=function(){var i=+b.dataset.i,ok=i===x.quiz.a;document.querySelectorAll('.quiz button').forEach(function(z,j){z.classList.toggle('ok',j===x.quiz.a)});if(!ok)b.classList.add('no');$('#qa').innerHTML=(ok?'✅ Yes. ':'Not quite. ')+esc(x.quiz.why)}});
  var c=$('#cp');if(c)c.onclick=function(){copy(x.message.text)};
  actWire(x);
  nsWire(x);
  psWire(x);
  document.querySelectorAll('.minis a').forEach(function(a){a.onclick=function(e){e.preventDefault();var t=document.getElementById(a.getAttribute('href').slice(1));if(t)window.scrollTo({top:t.getBoundingClientRect().top+window.scrollY-110,behavior:'smooth'})}})}
/* ── owner views ── */
/* ── team goal panel: all roster designers vs personal goal and on-pace marker ── */
var GP_SORT='pct';
function goalPanel(){var O=D.owner,M=D.meta,ts=M.typ_share,near=M.cfg.PACE_NEAR,PL=M.plan;
  var rows=O.rows.filter(function(r){return r.primary!=null}).map(function(r){var g=r.primary,fin=r.usd-r.pend,pace=r.pace_primary!=null?r.pace_primary:g*ts,pct=g?r.usd/g:0,behind=pace-r.usd;
    var st=r.primary_kind==='plan'&&r.target_status?r.target_status:(r.usd>=pace?'pos':(r.usd>=pace*(1-near)?'neu':'neg'));return{r:r,g:g,fin:fin,pace:pace,pct:pct,behind:behind,st:st}});
  rows.sort(GP_SORT==='pct'?function(a,b){return b.pct-a.pct}:function(a,b){return b.behind-a.behind});
  var leave=O.rows.filter(function(r){return r.primary==null});
  var sg=0,ss=0,sp=0,sj=0,spc=0,st_=0,spg=0;rows.forEach(function(x){sg+=x.g;ss+=x.r.usd;sp+=x.r.pend;sj+=x.r.proj;spc+=x.pace;if(x.r.primary_kind==='plan')st_+=x.r.target;spg+=(x.r.personal||0)});
  var tg=PL&&PL.month_goal!=null?PL.month_goal:M.goal,tst=PL?(PL.team_sold>=PL.path_now?'pos':(PL.path_now-PL.team_sold<PL.path_now*.03?'neu':'neg')):(ss>=spc?'pos':(ss>=spc*(1-near)?'neu':'neg'));
  var h='<div class="card gp"><div class="gph"><div><b>🎯 Goal progress: '+(PL?'every designer vs October target (goal-back plan)':'every designer vs personal goal')+'</b><div class="small">Day '+M.day+' of '+M.dim+' · '+(PL?'on-path marker follows CEO Coach\'s daily targets (checkpoints '+PL.checkpoints.map(function(c){return esc(c.label)+' '+mk(c.cum_month)}).join(', ')+')':'on pace today = '+pc(ts)+' of the month sold (typical month shape)')+'. Tap a designer to open the page.</div></div>'+
    '<div class="seg"><button data-gs="pct" class="'+(GP_SORT==='pct'?'on':'')+'">% of target</button><button data-gs="behind" class="'+(GP_SORT==='behind'?'on':'')+'">$ behind path</button></div></div>'+
    '<div class="legend" style="margin:6px 0 10px"><span><i style="background:#12263f"></i>sold Final</span><span><i style="background:#2f6fdd"></i>pending Final (Sold Designer)</span><span><i style="background:#9fb2c9"></i>projected month-end</span><span><i style="background:#14171c"></i>'+(PL?'on path now':'on pace today')+'</span><span><i style="background:#b26b00"></i>'+(PL?'October target':'goal')+'</span></div>';
  h+='<div class="gpt"><div class="gpn"><div class="gpl">Team total</div>'+
    (PL?'<div class="gpm"><span>October goal (Sales Board)</span><b>'+m0(tg)+'</b></div><div class="gpm"><span>Team sold</span><b class="'+tst+'">'+m0(PL.team_sold)+'</b></div><div class="gpm"><span>On path now</span><b>'+m0(PL.path_now)+'</b></div><div class="gpm"><span>'+(PL.team_sold>=PL.path_now?'Ahead':'Behind')+'</span><b class="'+tst+'">'+m0(Math.abs(PL.path_now-PL.team_sold))+'</b></div><div class="gpm"><span>Still to sell</span><b>'+(tg-PL.team_sold>0?m0(tg-PL.team_sold):'hit')+'</b></div><div class="gpm"><span>Needed per day ('+M.days_left+' left)</span><b>'+(tg-PL.team_sold>0?m0((tg-PL.team_sold)/Math.max(1,M.days_left)):'–')+'</b></div>'+PL.checkpoints.map(function(c){return '<div class="gpm"><span>'+esc(c.label)+'</span><b>'+m0(c.cum_month)+'</b></div>'}).join(''):
     '<div class="gpm"><span>Goal (sum of personal)</span><b>'+m0(sg)+'</b></div><div class="gpm"><span>Team month goal</span><b>'+m0(tg)+'</b></div><div class="gpm"><span>Sold (pending '+m0(sp)+')</span><b class="'+tst+'">'+m0(ss)+'</b></div><div class="gpm"><span>On pace today</span><b>'+m0(spc)+'</b></div>')+
    '<div class="gpm"><span>Projected (designers)</span><b class="'+cls(sj,sg,sg*.03)+'">'+m0(sj)+'</b></div></div>'+
    (PL?'<p class="fine" style="margin:6px 0 0"><b>How the plan adds up to '+m0(tg)+'.</b> Roster designers\' October targets '+m0(st_)+(PL.unmatched.length?' + '+PL.unmatched.map(esc).join(', ')+' (in the plan, not on this roster)':'')+' + '+PL.buckets.map(function(b){return esc(b.name.split(' (')[0].split(':')[0])+' '+m0(b.quota)}).join(' + ')+' + sales through Oct 18 by people without a target. Target = sold through Oct 18 (baseline) + remaining quota, read from the Sales Board\'s goal-back plan (same file and code as the board)'+(PL.board_check&&PL.board_check.ok===false?' <b>WARNING: differs from the Sales Board\'s last build; check goal_plan.json.</b>':(PL.board_check&&PL.board_check.ok?'; matches the Sales Board\'s last build.':'.'))+' Designers without a board target show no goal.</p>':
     '<p class="fine" style="margin:6px 0 0">Sum of personal goals is '+m0(Math.abs(sg-tg))+' '+(sg<tg?'BELOW':'ABOVE')+' the team month goal ('+pc(sg/tg)+').</p>')+
    (function(){var B=M.board_proj||{},all=O.rows.reduce(function(a,r){return a+r.proj},0),df=B.base?all/B.base-1:null,fl=df!=null&&Math.abs(df)>M.cfg.PROJ_DIFF_FLAG;
      return '<p class="fine" style="margin:6px 0 0"><b>Projection check.</b> Sum of designer projections '+m0(all)+' vs Sales Board true-pace base '+m0(B.base)+': '+(df==null?'–':(df>=0?'+':'−')+Math.abs(df*100).toFixed(1)+'%')+(fl?' <b>FLAG: differs by more than '+Math.round(M.cfg.PROJ_DIFF_FLAG*100)+'%.</b>':' (within '+Math.round(M.cfg.PROJ_DIFF_FLAG*100)+'%).')+'</p>'})()+'</div>';
  h+='<div class="gpg">'+rows.map(function(x){var r=x.r,mx=Math.max(x.g,r.proj,r.usd)*1.04||1,P=function(v){return Math.min(100,v/mx*100).toFixed(1)+'%'},isP=r.primary_kind==='plan';
    return '<div class="gpc" data-s="'+r.slug+'"><div class="gpr"><b class="gpname">'+esc(r.name)+'</b>'+(isP?'':'<span class="chip">'+(PL?'no Oct target · personal goal':'personal goal')+'</span>')+'<span class="gppct '+x.st+'">'+pc(x.pct)+'</span></div>'+
      '<div class="gbar"><div class="p" style="width:'+P(r.proj)+'"></div><div class="f" style="width:'+P(x.fin)+'"></div><div class="q" style="left:'+P(x.fin)+';width:'+(r.pend>0?Math.max(0.5,Math.min(100,r.pend/mx*100)).toFixed(1):0)+'%"></div><div class="m" style="left:'+P(x.pace)+'"></div><div class="m g" style="left:'+P(x.g)+'"></div></div>'+
      '<div class="gpd"><span>Sold <b class="'+x.st+'">'+m0(r.usd)+'</b>'+(r.pend>0?' <span class="small">(+'+m0(r.pend)+' pending)</span>':'')+'</span><span>'+(isP?'Oct target':'Goal')+' <b>'+m0(x.g)+'</b></span></div>'+
      '<div class="gpd"><span class="small">'+(isP?'On path ':'On pace ')+m0(x.pace)+' · '+(x.behind>0?'<b class="'+(x.st==='neg'?'neg':'neu')+'">'+m0(x.behind)+' behind</b>':'<b class="pos">'+m0(-x.behind)+' ahead</b>')+'</span><span class="small">Proj <b class="'+cls(r.proj,x.g,x.g*.05)+'">'+m0(r.proj)+'</b></span></div>'+
      (isP?'<div class="gpd"><span class="small">'+(r.target-r.usd>0?'Still to sell '+m0(r.target-r.usd)+' · '+m0((r.target-r.usd)/Math.max(1,M.days_left))+'/day':'Target hit')+'</span></div>':(r.no_target_why?'<div class="gpd"><span class="small">No October target: '+esc(r.no_target_why)+'</span></div>':''))+'</div>'}).join('')+'</div>';
  if(leave.length)h+='<p class="fine" style="margin:8px 0 0">'+(PL?'No October target on the Sales Board, so no goal shown: ':'On leave, no goal: ')+leave.map(function(r){return esc(r.name)+(PL&&r.no_target_why?' ('+esc(r.no_target_why)+')':'')}).join(', ')+'. Inactive designers are not on the roster. Color: green = at or above the path; black = near or too early to judge; red = behind by more than 10% of the plan since Oct 18'+(PL?'':' (personal-goal rows: more than 10% behind pace)')+'.</p>';
  return h+'</div>'}

function team(){var O=D.owner,T=D.team,M=D.meta,t=O.tot,h='';
  h+='<div class="card hero"><div class="m">'+esc(M.month)+' · day '+M.day+' of '+M.dim+' · owner view (all designers)</div><h2>Team coaching roll-up</h2><div class="m">Positive first, then where help pays off most. Drafts only: nothing is sent.</div></div>';
  h+='<div id="gp">'+goalPanel()+'</div>';
  h+=nsOwner();
  h+=actDash();
  h+=actOwnerCard();
  h+='<div class="card" style="border-left:5px solid #2f6fdd"><b>📋 New: activity tracker on every designer page</b><p class="small" style="margin:6px 0 0">Each designer can log calls, texts/emails, follow-ups, appointments, quotes/contracts sent, showroom visits, referral asks and closes (signed sales only) by voice (mic button) or by typing, check the counts, and see today / this week / this month against a suggested weekly target (2 touches per open quote from the playbook rhythm, their own appointment pace, one referral ask per sale). <b>Every saved entry is also sent to you automatically</b> (Google Form → '+(D.meta.activity_sheet?'<a href="'+esc(D.meta.activity_sheet)+'" target="_blank" rel="noopener noreferrer">Activity log (Google Sheet)</a>':'Activity log (Google Sheet)')+'). Entries made with no signal wait on the phone and send when it is back online. Deleting an entry on a phone does not remove it from the Sheet.</p></div>';
  h+='<div class="grid">'+tile('Sold this month',m0(T.mtd.usd),T.mtd.sales+' sales · ties to Sales Board ('+m0(M.board_mtd_usd)+' / '+M.board_mtd_sales+') · '+pc(t.usd/t.exp_td)+' of team-typical',cls(t.usd,t.exp_td,t.exp_td*.05))+
    tile('Team-typical by today',m0(t.exp_td),'sum of roster designers\' lead-adjusted expectations','neu')+
    tile('Projected month-end',m0(t.proj),'roster designers · '+(M.plan?'October goal (Sales Board) '+m0(M.plan.month_goal):'month goal '+m0(M.goal)),M.plan?cls(t.proj,M.plan.month_goal,M.plan.month_goal*.03):cls(t.proj,M.goal,M.goal*.03))+
    tile('Close rate YTD',pc(T.ytd.rate),'corporate basis · lead-appt '+pc(T.ytd.lead_rate),'neu')+
    tile('Open opps w/ dated future appointment',pc(T.notes.pct_next),T.notes.n+' open opps · '+m0(T.notes.usd),T.notes.pct_next<.5?'neg':'neu')+
    tile('Next-step compliance (team)',Math.round(T.notes.score),'0–100 · correct stage '+pc(T.notes.pct_stage)+' · fresh ≤14d '+pc(T.notes.pct_fresh),T.notes.score<50?'neg':'neu')+
    tile('Designer-created share (team, 90 days)',pc(T.dcl90.share),T.dcl90.dcl+' of '+T.dcl90.n+' sold deals · '+pc(T.dcl90.share_usd)+' of sold $ · target 20–30% · '+O.dcl_bands.below.length+' designers below 20%, '+O.dcl_bands.in.length+' in band, '+O.dcl_bands.above.length+' above','neu')+
    tile('$ at risk (heat map)',m0(t.at_risk),'expected $ most likely to slip without action','neu')+'</div>';
  h+='<div class="grid g2" style="margin-top:10px"><div class="card"><b>🏆 Leading the month</b>'+O.leaders.map(function(r){return '<div class="rk" data-s="'+r.slug+'"><div><div class="n">'+esc(r.name)+'</div><div class="x">'+r.sales+' sales · '+(r.att!=null?pc(r.att)+' of team-typical':'')+'</div></div><b class="pos">'+m0(r.usd)+'</b></div>'}).join('')+'</div>'+
    '<div class="card"><b>🤝 Who to help first</b> <span class="small">by $ at risk × next-step compliance</span>'+O.help.map(function(r){return '<div class="rk" data-s="'+r.slug+'"><div><div class="n">'+esc(r.name)+'</div><div class="x">notes '+Math.round(r.nscore||0)+' · '+pc(r.pct_next)+' dated · '+r.live_n+' live ('+mk(r.live_usd)+') · '+r.focus.map(function(k){return D.lib.skills[k].icon}).join(' ')+'</div></div><b>'+m0(r.at_risk)+'</b></div>'}).join('')+'</div></div>';
  var gp=t.personal,gg=M.goal,gap=gp-gg;
  if(!M.plan)h+='<div class="card"><b>Personal goals vs team goal</b><div class="kv"><span>Sum of personal goals (designers on leave have none)</span><b>'+m0(gp)+'</b></div><div class="kv"><span>Team month goal (Q4 '+m0(M.q4)+' × 31/92)</span><b>'+m0(gg)+'</b></div><div class="kv"><span>Gap</span><b class="'+(Math.abs(gap)<gg*.02?'neu':gap>0?'pos':'neg')+'">'+(gap>=0?'+':'−')+m0(Math.abs(gap)).replace('−','')+' ('+pc(gp/gg)+' of team goal)</b></div><p class="fine">'+(gap<0?'Personal goals add up to '+m0(-gap)+' LESS than the team goal: if everyone hits only their own goal, the team misses '+m0(gg)+' by about that much. Personal goals are not scaled to the team goal.':'Personal goals add up to '+m0(gap)+' MORE than the team goal. They are not scaled down.')+' Designers on the lead-based fallback are included at their lead share.</p></div>';
  h+=sec('roll',M.plan?'October target and lead-adjusted attainment by designer':'Personal goal and lead-adjusted attainment by designer',rollTable());
  return h}
function rollTable(){var O=D.owner,T=D.team;return '<div class="tw"><table><thead><tr><th>Designer</th><th>Sold MTD</th><th>Typical by today</th><th>Attained</th><th>Projected</th><th>Oct target</th><th>Gap</th><th>Personal goal</th><th>Lead-flow ×</th><th>Fair month</th><th>Lead share (old)</th><th>Goal check</th><th>Close MTD</th><th>Close 90d</th><th>Compliance</th><th>Dated appt</th><th>$ at risk</th><th>DCL % 90d</th><th>Focus</th></tr></thead><tbody>'+
  O.rows.map(function(r){return '<tr class="click" data-s="'+r.slug+'"><td>'+esc(r.name)+(r.low?' <span class="chip">low activity</span>':'')+'</td><td>'+m0(r.usd)+'</td><td>'+m0(r.exp_td)+'</td><td class="'+cls(r.att,1,.05)+'">'+pc(r.att)+'</td><td class="'+(r.primary!=null?cls(r.proj,r.primary,r.primary*.05):'neu')+'">'+m0(r.proj)+'</td><td><b>'+(r.target==null?'–':m0(r.target))+'</b></td><td class="'+(r.target==null?'neu':(r.target-r.usd<=0?'pos':(r.target_status||'neu')))+'">'+(r.target==null?'–':(r.target-r.usd>0?m0(r.target-r.usd):'hit'))+'</td><td>'+(r.personal==null?'no goal':m0(r.personal))+''+(r.basis==='lead'?' <span class="chip">lead-based</span>':'')+'</td><td>'+(r.basis==='history'?(r.lfac.toFixed(2)+(r.lapp?'':' <span class="chip">n/a</span>')):'–')+'</td><td>'+(r.basis==='none'?'–':m0(r.fair))+'</td><td>'+(r.goal_share==null?'–':m0(r.goal_share))+'</td><td>'+(r.gflag?'<span class="chip">'+(r.gflag==='above'?'+':'−')+Math.round(Math.abs(r.gdiff)*100)+'% vs fair</span>':(r.basis==='history'?'ok':'–'))+'</td>'+
    '<td class="'+(r.held>=8?cls(r.rate,T.mtd.rate,.03):'neu')+'">'+pc(r.rate)+'</td><td class="'+(r.held90>=20?cls(r.rate90,T.l90.rate,.03):'neu')+'">'+pc(r.rate90)+'</td><td class="'+(r.live_n>=3?cls(r.nscore,T.notes.score,5):'neu')+'">'+(r.nscore==null?'–':Math.round(r.nscore))+'</td><td class="'+(r.live_n>=3?cls(r.pct_next,T.notes.pct_next,.05):'neu')+'">'+pc(r.pct_next)+'</td><td>'+m0(r.at_risk)+'</td><td class="'+(r.dcl90.band==='below'?'neg':(r.dcl90.band?'pos':'neu'))+'">'+pc(r.dcl90.share)+' ('+r.dcl90.dcl+'/'+r.dcl90.n+')</td><td>'+r.focus.map(function(k){return D.lib.skills[k].icon}).join(' ')+'</td></tr>'}).join('')+'</tbody></table></div><p class="fine"><b>Oct target</b> = CEO Coach\'s goal-back plan (approved by Andrew): sold through Sun Oct 18 + remaining October quota; Gap = target − sold MTD (green = hit or at path, black = near / too early, red = behind path). Designers with no target had their quotes reassigned or are not in the plan; they have no goal (Projected stays neutral). <b>Personal goal</b> (owner diagnostic only, not shown to designers while the plan is active) = own trailing '+D.meta.cfg.HIST_MONTHS+'-month average × '+D.meta.cfg.HIST_STRETCH.toFixed(3)+' × lead-flow factor, clamped '+D.meta.cfg.LEAD_CLAMP[0].toFixed(2)+'–'+D.meta.cfg.LEAD_CLAMP[1].toFixed(2)+' (n/a = factor skipped) (lead-based when under '+D.meta.cfg.HIST_MIN_MONTHS+' months). Goal check flags a difference over '+Math.round(D.meta.cfg.FAIR_FLAG*100)+'% from the lead-adjusted fair month. Projected is colored against the October target. Attained = sold ÷ team-typical by today. Green/red ±5%. Corporate close rate can exceed 100% when sales without a logged appointment (designer-created, Costco, repeat) land in the period. Focus icons: '+Object.keys(D.lib.skills).map(function(k){return D.lib.skills[k].icon+' '+esc(D.lib.skills[k].name)}).join(' · ')+'.</p>'}
function people(){return '<div class="card"><b>Open a designer page</b><p class="small">This is exactly what each designer sees with their own code (minus the copy button).</p>'+D.owner.rows.map(function(r){return '<div class="rk" data-s="'+r.slug+'"><div><div class="n">'+esc(r.name)+(r.low?' <span class="chip">low activity</span>':'')+'</div><div class="x">'+m0(r.usd)+' sold · compliance '+(r.nscore==null?'–':Math.round(r.nscore))+' · '+r.focus.map(function(k){return D.lib.skills[k].icon+' '+D.lib.skills[k].name}).join(', ')+'</div></div><span>›</span></div>'}).join('')+'</div>'}
function topics(){var O=D.owner,mx=Math.max.apply(null,O.topics.map(function(t){return t.n}));return '<div class="card"><b>Common team shortfalls → training topics</b><p class="small">How often each skill is a top-3 focus area (active designers), and the monthly $ involved.</p>'+O.topics.map(function(t,i){var S=D.lib.skills[t.skill];return '<div class="topic"><div style="display:flex;justify-content:space-between;gap:8px"><b>'+(i+1)+'. '+S.icon+' '+esc(t.name)+'</b><span>'+t.n+' designers · ~'+mk(t.usd)+'/mo</span></div><div class="tb"><i style="width:'+(t.n/mx*100)+'%"></i></div><div class="small">'+t.who.map(esc).join(', ')+'</div></div>'}).join('')+'</div>'+
  '<div class="card"><b>Suggested workshop sequence</b><ol class="small">'+O.topics.slice(0,4).map(function(t){var r=((D.lib.videos||{})[t.skill]||D.lib.resources[t.skill]||[])[0];return '<li><b>'+esc(t.name)+'</b>: '+esc(D.lib.skills[t.skill].good[0])+(r?' Watch/read together: <a target="_blank" rel="noopener" href="'+esc(r.url)+'">'+esc(r.title)+'</a> ('+esc(r.length)+').':'')+'</li>'}).join('')+'</ol></div>'}
function queue(){return '<div class="card"><b>Teams message queue</b> <span class="draft">Drafts only, not sent</span><p class="small">Microsoft Teams is not connected. Review, edit, and send yourself, or approve later when Teams delivery is set up.</p></div>'+D.owner.queue.map(function(q,i){return '<div class="card"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b><a href="#d/'+q.slug+'">'+esc(q.name)+'</a></b><span class="small">'+q.words+' words · <span class="draft">'+esc(q.status)+'</span></span></div><div class="msg" style="margin-top:8px">'+esc(q.text)+'</div><button class="btn ghost" style="margin-top:8px" data-q="'+i+'">Copy</button></div>'}).join('')}
function library(){var nv=0,seen={};Object.keys(D.lib.videos||{}).forEach(function(k){D.lib.videos[k].forEach(function(v){if(!seen[v.vid]){seen[v.vid]=1;nv++}})});return '<div class="card"><b>Video library</b><p class="small">'+nv+' YouTube videos, re-matched on Oct 19, 2026 so each one is about exactly its focus area (1-2 per focus area, mostly 1-4 minutes). Each was checked on its YouTube page (title, channel, length, description) and with YouTube oEmbed. Two longer ones are kept on purpose and marked. Instagram reels are not included: none could be verified publicly (Instagram requires login). Full mapping and evidence: VIDEO_MAP.md in the coach tool folder.</p><p class="small">Articles were checked on Oct 17, 2026 (HTTP 200 and matching title); one site blocks automated checks and is labeled. CFNJ internal resources are marked.</p></div>'+librarySkills()}
function how(){var c=D.meta.cfg,w=c.NOTE_W;var PL=D.meta.plan;return (PL?'<div class="card" style="border-left:5px solid #b26b00"><b>October target (goal-back plan)</b><ul class="tight small"><li>For October 2026 everyone tracks to the same number: CEO Coach\'s goal-back plan, approved by Andrew. The team October goal is '+m0(PL.month_goal!=null?PL.month_goal:D.meta.goal)+' (Sales Board).</li><li><b>Your October target</b> = what you sold through Sun Oct 18 (the baseline: team '+m0(PL.baseline.sold)+') + your remaining October quota from the plan.</li><li><b>On path now</b> follows the plan\'s daily targets, not a straight line: '+PL.checkpoints.map(function(c){return esc(c.label)+' '+m0(c.cum_month)}).join(' · ')+'. Today\'s target builds up from 9 AM to 9 PM ET.</li><li>Green = at or above the path. Black = close (within 10% of the plan since Oct 18) or too early to judge (less than $2,500 of plan so far). Red = behind.</li><li>The Coach reads these targets from the Sales Board\'s plan (same file and code), so the two always match; the team total equals the board\'s October goal'+(PL.month_goal!=null?' ('+m0(PL.month_goal)+')':'')+'. Designers without a board target show no goal. Personal goals are not shown on designer pages while the plan is active. From November, goals go back to personal goals unless a new plan is loaded.</li></ul></div>':'')+'<div class="card"><b>How the personal goal works'+(PL?' (not used while the goal-back plan is active)':'')+'</b><ul class="tight small"><li><b>Personal goal</b> = your average monthly sold $ over the last '+c.HIST_MONTHS+' completed months (Sold Final + Sold Designer pending Final, by sale date; fewer months if you are newer, tenure starts the first full month after your first sale or held appointment) × '+c.HIST_STRETCH.toFixed(3)+' (a 7.5% stretch) × a lead-flow factor. Under '+c.HIST_MIN_MONTHS+' months of history the lead-based goal share is used and marked.</li><li><b>Lead-flow factor</b> = your held first appointments per 30 days over the last 60 days ÷ your own average per 30 days over the same history window, kept between '+c.LEAD_CLAMP[0].toFixed(2)+' and '+c.LEAD_CLAMP[1].toFixed(2)+' so one slow or busy stretch cannot swing the goal. It is skipped (1.00, marked n/a) when lead history is thin (under '+c.LEAD_MIN_APPTS+' held first appointments in the window) or when more than '+Math.round(c.LEAD_NOAPPT_MAX*100)+'% of your sales have no appointment record, because then appointment counts do not describe your pipeline.</li><li><b>Projected month-end (non-linear)</b>: sales are back-loaded, so we never draw a straight line. <b>On pace today</b> = personal goal × the typical share of a month already sold by today ('+pc(D.meta.typ_share)+' on day '+D.meta.day+'; the median cumulative sold-by-day curve of completed 2026 months, Sold Final + Sold Designer by date). The <b>projection</b> blends two views: (1) <i>the curve</i>: what you have sold ÷ that typical share; (2) <i>your typical month</i>: what you have sold plus your normal month × the share still to come. The curve gets more weight as the month goes on (weight = √share) and less when you have sold very little so far, so one early sale cannot explode the number and a zero does not project to zero. The projection is never lower than sold + expected closes from open quotes and booked appointments. The owner panel compares the team total with the Sales Board true-pace base and flags a gap over '+Math.round(c.PROJ_DIFF_FLAG*100)+'%. The team month goal itself is still a straight-line slice of the Q4 goal (31/92 days).</li><li><b>Fairness check</b> = the lead-adjusted fair month below. When your personal goal and the fair month differ by more than '+Math.round(c.FAIR_FLAG*100)+'% a flag shows: above = your own results beat what the leads alone predict; below = your leads would support more than your recent average.</li><li><b>Team total</b>: personal goals are not scaled. The owner view shows their sum next to the team month goal and the gap.</li><li>No goal is shown for designers on leave or inactive.</li></ul><b>Lead-adjusted fair month (fairness check)</b><ul class="tight small"><li><b>Lead flow</b> = first appointments held (not cancelled/no-show) in the last 60 days, per 30 days. The office sets appointments, so this is what each designer was given to work with.</li><li><b>Fair month</b> = lead flow × team $ sold per held first appointment over the last 90 days (excluding designer-created sales, '+m0(D.team.team_rate_usd)+') ÷ 0.75 so designer-created sales are the 25% midpoint of Andrew\'s 20–30% standard (no double counting: the team rate excludes designer-created sales).</li><li><b>Team-typical by today</b> = fair month × share of the month typical completed months had sold by day '+D.meta.day+' ('+pc(D.meta.typ_share)+'), so the back-loaded month shape is respected.</li><li><b>Lead-based goal share (reference, and the fallback for new designers)</b> = team month goal '+m0(D.meta.goal)+' (Q4 '+m0(D.meta.q4)+' × 31/92, straight line) split by each designer\'s share of the fair-month total.</li><li><b>Projected</b> = sold + expected closes from open quotes (close odds by age since appointment) + booked appointments through month end (Sales Board method).</li></ul></div>'+
 '<div class="card"><b>How Next-step compliance works (0–100)</b><ul class="tight small"><li>Scored on open opps: a working stage, amount > $0, first appointment within '+c.LIVE_DAYS+' days. Each opp gets up to 100; your score is the average.</li><li><b>'+w.next+' pts · dated next appointment in the note.</b> Date, place and time all written = '+w.next+'; a date without place or time = '+c.NEXT_PART+'; no date = 0. Best format: <i>'+esc(D.meta.note_template)+'</i></li><li><b>'+w.future+' pts · not overdue.</b> The appointment date is today or later.</li><li><b>'+w.stage+' pts · right stage.</b> Firm appointment → Current (or Future Sale). No appointment → an Aging bucket (Second 1-7, Last 8-14, Aging 14+) or Manager Review. Note says signed → Designer Sold. A no → Lost Sale or Manager Review.</li><li><b>'+w.fresh+' pts · fresh note.</b> Last dated update within '+c.FRESH_DAYS+' days ('+Math.round(w.fresh*.4)+' if within 30).</li><li>Keyword and date rules run privately; note text never leaves the data refresh. The old keyword items (decision-maker, concern, financing) are no longer scored.</li></ul></div>'+
 '<div class="card"><b>Focus-area rules</b><ul class="tight small"><li>Dated future appointment on under 50% of open opps → Next-step rule.</li><li>2+ open opps, $15K+, no update 14+ days → Aging: win the next appointment.</li><li>Close rate on first appts 30–120 days ago ≥3 pts under team (20+ appts) → Closing.</li><li>Average sale under 85% of team (10+ sales YTD) → Add-ons & whole-home design.</li><li>Designer-created share of sold deals (90 days, 8+ sales) under 20% → DCL.</li><li>2+ live quotes with price/budget in the note but no financing → Financing (Enhancify).</li><li>2+ live quotes waiting on a spouse/partner with no dated step, or return-visit logging 10+ pts under team → Multi-stakeholder.</li><li>Median first-appt-to-sale 7+ days slower than team → Urgency. 3+ deals in one stage 45+ days → Closing. $ per first appt under 80% of team → Discovery.</li><li>Ranked by monthly $ involved; top 3 kept, one per skill.</li></ul></div>'+
 '<div class="card"><b>Designer-created lead (DCL) standard</b><ul class="tight small"><li><b>Standard: 20–30% of each designer\'s sold deals should be designer-created.</b> Andrew\'s standard, Oct 17, 2026.</li><li><b>Measure of record</b> = designer-created sold deals ÷ all sold deals (Sold Final + Sold Designer pending Final), by count, over the trailing 90 days. Month-to-date and share of sold $ are shown for context (a designer-created sale can be bigger or smaller than average, so $ share can differ).</li><li><b>Colors</b>: green at 20% or above (in band or above), red below 20%, black when fewer than '+D.meta.cfg.DCL_MIN_DEALS+' sold deals in the window.</li><li><b>Fair month</b> uses the 25% midpoint: assigned-lead production ÷ 0.75.</li></ul></div>'+
 '<div class="card"><b>Activity tracker</b><ul class="tight small"><li>On each designer page (section "My activity"). Voice uses the browser\'s speech recognition where available (Chrome, Edge, Safari on iPhone); otherwise the mic button hides and the text box (with the phone keyboard\'s own mic) is used.</li><li>The note is read into counts (calls, texts/emails, follow-ups, appointments held, quotes/proposals/contracts sent (not yet signed), showroom visits, referral asks / own leads, closes (signed sales only)); the designer checks and edits the counts before saving. The raw note is kept with the entry.</li><li>Weekly targets: touches = 2 per open quote (playbook: recap same day, check in at 24-72 hours, call at day 7, decision by day 14); appointments = own held first appointments per 30 days (last 60) × 7/30; referral asks = own sales in the last 90 days ÷ 13 weeks. Streak skips Sundays.</li><li><b>Storage and sync:</b> each entry is saved in the designer\'s browser (localStorage, per designer) and, on Save, also submitted to Andrew\'s Google Form (Designer, Date, Counts, Note), which feeds the '+(D.meta.activity_sheet?'<a href="'+esc(D.meta.activity_sheet)+'" target="_blank" rel="noopener noreferrer">Activity log (Google Sheet)</a>':'activity log Google Sheet')+'. Each entry shows sent or pending; pending entries retry on the next page load and when the phone comes back online. Entries logged in the owner preview are tagged "(owner preview)". No sign-in or token in the page (form ids are public).</li><li><b>Deletes do not propagate:</b> deleting an entry removes it only from that device; the row stays in the Sheet (delete it there if needed).</li></ul></div>'+'<div class="card"><b>Data limits</b><ul class="tight small"><li>Discounting is not tracked in ClosetWare (no discount field), so it is not scored.</li><li>Next-step compliance reads dates, places and times in the note by rule, not meaning; a note outside the one-line format can be missed. Signed-but-not-moved is detected only when the note says so.</li><li>Return visits only count when logged as appointments.</li><li>Small samples (few appointments this month) are shown in black, not judged.</li><li>Pending (Sold Designer) counts as sold, dated by designer-sold date.</li></ul></div>'}
function wireOwner(){document.querySelectorAll('[data-gs]').forEach(function(b){b.onclick=function(){GP_SORT=b.dataset.gs;var e=$('#gp');if(e){e.innerHTML=goalPanel();wireOwner()}}});document.querySelectorAll('[data-s]').forEach(function(e){e.onclick=function(){location.hash='d/'+e.dataset.s}});document.querySelectorAll('[data-q]').forEach(function(b){b.onclick=function(){copy(D.owner.queue[+b.dataset.q].text)}})}
/* ── activity tracker (UI; parser + storage in activity.js). Entries stay in this browser (localStorage), keyed per designer. ── */
var ACT_DRAFT=null,ACT_REC=null,ACT_CUR=null;
function actWho(x){return D.kind==='owner'?x.name+' (owner preview)':(x.act_who||x.name)}   /* test page: act_who='Test Designer' (coach.py TEST_NAME) */
window.ACT_ONSYNC=function(sl){if(D&&ACT_CUR&&ACT_CUR.slug===sl&&$('#actTotals'))actRender(ACT_CUR)};
function actSection(x){var tg=x.activity_target||{};
  var h='<div class="card actin">'+(D.kind==='owner'?'<div class="ownnote small"><b>Owner preview.</b> Anything you log here is saved on <b>this</b> device under '+esc(x.first)+'\'s page and sent to the log tagged "(owner preview)". Designers\' own entries are sent to you automatically when they save.'+(D.meta.activity_sheet?' <a href="'+esc(D.meta.activity_sheet)+'" target="_blank" rel="noopener noreferrer">Activity log (Google Sheet)</a>':'')+'</div>':'')+
   '<p class="small" style="margin:0 0 10px">Log what you did, by voice or typing. It takes about 20 seconds and shows you your real week: today, this week and this month.</p>'+
   '<div class="micwrap"><button type="button" id="actMic" class="mic" aria-label="Tap and speak">🎤</button><div><b id="actMicL">Tap the mic and say what you did</b><div class="small" id="actMicS">For example: "called 5 clients, sent 3 follow-up texts, 1 showroom visit, 2 in-home appointments, 1 quote sent"</div></div></div>'+
   '<textarea id="actTxt" rows="3" placeholder="Or type here (your keyboard\'s 🎤 works too): called 5 clients, sent 3 follow-up texts, 2 in-home appointments, 1 quote sent"></textarea>'+
   '<div class="actrow"><select id="actDay" aria-label="Which day"><option value="0">Today</option><option value="1">Yesterday</option><option value="2">2 days ago</option></select><button type="button" class="btn" id="actRead">Save my note →</button></div>'+
   '<div id="actConfirm" class="hidden"></div>'+(D.meta.activity_form?'<p class="fine actsync" style="margin:10px 0 0">Your entries are also sent to Andrew automatically. Deleting an entry here removes it from this device only, not from Andrew\'s copy.<span id="actPend"></span></p>':'')+'</div><div id="actTotals"></div>';
  return sec('activity','📋 My activity',h)}
function actTargetText(tg){var p=[];
  p.push(tg.touches?'<b>'+tg.touches+' touches a week</b> (calls + texts/emails + follow-ups) = '+tg.per_quote+' per open quote × your '+tg.open_quotes+' open quote'+(tg.open_quotes===1?'':'s')+'. That is the playbook\'s follow-up rhythm: recap the same day, check in within 24-72 hours, call on day 7, decision date by day 14 (4 touches in 2 weeks).':'No touch target right now: you have no open quotes in the last 90 days. Every new quote adds 2 touches a week.');
  p.push(tg.appts?'<b>About '+tg.appts+' appointment'+(tg.appts===1?'':'s')+' a week</b>: your own pace over the last 60 days ('+tg.appts_basis+' held first appointments per 30 days). The office books these, so this is a pace check, not a quota.':'No appointment target: your recent pace is under 1 held first appointment a week ('+(tg.appts_basis||0)+' per 30 days over the last 60 days).');
  p.push(tg.asks?'<b>About '+tg.asks+' referral ask'+(tg.asks===1?'':'s')+' a week</b>: one for each sale at your recent pace ('+tg.sales90+' sales in the last 90 days). The playbook: ask every happy client.':'No referral-ask target yet: no sales in the last 90 days. Ask every happy client you meet.');
  return p}
function actBar(lbl,v,t,cap){var pct=t?Math.min(100,v/t*100):0;return '<div class="abar"><div class="abh"><span>'+lbl+'</span><b>'+v+(t?' <span class="small">of '+t+'</span>':'')+'</b></div>'+(t?'<div class="abt"><i style="width:'+pct.toFixed(1)+'%" class="'+(v>=t?'ok':'')+'"></i></div>':'')+'<div class="small">'+cap+'</div></div>'}
function actCap(v,t,left,unit){if(!t)return'Logged this week. No target set for this one.';if(v>=t)return'Target reached this week. Nice work!';var need=t-v,per=Math.ceil(need/left);
  if(need<=left)return v===0?'Nothing logged yet this week. The target is '+t+' this week.':need+' more to reach this week\'s target.';
  return v===0?'Nothing logged yet this week. About '+per+' '+unit+' a day gets you there.':need+' more to reach the target: about '+per+' a day for the '+(left===1?'rest of today':'next '+left+' days')+'.'}
/* ── Sheet history (Andrew, Oct 21, 2026): the Activity Sheet is the source of truth. Each bundle carries the designer's own Sheet rows
   (x.activity.rows: k = dedupe key, d, c, n, t). Shown = Sheet rows + local entries not yet in the Sheet. Key = SHA-256 of
   who|date|counts|note (who = Designer field, lowercase; counts = the form's 8-key string; note NFC + whitespace collapsed), first 16 hex,
   the same as coach activity_rows.key(); the Sheet timestamp is not part of it. A local entry found in the bundle is moved out of the
   counted log into an archive key (used only if a bundle ever arrives without Sheet history), so nothing double counts or resets. */
var ACT_ARCH='cfnj_activity_arch_v1_';
function actNote(n){var s=String(n||'');try{s=s.normalize('NFC')}catch(e){}return s.replace(/\s+/g,' ').trim()}
async function actKey(who,e){var s=String(who||'').toLowerCase().replace(/\s+/g,' ').trim()+'|'+e.d+'|'+ACT.countsStr(e.c)+'|'+actNote(e.note);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).slice(0,16)}
function actArch(slug){try{var a=JSON.parse(localStorage.getItem(ACT_ARCH+slug)||'[]');return Array.isArray(a)?a:[]}catch(e){return[]}}
function actBag(x){var b={};((x.activity&&x.activity.rows)||[]).forEach(function(r){b[r.k]=(b[r.k]||0)+1});return b}
/* Give every local entry its key, then retire the ones already in this bundle's Sheet rows (sent entries only; pending ones are not in the Sheet yet). */
async function actReconcile(x){var es=ACT.load(x.slug),ch=false;
  for(var i=0;i<es.length;i++){if(!es[i].k){try{es[i].k=await actKey(es[i].w||actWho(x),es[i]);ch=true}catch(e){}}}
  if(x.activity){var bag=actBag(x),keep=[],gone=[];es.forEach(function(e){if(e.k&&e.s!=='pending'&&bag[e.k]>0){bag[e.k]--;gone.push(e)}else keep.push(e)});
    if(gone.length){var ar=actArch(x.slug).concat(gone).slice(-500);try{localStorage.setItem(ACT_ARCH+x.slug,JSON.stringify(ar))}catch(e){}es=keep;ch=true}}
  if(ch)ACT.save(x.slug,es);return ch}
/* Everything to count and list: Sheet rows + local entries not matched to a Sheet row (no Sheet history in the bundle: local + archive). */
function actAll(x){var es=ACT.load(x.slug);if(!x.activity)return es.concat(actArch(x.slug).map(function(e){return Object.assign({},e,{s:'sent',arch:1})}));
  var bag=actBag(x),loc=es.filter(function(e){if(e.k&&e.s!=='pending'&&bag[e.k]>0){bag[e.k]--;return false}return true});
  return x.activity.rows.map(function(r,i){return{id:'sheet-'+r.k+'-'+i,d:r.d,t:r.t||0,c:r.c||{},note:r.n||'',s:'sheet',p:r.p,x:r.x,oc:r.oc}}).concat(loc)}
function actRender(x){ACT_CUR=x;var F=D.meta.activity_form,es=actAll(x),np=ACT.pending(es),pe=$('#actPend');if(pe)pe.textContent=np?' '+np+' entr'+(np===1?'y is':'ies are')+' waiting to send; they go automatically when you are online.':'';var s=ACT.stats(es),tg=x.activity_target||{},w=s.week,C=ACT.CATS,left=s.workLeft;
  var nl=es.filter(function(e){return e.s!=='sheet'&&!e.arch}).length;
  var tw=ACT.touches(w),h=(x.activity?'<p class="fine actsynced" style="margin:0 0 8px">Synced from all your devices · updated '+esc(x.activity.asof)+(nl?' · '+nl+' newer entr'+(nl===1?'y':'ies')+' from this device included':'')+'</p>':'')+'<div class="card"><b>This week</b> <span class="small">(since Monday '+esc(s.weekStart.slice(5).replace('-','/'))+')</span>'+
   actBar('📞💬🔁 Touches',tw,tg.touches,actCap(tw,tg.touches,left,'touches'))+actBar('🏠 Appointments held',w.appts,tg.appts||0,actCap(w.appts,tg.appts||0,left,'appointments'))+
   actBar('🌱 Referral asks / own leads',w.leads,tg.asks||0,actCap(w.leads,tg.asks||0,left,'asks'))+
   '<div class="achips"><span class="chip">'+s.daysWeek+' of 6 days logged this week</span><span class="chip">'+s.daysMonth+' days logged this month</span><span class="chip '+(s.streak>=3?'g':'')+'">🔥 '+s.streak+'-day streak</span></div></div>';
  var tot=function(t){return C.reduce(function(a,c){return a+t[c.k]},0)};
  h+='<div class="card"><div class="tw"><table class="atab"><thead><tr><th>Activity</th><th>Today</th><th>Week</th><th>Month</th></tr></thead><tbody>'+C.map(function(c){return '<tr><td>'+c.i+' '+esc(c.l)+'</td><td>'+s.today[c.k]+'</td><td>'+w[c.k]+'</td><td>'+s.month[c.k]+'</td></tr>'}).join('')+
   '<tr class="atot"><td><b>All activity</b></td><td><b>'+tot(s.today)+'</b></td><td><b>'+tot(w)+'</b></td><td><b>'+tot(s.month)+'</b></td></tr></tbody></table></div>'+
   '<p class="small" style="margin:8px 0 0">'+(tot(s.month)?'This is your own count of the work behind your sales. Busy weeks and quiet weeks both show up here, so you can see the pattern for yourself.':'Nothing logged this month yet. Log today and watch your week build up.')+'</p>'+
   '<div class="actrow"><button type="button" class="btn" id="actShare">Export / share my week</button>'+'</div></div>';
  var rec=es.slice().sort(function(a,b){return b.t-a.t}).slice(0,10);
  h+='<details><summary>Recent entries ('+es.length+')</summary>'+(rec.length?rec.map(function(e){return '<div class="aent"><div><b>'+esc(e.d.slice(5).replace('-','/'))+'</b> · '+C.filter(function(c){return e.c[c.k]}).map(function(c){return c.i+' '+e.c[c.k]}).join(' ')+(e.s==='sheet'?' <span class="chip g" title="In Andrew\'s activity log; shows on all your devices">✓ synced</span>'+(e.p?' <span class="chip">owner preview</span>':'')+(e.x?' <span class="chip warn" title="Counts corrected by Andrew (old parser misread a date, time, $ amount or pasted message). Was: '+esc(C.filter(function(c){return e.oc&&e.oc[c.k]}).map(function(c){return c.l+' '+e.oc[c.k]}).join(', '))+'">corrected</span>':''):e.s==='sent'?' <span class="chip g" title="Sent to Andrew">✓ sent</span>':e.s==='pending'?' <span class="chip" title="Will send when online">⏳ pending</span>':e.s==='hold'?' <span class="chip" title="Sends in a few seconds (Undo window)">⏳ sending…</span>':'')+(e.note?'<div class="small">'+esc(e.note)+'</div>':'')+'</div>'+(e.s==='sheet'||e.arch?'':'<button type="button" class="adel" data-id="'+esc(e.id)+'" aria-label="Delete entry">✕</button>')+'</div>'}).join(''):'<p class="small">No entries yet.</p>')+'</details>';
  h+='<div class="card"><b class="small">Suggested weekly targets (from the CFNJ playbook and your own numbers)</b><ul class="tight small">'+actTargetText(tg).map(function(t){return '<li>'+t+'</li>'}).join('')+'</ul>'+
   '<p class="fine" style="margin:6px 0 0"><b>Where this is saved:</b> '+(x.activity?'each entry is saved on this device right away and sent to Andrew\'s activity log. That log is your running total: it shows on every device you use, refreshed through the day, so switching phones or computers keeps your history.':'in this browser on this device'+(F?', and each entry is also sent to Andrew':'')+'. Clearing browser data, private browsing, or switching phones starts a fresh log here.')+'</p></div>';
  $('#actTotals').innerHTML=h;
  document.querySelectorAll('.adel').forEach(function(b){b.onclick=function(){if(!confirm(D.meta.activity_form?'Delete this entry from this device? Andrew\'s copy is not changed.':'Delete this entry?'))return;ACT.save(x.slug,ACT.load(x.slug).filter(function(e){return String(e.id)!==b.dataset.id}));actRender(x);toast('Deleted')}});
  $('#actShare').onclick=function(){var t=ACT.summary(x.name,actAll(x),tg);
    if(navigator.share){navigator.share({title:'My week (CFNJ)',text:t}).catch(function(){})}else if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){toast('Copied: paste it into a text or email')},function(){actShow(t)})}else actShow(t)};
}
function actOwnerCard(){var A=D.activity_all;if(!A)return'';var mo=ACT.ymd(new Date()).slice(0,8),g={};
  A.rows.forEach(function(r){var w=r.who||'(blank)';var o=g[w]||(g[w]={n:0,last:'',mo:0});o.n++;if(r.d>o.last)o.last=r.d;if(r.d.slice(0,8)===mo)o.mo+=Object.keys(r.c||{}).reduce(function(a,k){return a+(+r.c[k]||0)},0)});
  var ks=Object.keys(g).sort(function(a,b){return g[b].n-g[a].n||a.localeCompare(b)});
  return '<div class="card"><b>📋 Activity log (all devices)</b> <span class="small">· updated '+esc(A.asof)+' · '+A.rows.length+' entries</span>'+(ks.length?'<div class="tw"><table class="atab"><thead><tr><th>Designer field</th><th>Entries</th><th>Last date</th><th>This month (all counts)</th></tr></thead><tbody>'+
    ks.map(function(k){return '<tr><td>'+esc(k)+'</td><td>'+g[k].n+'</td><td>'+esc(g[k].last)+'</td><td>'+g[k].mo+'</td></tr>'}).join('')+'</tbody></table></div>':'<p class="small">No entries yet.</p>')+
    '<p class="fine" style="margin:6px 0 0">Each designer page shows only that designer\'s own rows. "(owner preview)" and test rows never count toward a real designer.</p></div>'}
function actShow(t){var c=$('#actConfirm');c.classList.remove('hidden');c.innerHTML='<p class="small">Select and copy this, then paste it into a text or email:</p><textarea rows="8" readonly>'+esc(t)+'</textarea>'}
function actConfirm(x,res,note){var C=ACT.CATS,c=$('#actConfirm');ACT_DRAFT={c:res.counts,note:note};c.classList.remove('hidden');
  var found=res.hits.length?'We read: '+res.hits.map(function(h){var cc=C.filter(function(k){return k.k===h.cat})[0];return cc.l+' '+h.n}).join(' · ')+'.':'We couldn\'t find any numbers in that note. Enter the counts below.';
  var big=(res.big||[]).map(function(b){return C.filter(function(k){return k.k===b})[0].l+' '+res.counts[b]});
  c.innerHTML=(big.length?'<div class="small warnbox" role="alert" style="margin:10px 0 6px"><b>⚠️ That is a lot for one entry: '+esc(big.join(', '))+'.</b> Is that right? Dates, times and $ amounts are not counts. Fix the number below if needed, then save.</div>':'')+'<div class="small" style="margin:10px 0 6px"><b>Check the counts, fix anything, then save.</b> '+esc(found)+'</div><div class="steps">'+C.map(function(k){return '<div class="step"><span>'+k.i+' '+esc(k.l)+'</span><div class="sp"><button type="button" data-k="'+k.k+'" data-d="-1" aria-label="minus">−</button><input inputmode="numeric" pattern="[0-9]*" data-k="'+k.k+'" value="'+(res.counts[k.k]||0)+'"><button type="button" data-k="'+k.k+'" data-d="1" aria-label="plus">+</button></div></div>'}).join('')+'</div>'+
   '<div class="actrow"><button type="button" class="btn" id="actSave">Save</button><button type="button" class="btn ghost" id="actCancel">Cancel</button></div>';
  c.querySelectorAll('.sp button').forEach(function(b){b.onclick=function(){var i=c.querySelector('input[data-k="'+b.dataset.k+'"]');i.value=Math.max(0,(parseInt(i.value,10)||0)+(+b.dataset.d))}});
  $('#actCancel').onclick=function(){c.classList.add('hidden');c.innerHTML='';var tb=$('#actTxt');if(tb&&!tb.value&&note)tb.value=note};
  $('#actSave').onclick=function(){var cnt={},any=0;c.querySelectorAll('input[data-k]').forEach(function(i){var v=Math.max(0,Math.min(999,parseInt(i.value,10)||0));if(v){cnt[i.dataset.k]=v;any+=v}});
    if(!any){toast('Add at least one count');return}
    var over=C.filter(function(k){return cnt[k.k]>ACT.CAP}).map(function(k){return k.l+' '+cnt[k.k]});if(over.length&&!window.confirm('Save '+over.join(', ')+' for this one entry? That is more than '+ACT.CAP+'.'))return;
    actCommit(x,cnt,note,'Saved')}}
/* One-tap save (Andrew Oct 21): used by the Save my note button and the manual Save above. */
function actCommit(x,cnt,note,msg){var c=$('#actConfirm');var d=new Date();d.setDate(d.getDate()-(+$('#actDay').value||0));
    var F=D.meta.activity_form,es=ACT.load(x.slug),ne={id:Date.now()+'-'+Math.random().toString(36).slice(2,7),d:ACT.ymd(d),t:Date.now(),c:cnt,note:(note||'').slice(0,500)};if(F){ne.s='pending';ne.w=actWho(x)}es.push(ne);
    actKey(ne.w||actWho(x),ne).then(function(k){var a=ACT.load(x.slug);a.forEach(function(z){if(z.id===ne.id)z.k=k});ACT.save(x.slug,a)},function(){});
    if(!ACT.save(x.slug,es)){toast('Could not save on this device (storage is off or full)');return}
    c.classList.add('hidden');c.innerHTML='';$('#actTxt').value='';actRender(x);toast(msg||'Saved');
    if(F)ACT.sync(x.slug,F,function(ch){if(ch){toast((msg||'Saved')+' and sent to Andrew');window.ACT_ONSYNC(x.slug)}else if(ACT.pending(ACT.load(x.slug)))toast((msg||'Saved')+'. It will send when you are online')})}
function actWire(x){if(!$('#actTotals'))return;actRender(x);actReconcile(x).then(function(ch){if(ch&&ACT_CUR===x)actRender(x)},function(){});var txt=$('#actTxt'),mic=$('#actMic'),L=$('#actMicL'),S=$('#actMicS');
  $('#actRead').onclick=function(){var t=txt.value.trim();if(rec){try{rec.onresult=null;rec.stop()}catch(e){}}if(!t){toast('Say or type what you did first');return}var r=ACT.parse(t),C=ACT.CATS,cnt={},any=0;C.forEach(function(k){var v=Math.min(999,+r.counts[k.k]||0);if(v>0){cnt[k.k]=v;any+=v}});if(!any||(r.big&&r.big.length)){actConfirm(x,r,t);txt.value='';txt.blur();return}  /* over ACT.CAP in one category: confirm first (Oct 22, 2026) */var lbl=C.filter(function(k){return cnt[k.k]}).map(function(k){return k.l+' '+cnt[k.k]}).join(', ');txt.blur();actCommit(x,cnt,t,'Logged: '+lbl)};  /* Andrew Oct 21: clear the box once read; Cancel puts the note back */
  if(!ACT.speechOK()){mic.classList.add('hidden');L.textContent='Voice button not available in this browser';S.innerHTML='No problem: tap the box below and use the 🎤 on your phone\'s keyboard to dictate, or just type.';return}
  var R=window.SpeechRecognition||window.webkitSpeechRecognition,rec=null,base='';
  mic.onclick=function(){if(rec){try{rec.stop()}catch(e){}return}
    try{rec=new R()}catch(e){mic.classList.add('hidden');L.textContent='Voice is not available here';S.textContent='Type in the box below, or use your keyboard\'s 🎤.';return}
    rec.lang='en-US';rec.interimResults=true;rec.continuous=false;rec.maxAlternatives=1;base=txt.value.trim();
    rec.onstart=function(){mic.classList.add('on');L.textContent='Listening… tap again to stop';S.textContent='Say what you did today.'};
    rec.onresult=function(ev){var f='',it='';for(var i=0;i<ev.results.length;i++){if(ev.results[i].isFinal)f+=ev.results[i][0].transcript;else it+=ev.results[i][0].transcript}txt.value=(base?base+', ':'')+(f+it).trim()};
    rec.onerror=function(ev){var m={'not-allowed':'Microphone access is off for this site. You can type, or use your keyboard\'s 🎤.','service-not-allowed':'Voice is blocked here. You can type, or use your keyboard\'s 🎤.','no-speech':'Didn\'t catch that. Tap the mic and try again.','network':'Voice needs an internet connection. You can type instead.','audio-capture':'No microphone found. You can type instead.'}[ev.error];S.textContent=m||'Voice stopped. You can type instead.'};
    rec.onend=function(){mic.classList.remove('on');rec=null;L.textContent='Tap the mic and say what you did';var t=txt.value.trim();if(t&&t!==base)S.textContent='Got it. Tap Save my note to log it.'};
    try{rec.start()}catch(e){rec=null;S.textContent='Voice could not start. You can type instead.'}}}
/* ── OWNER-ONLY activity dashboard (Andrew, Oct 21, 2026). Data: D.act_dash (owner bundle only; built in coach.py from the Activity Sheet
   cache: approved live designers, counts + dates, NO note text; test / owner-preview rows excluded). Called only from team(), so designer
   pages never render it. Inline SVG, no chart library. Colors: one per activity type (no red, no amber); amber = missing; neutral = facts. ── */
var AD={p:'month',who:-1};
var AD_COL={calls:'#2f6fdd',texts:'#12a4a4',followups:'#7b5cd6',appts:'#12263f',quotes:'#8d6e63',showroom:'#b05fb5',leads:'#8a94a6',closes:'#0d7a45'};
var AD_P=[['week','This week'],['l7','Last 7 days'],['month','This month'],['all','All time']];
function adYmd(d){return ACT.ymd(d)}
function adShift(s,n){var p=s.split('-'),d=new Date(+p[0],+p[1]-1,+p[2]);d.setDate(d.getDate()+n);return adYmd(d)}
function adFmt(s){if(!s)return'–';var p=s.split('-');return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][+p[1]-1]+' '+(+p[2])}
function adRange(){var A=D.act_dash,t=adYmd(new Date()),n=new Date(),a;
  if(AD.p==='month')a=t.slice(0,8)+'01';
  else if(AD.p==='week'){var wd=(n.getDay()+6)%7;a=adShift(t,-wd)}
  else if(AD.p==='l7')a=adShift(t,-6);
  else{a=A.rows.length?A.rows[0].d:t;var mx=A.rows.length?A.rows[A.rows.length-1].d:t;if(mx>t)t=mx;if(a>t)a=t}
  return [a,t]}
function adZero(){var z={};ACT.CATS.forEach(function(c){z[c.k]=0});return z}
function adSum(c){return ACT.CATS.reduce(function(a,k){return a+(+c[k.k]||0)},0)}
function adStack(c,tot,max){if(!tot)return '<div class="adbar"></div>';
  return '<div class="adbar" title="'+tot+' actions"><div class="adfill" style="width:'+Math.max(2,100*tot/max).toFixed(1)+'%">'+ACT.CATS.filter(function(k){return c[k.k]}).map(function(k){return '<i style="width:'+(100*c[k.k]/tot).toFixed(2)+'%;background:'+AD_COL[k.k]+'" title="'+esc(k.l)+': '+c[k.k]+'"></i>'}).join('')+'</div></div>'}
function adLegend(){return '<div class="legend adleg">'+ACT.CATS.map(function(k){return '<span><i style="background:'+AD_COL[k.k]+'"></i>'+esc(k.l)+'</span>'}).join('')+'</div>'}
function actDash(){var A=D.act_dash;if(!A)return '';return '<section class="sec" id="actdash"><h2>Activity dashboard</h2><div id="adBody">'+adBody()+'</div></section>'}
function adBody(){var A=D.act_dash,C=ACT.CATS,r=adRange(),a=r[0],b=r[1],rows=A.rows.filter(function(x){return x.d>=a&&x.d<=b});
  var team=adZero(),per=A.designers.map(function(d){return {d:d,c:adZero(),days:{},last:''}});
  A.rows.forEach(function(x){if(x.d>per[x.i].last)per[x.i].last=x.d});
  rows.forEach(function(x){var p=per[x.i];C.forEach(function(k){var v=+(x.c[k.k]||0);p.c[k.k]+=v;team[k.k]+=v});p.days[x.d]=1});
  per.forEach(function(p){p.tot=adSum(p.c);p.nd=Object.keys(p.days).length});
  var tt=adSum(team),active=per.filter(function(p){return p.tot>0}).length,nd=A.designers.length,max=Math.max.apply(null,per.map(function(p){return p.tot}).concat([1]));
  per.sort(function(x,y){return (y.tot-x.tot)||(y.nd-x.nd)||x.d.name.localeCompare(y.d.name)});
  var plab=AD_P.filter(function(p){return p[0]===AD.p})[0][1],h='';
  h+='<div class="card"><div class="gph"><div><b>📊 Team activity · '+esc(plab)+'</b><div class="small">'+adFmt(a)+(a!==b?' – '+adFmt(b):'')+' · from the Activity Sheet, updated '+esc(A.asof)+'</div></div>'+
    '<div class="seg" role="group" aria-label="Period">'+AD_P.map(function(p){return '<button type="button" data-adp="'+p[0]+'" class="'+(p[0]===AD.p?'on':'')+'">'+esc(p[1])+'</button>'}).join('')+'</div></div>';
  h+='<div class="adtiles">'+'<div class="adt adtot"><div class="k">All actions</div><div class="v">'+n0(tt)+'</div><div class="s">'+active+' of '+nd+' designers logged</div></div>'+
    C.map(function(k){return '<div class="adt" style="border-top-color:'+AD_COL[k.k]+'"><div class="k"><i style="background:'+AD_COL[k.k]+'"></i>'+k.i+' '+esc(k.l)+'</div><div class="v">'+n0(team[k.k])+'</div></div>'}).join('')+'</div>';
  h+=(tt?'<div class="admix">'+adStack(team,tt,tt)+'</div>':'')+adLegend();
  if(nd-active)h+='<p class="adnote">'+(nd-active)+' of '+nd+' designers have no activity logged for '+esc(plab.toLowerCase())+'.</p>';
  var nx=rows.filter(function(x){return x.x}).length;if(nx)h+='<p class="adnote"><span class="chip warn">corrected</span> '+nx+' entr'+(nx===1?'y':'ies')+' in this period use corrected counts (a date, time, $ amount or pasted client message had been read as a count). The Activity Sheet itself is unchanged.</p>';
  h+='</div>';
  h+='<div class="card"><b>👥 By designer</b> <span class="small">· '+esc(plab)+' · sorted by total actions · all '+nd+' approved designers</span><div class="adlist">'+
    '<div class="adr adhd"><span>Designer</span><span>Mix</span><span>Actions</span><span>Days</span><span>Last logged</span></div>'+
    per.map(function(p){var z=!p.tot;return '<div class="adr'+(z?' adz':'')+'"><span class="adn">'+esc(p.d.name)+'</span>'+
      '<span class="adm">'+(z?'<span class="chip">No activity logged</span>':adStack(p.c,p.tot,max)+'<span class="adcnt">'+C.filter(function(k){return p.c[k.k]}).map(function(k){return '<em style="color:'+AD_COL[k.k]+'">'+k.i+'</em>'+p.c[k.k]}).join(' ')+'</span>')+'</span>'+
      '<span class="adv"><b>'+(z?'0':n0(p.tot))+'</b><small> actions</small></span><span class="adv">'+p.nd+'<small> '+(p.nd===1?'day':'days')+'</small></span><span class="adv adl">'+(p.last?'<small>last </small>'+adFmt(p.last):'<small>never logged</small>')+'</span></div>'}).join('')+'</div>'+adLegend()+'</div>';
  h+=adCb(rows,plab,a,b);
  h+='<div class="card"><div class="gph"><div><b>📈 Actions per day</b> <span class="small">· '+esc(plab)+'</span></div><select id="adWho" aria-label="Designer"><option value="-1">Whole team</option>'+
    A.designers.map(function(d,i){return '<option value="'+i+'"'+(AD.who===i?' selected':'')+'>'+esc(d.name)+'</option>'}).join('')+'</select></div><div id="adTrend"></div>'+adLegend()+'</div>';
  h+='<p class="fine">Counts and dates only; notes are never shown here (they can mention clients). Not counted: '+A.excluded.test+' test / owner-preview entries'+(A.excluded.other?' and '+A.excluded.other+' entries whose Designer name matches no approved designer':'')+'. They still appear in the Activity log card. Updates with every activity sync.</p>';
  return h}
/* contact-button taps (rows with b=[pc|deal, Action, record #]); test / owner-preview rows are already excluded by coach.py */
function adCb(rows,plab,a,b){var A=D.act_dash,per=A.designers.map(function(d){return{d:d,pc:0,pcs:{},deal:0,deals:{},a:{Texted:0,Called:0,Visited:0,Emailed:0}}}),T={pc:0,pcs:{},deal:0,deals:{}};
  rows.forEach(function(x){if(!x.b)return;var p=per[x.i],k=x.b[0],r=x.b[2]||'';p.a[x.b[1]]=(p.a[x.b[1]]||0)+1;
    if(k==='pc'){p.pc++;T.pc++;if(r){p.pcs[r]=1;T.pcs[r]=1}}else{p.deal++;T.deal++;if(r){p.deals[r+'|'+x.d]=1;T.deals[r]=1}}});
  var on=per.filter(function(p){return p.pc||p.deal});on.sort(function(x,y){return (y.pc+y.deal)-(x.pc+x.deal)||x.d.name.localeCompare(y.d.name)});
  var nk=function(o){return Object.keys(o).length};
  return '<div class="card"><b>📇 Contact buttons</b> <span class="small">· '+esc(plab)+' · taps on 💬 Texted / 📞 Called / 🏠 Visited / ✉️ Emailed (already counted in the totals above)</span>'+
    '<div class="adtiles" style="margin-top:8px"><div class="adt"><div class="k">Past clients contacted</div><div class="v">'+n0(nk(T.pcs))+'</div><div class="s">'+n0(T.pc)+' tap'+(T.pc===1?'':'s')+'</div></div><div class="adt"><div class="k">Deals touched</div><div class="v">'+n0(nk(T.deals))+'</div><div class="s">'+n0(T.deal)+' tap'+(T.deal===1?'':'s')+'</div></div></div>'+
    (on.length?'<div class="adlist"><div class="adr adhd cbr"><span>Designer</span><span>Past clients</span><span>Deals</span><span>How</span></div>'+on.map(function(p){return '<div class="adr cbr"><span class="adn">'+esc(p.d.name)+'</span><span class="adv"><b>'+nk(p.pcs)+'</b><small> contacted</small></span><span class="adv"><b>'+nk(p.deals)+'</b><small> touched</small></span><span class="adv adcnt">'+CB_ACT.filter(function(z){return p.a[z[0]]}).map(function(z){return z[1]+p.a[z[0]]}).join(' ')+'</span></div>'}).join('')+'</div>'
      :'<p class="adnote" style="margin:8px 0">No contact-button taps synced for '+esc(plab.toLowerCase())+' yet. They show here after the next activity sync (:20 and :40 past the hour).</p>')+
    '<p class="fine">Deals touched counts each deal once per day. Record numbers stay in the Activity Sheet; client names are never shown here.</p></div>'}
function adTrend(){var el=$('#adTrend');if(!el)return;var A=D.act_dash,C=ACT.CATS,r=adRange(),a=r[0],b=r[1],days=[],by={};
  for(var d=a,g=0;d<=b&&g<400;d=adShift(d,1),g++){days.push(d);by[d]=adZero()}
  A.rows.forEach(function(x){if(by[x.d]&&(AD.who<0||x.i===AD.who))C.forEach(function(k){by[x.d][k.k]+=+(x.c[k.k]||0)})});
  var W=Math.max(300,Math.round(el.clientWidth||600)),H=190,L=30,R=8,T=16,B=26,n=days.length,cw=(W-L-R)/n,bw=Math.max(2,Math.min(38,cw*.72));
  var mx=Math.max.apply(null,days.map(function(d){return adSum(by[d])}).concat([1])),step=mx<=5?1:mx<=10?2:mx<=25?5:Math.ceil(mx/5/5)*5;mx=Math.ceil(mx/step)*step;
  var y=function(v){return T+(H-T-B)*(1-v/mx)},s='<svg class="adsvg" viewBox="0 0 '+W+' '+H+'" width="'+W+'" height="'+H+'" role="img" aria-label="Actions per day">';
  for(var v=0;v<=mx;v+=step)s+='<line x1="'+L+'" x2="'+(W-R)+'" y1="'+y(v)+'" y2="'+y(v)+'" stroke="#e4dfd3"/><text x="'+(L-5)+'" y="'+(y(v)+4)+'" text-anchor="end" font-size="11" fill="#667085">'+v+'</text>';
  var every=Math.max(1,Math.ceil(n/(W/48))),tot=0;
  days.forEach(function(d,i){var x=L+cw*i+(cw-bw)/2,base=0,t=adSum(by[d]);tot+=t;
    C.forEach(function(k){var v=by[d][k.k];if(!v)return;s+='<rect x="'+x.toFixed(1)+'" y="'+y(base+v).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+(y(base)-y(base+v)).toFixed(1)+'" fill="'+AD_COL[k.k]+'"><title>'+adFmt(d)+' · '+esc(k.l)+': '+v+'</title></rect>';base+=v});
    if(t&&bw>=12)s+='<text x="'+(x+bw/2).toFixed(1)+'" y="'+(y(t)-3).toFixed(1)+'" text-anchor="middle" font-size="11" font-weight="700" fill="#14171c">'+t+'</text>';
    if(i%every===0||i===n-1&&n<=31)s+='<text x="'+(L+cw*i+cw/2).toFixed(1)+'" y="'+(H-8)+'" text-anchor="middle" font-size="11" fill="#667085">'+(n>45?adFmt(d):d.slice(8).replace(/^0/,''))+'</text>'});
  s+='</svg>';
  el.innerHTML=(tot?'':'<p class="adnote" style="margin:8px 0">No activity logged '+(AD.who<0?'by the team':'by '+esc(A.designers[AD.who].name))+' in this period.</p>')+s+(n<=45&&n>1?'<div class="fine">Day of month: '+adFmt(a)+' – '+adFmt(b)+'</div>':'')}
function adWire(){if(!$('#adBody'))return;adTrend();
  document.querySelectorAll('[data-adp]').forEach(function(btn){btn.onclick=function(){AD.p=btn.dataset.adp;$('#adBody').innerHTML=adBody();adWire()}});
  var s=$('#adWho');if(s)s.onchange=function(){AD.who=+s.value;adTrend()}}
window.addEventListener('resize',function(){var t;clearTimeout(window.__adT);window.__adT=setTimeout(function(){if($('#adTrend'))adTrend()},150)});

/* ── Goal section in a goal-back plan month (Andrew, Oct 21, 2026): ONE goal = the Sales Board's October target (same plan file and code
   as the board). No personal goal on the page. Designers without a board target get no goal. Colors: hit / ahead = green, near = neutral,
   behind = red (board status rules). ── */
function goalPlanSec(x){var s=x.snap,g=x.goal,M=D.meta,T=D.team,dl=Math.max(1,M.days_left);
  if(g.target==null)return sec('goal','🎯 October goal','<div class="card"><p class="small"><b>No October goal for you this month.</b> '+(g.no_target_why?'Reason: '+esc(g.no_target_why)+'. ':'')+'Every sale still counts toward the team\'s October goal.</p>'+
    '<div class="grid g2">'+tile('Sold so far',m0(s.usd),'incl. pending Final · '+s.sales+' sale'+(s.sales===1?'':'s'),'neu')+tile('Projected month-end',m0(g.proj),'back-loaded curve + your pipeline','neu')+'</div></div>');
  var gap=g.target-s.usd,mx=Math.max(g.target,g.proj,s.usd)*1.08||1,P=function(v){return Math.min(100,v/mx*100).toFixed(1)+'%'},st=gap<=0?'pos':(g.target_status||'neu');
  var h='<div class="card" style="border-left:5px solid #b26b00"><div class="grid">'+
    tile('October goal',m0(g.target),'your Sales Board target: sold through Oct 18 '+m0(g.target_base)+' + remaining quota '+m0(g.target_quota),'neu')+
    tile('Sold so far',m0(s.usd),pc(s.usd/g.target)+' of your goal · incl. pending Final',st)+
    tile('Still to sell',gap>0?m0(gap):'hit',gap>0?'about '+m0(gap/dl)+' a day for the '+M.days_left+' day'+(M.days_left===1?'':'s')+' left (incl. today)':'goal reached',gap<=0?'pos':'neu')+
    tile('On path now',m0(g.target_pace),'daily targets path · you are '+(s.usd>=g.target_pace?m0(s.usd-g.target_pace)+' ahead':m0(g.target_pace-s.usd)+' behind'),g.target_status||'neu')+'</div>'+
    '<div class="bar"><div class="proj" style="width:'+P(g.proj)+'"></div><div class="fill" style="width:'+P(s.usd)+'"></div>'+
    '<div class="mk" style="left:'+P(g.target_pace)+'"><span class="lb">on path '+mk(g.target_pace)+'</span></div>'+
    '<div class="mk bt" style="left:'+P(g.target)+';background:#b26b00"><span class="lb" style="color:#b26b00">October goal '+mk(g.target)+'</span></div></div>'+
    '<div class="legend"><span><i style="background:#12263f"></i>sold</span><span><i style="background:#9fb2c9"></i>projected month-end</span><span><i style="background:#14171c"></i>on path now (daily targets)</span><span><i style="background:#b26b00"></i>October goal</span></div>'+
    '<div class="kv" style="margin-top:10px"><span>Projected month-end (back-loaded curve, never below sold + expected closes from open quotes and booked appointments)</span><b class="'+cls(g.proj,g.target,g.target*.05)+'">'+m0(g.proj)+'</b></div>'+
    '<p class="fine">Everyone tracks to the same October number as the Sales Board: CEO Coach\'s goal-back plan, approved by Andrew. The path follows the daily targets'+(M.plan.checkpoints&&M.plan.checkpoints.length?' (checkpoints '+M.plan.checkpoints.map(function(c){return esc(c.label)}).join(' and ')+')':'')+'. Green = at or above the path, black = close or too early to judge, red = behind.</p></div>';
  h+='<details><summary>How your projection is built</summary>'+
    '<div class="kv"><span>Pipeline floor (sold + open quotes + booked appts) · month-to-date on the typical curve ('+(g.proj_curve==null?'–':m0(g.proj_curve))+') · weight on the curve '+pc(g.proj_w)+'</span><b>'+m0(g.proj_pipe)+'</b></div>'+
    '<div class="kv"><span>Your lead flow (held first appts per 30 days, last 60 days)</span><b>'+g.flow.toFixed(1)+'</b></div>'+
    '<div class="kv"><span>Team-typical by day '+M.day+' for your lead flow (fairness reference, not a goal)</span><b>'+m0(g.exp_td)+'</b></div>'+
    '<p class="fine">Sales back-load: typical months have '+pc(M.typ_share)+' sold by day '+M.day+'.</p></details>';
  return sec('goal','🎯 October goal',h)}
/* ── Close This Month (Andrew, Oct 22, 2026): per-deal next steps, past clients to call, strengths/habits (designer page) and the owner
   30,000-ft roll-up. Data: x.ns / D.owner.ns built by nextsteps.py. Colors: good = green/neutral, bad = red/amber, facts neutral. ── */
var NS_RULES=[['Note says signed','Confirm the paperwork and move to Sold (Designer) today','CFNJ stage rules'],
 ['Appointment booked within 3 weeks','Run it to a decision: agree up front on a yes, a no or a dated next visit; offer the Fanwood showroom on $5,000+ designs','Sandler up-front contract'],
 ['Next step more than 3 weeks out','Check in now with this month\'s showroom special','Rackham "advance"; honest urgency (this month\'s special)'],
 ['Planned step in the note passed within 14 days','Log what happened and book the next visit today','CFNJ three-outcome rule'],
 ['Note mentions a spouse/partner','Joint review with both decision-makers at the showroom','Miller Heiman buying influences; Sandler one-legged calls'],
 ['Note mentions price/budget','Show the full and a phased version; Lowe\'s 18-mo no interest if paid in full only for Lowe\'s leads, otherwise Enhancify (terms depend on credit)','SPIN need-payoff; good/better/best'],
 ['Note mentions another company','Showroom side-by-side: own Fanwood factory, lifetime guarantee','Challenger teach & tailor'],
 ['Note mentions timing/project','Agree a dated decision; mention this month\'s showroom special','SPIN implication; honest urgency only'],
 ['Quote under 30 days, no dated step','Book the showroom review visit (24-72 h, day 7, day 14 rhythm)','HBR lead-response research; 24-72-7-14'],
 ['No dated note 14+ days','Call with a reason: the showroom invite; the goal is a firm appointment, not a sale on the call','24-72-7-14 rhythm; Rackham "advance"'],
 ['Appointment 90+ days ago, quiet','Re-open with an updated design. Aged quotes are still winnable: they got old because the follow-up stopped','Rackham "advance"'],
 ['ClosetWare project type is Garage','Texts and talking points say "the space we designed for you" instead of naming a garage, unless the booking note clearly names one room; next-room ideas do not assume a garage','ClosetWare often uses Garage as a placeholder (service coordinator, Oct 26)']];
var NS_F={},NS_APPLY=null;
/* Past-client texting do's and don'ts (Andrew, Oct 22, 2026; modeled on the past-client text a CFNJ designer shared in the Design Team chat). Sources: playbook s.15. */
var NS_DOS=[['do','Personalize: their first name, their project, from you. Lead with the relationship, not the pitch.','Reichheld, HBR 2003; HBR 2014 on keeping customers'],
 ['do','Make one clear ask: reply to you (or book a showroom visit).','Rackham: aim for an "advance"'],
 ['do','Ask for referrals when clients are happiest: right after install and at the thank-you call. Referred clients are worth more and stay longer.','Schmitt, Skiera & Van den Bulte 2011; Reichheld (NPS)'],
 ['do','Give an honest reason to reply now: this month\'s special. Never a fake deadline.','Challenger "take control"; CFNJ honest urgency'],
 ['do','No reply? Follow up once or twice, then call.','24-72-7-14 follow-up rhythm'],
 ['do','Log every contact in Designer Coach (My activity).','CFNJ rule'],
 ['dont','Don\'t mass-blast. Text only past clients you worked with, one-to-one from your own phone, and honor any "stop" right away. Bulk or automated marketing texts have consent rules (TCPA); this is not legal advice, so ask Andrew before any group or automated send.','FCC, TCPA consumer guide'],
 ['dont','Don\'t overpromise financing: Lowe\'s 18-mo no interest if paid in full is deferred interest (if the balance isn\'t paid in full within 18 months, interest is charged back to the purchase date) and is for Lowe\'s customers only; Enhancify terms depend on credit. Never promise approval or quote a payment.','CFPB on deferred interest'],
 ['dont','Don\'t discount on top of the special.','CFNJ rule'],
 ['dont','Don\'t pay or record the $50 Amazon gift card until the referral actually purchases.','CFNJ referral offer']];
function nsDos(){return '<details class="card nsdos" open><summary><b>Texting past clients: do\'s and don\'ts</b></summary><ul class="tight small">'+NS_DOS.map(function(d){return '<li><b class="'+(d[0]==='do'?'pos':'neg')+'">'+(d[0]==='do'?'Do':'Don\'t')+':</b> '+esc(d[1].replace(/^Don't /,''))+' <span class="fine">('+esc(d[2])+')</span></li>'}).join('')+'</ul></details>'}
function nsWho(p){return esc(p.name||'(no first name)')+(p.li?' '+esc(p.li)+'.':'')}
/* Client phone + email (Andrew, Oct 25, 2026): every client record on a designer page shows a tap-to-call (tel:) and tap-to-email
   (mailto:) link from ClosetWare (contacts.py: ph = mobile first, ph2 = other number, em, eo = email opt-out). Tapping a link only opens
   the phone/mail app; it never logs anything (logging stays on the Texted / Called / Visited / Emailed buttons). */
function ctFmt(d){d=String(d||'');return d.length===10?'('+d.slice(0,3)+') '+d.slice(3,6)+'-'+d.slice(6):d}
function ctTel(d){d=String(d||'');return 'tel:'+(d.length===10?'+1'+d:d)}
function ctLine(r,inl){if(!r)return'';var h=[];
  if(r.ph)h.push('<a class="ctl" href="'+ctTel(r.ph)+'">'+(r.pm?'📱 ':'📞 ')+esc(ctFmt(r.ph))+'</a>');
  if(r.ph2)h.push('<a class="ctl" href="'+ctTel(r.ph2)+'">📞 '+esc(ctFmt(r.ph2))+'</a>');
  if(r.em)h.push('<a class="ctl cte" href="mailto:'+encodeURI(r.em)+'">✉️ '+esc(r.em)+'</a>'+(r.eo?'<span class="ctn"> (opted out of marketing email)</span>':''));
  if(!h.length)h.push('<span class="ctn">no phone or email on file</span>');
  return (inl?'<span class="ct cti">':'<div class="ct">')+h.join(inl?' ':'')+(inl?'</span>':'</div>')}
function nsPromo(P,compact){var s=P.showroom,l=P.lowes;return '<div class="card nspromo"><div class="nsp"><span class="nsi">🍂</span><div><b>'+esc(s.name)+'</b><div class="small">'+esc(s.text)+'</div></div></div>'+
  '<div class="nsp"><span class="nsi">🏠</span><div><b>'+esc(l.name)+'</b><div class="small">'+esc(l.text)+(compact?'':' Deals and past clients that qualify carry the "Lowe\'s 18-mo" tag.')+(l.terms_note?'<br><i>For you, not for clients: '+esc(l.terms_note)+'</i>':'')+'</div></div></div>'+
  (P.referral?'<div class="nsp"><span class="nsi">🎁</span><div><b>'+esc(P.referral.name)+'</b><div class="small">'+esc(P.referral.text)+'</div></div></div>':'')+'</div>'}
function nsCard(p,T){var tod=p.due===T,dc='';
  return '<div class="nsd" data-k="'+p.k+'" data-due="'+(tod?1:0)+'" data-sr="'+(p.showroom?1:0)+'" data-lw="'+(p.lowes?1:0)+'" data-usd="'+p.usd+'" data-i="'+p.i+'" data-ref="'+esc(p.ref)+'">'+
  '<div class="top"><span><input type="checkbox" class="nsdone" aria-label="done"> <b>'+nsWho(p)+'</b> <span class="ref">'+esc(p.ref)+'</span></span><span class="amt">'+m0(p.usd)+'</span></div>'+ctLine(p)+
  '<div class="nsa"><span class="chip '+dc+'">'+(tod?'Due today':'By '+esc(p.due_l))+'</span><b>'+esc(p.label)+'</b></div>'+
  '<div class="small nsm">'+esc(p.room)+' · '+esc(p.stage)+' · '+esc(p.src)+(p.chips||[]).map(function(c){return ' <span class="chip '+(c==='showroom upgrade'?'g':'')+'">'+esc(c)+'</span>'}).join('')+'</div>'+gphHint(p)+
  '<div class="why small"><b>Why:</b> '+p.why.map(esc).join(' · ')+'</div>'+
  '<div class="nss"><span>'+esc(p.script)+'</span><button class="btn ghost nscp" type="button">Copy</button></div>'+cbBtns('deal',p.ref)+fuBox('deal',p.ref)+'</div>'}
/* Garage placeholder (Andrew, Oct 26, 2026): ClosetWare's "Garage" project type is often a catch-all, so cards whose type is Garage carry
   this hint; their scripts are neutral unless the booking note clearly names one room (nextsteps.py room_for). */
var GPH_NOTE='ClosetWare often shows Garage as a placeholder project type. Check your own records before mentioning a specific room.';
function gphHint(c){return c&&c.gph?'<div class="fine gph">⚠️ '+GPH_NOTE+'</div>':''}
/* Clients from designers no longer here (Oct 28, 2026): former designer (first name + last initial), their history with us, and why they were matched to you */
function inBlock(c){if(!c||!c.inact)return '';var H=c.hist||[];
  return '<div class="inb small"><div><b>Former designer:</b> '+esc(c.fd)+' <span class="fine">(no longer with CFNJ)</span> · <b>Lead source:</b> '+esc(c.src||'not recorded')+' · <b>Last ClosetWare activity:</b> '+esc(c.last_act||'none on record')+'</div>'+
   (H.length?'<details class="inh"><summary><b>Client history</b> ('+(c.hist_n||H.length)+' record'+((c.hist_n||H.length)===1?'':'s')+(c.hist_n>H.length?', latest '+H.length+' shown':'')+')</summary><div class="int">'+
     H.map(function(h){return '<div class="inr"><b>'+esc(h.d)+'</b> · '+esc(h.st)+' · '+(h.usd!=null?m0(h.usd):'–')+' · '+esc(h.room||'room not recorded')+' · '+esc(h.src||'lead source not recorded')+' · <span class="fine">designer:</span> '+esc(h.des||'–')+'</div>'}).join('')+'</div></details>':'')+
   (c.match?'<div class="inm">🤝 '+esc(c.match)+'</div>':'')+'</div>'}
function pcCard(c,P){return '<div class="nsd pc" data-pref="'+esc(c.ref)+'"><div class="top"><span><b>'+nsWho(c)+'</b> <span class="ref">'+esc(c.ref)+'</span></span><span class="amt">'+m0(c.usd)+'</span></div>'+ctLine(c)+
    '<div class="small nsm">'+esc(c.rooms_d||c.rooms.join(', '))+' · sold '+esc(c.sold)+(c.n>1?' · '+c.n+' projects':'')+' '+c.tags.map(function(t){return '<span class="chip '+(t.indexOf('Lowe')===0?'':'g')+'">'+esc(t)+'</span>'}).join('')+'</div>'+gphHint(c)+inBlock(c)+
    '<div class="why small"><b>Why this person:</b> '+esc(c.why)+(c.fit?' <span class="chip">'+esc(c.fit)+'</span>':'')+'</div>'+
    (c.text?'<div class="small nslab"><b>📱 Text (ready to send)</b></div><div class="nss nstx"><span>'+esc(c.text)+'</span><button class="btn ghost nscp" type="button">Copy</button></div>':'')+
    (c.lowes&&P.lowes.terms_note?'<div class="fine nslw">For you only, not in the text: '+esc(P.lowes.terms_note)+'</div>':'')+
    '<details class="nscall"><summary class="small"><b>📞 Call version</b></summary><div class="nss"><span>'+esc(c.script)+'</span><button class="btn ghost nscp" type="button">Copy</button></div></details>'+cbBtns('pc',c.ref)+fuBox('pc',c.ref)+'<button type="button" class="cbdnc" data-ref="'+esc(c.ref)+'">🚫 Don\'t contact</button></div>'}
function nsSection(x){var N=x.ns;if(!N)return'';var T=N.asof,P=N.promo,h='',ds=N.deals||[];
  h+=nsPromo(P);
  h+='<div class="grid">'+tile('In play',m0(N.usd),N.n+' open quote'+(N.n===1?'':'s')+' · every one is winnable','neu')+tile('Due today',n0(N.today_n),'next steps to do today ('+N.per_day+' a day, biggest $ first)',N.today_n?'neu':'neu')+
   tile('Quiet 14+ days',n0(N.nodate_n),m0(N.nodate_usd)+' with no dated note in 14+ days',N.nodate_n?'neg':'pos')+tile('Showroom invites',n0(ds.filter(function(p){return p.showroom&&p.usd>=5000}).length),'quotes over $5,000 that qualify for the free color upgrade with a visit','neu')+'</div>';
  if(!ds.length)h+='<div class="card"><p class="small" style="margin:0">No open quotes right now. Your past clients below are the fastest way to build October.</p></div>';
  else{h+='<div class="card"><div class="nsbar"><div class="seg nsf"><button data-f="all" class="on">All '+ds.length+'</button><button data-f="due">Today</button><button data-f="sr">Showroom</button><button data-f="lw">Lowe\'s</button></div><div class="seg nso"><button data-o="pri" class="on">Priority</button><button data-o="usd">$</button></div></div>'+
   '<p class="fine" style="margin:4px 0 8px">One next step per quote, ordered by dollars × urgency. Tap Copy for the talk track; tick the box when it is done (saved on this device). After each call, write the one-line note: date, place, time.</p><div id="nsl">'+ds.map(function(p){return nsCard(p,T)}).join('')+'</div>'+
   (ds.length>8?'<button class="btn ghost" id="nsmore" type="button" style="width:100%">Show all '+ds.length+'</button>':'')+
   '<div id="nstd" class="nstd hidden"><div class="nstdh"><b>✓ Contacted today</b> <span class="small" id="nstdn"></span></div><p class="fine" style="margin:2px 0 6px">Logged with the buttons. Each one goes back to its normal place in your list tomorrow. Tap a name to open the card.</p><div id="nstdl"></div></div>'+
   '<div id="nssc" class="nstd nssc hidden"><div class="nstdh"><b>📅 Scheduled by your notes</b> <span class="small" id="nsscn"></span></div><p class="fine" style="margin:2px 0 6px">Your result / next-step note set a later date. Each one comes back pinned under "Follow up today" at the top of the page on that day. Tap a name to open the card.</p><div id="nssl"></div></div></div>'}
  h+='<details class="card"><summary><b>How each next step is picked</b> <span class="small">(rules + sources)</span></summary><ul class="tight small">'+NS_RULES.map(function(r){return '<li><b>'+esc(r[0])+'</b> → '+esc(r[1])+' <span class="fine">('+esc(r[2])+')</span></li>'}).join('')+'</ul><p class="fine">First rule that fits wins. Read from ClosetWare (stage, amount, appointment, follow-up date, dated notes) by rule, not by meaning: if the tag is wrong, trust what you know about the client. Never treat a quote as gone: a quiet quote needs a reason to call.</p></details>';
  var out=sec('close','💼 Close this month',h);
  /* past clients */
  var pc=N.past||[],ph='';
  ph+=nsDos();
  ph+='<div class="card"><p class="small" style="margin:0 0 8px">'+(pc.length?'<b>Past clients are your most important contacts right now.</b> Each one has a ready-to-send text (modeled on a past-client text that works on our team; ready to copy and paste into a text from your phone) and a short call version. <b>Room names:</b> '+GPH_NOTE+' These are your <span id="pcn">'+Math.min(10,pc.length)+'</span> best past clients to contact in October (from '+N.past_pool+' of your sold clients in the last 24 months, 60+ days after the sale'+(N.deep&&N.deep.n?', plus '+N.deep.n+' from earlier years':'')+'), best opportunity first. Tap the phone number or email on a card to reach them; the record number finds them in ClosetWare. Running low? Your list reaches back into earlier years automatically (marked "from earlier years").':'No past clients in the window (sold Final in the last 24 months, 60+ days ago).')+'</p>'+
   (pc.length?'<p class="small cbhelp"><b>After you reach out, tap what you did</b> (💬 Texted · 📞 Called · 🏠 Visited · ✉️ Emailed). It is logged in your activity and sent to Andrew, that client leaves your list for '+(N.pc_quiet||60)+' days and the next best past client moves up. Changed your mind? Tap Undo within 5 seconds. Someone who must never hear from us again? Tap <b>🚫 Don\'t contact</b>: they leave every designer\'s list for good (Andrew can restore them).</p>':'')+
   '<div id="pcl"></div><p class="small hidden" id="pcend"></p>'+
   '<p class="fine">Ask every happy client for a referral; enter any lead they give you as designer-created. Installed is estimated (sold Final 60+ days ago; install lead time runs 40-60 days).</p></div>';
  out+=sec('pastc','📞 Call past clients (October)',ph);
  /* clients from designers no longer here */
  if(N.inact){var ih='<div class="card"><p class="small" style="margin:0 0 8px">'+((N.inact||[]).length?'<b>These clients bought from a CFNJ designer who is no longer here</b>, so nobody is looking after them now. They are yours to call: each household is on one designer\'s page only, matched to you by what you sell well and where you work. Each card shows who they worked with and their history with us, so you have context. The text introduces you as their designer now (it does not name the former designer). Showing <span id="inn">'+Math.min(10,N.inact.length)+'</span> at a time; the next one moves up when you log a contact.':'No clients from former designers on your list right now. More come in at the next refresh.')+'</p>'+
     ((N.inact||[]).length?'<p class="small cbhelp">Same buttons as your past clients: tap what you did (💬 Texted · 📞 Called · 🏠 Visited · ✉️ Emailed) and it is logged in your activity; 🚫 Don\'t contact takes them off every list.</p>':'')+
     '<div id="inl"></div><p class="small hidden" id="inend"></p></div>';
   out+=sec('inact','👥 Clients from designers no longer here',ih)}
  /* strengths / habits */
  var C=N.coach||{},a=C.act||{},ch='<div class="grid g2">';
  ch+='<div class="card"><b>What you do well</b>'+(C.strengths||[]).map(function(s){return '<div class="win" style="margin-top:8px"><div class="i">✅</div><div><b>'+esc(s.t)+'</b><span>'+esc(s.d)+'</span></div></div>'}).join('')+'</div>';
  ch+='<div class="card"><b>Habits to fix</b>'+((C.habits||[]).length?C.habits.map(function(s){return '<div class="nsh"><b>'+esc(s.t)+'</b><div class="small">'+esc(s.d)+'</div></div>'}).join(''):'<p class="small">Nothing big flagged from your numbers. Keep the rhythm: a yes, a no or a firm next appointment, every time.</p>')+'</div></div>';
  ch+='<p class="small" style="margin:0 2px">Your tracker, last 7 days: '+(a.days?(a.calls+' calls · '+a.texts+' texts/emails · '+a.followups+' follow-ups · '+a.showroom+' showroom visits · logged on '+a.days+' day'+(a.days===1?'':'s')):'nothing logged yet. Log each call above so your follow-ups count.')+'</p>';
  out+=sec('edge','💪 Your edge and your fix',ch);
  return out}
function nsWire(x){var N=x.ns;if(!N)return;var key='cfnj_ns_done_'+x.slug,st={};try{st=JSON.parse(localStorage.getItem(key)||'{}')}catch(e){}
  var L=$('#nsl'),more=$('#nsmore'),f='all',o='pri',all=false;
  function apply(){if(!L)return;var cs=[].slice.call(L.querySelectorAll('.nsd'));cs.sort(o==='usd'?function(a,b){return b.dataset.usd-a.dataset.usd}:function(a,b){return a.dataset.i-b.dataset.i});cs.forEach(function(c){L.appendChild(c)});var k=0;
    cs.forEach(function(c){var ok=f==='all'||(f==='due'&&c.dataset.due==='1')||(f==='sr'&&c.dataset.sr==='1')||(f==='lw'&&c.dataset.lw==='1');if(ok)k++;c.style.display=ok&&(all||f!=='all'||k<=8)?'':'none'});if(more)more.style.display=(!all&&f==='all'&&cs.length>8)?'':'none'}
  document.querySelectorAll('.nsf button').forEach(function(b){b.onclick=function(){f=b.dataset.f;document.querySelectorAll('.nsf button').forEach(function(z){z.classList.toggle('on',z===b)});apply()}});
  document.querySelectorAll('.nso button').forEach(function(b){b.onclick=function(){o=b.dataset.o;document.querySelectorAll('.nso button').forEach(function(z){z.classList.toggle('on',z===b)});apply()}});
  if(more)more.onclick=function(){all=true;apply()};
  document.querySelectorAll('#close .nscp').forEach(function(b){b.onclick=function(){copy(b.previousElementSibling.textContent)}});
  document.querySelectorAll('.nsd[data-ref]').forEach(function(c){var cb=c.querySelector('.nsdone'),r=c.dataset.ref;if(!cb)return;cb.checked=!!st[r];c.classList.toggle('done',cb.checked);cb.onchange=function(){st[r]=cb.checked?D.meta.today:0;if(!cb.checked)delete st[r];c.classList.toggle('done',cb.checked);try{localStorage.setItem(key,JSON.stringify(st))}catch(e){}}});
  apply();NS_APPLY=apply;cbWire(x)}
/* ── Contact buttons (Andrew, Oct 22, 2026, 12:38 PM). Past-client and deal cards carry 💬 Texted · 📞 Called · 🏠 Visited · ✉️ Emailed.
   A tap = one tracker entry (same localStorage log, same Google Form, same SHA-256 dedupe key as "Save my note"):
     Counts: the tracker's 8-key string with 1 in the matching box: Texted/Emailed -> texts_emails, Called -> calls, Visited -> appts
             (the tracker's own voice parser maps "visit" to appointments held).
     Note:   "[pc] Past client #<ref> - Texted (14:05:09)" / "[deal] Opp #<ref> - Called (14:05:09)". Record number only, no client name or
             contact data. The tap time makes each tap unique, so a row that is ever sent twice is an exact duplicate (activity_rows.load drops it).
     Detail (optional): "[pc] Past client #<ref> - detail: <text> (14:06:30)", all counts 0, phone numbers / emails masked.
   Undo: the entry is saved at once with s='hold' (shows in the log right away) and sent after CB_HOLD ms. Undo inside that window deletes
   it, so nothing reaches the Sheet. If the page is hidden or closed first, every held entry is promoted to 'pending' and sent with
   fetch keepalive; anything that still did not go out is sent on the next open (ACT.sync promotes expired holds). Nothing is lost and
   an undone tap never creates a row.
   Past clients: a tapped client leaves the list for pc_quiet (60) days; the next one from the reserve (ns.past_res) is appended; never
   more than 10 shown. Deals: never removed; the card moves to the "Contacted today" strip under the deal list until tomorrow.
   State = this device's taps (cfnj_cb_v1_<slug>) + the tracker log on this device + the Sheet rows in the bundle (x.activity) + the
   build's pc_recent / deal touch (Activity Sheet, synced :20/:40 and hourly), merged by record number, so phone and computer agree
   after the next sync and nothing counts twice (counting is the tracker's key-based Sheet/local merge). ── */
var CB_ACT=[['Texted','💬','texts'],['Called','📞','calls'],['Visited','🏠','appts'],['Emailed','✉️','texts']],CB_HOLD=5000,CB_T={},CB_X=null,CB_SHEET=null;
var CB_DNC_RX=/^\s*\[pc\]\s*past client\s*#([A-Za-z0-9]{4,18})\s*-\s*do not contact\b/i;
var CB_RX=/^\s*\[(pc|deal)\]\s*(?:past client|opp)\s*#([A-Za-z0-9]{4,18})\s*-\s*(texted|called|visited|emailed)\b/i;
function cbBtns(kind,ref){return '<div class="cbb" role="group" aria-label="Log a contact">'+CB_ACT.map(function(a){return '<button type="button" class="cbt" data-cb="'+a[0]+'" data-kind="'+kind+'" data-ref="'+esc(ref)+'"><span aria-hidden="true">'+a[1]+'</span>'+a[0]+'</button>'}).join('')+'</div>'}
function cbPad(n){return String(n).padStart(2,'0')}
function cbHms(d){return cbPad(d.getHours())+':'+cbPad(d.getMinutes())+':'+cbPad(d.getSeconds())}
function cbClock(t){var d=new Date(t);return d.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit'})}
function cbNote(kind,ref,a,d,detail){return (kind==='pc'?'[pc] Past client #':'[deal] Opp #')+ref+' - '+(detail!=null?'detail: '+detail:a)+' ('+cbHms(d)+')'}
function cbMask(t){return String(t||'').replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,'[email]').replace(/\+?\d[\d\s().-]{8,}\d/g,'[phone]').replace(/\s+/g,' ').trim().slice(0,400)}
function cbKey(x){return 'cfnj_cb_v1_'+x.slug}
function cbLoad(x){try{var o=JSON.parse(localStorage.getItem(cbKey(x))||'{}');return{pc:o.pc||{},deal:o.deal||{},dnc:o.dnc||{}}}catch(e){return{pc:{},deal:{},dnc:{}}}}
function cbSave(x,o){var q=cbAgo(x.ns.pc_quiet||60);Object.keys(o.pc).forEach(function(r){if(o.pc[r].d<q)delete o.pc[r]});
  Object.keys(o.deal).forEach(function(r){if(o.deal[r].d<ACT.ymd(new Date()))delete o.deal[r]});try{localStorage.setItem(cbKey(x),JSON.stringify(o))}catch(e){}}
function cbAgo(n){var d=new Date();d.setDate(d.getDate()-n);return ACT.ymd(d)}
/* merged contact state: {pc:{ref:{a,d,t}}, deal:{ref:{a,d,t}}, dnc:{ref:1}} (deal = today only; dnc = Don't contact, permanent) */
function cbState(x){var N=x.ns,td=ACT.ymd(new Date()),q=cbAgo(N.pc_quiet||60),st={pc:{},deal:{},dnc:{}};
  function add(kind,ref,a,d,t){if(kind==='pc'?(d<q||d>td):d!==td)return;var o=st[kind][ref];if(!o||(t||0)>(o.t||0))st[kind][ref]={a:a,d:d,t:t||0}}
  var RS=N.dnc_rs||{};function rsd(r,d){return Object.prototype.hasOwnProperty.call(RS,r)&&(!RS[r]||!d||d<=RS[r])}
  function fromNote(n,d,t){var z=CB_DNC_RX.exec(n||'');if(z){if(!rsd(z[1],d))st.dnc[z[1]]=1;return}var m=CB_RX.exec(n||'');if(m)add(m[1].toLowerCase(),m[2],m[3].charAt(0).toUpperCase()+m[3].slice(1).toLowerCase(),d,t)}
  (N.pc_recent||[]).forEach(function(r){add('pc',r.ref,r.a,r.d,r.t)});
  if(N.asof===td)(N.deals||[]).forEach(function(p){if(p.touch)add('deal',p.ref,p.touch.a,td,p.touch.t)});
  ((x.activity&&x.activity.rows)||[]).forEach(function(r){fromNote(r.n,r.d,r.t)});
  ACT.load(x.slug).concat(actArch(x.slug)).forEach(function(e){fromNote(e.note,e.d,e.t)});
  var L=cbLoad(x);['pc','deal'].forEach(function(k){Object.keys(L[k]).forEach(function(r){var o=L[k][r];add(k,r,o.a,o.d,o.t)})});var ch=0;Object.keys(L.dnc).forEach(function(r){if(rsd(r,(L.dnc[r]||{}).d)){delete L.dnc[r];ch=1}else st.dnc[r]=1});if(ch)cbSave(x,L);
  return st}
/* past-client list: ranked (top 10 + reserve) minus everyone contacted in the quiet window, first 10 */
function cbPast(x,st,k){var N=x.ns,g=fuState(x);k=k||'past';return (N[k]||[]).concat(N[k+'_res']||[]).filter(function(c){return !st.pc[c.ref]&&!st.dnc[c.ref]&&!(g[c.ref]&&g[c.ref].g)}).slice(0,10)}   /* a governing follow-up note holds the client until its date (then pinned) */
function cbPcRender(x,anim){cbListRender(x,anim,'inact','#inl','#inn','#inend');cbListRender(x,anim,'past','#pcl','#pcn','#pcend')}
function cbListRender(x,anim,k,lid,nid,eid){var L=$(lid);if(!L)return;var st=cbState(x),want=cbPast(x,st,k),have={};
  [].slice.call(L.querySelectorAll('.nsd.pc')).forEach(function(el){var r=el.dataset.pref;if(want.some(function(c){return c.ref===r}))have[r]=el;else el.remove()});
  want.forEach(function(c){var el=have[c.ref];if(!el){var t=document.createElement('div');t.innerHTML=pcCard(c,x.ns.promo);el=t.firstChild;cbWireCard(el);if(anim){el.classList.add('cbin');setTimeout(function(){el.classList.remove('cbin')},600)}}L.appendChild(el)});
  var n=$(nid);if(n)n.textContent=want.length;var e=$(eid),nc=Object.keys(st.pc).length;
  if(k==='inact'){if(e){var ni=((x.ns.inact||[]).concat(x.ns.inact_res||[])).filter(function(c){return st.pc[c.ref]}).length;e.classList.toggle('hidden',!ni&&want.length===10);e.innerHTML=(ni?'✓ '+ni+' contacted in the last '+(x.ns.pc_quiet||60)+' days (off the list for now). ':'')+(want.length<10?'<b>That is everyone on this list for now.</b> More come in with the next refresh.':'')}return}
  if(e){e.classList.toggle('hidden',!nc&&want.length===10);e.innerHTML=(nc?'✓ '+nc+' past client'+(nc===1?'':'s')+' contacted in the last '+(x.ns.pc_quiet||60)+' days (off the list for now). ':'')+(want.length<10&&(x.ns.past||[]).length?'<b>That is everyone on your list for now.</b> More come in with the next refresh as clients reach 60 days after the sale.':'')}}
function cbDealRender(x){var S=$('#nstd'),SL=$('#nstdl'),L=$('#nsl');if(!S||!L)return;var st=cbState(x),n=0;
  document.querySelectorAll('#nsl .nsd[data-ref], #nstdl .nsd[data-ref]').forEach(function(el){var r=el.dataset.ref,t=st.deal[r],ch=el.querySelector('.cbdone');
    if(t){if(el.parentNode!==SL)SL.appendChild(el);el.classList.add('tch');n++;if(!ch){ch=document.createElement('span');ch.className='chip g cbdone';el.querySelector('.top').appendChild(ch)}ch.textContent='✓ '+t.a+' '+cbClock(t.t||Date.now())}
    else if(el.parentNode===SL){el.classList.remove('tch','open');if(ch)ch.remove();L.appendChild(el)}});
  S.classList.toggle('hidden',!n);$('#nstdn').textContent=n?'· '+n+' deal'+(n===1?'':'s'):'';if(NS_APPLY)NS_APPLY()}
function cbWireCard(el){el.querySelectorAll('.nscp').forEach(function(b){b.onclick=function(){copy(b.previousElementSibling.textContent)}})}
/* entry helpers (tracker log) */
function cbEntry(x,kind,ref,a,detail){var now=new Date(),F=D.meta.activity_form,c={},cat=null;if(detail==null){CB_ACT.forEach(function(z){if(z[0]===a)cat=z[2]});c[cat]=1}
  var e={id:Date.now()+'-'+Math.random().toString(36).slice(2,7),d:ACT.ymd(now),t:+now,c:c,note:cbNote(kind,ref,a,now,detail),cb:kind};
  if(F){e.w=actWho(x);if(detail==null){e.s='hold';e.hu=+now+CB_HOLD}else e.s='pending'}
  var es=ACT.load(x.slug);es.push(e);if(!ACT.save(x.slug,es))return null;
  actKey(e.w||actWho(x),e).then(function(k){var a2=ACT.load(x.slug);a2.forEach(function(z){if(z.id===e.id)z.k=k});ACT.save(x.slug,a2)},function(){});
  return e}
function cbSend(x){var F=D.meta.activity_form;if(!F)return;ACT.sync(x.slug,F,function(ch){if(ch&&window.ACT_ONSYNC)window.ACT_ONSYNC(x.slug)})}
function cbCommit(x,id){clearTimeout(CB_T[id]);delete CB_T[id];var es=ACT.load(x.slug),hit=false;es.forEach(function(e){if(e.id===id&&e.s==='hold'){e.s='pending';delete e.hu;hit=true}});if(hit){ACT.save(x.slug,es);cbSend(x)}}
/* page closing / hidden inside the Undo window: hand every held tap to the browser with navigator.sendBeacon (the web's built-in "deliver this
   even though the page is going away"; the browser queues it and sends after unload). Beacon accepted -> marked sent. Not available or refused
   -> 'pending' + keepalive fetch now, and the normal retry on the next open. A rare double delivery is the identical row (same tap time) and
   activity_rows.load keeps one. */
function cbFlushAll(){var x=CB_X;if(!x)return;var F=D.meta.activity_form,es=ACT.load(x.slug),hit=false;es.forEach(function(e){if(e.s!=='hold')return;delete e.hu;
    var ok=false;try{ok=!!(F&&e.w&&navigator.sendBeacon&&navigator.sendBeacon(F.url,new URLSearchParams(ACT.payload(F,e.w,e))))}catch(_){ok=false}
    if(ok){e.s='sent';e.sa=Date.now();e.sb=1}else{e.s='pending';hit=true}});ACT.save(x.slug,es);
  Object.keys(CB_T).forEach(function(k){clearTimeout(CB_T[k]);delete CB_T[k]});if(hit){ACT.save(x.slug,es);cbSend(x)}
  if(CB_SHEET&&CB_SHEET.held){CB_SHEET.held=false;var u=$('#cbUndo');if(u)u.remove();var m=$('#cbMsg');if(m)m.textContent=CB_SHEET.done}}
function cbRefresh(x,anim){cbPcRender(x,anim);fuRender(x);cbDealRender(x);if($('#actTotals')&&ACT_CUR)actRender(ACT_CUR)}
/* a tap */
function cbTap(x,btn){var kind=btn.dataset.kind,ref=btn.dataset.ref,a=btn.dataset.cb,card=btn.closest('.nsd');
  var box=card&&card.querySelector('.fu'),pend=box&&(box.querySelector('.futx').value.trim()||box.dataset.ov);
  var e=cbEntry(x,kind,ref,a);if(!e){toast('Could not save on this device (storage is off or full)');return}
  var L=cbLoad(x),prev=L[kind][ref]||null;L[kind][ref]={a:a,d:e.d,t:e.t};cbSave(x,L);
  var fr=pend?fuSave(x,box,e.t,true):null;          /* result / next step typed first: saved with the tap (1 s later, so the note governs) */
  if(e.s==='hold')CB_T[e.id]=setTimeout(function(){cbCommit(x,e.id);if(CB_SHEET&&CB_SHEET.id===e.id){CB_SHEET.held=false;var u=$('#cbUndo');if(u)u.remove();var m=$('#cbMsg');if(m)m.textContent=CB_SHEET.done}},CB_HOLD);
  var what=(kind==='pc'?'Past client #':'Deal #')+ref;
  if(card&&kind==='pc'){card.classList.add('cbout');setTimeout(function(){cbRefresh(x,true)},330)}
  else if(card){card.classList.add('cbout');setTimeout(function(){card.classList.remove('cbout','open');cbRefresh(x,false)},330)}else cbRefresh(x,true);
  cbSheet(x,{id:e.id,t:e.t,kind:kind,ref:ref,a:a,prev:prev,what:what,held:e.s==='hold',fumsg:fr&&fr.msg,done:'✓ '+a+' · '+what+' · logged'+(fr?' · '+fr.msg:'')})}
function cbUndo(x,s){clearTimeout(CB_T[s.id]);delete CB_T[s.id];var es=ACT.load(x.slug),left=es.filter(function(e){return !(e.id===s.id&&e.s==='hold')});
  if(left.length===es.length){toast('Already sent; it can\'t be undone now');return false}
  ACT.save(x.slug,left);var L=cbLoad(x);if(s.prev)L[s.kind][s.ref]=s.prev;else delete L[s.kind][s.ref];cbSave(x,L);cbRefresh(x,true);toast('Undone. Nothing was sent');return true}
/* bottom sheet: Undo (5 s) + optional detail (voice or typing), never blocks the page */
function cbSheet(x,s){var el=$('#cbsheet');if(!el){el=document.createElement('div');el.id='cbsheet';el.setAttribute('role','status');document.body.appendChild(el)}
  if(CB_SHEET&&CB_SHEET.hide)clearTimeout(CB_SHEET.hide);CB_SHEET=s;
  el.innerHTML='<div class="cbrow"><span id="cbMsg">✓ '+esc(s.a)+' · '+esc(s.what)+'</span>'+(s.held?'<button type="button" class="cbu" id="cbUndo">Undo <span id="cbCd">5</span></button>':'')+'<button type="button" class="cbx" id="cbClose" aria-label="Close">✕</button></div>'+
    (s.nodet?'':s.fumsg?'<div class="small cbfu">📝 '+esc(s.fumsg)+'</div>':'<button type="button" class="cbdet" id="cbDet">＋ Add result / next step (optional): voice or typing</button><div id="cbBox" class="hidden">'+fuBox(s.kind,s.ref)+
    '<div class="fine" style="margin:2px 0 0">No last names or phone numbers, please: this goes to Andrew\'s activity log with the record number. The date under the box decides when this client comes back on your page.</div></div>')+'';
  el.classList.remove('hidden');
  var cd=5,iv=s.held?setInterval(function(){cd--;var c=$('#cbCd');if(!c||cd<=0||CB_SHEET!==s){clearInterval(iv);return}c.textContent=cd},1000):null;
  var u=$('#cbUndo');if(u)u.onclick=function(){clearInterval(iv);if(cbUndo(x,s))cbClose()};
  $('#cbClose').onclick=function(){cbClose()};
  function arm(){if(s.hide)clearTimeout(s.hide);s.hide=setTimeout(function(){if(CB_SHEET===s&&(!$('#cbBox')||$('#cbBox').classList.contains('hidden'))&&!s.held)cbClose();else if(CB_SHEET===s)arm()},s.nodet?7000:14000)}arm();
  if(s.nodet)return;
  if(s.fumsg)return;
  $('#cbDet').onclick=function(){$('#cbDet').classList.add('hidden');$('#cbBox').classList.remove('hidden');clearTimeout(s.hide);var b=$('#cbBox .fu');fuPaint(CB_X||x);var t=b&&b.querySelector('.futx');if(t)t.focus({preventScroll:true})}}
/* ── Don't contact (Andrew, Oct 22, 2026, 4:41 PM). "🚫 Don't contact" on every past-client card (designer pages + owner view):
   confirm dialog with an optional reason (voice or typing, phone numbers / emails masked like detail rows) -> one Activity form row with
   ALL counts 0 and the note "[pc] Past client #<ref> - Do not contact" (+ " - reason: <text>"), held CB_HOLD ms with the same Undo as the
   contact buttons (nothing is sent inside that window). The card leaves at once and the next one comes up from the reserve. The build
   (nextsteps.py) then removes that household (ClosetWare account) from EVERY designer's list for good, until Andrew restores it
   (raw/dnc_restore.json). Never a contact: 0 counts, and the tracker / owner dashboard / tap counts skip it. ── */
function cbDncAsk(x,btn){var ref=btn.dataset.ref,card=btn.closest('.nsd');cbDncClose();var el=document.createElement('div');el.id='cbdlg';el.setAttribute('role','dialog');el.setAttribute('aria-modal','true');el.setAttribute('aria-labelledby','cbdlgT');
  el.innerHTML='<div class="cbdlgb"><b id="cbdlgT">🚫 Don\'t contact past client #'+esc(ref)+'?</b><p class="small" style="margin:6px 0 8px">They leave your list for good, and every designer\'s list (the same household too). Andrew sees it on his page and can restore it. Nothing is sent to the client.</p>'+
   '<div class="cbmicw"><button type="button" class="mic sm" id="cbdMic" aria-label="Tap and speak">🎤</button><span class="small" id="cbdMicS">Reason (optional): tap the mic and say it, or type below.</span></div>'+
   '<textarea id="cbdTxt" rows="2" maxlength="400" placeholder="e.g. Asked not to be contacted again. Moved out of state."></textarea><div class="fine" style="margin:2px 0 8px">No last names or phone numbers, please: the reason goes to Andrew\'s activity log with the record number.</div>'+
   '<div class="cbdlgbtn"><button type="button" class="btn ghost" id="cbdNo">Cancel</button><button type="button" class="btn cbdyes" id="cbdYes">🚫 Don\'t contact</button></div></div>';
  document.body.appendChild(el);cbDictate($('#cbdMic'),$('#cbdTxt'),$('#cbdMicS'));
  $('#cbdNo').onclick=cbDncClose;el.onclick=function(ev){if(ev.target===el)cbDncClose()};
  $('#cbdYes').onclick=function(){var r=cbMask($('#cbdTxt').value);cbDncClose();cbDnc(x,ref,r,card)}}
function cbDncClose(){var el=$('#cbdlg');if(el)el.remove()}
function cbDnc(x,ref,reason,card){var now=new Date(),F=D.meta.activity_form;
  var e={id:Date.now()+'-'+Math.random().toString(36).slice(2,7),d:ACT.ymd(now),t:+now,c:{},note:'[pc] Past client #'+ref+' - Do not contact'+(reason?' - reason: '+reason:''),cb:'pc',dnc:1};
  if(F){e.w=actWho(x);e.s='hold';e.hu=+now+CB_HOLD}
  var es=ACT.load(x.slug);es.push(e);if(!ACT.save(x.slug,es)){toast('Could not save on this device (storage is off or full)');return}
  actKey(e.w||actWho(x),e).then(function(k){var a2=ACT.load(x.slug);a2.forEach(function(z){if(z.id===e.id)z.k=k});ACT.save(x.slug,a2)},function(){});
  var L=cbLoad(x);L.dnc[ref]={d:e.d,t:e.t};cbSave(x,L);
  if(e.s==='hold')CB_T[e.id]=setTimeout(function(){cbCommit(x,e.id);if(CB_SHEET&&CB_SHEET.id===e.id){CB_SHEET.held=false;var u=$('#cbUndo');if(u)u.remove();var m=$('#cbMsg');if(m)m.textContent=CB_SHEET.done}},CB_HOLD);
  if(card){card.classList.add('cbout');setTimeout(function(){cbRefresh(x,true)},330)}else cbRefresh(x,true);
  var what='Past client #'+ref;cbSheet(x,{id:e.id,kind:'dnc',ref:ref,a:'Don\'t contact',prev:null,what:what,held:e.s==='hold',nodet:true,done:'🚫 Don\'t contact · '+what+(F?' · sent to Andrew':' · saved')})}
function cbClose(){var el=$('#cbsheet');if(el){el.classList.add('hidden');el.innerHTML=''}if(CB_SHEET&&CB_SHEET.hide)clearTimeout(CB_SHEET.hide);CB_SHEET=null}
/* voice to text for the detail box (same Web Speech API setup as the tracker's mic; keyboard 🎤 always works too) */
function cbDictate(mic,txt,S,done){if(!ACT.speechOK()){mic.classList.add('hidden');S.textContent='Type below, or use your keyboard\'s 🎤 to dictate.';return}
  var R=window.SpeechRecognition||window.webkitSpeechRecognition,rec=null,base='';
  mic.onclick=function(){if(rec){try{rec.stop()}catch(e){}return}try{rec=new R()}catch(e){mic.classList.add('hidden');S.textContent='Type below, or use your keyboard\'s 🎤.';return}
    rec.lang='en-US';rec.interimResults=true;rec.continuous=false;base=txt.value.trim();
    rec.onstart=function(){mic.classList.add('on');S.textContent='Listening… tap again to stop'};
    rec.onresult=function(ev){var f='';for(var i=0;i<ev.results.length;i++)f+=ev.results[i][0].transcript;txt.value=(base?base+' ':'')+f.trim();try{txt.dispatchEvent(new Event('input',{bubbles:true}))}catch(e){}};
    rec.onerror=function(ev){S.textContent=ev.error==='not-allowed'?'Microphone access is off for this site. Type, or use your keyboard\'s 🎤.':'Voice stopped. You can type instead.'};
    rec.onend=function(){mic.classList.remove('on');rec=null;if(done)done();else if(txt.value.trim())S.textContent='Got it. Tap Save detail.'};
    try{rec.start()}catch(e){rec=null;S.textContent='Voice could not start. You can type instead.'}}}
function cbWire(x){CB_X=x;cbPcRender(x,false);fuRender(x);cbDealRender(x);fuWire();
  if(!cbWire.on){cbWire.on=1;
    document.addEventListener('click',function(ev){var dn=ev.target.closest&&ev.target.closest('.cbdnc');if(dn&&CB_X){ev.preventDefault();cbDncAsk(CB_X,dn);return}
      var b=ev.target.closest&&ev.target.closest('.cbt');if(b&&CB_X){ev.preventDefault();cbTap(CB_X,b);return}
      var h=ev.target.closest&&ev.target.closest('#nstdl .nsd.tch .top, #nssl .nsd.tch .top');if(h&&!ev.target.closest('input')){h.parentNode.classList.toggle('open')}});
    window.addEventListener('pagehide',cbFlushAll);document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')cbFlushAll()})}}
/* owner: 30,000-ft roll-up */
function nsOwner(){var N=D.owner&&D.owner.ns;if(!N)return'';var pc=N.promo_cnt,mx=Math.max.apply(null,N.types.map(function(t){return t.usd}).concat([1])),h='';
  h+='<div class="card" style="border-left:5px solid #12263f"><b>Top 3 things to know</b><ol class="small" style="margin:6px 0 0;padding-left:20px">'+N.top3.map(function(t){return '<li style="margin:4px 0">'+esc(t)+'</li>'}).join('')+'</ol></div>';
  h+='<div class="grid">'+tile('In play',m0(N.usd),N.n+' open quotes · roster designers · every one gets one next step','neu')+tile('$ at risk',m0(N.risk_usd),pc0(N.risk_usd,N.usd)+' of in play · no dated note in 14+ days and no dated next step',N.risk_usd>0?'neg':'pos')+
   tile('Quiet 14+ days',n0(N.nodate_n),m0(N.nodate_usd)+' with no dated note in 14+ days','neg')+tile('Showroom invites',n0(pc.showroom_deals),m0(pc.showroom_usd)+' over $5,000 · plus '+pc.scope_deals+' at $2,500-$4,999 ('+m0(pc.scope_usd)+') where added scope may fit','neu')+
   tile('Lowe\'s 18-mo eligible',n0(pc.lowes_deals)+' deals',m0(pc.lowes_usd)+' · plus '+pc.lowes_past+' past clients on the October call lists','neu')+tile('Past clients to call',n0(pc.past),'top 10 per designer from '+pc.past_pool+' sold clients (last 24 months, 60+ days after sale; older years when a list runs low)','neu')+'</div>';
  h+='<div class="card"><b>$ by recommended next step</b><div style="margin-top:8px">'+N.types.map(function(t){return '<div class="nst"><div class="nstl"><span>'+esc(t.label)+'</span><b>'+m0(t.usd)+' <span class="small">('+t.n+')</span></b></div><div class="tb"><i style="width:'+(t.usd/mx*100).toFixed(1)+'%"></i></div></div>'}).join('')+'</div></div>';
  h+='<div class="card"><b>$ at risk by designer</b> <span class="small">most dollars at risk first · tap a row to open the page</span><div class="tw"><table><thead><tr><th>Designer</th><th>In play</th><th>$ at risk</th><th>Quiet 14+ d</th><th>Showroom</th><th>Lowe\'s deals / past</th><th>Past clients</th><th>Top next step</th></tr></thead><tbody>'+
   N.designers.map(function(r){return '<tr class="click" data-s="'+r.slug+'"><td>'+esc(r.name)+'</td><td>'+m0(r.usd)+' <span class="small">('+r.n+')</span></td><td class="'+(r.risk_usd>0?'neg':'neu')+'">'+m0(r.risk_usd)+'</td><td class="'+(r.nodate_n?'neg':'neu')+'">'+r.nodate_n+'</td><td>'+r.showroom+'</td><td>'+r.lowes_deals+' / '+r.lowes_past+'</td><td>'+r.past+' <span class="small">of '+r.past_pool+'</span></td><td class="small">'+(r.top?esc(r.top.label)+' ('+mk(r.top.usd)+')':'–')+'</td></tr>'}).join('')+'</tbody></table></div>'+
   '<details style="margin-top:8px"><summary class="small">Strengths and habits by designer</summary><ul class="tight small">'+N.designers.map(function(r){return '<li><b>'+esc(r.name)+'</b>: <span class="pos">'+r.strengths.map(esc).join('; ')+'</span>'+(r.habits.length?' · <span class="neg">'+r.habits.map(esc).join('; ')+'</span>':'')+'</li>'}).join('')+'</ul></details></div>';
  h+=inOwner(N.inact);
  h+=fuOwner();
  h+=nsDnc(N.dnc);
  h+=nsPromo(N.promo,true);
  h+='<p class="small" style="margin:4px 2px 10px">📱 The past-client text template on every designer page is modeled on Angela\'s past-client text (Teams Design Team chat, Oct 22). The $5,000 threshold is enforced: every text says "free color upgrade on agreements over $5,000 when you visit our Fanwood showroom", with no end date and no phone numbers (clients already have your cell because you text from it).</p>';
  h+='<p class="fine">$ at risk = open quote with no dated note in 14+ days AND no dated next step (note date, follow-up date, booked appointment or open task). Lowe\'s customers are identified by ClosetWare lead source type LOWES (Category "Lowes Store"); Lowe\'s 18-mo no interest if paid in full is offered only to them. Rules and sources: playbook section 15. '+N.limits.map(esc).join(' ')+'</p>';
  return sec('nsown','💼 Close this month: 30,000-ft view',h)}
/* owner: clients from designers no longer here + deep-history fallback (Oct 28, 2026). Real counts from the build only. */
function inOwner(I){if(!I)return '';
  var h='<div class="card" style="border-left:5px solid #2f7d5b"><b>👥 Clients from designers no longer here + older history</b> <span class="small">new Oct 28, 2026</span><ul class="tight small" style="margin-top:6px">'+I.lines.map(function(l){return '<li>'+esc(l)+'</li>'}).join('')+'</ul>';
  h+='<div class="grid">'+tile('Callable households',n0(I.households),'of '+n0(I.candidates)+' NJ households a former designer sold','neu')+tile('Assigned to designers',n0(I.assigned),m0(I.usd)+' in past sales','neu')+
     tile('Contacted',n0(I.contacted),'of '+n0(I.assigned)+' assigned (logged taps)','neu')+tile('Reached into older years',n0(I.deep_found||0)+' designers',(I.deep_year?'as far back as '+I.deep_year+' · ':'')+n0(I.deep_added||0)+' older clients added · '+I.deep_n+' ran low (under '+I.fallback_min+' left)','neu')+'</div>';
  h+='<div class="tw"><table><thead><tr><th>Designer</th><th>Assigned</th><th>Showing now</th><th>Past sales</th><th>Contacted</th><th>Own list ran low?</th></tr></thead><tbody>'+I.per.map(function(r){return '<tr class="click" data-s="'+r.slug+'"><td>'+esc(r.name)+'</td><td>'+r.n+'</td><td>'+Math.min(r.left,45)+'</td><td>'+m0(r.usd)+'</td><td>'+r.contacted+'</td><td class="small">'+(r.deep?(r.deep_n?'yes: '+r.deep_n+' older clients back to '+r.deep_year:'yes: no older clients of their own, so a bigger share here'):'no')+'</td></tr>'}).join('')+'</tbody></table></div>';
  var F=(I.former||[]).filter(function(f){return f.hh});
  h+='<details style="margin-top:8px"><summary class="small">Who counts as "no longer here" ('+F.length+' former designers with callable clients)</summary><p class="fine">'+esc(I.rule)+'</p><ul class="tight small">'+F.map(function(f){return '<li><b>'+esc(f.name)+'</b>: '+f.hh+' household'+(f.hh===1?'':'s')+' <span class="fine">('+esc(f.why)+')</span></li>'}).join('')+'</ul>'+
     '<p class="fine">Left out: '+Object.keys(I.excl||{}).map(function(k){return esc(k)+' '+n0(I.excl[k])}).join(' · ')+'. Every designer gets at least '+I.floor+' (most '+I.base+'), capped at '+I.cap+'.</p></details></div>';
  return h}
/* owner: Don't contact list (record #, who blocked it, date, reason). Owner bundle only. */
function nsDnc(Z){var R=(Z&&Z.rows)||[];return '<div class="card nsdnc"><b>🚫 Do not contact list</b> <span class="small">· '+R.length+' past client'+(R.length===1?'':'s')+' · off every designer\'s list (whole household)</span>'+
  (R.length?'<div class="tw"><table><thead><tr><th>Record #</th><th>Blocked by</th><th>Date</th><th>Reason</th></tr></thead><tbody>'+R.map(function(r){var w=String(r.who||'').replace(/ \(owner preview\)$/i,function(){return ' (you, owner preview)'});return '<tr><td class="ref">'+esc(r.ref)+'</td><td>'+esc(w)+'</td><td>'+esc(r.d)+'</td><td class="small">'+(r.reason?esc(r.reason):'<span class="fine">no reason given</span>')+'</td></tr>'}).join('')+'</tbody></table></div>'
   :'<p class="small" style="margin:6px 0 0">Nobody yet. When a designer taps 🚫 Don\'t contact on a past-client card, it shows here after the next activity sync.</p>')+
  '<p class="fine" style="margin-top:6px">Want one back on the lists? Ask Sales Manager to restore it by record number; it returns at the next refresh.'+(Z&&Z.restored?' Restored so far: '+Z.restored+'.':'')+'</p></div>'}
function pc0(a,b){return b?Math.round(a/b*100)+'%':'–'}
/* ── Follow-up notes (Andrew, Oct 25, 2026). Every record on a designer page (open quotes, past clients incl. the ones that slide in,
   Opps to fix, focus deals, the "Follow up today" pins, the owner drill-downs) carries one "Result / next step" box: type or dictate what
   happened, e.g. "let's follow up tomorrow". site/followup.js turns the words into the next follow-up date (Eastern time, no outside
   service; chips / date picker override; nothing found -> open quote 3 business days, past client 30 days, and the page says so).
   Save = one tracker entry with ALL counts 0 (never a contact, never a day logged), note
     "[pc] Past client #<ref> - note [fu 2026-10-26]: <masked text> (14:05:09)"  ([fu none] = No date),
   stored on this device at once and sent through the same Activity Google Form (no new field: the Sheet keeps its 5 columns).
   Rule per record: the latest note governs while no tap is newer (same-day HH:MM:SS from the note text; a note typed into the box before
   a tap is saved 1 s after that tap). Governing + date later -> off its list (past client) / into "📅 Scheduled" (quote) until then;
   on/after the date -> pinned under "📌 Follow up today" at the top of the page, overdue first in amber, with the note, until a new note or
   tap. A tap after the note replaces it (normal tap rules). No date -> just shows the text. Don't contact always wins. The build
   (nextsteps.fu_state) applies the same rule from the Sheet rows, so phone and computer agree after the next sync. ── */
var FU_CUR={};
function fuToday(){return FU.etToday()}
function fuState(x){var N=x.ns||{},note={},tap={},srv=N.fu||{};
  function nt(ref,v){var o=note[ref],w=v.d+' '+v.h;if(o&&w<o.d+' '+o.h)return;if(o&&w===o.d+' '+o.h){if(o.sg!=null)v.sg=o.sg;if(!v.f&&o.f)return}note[ref]=v}
  function tp(ref,d,h){var w=d+' '+h;if(!tap[ref]||w>tap[ref])tap[ref]=w}
  Object.keys(srv).forEach(function(r){var v=srv[r];nt(r,{k:v.k,d:v.d,h:v.h,n:v.n,f:v.f,sg:v.g?1:0})});
  function row(n,d){var a=FU.read(n);if(a){nt(a.ref,{k:a.k,d:d,h:a.h,n:a.n,f:a.f});return}var b=FU.tap(n);if(b)tp(b.ref,d,b.h)}
  ((x.activity&&x.activity.rows)||[]).forEach(function(r){row(r.n,r.d)});
  ACT.load(x.slug).concat(actArch(x.slug)).forEach(function(e){row(e.note,e.d)});
  var L=cbLoad(x);['pc','deal'].forEach(function(k){Object.keys(L[k]).forEach(function(r){var o=L[k][r];if(o.t)tp(r,o.d,cbHms(new Date(o.t)))})});
  Object.keys(note).forEach(function(r){var v=note[r];v.g=!!(v.f&&v.sg!==0&&(!tap[r]||v.d+' '+v.h>=tap[r]))});
  return note}
function fuFind(x,ref){var N=x.ns||{},a=[].concat(N.fu_recs||[],N.past||[],N.past_res||[],N.inact||[],N.inact_res||[]);for(var i=0;i<a.length;i++)if(a[i].ref===ref)return{k:'pc',c:a[i]};
  var ds=N.deals||[];for(i=0;i<ds.length;i++)if(ds[i].ref===ref)return{k:'deal',p:ds[i]};
  var o=(x.deals||[]).concat.apply(x.deals||[],(x.focus||[]).map(function(f){return f.deals||[]}));for(i=0;i<o.length;i++)if(o[i].ref===ref)return{k:'deal',m:o[i]};return null}
function fuBox(kind,ref,fold){return '<div class="fu" data-kind="'+kind+'" data-ref="'+esc(ref)+'"><div class="fulast hidden"></div>'+(fold?'<details class="fufold"><summary>📝 Result / next step</summary>':'')+
  '<div class="furow"><textarea class="futx" rows="1" maxlength="400" enterkeyhint="done" autocapitalize="sentences" aria-label="Result and next step" placeholder="Result / next step…"></textarea><button type="button" class="mic sm fumic" aria-label="Tap and speak">🎤</button><button type="button" class="btn fusv">Save</button></div>'+
  '<div class="fumore"><div class="fupv"></div><div class="fuch">'+FU.CHIPS.map(function(c){return '<button type="button" class="fuc" data-c="'+c[1]+'">'+c[0]+'</button>'}).join('')+'<input type="date" class="fudt" aria-label="Pick a follow-up date"></div></div>'+(fold?'</details>':'')+'</div>'}
function fuMini(x,ref,m){return '<div class="nsd fum" data-fref="'+esc(ref)+'"><div class="top"><span><b>'+esc(m.name||'(no first name)')+'</b> <span class="ref">'+esc(ref)+'</span></span><span class="amt">'+m0(m.usd||0)+'</span></div>'+ctLine(m)+
  '<div class="small nsm">Open quote'+(m.stage?' · '+esc(m.stage):'')+(m.src?' · '+esc(m.src):'')+'</div>'+cbBtns('deal',ref)+fuBox('deal',ref)+'</div>'}
function fuPick(box){var ov=box.dataset.ov||'',k=box.dataset.kind,t=cbMask(box.querySelector('.futx').value),td=fuToday();
  if(ov==='none')return{d:null,src:'chip',t:t};if(ov)return{d:ov,src:'chip',t:t};var p=FU.parse(t,td,k);return{d:p.d,src:p.src,why:p.why,t:t}}
function fuPreview(box){var pv=box.querySelector('.fupv'),tx=box.querySelector('.futx'),td=fuToday(),has=!!tx.value.trim()||!!box.dataset.ov;
  box.classList.toggle('fuopen',has||box.contains(document.activeElement));
  [].forEach.call(box.querySelectorAll('.fuc'),function(b){b.classList.toggle('on',(box.dataset.ovc||'')===b.dataset.c)});
  if(!has){pv.innerHTML='<span class="fine">Say or type what happened and when, e.g. "call back Friday" or "follow up in 2 weeks". Or pick a date:</span>';return}
  var p=fuPick(box),w=p.d?'<b>Next follow-up: '+esc(FU.label(p.d,td))+'</b> <span class="fine">('+esc(FU.rel(p.d,td))+')</span>':'<b>No follow-up date</b>';
  pv.innerHTML=w+' <span class="fine">'+(p.src==='chip'?'· you picked it':p.src==='parsed'?'· from your note':p.src==='default'?'· nothing in the note says when, so '+esc(p.why)+'. Pick a date to change it.':p.src==='none'?'· '+esc(p.why||'')+'. Pick a date if you want one.':'')+'</span>'}
function fuEntry(x,kind,ref,d,text,at){var F=D.meta.activity_form,e={id:Date.now()+'-'+Math.random().toString(36).slice(2,7),d:ACT.ymd(at),t:+at,c:{},note:FU.note(kind,ref,d,text,at),cb:kind,fu:1};
  if(F){e.w=actWho(x);e.s='pending'}var es=ACT.load(x.slug);es.push(e);if(!ACT.save(x.slug,es))return null;
  actKey(e.w||actWho(x),e).then(function(k){var a2=ACT.load(x.slug);a2.forEach(function(z){if(z.id===e.id)z.k=k});ACT.save(x.slug,a2)},function(){});return e}
/* save the box; after = tap time (ms) when saved together with a tap: the note is stamped 1 s later so it governs */
function fuSave(x,box,after,quiet){var p=fuPick(box),td=fuToday();if(!p.t&&!box.dataset.ov){if(!quiet)toast('Type or say the result first');return null}
  var at=new Date();if(after&&+at<=after)at=new Date(after+1000);
  var e=fuEntry(x,box.dataset.kind,box.dataset.ref,p.d,p.t,at);if(!e){toast('Could not save on this device (storage is off or full)');return null}
  box.querySelector('.futx').value='';delete box.dataset.ov;delete box.dataset.ovc;var dt=box.querySelector('.fudt');if(dt)dt.value='';box.classList.remove('fuopen');
  cbSend(x);var msg=(p.d?'Next follow-up '+FU.label(p.d,td):'Note saved, no follow-up date')+(D.meta.activity_form?' · sent to Andrew':' · saved');
  if(!quiet)toast(msg);if(!after)fuRefreshAll(x);return {e:e,d:p.d,msg:msg}}
function fuLast(v,td){if(!v)return'';var s=v.g?FU.status(v.f,td):'',t=v.n?esc(v.n):'<i>(date only)</i>';
  var chip=s==='over'?'<span class="chip a">⚠️ Overdue · was due '+esc(FU.label(v.f,td))+'</span>':s==='due'?'<span class="chip fud">📌 Follow up today</span>':s==='later'?'<span class="chip">📅 Next: '+esc(FU.label(v.f,td))+'</span>':v.f&&!v.g?'<span class="chip g">✓ contacted since</span>':'';
  return chip+' <span class="fun">📝 '+esc(FU.label(v.d,td))+': '+t+'</span>'}
function fuPaint(x){var st=FU_CUR,td=fuToday();document.querySelectorAll('.fu[data-ref]').forEach(function(b){var v=st[b.dataset.ref],l=b.querySelector('.fulast');if(!l)return;
    l.classList.toggle('hidden',!v);l.innerHTML=fuLast(v,td);var s=v&&v.g?FU.status(v.f,td):'';l.className='fulast'+(v?'':' hidden')+(s==='over'?' fuo':'');
    if(!ACT.speechOK()){var m=b.querySelector('.fumic');if(m)m.classList.add('hidden')}fuPreview(b)})}
function fuSort(st,refs){return refs.sort(function(a,b){var x=st[a],y=st[b];return x.f<y.f?-1:x.f>y.f?1:(x.d+x.h<y.d+y.h?-1:1)})}
function fuRender(x){var st=fuState(x),td=fuToday(),cs=cbState(x),due=[],later=[];FU_CUR=st;var F=$('#ful');
  Object.keys(st).forEach(function(r){var v=st[r];if(!v.g||cs.dnc[r]||!fuFind(x,r))return;(v.f<=td?due:later).push(r)});fuSort(st,due);fuSort(st,later);   /* no card = sold, lost or blocked since: skip */
  var NL=$('#nsl'),SL=$('#nssl'),dueS={},latS={};due.forEach(function(r){dueS[r]=1});later.forEach(function(r){latS[r]=1});
  if(F){[].slice.call(F.children).forEach(function(el){var r=el.dataset.ref||el.dataset.pref||el.dataset.fref;if(dueS[r])return;
      if(el.dataset.ref&&NL){el.classList.remove('fuover','fudue');NL.appendChild(el)}else el.remove()});
    due.forEach(function(r){var el=document.querySelector('.nsd[data-ref="'+r+'"]')||F.querySelector('[data-pref="'+r+'"],[data-fref="'+r+'"]');
      if(!el){var f=fuFind(x,r);if(!f)return;var t=document.createElement('div');t.innerHTML=f.k==='pc'?pcCard(f.c,x.ns.promo):fuMini(x,r,f.m||f.p);el=t.firstChild;cbWireCard(el);if(f.p&&!f.m){}}
      el.classList.remove('tch','open');var ch=el.querySelector('.cbdone');if(ch)ch.remove();el.classList.toggle('fuover',st[r].f<td);el.classList.toggle('fudue',st[r].f===td);F.appendChild(el)})}
  if(SL){[].slice.call(SL.children).forEach(function(el){if(!latS[el.dataset.ref]&&NL){el.classList.remove('tch','open','fusch');NL.appendChild(el)}});
    later.forEach(function(r){var el=document.querySelector('#nsl .nsd[data-ref="'+r+'"], #nstdl .nsd[data-ref="'+r+'"]');if(el){var ch=el.querySelector('.cbdone');if(ch)ch.remove();el.classList.add('tch','fusch');el.classList.remove('open');SL.appendChild(el)}});
    var ns=SL.children.length;$('#nssc').classList.toggle('hidden',!ns);$('#nsscn').textContent=ns?'· '+ns+' quote'+(ns===1?'':'s'):''}
  var S=$('#fut');if(S){S.classList.toggle('hidden',!due.length&&!later.length);var ov=due.filter(function(r){return st[r].f<td}).length;
    $('#futh').innerHTML=due.length?'<b>'+due.length+' to follow up today</b>'+(ov?' · <span class="fuoc">'+ov+' overdue</span>':'')+'. From your own notes; overdue first. Log what you did (a tap or a new note) and it leaves this list.':'<b>Nothing due today.</b> Your notes have scheduled the ones below; each comes back here on its day.';
    var sc=$('#fuscl');if(sc)sc.innerHTML=later.map(function(r){var v=st[r],f=fuFind(x,r),nm=f?(f.c||f.p||f.m).name:'';return '<div class="fusr"><span class="chip">'+esc(FU.label(v.f,td))+'</span> <b>'+esc(nm||'(no first name)')+'</b> <span class="ref">'+esc(r)+'</span> <span class="small">· '+(v.k==='pc'?'past client':'quote')+' · '+(v.n?esc(v.n):'<i>(date only)</i>')+'</span></div>'}).join('');
    var sd=$('#fusc');if(sd){sd.classList.toggle('hidden',!later.length);$('#fuscn').textContent=later.length}}
  var O=$('#opps');if(O){var os=[].slice.call(O.querySelectorAll('.deal[data-ref]'));os.sort(function(a,b){function k(e){var v=st[e.dataset.ref],g=v&&v.g&&!cs.dnc[e.dataset.ref];return (g?(v.f<=td?'0'+v.f:'2'+v.f):'1')+'|'+String(1e4+ +e.dataset.oi)}return k(a)<k(b)?-1:1});os.forEach(function(e){O.appendChild(e)})}
  fuPaint(x)}
function fuRefreshAll(x){cbPcRender(x,false);fuRender(x);cbDealRender(x);if($('#actTotals')&&ACT_CUR)actRender(ACT_CUR)}
function fuWire(){if(fuWire.on)return;fuWire.on=1;
  document.addEventListener('input',function(ev){var b=ev.target.closest&&ev.target.closest('.fu');if(b&&ev.target.classList.contains('futx')){ev.target.style.height='auto';ev.target.style.height=Math.min(ev.target.scrollHeight,140)+'px';fuPreview(b)}});
  document.addEventListener('focusin',function(ev){var b=ev.target.closest&&ev.target.closest('.fu');if(b){b.classList.add('fuopen');fuPreview(b)}});
  document.addEventListener('focusout',function(ev){var b=ev.target.closest&&ev.target.closest('.fu');if(b)setTimeout(function(){fuPreview(b)},150)});
  document.addEventListener('keydown',function(ev){if(ev.key==='Enter'&&!ev.shiftKey&&ev.target.classList&&ev.target.classList.contains('futx')){ev.preventDefault();var b=ev.target.closest('.fu');if(b)fuSaveBtn(b)}});
  document.addEventListener('change',function(ev){if(!ev.target.classList||!ev.target.classList.contains('fudt'))return;var b=ev.target.closest('.fu');if(!b)return;if(ev.target.value){b.dataset.ov=ev.target.value;b.dataset.ovc=''}else{delete b.dataset.ov;delete b.dataset.ovc}fuPreview(b)});
  document.addEventListener('click',function(ev){var t=ev.target.closest&&ev.target.closest('.fuc,.fusv,.fumic');if(!t)return;var b=t.closest('.fu');if(!b)return;
    if(t.classList.contains('fuc')){ev.preventDefault();if(b.dataset.ovc===t.dataset.c){delete b.dataset.ov;delete b.dataset.ovc}else{b.dataset.ovc=t.dataset.c;b.dataset.ov=t.dataset.c==='none'?'none':FU.chip(t.dataset.c,fuToday())}var dt=b.querySelector('.fudt');if(dt)dt.value=b.dataset.ov&&b.dataset.ov!=='none'?b.dataset.ov:'';fuPreview(b);return}
    if(t.classList.contains('fusv')){ev.preventDefault();fuSaveBtn(b);return}
    if(t.classList.contains('fumic')&&!t.dataset.w){t.dataset.w=1;cbDictate(t,b.querySelector('.futx'),b.querySelector('.fupv'),function(){fuPreview(b)});if(t.onclick)t.onclick()}})}
function fuSaveBtn(b){var x=CB_X;if(!x)return;if(b.closest('#cbsheet')&&CB_SHEET){var s=CB_SHEET;if(s.held){cbCommit(x,s.id);s.held=false}var r=fuSave(x,b,s.t);if(r){fuRefreshAll(x);cbClose();toast(r.msg)}return}fuSave(x,b)}
/* owner: follow-ups due / overdue / scheduled per designer (recomputed with the real date from each designer's notes) */
function fuOwner(){var td=fuToday(),rows=(D.designers||[]).map(function(x){var st=fuState(x),c={name:x.name,slug:x.slug,due:0,over:0,later:0,top:null};
    Object.keys(st).forEach(function(r){var v=st[r];if(!v.g||!fuFind(x,r))return;var s=FU.status(v.f,td);c[s==='over'?'over':s==='due'?'due':'later']++;if(s!=='later'&&(!c.top||v.f<c.top.f))c.top=v});return c}).filter(function(c){return c.due||c.over||c.later});
  rows.sort(function(a,b){return (b.over-a.over)||(b.due-a.due)||(b.later-a.later)});var to=0,tu=0;rows.forEach(function(r){to+=r.over;tu+=r.due});
  return '<div class="card" id="furoll"><b>📌 Follow-ups by designer</b> <span class="small">from the result / next-step notes designers save on their cards · tap a row to open the page</span>'+
  (rows.length?'<div class="tw" style="margin-top:8px"><table><thead><tr><th>Designer</th><th>Due today</th><th>Overdue</th><th>Scheduled ahead</th><th>Oldest due note</th></tr></thead><tbody>'+rows.map(function(r){return '<tr class="click" data-s="'+r.slug+'"><td>'+esc(r.name)+'</td><td class="neu">'+r.due+'</td><td class="'+(r.over?'fuoc':'neu')+'">'+r.over+'</td><td>'+r.later+'</td><td class="small">'+(r.top?esc(FU.label(r.top.f,td))+': '+esc(String(r.top.n||'').slice(0,60)):'–')+'</td></tr>'}).join('')+'</tbody></table></div>'+
   '<p class="fine" style="margin:6px 0 0">'+tu+' due today · '+to+' overdue across the team. Overdue = the date in the designer\'s note has passed and nothing was logged on that record since. Notes never count as contacts.</p>'
   :'<p class="small" style="margin:6px 0 0">No follow-up notes yet. When a designer saves a result / next step on a card, it shows here after the next activity sync.</p>')+'</div>'}
function fuSection(x){if(!x.ns)return'';return '<section class="sec hidden" id="fut"><h2>📌 Follow up today</h2><div class="card fucard"><p class="small" id="futh" style="margin:0 0 8px"></p><div id="ful"></div>'+
  '<details id="fusc" class="hidden"><summary class="small"><b>📅 Scheduled by your notes (<span id="fuscn">0</span>)</b></summary><div id="fuscl"></div><p class="fine">Each one comes back here on its date. A new note or a tap on that record replaces the date.</p></details></div></section>'}
