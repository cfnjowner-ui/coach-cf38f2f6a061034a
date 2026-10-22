/* CFNJ Designer Coach: activity tracker (voice or typing). Entries live in this browser's localStorage, keyed per designer, and each saved
   entry is also POSTed to Andrew's Google Form (config: coach.py ACTIVITY_FORM -> D.meta.activity_form). Sync status per entry: s='pending'|'sent'
   (entries saved before sync existed have no s and are not back-filled). s='hold' = contact-button tap inside its 5 s Undo window
   (app.js cbTap); sync() sends it once hu has passed. Pending entries retry on page load and on the browser 'online' event.
   Deletes stay local (not propagated). No tokens or secrets here (form/entry ids are public). Parser is pure (ACT.parse) so it can be tested without a browser. */
'use strict';
var ACT=(function(){
var CATS=[{k:'calls',l:'Calls',i:'📞'},{k:'texts',l:'Texts / emails',i:'💬'},{k:'followups',l:'Follow-ups',i:'🔁'},{k:'appts',l:'Appointments held',i:'🏠'},
  {k:'quotes',l:'Quotes / proposals sent',i:'📄'},{k:'showroom',l:'Showroom visits',i:'🏬'},{k:'leads',l:'Referrals asked / own leads',i:'🌱'},{k:'closes',l:'Closes',i:'✅'}];
var NUM={one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,ten:10,eleven:11,twelve:12,thirteen:13,fourteen:14,fifteen:15,sixteen:16,seventeen:17,eighteen:18,nineteen:19,twenty:20,thirty:30,forty:40,fifty:50,couple:2,pair:2,dozen:12,once:1,twice:2};
/* word -> category (nouns and verbs). Order of checks in catOf() handles compounds. */
var RX={showroom:/^showrooms?$/,followups:/^(followups?|followedup|checkins?|checkedin)$/,quotes:/^(quotes?|quoted|proposals?|estimates?|bids?)$/,
  appts:/^(appointments?|appts?|inhomes?|consults?|consultations?|measures?|meetings?|visits?|presentations?|met)$/,leads:/^(referrals?|leads?|dcls?|referred)$/,
  closes:/^(closes?|closed|sales?|sold|signed|deals?|deposits?|contracts?)$/,texts:/^(texts?|texted|texting|emails?|emailed|emailing|messages?|messaged|sms)$/,
  calls:/^(calls?|called|calling|phoned|dials?|dialed|voicemails?)$/};
var VERB={called:'calls',calling:'calls',phoned:'calls',dialed:'calls',texted:'texts',emailed:'texts',messaged:'texts',followedup:'followups',checkedin:'followups',
  quoted:'quotes',sold:'closes',closed:'closes',signed:'closes',met:'appts',referred:'leads'};
function catOf(w){if(RX.showroom.test(w))return'showroom';for(var k in RX){if(RX[k].test(w))return k}return null}
function norm(t){return String(t||'').toLowerCase().replace(/[’']/g,'').replace(/follow[\s-]*ups?\b/g,'followup').replace(/followed[\s-]+up/g,'followedup')
  .replace(/check(ed)?[\s-]+in(s)?\b/g,function(m,a,b){return a?'checkedin':'checkin'+(b||'')}).replace(/in[\s-]+home/g,'inhome').replace(/designer[\s-]*created(\s+leads?)?/g,'dcl').replace(/self[\s-]*gen(erated)?(\s+leads?)?/g,'dcl')
  .replace(/\bsales\s+calls?\b/g,'calls').replace(/\bphone\s+calls?\b/g,'calls')}
function numOf(w,next,next2){if(/^\d+$/.test(w))return parseInt(w,10);if(NUM[w]!=null)return NUM[w];
  if((w==='a'||w==='an'||w==='another')&&(catOf(next||'')||catOf(next2||'')))return 1;return null}
/* Parse free text ("called 5 clients, sent 3 follow-up texts, 1 showroom visit") into counts. Returns {counts, hits:[{n,cat,phrase}]}. */
function parse(text){var counts={},hits=[];CATS.forEach(function(c){counts[c.k]=0});
  var clauses=norm(text).split(/[,;.\n!?]+|\band\b|\bplus\b|\balso\b|\bthen\b/);
  clauses.forEach(function(cl){var w=cl.split(/[^a-z0-9]+/).filter(Boolean),got=false;
    for(var i=0;i<w.length;i++){var n=numOf(w[i],w[i+1],w[i+2]);if(n==null||n<=0||n>500)continue;
      if(w[i]==='a'&&w[i+1]==='couple'){continue}
      if(NUM[w[i]]===2&&(w[i]==='couple'||w[i]==='pair')&&w[i+1]==='of')i++;
      var win=[],cat=null;for(var j=i+1;j<w.length&&j<=i+6;j++){if(numOf(w[j],w[j+1],w[j+2])!=null&&/^\d+$|^(one|two|three|four|five|six|seven|eight|nine|ten)$/.test(w[j]))break;win.push(w[j])}
      if(win.indexOf('followup')>=0)cat='followups';else if(win.indexOf('showroom')>=0||win.indexOf('showrooms')>=0)cat='showroom';
      else{for(var a=0;a<win.length;a++){var c=catOf(win[a]);if(c){var c2=a+1<win.length?catOf(win[a+1]):null;cat=(c2&&!VERB[win[a+1]])?c2:c;break}}}
      if(!cat){for(var b=i-1;b>=0&&b>=i-3;b--){if(VERB[w[b]]){cat=VERB[w[b]];break}var cb=catOf(w[b]);if(cb){cat=cb;break}}}
      if(cat){counts[cat]+=n;got=true;hits.push({n:n,cat:cat,phrase:w.slice(Math.max(0,i-2),i+1+Math.min(win.length,4)).join(' ')})}}
    if(!got){for(var v=0;v<w.length;v++){if(VERB[w[v]]){counts[VERB[w[v]]]+=1;hits.push({n:1,cat:VERB[w[v]],phrase:w.slice(v,v+4).join(' '),implied:true});break}}}});
  return{counts:counts,hits:hits}}
/* ── dates (local) ── */
function ymd(d){return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
function dOf(s){var p=s.split('-');return new Date(+p[0],+p[1]-1,+p[2])}
function monday(d){var x=new Date(d.getFullYear(),d.getMonth(),d.getDate());x.setDate(x.getDate()-((x.getDay()+6)%7));return x}
function sum(es){var t={};CATS.forEach(function(c){t[c.k]=0});es.forEach(function(e){CATS.forEach(function(c){t[c.k]+=+(e.c[c.k]||0)})});return t}
function touches(t){return t.calls+t.texts+t.followups}
function stats(es,now){now=now||new Date();var td=ymd(now),wk=ymd(monday(now)),mo=td.slice(0,8);
  var T=es.filter(function(e){return e.d===td}),W=es.filter(function(e){return e.d>=wk&&e.d<=td}),M=es.filter(function(e){return e.d.slice(0,8)===mo&&e.d<=td});
  var days={};es.forEach(function(e){days[e.d]=1});var dw=Object.keys(days).filter(function(d){return d>=wk&&d<=td}).length,dm=Object.keys(days).filter(function(d){return d.slice(0,8)===mo&&d<=td}).length;
  var st=0,c=new Date(now.getFullYear(),now.getMonth(),now.getDate());if(!days[ymd(c)])c.setDate(c.getDate()-1);                 /* today not logged yet: streak still counts through yesterday */
  for(var k=0;k<400;k++){if(c.getDay()===0&&!days[ymd(c)]){c.setDate(c.getDate()-1);continue}if(!days[ymd(c)])break;st++;c.setDate(c.getDate()-1)}  /* Sundays off never break a streak */
  var wd=((now.getDay()+6)%7);return{today:sum(T),week:sum(W),month:sum(M),daysWeek:dw,daysMonth:dm,streak:st,workLeft:Math.max(1,6-wd),weekStart:wk}}
function summary(name,es,tg,now){now=now||new Date();var s=stats(es,now),w=s.week,L=[name.split(' ')[0]+'\'s activity, week of '+dOf(s.weekStart).toLocaleDateString('en-US',{month:'short',day:'numeric'})+' (through '+now.toLocaleDateString('en-US',{weekday:'short',month:'short',day:'numeric'})+')'];
  CATS.forEach(function(c){L.push(c.l+': '+w[c.k])});
  L.push('Touches (calls + texts/emails + follow-ups): '+touches(w)+(tg&&tg.touches?' of '+tg.touches+' suggested':''));
  L.push('Days logged this week: '+s.daysWeek+' · streak: '+s.streak+' day'+(s.streak===1?'':'s'));
  var wk=s.weekStart,notes=es.filter(function(e){return e.d>=wk&&e.note}).map(function(e){return '- '+e.d.slice(5).replace('-','/')+': '+e.note.replace(/\s+/g,' ').slice(0,160)});
  if(notes.length)L.push('Notes:\n'+notes.join('\n'));return L.join('\n')}
/* ── storage ── */
function key(slug){return 'cfnj_activity_v1_'+slug}
function load(slug){try{var a=JSON.parse(localStorage.getItem(key(slug))||'[]');return Array.isArray(a)?a:[]}catch(e){return[]}}
function save(slug,a){try{localStorage.setItem(key(slug),JSON.stringify(a));return true}catch(e){return false}}
/* ── central sync (Google Form formResponse; opaque no-cors response: no network error = sent) ── */
var CKEY={calls:'calls',texts:'texts_emails',followups:'followups',appts:'appts',quotes:'quotes',showroom:'showroom',leads:'referrals',closes:'closes'};
function countsStr(c){return CATS.map(function(k){return CKEY[k.k]+'='+(+((c||{})[k.k])||0)}).join('; ')}
function payload(F,who,e){var f=F.fields,p={};p[f.designer]=who;p[f.date]=e.d;p[f.counts]=countsStr(e.c);p[f.note]=e.note||'';return p}
function enc(p){return Object.keys(p).map(function(k){return encodeURIComponent(k)+'='+encodeURIComponent(p[k])}).join('&')}
function postForm(url,p){                                    /* resolves on send, rejects on network error / timeout */
  if(typeof fetch==='function'){var tm;return Promise.race([
      fetch(url,{method:'POST',mode:'no-cors',credentials:'omit',keepalive:true,headers:{'Content-Type':'application/x-www-form-urlencoded'},body:enc(p)}),
      new Promise(function(_,rej){tm=setTimeout(function(){rej(new Error('timeout'))},25000)})]).then(function(r){clearTimeout(tm);return r},function(e){clearTimeout(tm);throw e})}
  return new Promise(function(res,rej){try{                   /* fallback without fetch: hidden form into a hidden iframe */
    var n='actf'+Date.now()+Math.floor(Math.random()*1e6),ifr=document.createElement('iframe'),fm=document.createElement('form');
    ifr.name=n;ifr.style.display='none';fm.method='POST';fm.action=url;fm.target=n;fm.style.display='none';
    Object.keys(p).forEach(function(k){var i=document.createElement('input');i.type='hidden';i.name=k;i.value=p[k];fm.appendChild(i)});
    var done=false;ifr.onload=function(){if(done)return;done=true;res();setTimeout(function(){ifr.remove();fm.remove()},1000)};
    document.body.appendChild(ifr);document.body.appendChild(fm);fm.submit();setTimeout(function(){if(!done){done=true;rej(new Error('timeout'))}},25000)}catch(e){rej(e)}})}
var INFLIGHT={},FKEY='cfnj_activity_form_v1';
/* Send every pending entry of one designer (Designer field = e.w, the name stored with the entry at save time). back(changed) when done. */
function sync(slug,F,back){if(!F||!F.url){back&&back(false);return}
  if(typeof navigator!=='undefined'&&navigator.onLine===false){back&&back(false);return}
  var all=load(slug),now=Date.now(),hu=false;all.forEach(function(e){if(e.s==='hold'&&!(e.hu>now)){e.s='pending';delete e.hu;hu=true}});if(hu)save(slug,all);  /* contact-button taps: an Undo window that ran out (or a closed page) = send */
  var todo=all.filter(function(e){return e.s==='pending'&&e.w&&!INFLIGHT[e.id]});if(!todo.length){back&&back(false);return}
  var left=todo.length,changed=false;todo.forEach(function(e){INFLIGHT[e.id]=1;
    postForm(F.url,payload(F,e.w,e)).then(function(){var a=load(slug);a.forEach(function(z){if(z.id===e.id){z.s='sent';z.sa=Date.now()}});save(slug,a);changed=true},function(){})
    .then(function(){delete INFLIGHT[e.id];if(--left===0)back&&back(changed)})})}
/* Form config is cached in localStorage (not secret) so pending entries retry on page load even before the page is unlocked. */
function setForm(F){try{if(F)localStorage.setItem(FKEY,JSON.stringify(F));else localStorage.removeItem(FKEY)}catch(e){}}
function getForm(){try{return JSON.parse(localStorage.getItem(FKEY)||'null')}catch(e){return null}}
function syncAll(F,back){F=F||getForm();if(!F)return;var slugs=[];try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);if(k&&k.indexOf(key(''))===0)slugs.push(k.slice(key('').length))}}catch(e){return}
  slugs.forEach(function(sl){sync(sl,F,function(ch){if(ch&&back)back(sl)})})}
function pending(es){return es.filter(function(e){return e.s==='pending'}).length}
function speechOK(){return typeof window!=='undefined'&&!!(window.SpeechRecognition||window.webkitSpeechRecognition)}
return{CATS:CATS,countsStr:countsStr,payload:payload,sync:sync,syncAll:syncAll,setForm:setForm,getForm:getForm,pending:pending,parse:parse,stats:stats,summary:summary,touches:touches,load:load,save:save,ymd:ymd,speechOK:speechOK}})();
if(typeof module!=='undefined')module.exports=ACT;
/* retry pending entries on page load and whenever the browser comes back online (app.js re-renders via ACT_ONSYNC) */
if(typeof window!=='undefined'&&window.addEventListener){var actRetry=function(){ACT.syncAll(null,function(sl){if(typeof window.ACT_ONSYNC==='function')window.ACT_ONSYNC(sl)})};
  window.addEventListener('online',actRetry);if(document.readyState==='complete')setTimeout(actRetry,500);else window.addEventListener('load',function(){setTimeout(actRetry,500)})}
