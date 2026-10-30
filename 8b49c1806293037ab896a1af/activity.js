/* CFNJ Designer Coach: activity tracker (voice or typing). Entries live in this browser's localStorage, keyed per designer, and each saved
   entry is also POSTed to Andrew's Google Form (config: coach.py ACTIVITY_FORM -> D.meta.activity_form). Sync status per entry: s='pending'|'sent'
   (entries saved before sync existed have no s and are not back-filled). s='hold' = contact-button tap inside its 5 s Undo window
   (app.js cbTap); sync() sends it once hu has passed. Pending entries retry on page load and on the browser 'online' event.
   Deletes stay local (not propagated). No tokens or secrets here (form/entry ids are public). Parser is pure (ACT.parse) so it can be tested without a browser. */
'use strict';
var ACT=(function(){
var CATS=[{k:'calls',l:'Calls',i:'📞'},{k:'texts',l:'Texts / emails',i:'💬'},{k:'followups',l:'Follow-ups',i:'🔁'},{k:'appts',l:'Appointments held',i:'🏠'},
  {k:'quotes',l:'Quotes / contracts sent',i:'📄'},{k:'showroom',l:'Showroom visits',i:'🏬'},{k:'leads',l:'Referrals asked / own leads',i:'🌱'},{k:'closes',l:'Closes (signed)',i:'✅'},
  {k:'social',l:'Social posts',i:'📱'}];   /* Oct 29, 2026 (Andrew): social media posts. Form key social=N, sent only when N>0 (see countsStr) */
var NUM={one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,ten:10,eleven:11,twelve:12,thirteen:13,fourteen:14,fifteen:15,sixteen:16,seventeen:17,eighteen:18,nineteen:19,twenty:20,thirty:30,forty:40,fifty:50,couple:2,pair:2,dozen:12,once:1,twice:2};
/* word -> category (nouns and verbs). Order of checks in catOf() handles compounds. */
var RX={showroom:/^showrooms?$/,followups:/^(followups?|followedup|checkins?|checkedin)$/,quotes:/^(quotes?|quoted|proposals?|estimates?|bids?|contracts?|agreements?|docusigns?)$/,
  appts:/^(appointments?|appts?|inhomes?|consults?|consultations?|measures?|meetings?|visits?|presentations?|met)$/,leads:/^(referrals?|leads?|dcls?|referred)$/,
  closes:/^(closes?|closed|sales?|sold|signed|deals?|deposits?)$/,texts:/^(texts?|texted|texting|emails?|emailed|emailing|messages?|messaged|sms)$/,
  calls:/^(calls?|called|calling|phoned|dials?|dialed|voicemails?|vms?)$/,
  social:/^(social|socialmedia|instagram|insta|ig|facebook|fb|tiktok|pinterest|houzz|nextdoor|posts?|posted|posting|reels?)$/};
var VERB={called:'calls',calling:'calls',phoned:'calls',dialed:'calls',texted:'texts',emailed:'texts',messaged:'texts',followedup:'followups',checkedin:'followups',
  quoted:'quotes',sold:'closes',closed:'closes',signed:'closes',met:'appts',referred:'leads',posted:'social'};
/* Social posts (Oct 29, 2026): "posted on Instagram / Facebook / social media", "shared a reel on IG", "2 Instagram posts" = 1 (or N) social post. */
var SOCIAL_RX=/\b(posted|posting|post|shared|sharing|reel|story)\b.*\b(instagram|insta|ig|facebook|fb|social|socialmedia|tiktok|pinterest|houzz|nextdoor|linkedin)\b|\b(instagram|insta|ig|facebook|fb|tiktok|pinterest|socialmedia)\s+(post|reel|story)\b/;
function catOf(w){if(RX.showroom.test(w))return'showroom';for(var k in RX){if(RX[k].test(w))return k}return null}
/* ── Parser rules (Oct 22, 2026 fix, Andrew): a number counts ONLY when it directly qualifies an activity noun or verb ("texted 20 clients",
   "3 calls"). Removed before reading: dates (10/22, 10-22, 10/22/2026, Oct 22), times (6pm, 2:30, 12noon, at six, 10 o'clock), money ($50,
   $11,303, 11K), percentages, phone numbers, durations (1 hour, 45 minutes), ordinals (3rd), record #s, decimals, and any pasted client
   message (from "Hi <name>!", "It's <name> from Closet Factory", "This month we're offering", gift-card / reply-here lines on). A pasted
   message that asks for referrals counts as ONE referral ask. Oct 22, 2026 9:17 PM (Andrew): a contract / agreement / proposal / DocuSign SENT
   is a QUOTE; only signed / sold / closed / deposit is a close ("Closes (signed)"). Per entry, a category above CAP is flagged (big) and the page asks to confirm. */
var CAP=50;
var MON='jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?';
var NUMW='one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve';
var SCRIPT_RX=[/(^|[\s.!?\/])(hi|hello|hey|dear|good (?:morning|afternoon|evening))\b[^.!?,:\n\/]{0,30}[!,:]/i,/\bit[’']?s [a-z]+ (?:here )?from closet factory\b/i,
  /\bthis month we[’']?re offering\b/i,/\bif you know (?:a|anyone|someone)\b/i,/\bgift ?cards?\b/i,/\breply here\b/i,/\bthank you again for\b/i,/\b(?:text|call)\s*\/\s*(?:text|call) me\b/i];
function scriptCut(t){var s=String(t||''),at=-1;SCRIPT_RX.forEach(function(rx){var m=rx.exec(s);if(m){var i=m.index+(m[1]?m[1].length:0);if(at<0||i<at)at=i}});
  return at<0?{own:s,script:''}:{own:s.slice(0,at),script:s.slice(at)}}
var STOPN=new RegExp('(?!\\s*(?:calls?|texts?|emails?|clients?|people|customers|leads?|referrals?|appointments?|appts?|quotes?|proposals?|followups?|visits?)\\b)');
function mask(t){return String(t||'')
  .replace(/(\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}\b/g,' ')                                  /* phone numbers */
  .replace(/\$\s?\d[\d,]*(\.\d+)?\s*(k|m|mil|million|thousand)?\b/g,' ')                                 /* $50, $11,303, $40K */
  .replace(/\b\d[\d,]*(\.\d+)?\s*(k|grand|thousand|million|dollars?|bucks)\b/g,' ')                      /* 11K, 11.3k, 500 dollars */
  .replace(/\b\d+(\.\d+)?\s*(%|percent\b|pct\b)/g,' ')                                                   /* 7.5%, 10 percent */
  .replace(/\b\d{4}-\d{1,2}-\d{1,2}\b/g,' ').replace(/\b\d{1,2}[\/-]\d{1,2}([\/-]\d{2,4})?\b/g,' ')        /* 2026-10-22, 10/22, 10-22, 10/22/2026 */
  .replace(new RegExp('\\b('+MON+')\\.?\\s+\\d{1,2}(st|nd|rd|th)?\\b','g'),' ')                         /* Oct 22, November 4 */
  .replace(/\b\d{1,2}:\d{2}(\s*[ap]\.?m\b\.?)?[a-z]?/g,' ')                                              /* 2:30, 11:30z, 1:45 */
  .replace(/\b\d{1,4}\s*([ap]\.?m\b\.?|noon|midnight)/g,' ')                                             /* 6pm, 230pm, 10 am, 12noon */
  .replace(new RegExp('\\b(\\d{1,2}|'+NUMW+')\\s*o\\s?clock\\b','g'),' ')                                /* 10 oclock */
  .replace(new RegExp('(\\b(?:at|by|until|till?|around)\\s+|@\\s*)(\\d{1,2}|'+NUMW+')\\b'+STOPN.source,'g'),' ')   /* at 6, at six, @7 */
  .replace(/\b\d+(\.\d+)?\s*(hours?|hrs?|minutes?|mins?|seconds?|secs?|days?|weeks?|wks?|months?|years?|yrs?|feet|ft|inches)\b/g,' ')
  .replace(/\b\d+(st|nd|rd|th)\b/g,' ')                                                                   /* 3rd, 22nd */
  .replace(/#\s?[a-z0-9]+/g,' ')                                                                          /* record #s */
  .replace(/\b\d+\.\d+\b/g,' ')}                                                                          /* other decimals */
function norm(t){return String(t||'').toLowerCase().replace(/[’']/g,'').replace(/follow[\s-]*ups?\b/g,'followup').replace(/followed[\s-]+up/g,'followedup')
  .replace(/check(ed)?[\s-]+in(s)?\b/g,function(m,a,b){return a?'checkedin':'checkin'+(b||'')}).replace(/in[\s-]+home/g,'inhome').replace(/designer[\s-]*created(\s+leads?)?/g,'dcl').replace(/self[\s-]*gen(erated)?(\s+leads?)?/g,'dcl')
  .replace(/\bno[\s-]+sales?\b/g,'nosale').replace(/\bservice[\s-]+calls?\b/g,'servicecall').replace(/\b(sales|team|corporate|designer|bni|networking|staff|company|zoom)\s+meetings?\b/g,'groupmeeting')
  .replace(/\bdocu[\s-]+sign/g,'docusign').replace(/\b(not|never)\s+(yet\s+)?signed\b|\bunsigned\b/g,'unsigned').replace(/\bsales\s+calls?\b/g,'calls').replace(/\bphone\s+calls?\b/g,'calls').replace(/\bsocial[\s-]+media\b/g,'socialmedia')}
function numOf(w,next,next2){if(/^\d+$/.test(w))return parseInt(w,10);if(NUM[w]!=null)return NUM[w];
  if((w==='a'||w==='an'||w==='another')&&(catOf(next||'')||catOf(next2||'')))return 1;return null}
var STOPW={about:1,regarding:1,re:1,for:1,to:1,with:1,from:1,on:1,because:1,since:1,who:1,that:1,which:1,after:1,before:1,of:1,at:1,in:1};
/* Parse free text ("called 5 clients, sent 3 follow-up texts, 1 showroom visit") into counts.
   Returns {counts, hits:[{n,cat,phrase}], big:[category keys above CAP], script:true if a pasted client message was skipped}. */
function parse(text){var counts={},hits=[];CATS.forEach(function(c){counts[c.k]=0});
  var sc=scriptCut(text),clauses=mask(norm(sc.own)).split(/[,;.\n!?]+|\band\b|\bplus\b|\balso\b|\bthen\b/);
  clauses.forEach(function(cl){var w=cl.split(/[^a-z0-9]+/).filter(Boolean),got=false;
    for(var i=0;i<w.length;i++){var n=numOf(w[i],w[i+1],w[i+2]);if(n==null||n<=0||n>500)continue;
      if(w[i]==='a'&&w[i+1]==='couple'){continue}
      if(NUM[w[i]]===2&&(w[i]==='couple'||w[i]==='pair')&&w[i+1]==='of')i++;
      /* forward: the noun right after the number (up to 2 words of modifiers, stops at a preposition or the next number) */
      var win=[],cat=null;for(var j=i+1;j<w.length&&j<=i+3;j++){if(STOPW[w[j]]||numOf(w[j],w[j+1],w[j+2])!=null&&/^\d+$|^(one|two|three|four|five|six|seven|eight|nine|ten)$/.test(w[j]))break;win.push(w[j])}
      if(win.indexOf('followup')>=0)cat='followups';else if(win.some(function(z){return /^(signed|sold|closed|deposits?)$/.test(z)}))cat='closes';else if(win.indexOf('showroom')>=0||win.indexOf('showrooms')>=0)cat='showroom';
      else{for(var a=0;a<win.length;a++){var c=catOf(win[a]);if(c){var c2=a+1<win.length?catOf(win[a+1]):null;cat=(c2&&!VERB[win[a+1]])?c2:c;break}}}
      /* backward: an activity verb/noun right before the number ("texted 20", "text to 3") */
      if(!cat){for(var b=i-1;b>=0&&b>=i-2;b--){if(VERB[w[b]]){cat=VERB[w[b]];break}var cb=catOf(w[b]);if(cb){cat=cb;break}if(!STOPW[w[b]])break}}
      if(cat){counts[cat]+=n;got=true;hits.push({n:n,cat:cat,phrase:w.slice(Math.max(0,i-2),i+1+Math.min(win.length,4)).join(' ')})}}
    if(!got){for(var q=1;q<w.length;q++){if(catOf(w[q])==='quotes'&&!/^quot/.test(w[q])&&w.slice(Math.max(0,q-3),q).some(function(z){return /^(sent|send|sending|emailed|emailing|texted|docusigned)$/.test(z)})){counts.quotes+=1;got=true;hits.push({n:1,cat:'quotes',phrase:w.slice(Math.max(0,q-3),q+1).join(' '),implied:true});break}}}
    if(!got&&SOCIAL_RX.test(w.join(' '))){counts.social+=1;got=true;hits.push({n:1,cat:'social',phrase:w.slice(0,6).join(' '),implied:true})}
    if(!got){for(var v=0;v<w.length;v++){var iv=VERB[w[v]]||(v>0&&/^(sent|send|sending|left|made|did|had)$/.test(w[v-1])&&catOf(w[v]));if(iv){counts[iv]+=1;hits.push({n:1,cat:iv,phrase:w.slice(Math.max(0,v-1),v+4).join(' '),implied:true});break}}}});
  var scr=!!sc.script.replace(/\s+/g,'');
  if(scr&&/\breferr/i.test(sc.script)&&!counts.leads){counts.leads=1;hits.push({n:1,cat:'leads',phrase:'referral ask in the pasted message',implied:true})}
  return{counts:counts,hits:hits,big:CATS.filter(function(c){return counts[c.k]>CAP}).map(function(c){return c.k}),script:scr}}
/* ── dates (local) ── */
function ymd(d){return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
function dOf(s){var p=s.split('-');return new Date(+p[0],+p[1]-1,+p[2])}
function monday(d){var x=new Date(d.getFullYear(),d.getMonth(),d.getDate());x.setDate(x.getDate()-((x.getDay()+6)%7));return x}
function sum(es){var t={};CATS.forEach(function(c){t[c.k]=0});es.forEach(function(e){CATS.forEach(function(c){t[c.k]+=+(e.c[c.k]||0)})});return t}
function touches(t){return t.calls+t.texts+t.followups}
var DNC_RX=/^\s*\[pc\]\s*past client\s*#[A-Za-z0-9]{4,18}\s*-\s*do not contact\b/i;   /* Don't contact rows (Oct 22, 2026): 0 counts, never a day logged */
var NOTE_RX=/^\s*\[(pc|deal)\]\s*(past client|opp)\s*#[A-Za-z0-9]{4,18}\s*-\s*note\s*\[fu\s/i;   /* follow-up notes (Oct 25, 2026): 0 counts, never a day logged */
function stats(es,now){now=now||new Date();es=es.filter(function(e){return !DNC_RX.test(e.note||'')&&!NOTE_RX.test(e.note||'')});var td=ymd(now),wk=ymd(monday(now)),mo=td.slice(0,8);
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
var CKEY={calls:'calls',texts:'texts_emails',followups:'followups',appts:'appts',quotes:'quotes',showroom:'showroom',leads:'referrals',closes:'closes',social:'social'};
/* Counts string = the 8 original keys always (zeros included), then '; social=N' ONLY when N>0 (Oct 29, 2026). Older rows and every entry without a
   social post keep exactly the old string, so their de-dup key (app.js actKey / activity_rows.key) is unchanged. Must match activity_rows.parse_counts. */
function countsStr(c){return CATS.filter(function(k){return k.k!=='social'||+((c||{}).social)>0}).map(function(k){return CKEY[k.k]+'='+(+((c||{})[k.k])||0)}).join('; ')}
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
return{CAP:CAP,mask:mask,scriptCut:scriptCut,DNC_RX:DNC_RX,NOTE_RX:NOTE_RX,CATS:CATS,countsStr:countsStr,payload:payload,sync:sync,syncAll:syncAll,setForm:setForm,getForm:getForm,pending:pending,parse:parse,stats:stats,summary:summary,touches:touches,load:load,save:save,ymd:ymd,speechOK:speechOK}})();
if(typeof module!=='undefined')module.exports=ACT;
/* retry pending entries on page load and whenever the browser comes back online (app.js re-renders via ACT_ONSYNC) */
if(typeof window!=='undefined'&&window.addEventListener){var actRetry=function(){ACT.syncAll(null,function(sl){if(typeof window.ACT_ONSYNC==='function')window.ACT_ONSYNC(sl)})};
  window.addEventListener('online',actRetry);if(document.readyState==='complete')setTimeout(actRetry,500);else window.addEventListener('load',function(){setTimeout(actRetry,500)})}
