/* CFNJ Designer Coach: follow-up notes (Andrew, Oct 25, 2026). Pure helpers, no network, no external services; testable in node
   (tests/test_followup_parse.js). FU.parse(text, todayYMD, kind) reads a designer's result note ("let's follow up tomorrow", "call back
   Friday", "f/u in 2 weeks", "10/30", "after the holidays") and returns the next follow-up date in Eastern time. Nothing found -> the
   default for the record type (open quote / deal: 3 business days, past client: 30 days), and the page says so.
   Row format (the existing Activity form note field, all counts 0, so it is never a contact or a day logged):
     "[pc] Past client #<ref> - note [fu 2026-10-26]: <masked text> (14:05:09)"   ("[fu none]" = designer chose No date)
     "[deal] Opp #<ref> - note [fu 2026-10-28]: <masked text> (14:05:09)"
   Same record # + tap-time scheme as the contact buttons; nextsteps.py FU_RX reads the same text. */
'use strict';
var FU=(function(){
var WDN=['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
var MONF=['january','february','march','april','may','june','july','august','september','october','november','december'];
var MON_RX='jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?';
var WD_RX='sun(?:day)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:s|nesday)?|thu(?:r(?:s(?:day)?)?)?|fri(?:day)?|sat(?:urday)?';
var NUMW={a:1,an:1,one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,ten:10,eleven:11,twelve:12,couple:2,'a couple':2,'a couple of':2,'couple of':2,few:3,'a few':3,several:4};
var NUM_RX='\\d{1,3}|a couple(?: of)?|couple(?: of)?|a few|few|several|an?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve';
var RX=/^\s*\[(pc|deal)\]\s*(?:past client|opp)\s*#([A-Za-z0-9]{4,18})\s*-\s*note\s*\[fu\s+(\d{4}-\d{2}-\d{2}|none)\]:\s*([\s\S]*?)\s*\((\d{2}:\d{2}:\d{2})\)\s*$/i;
var DET_RX=/^\s*\[(pc|deal)\]\s*(?:past client|opp)\s*#([A-Za-z0-9]{4,18})\s*-\s*detail:\s*([\s\S]*?)\s*\((\d{2}:\d{2}:\d{2})\)\s*$/i;   /* pre-Oct 25 "Add detail" rows: text only, no date */
var TAP_RX=/^\s*\[(pc|deal)\]\s*(?:past client|opp)\s*#([A-Za-z0-9]{4,18})\s*-\s*(texted|called|visited|emailed)\b[^(]*\((\d{2}:\d{2}:\d{2})\)/i;
/* ── date helpers: plain calendar dates as UTC midnights (no DST/zone drift) ── */
function D(s){var p=String(s).split('-');return new Date(Date.UTC(+p[0],+p[1]-1,+p[2]))}
function S(d){return d.toISOString().slice(0,10)}
function add(d,n){var x=new Date(d.getTime());x.setUTCDate(x.getUTCDate()+n);return x}
function addM(d,n){var y=d.getUTCFullYear(),m=d.getUTCMonth()+n,last=new Date(Date.UTC(y,m+1,0)).getUTCDate();return new Date(Date.UTC(y,m,Math.min(d.getUTCDate(),last)))}
function bdays(d,n){var x=d;while(n>0){x=add(x,1);var w=x.getUTCDay();if(w!==0&&w!==6)n--}return x}
function noSun(d){return d.getUTCDay()===0?add(d,1):d}                                         /* Sundays off: a relative date that lands on Sunday moves to Monday */
function wkday(d){var w=d.getUTCDay();return w===6?add(d,2):w===0?add(d,1):d}                 /* Sat/Sun -> Monday */
function onOrAfterMon(d){var w=d.getUTCDay();return add(d,(8-w)%7)}                              /* the Monday on or after d */
function weekMon(d){return add(d,-((d.getUTCDay()+6)%7))}                                       /* Monday of d's Mon-Sun week */
function etToday(now){now=now||new Date();
  try{var p={};new Intl.DateTimeFormat('en-US',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(now).forEach(function(z){p[z.type]=z.value});
    if(p.year&&p.month&&p.day)return p.year+'-'+p.month+'-'+p.day}catch(e){}
  return now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0')}
var WDS=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'],MOS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function label(ymd,today){if(!ymd)return'';var d=D(ymd),t=today?D(today):null,s=WDS[d.getUTCDay()]+' '+MOS[d.getUTCMonth()]+' '+d.getUTCDate();
  if(t&&d.getUTCFullYear()!==t.getUTCFullYear())s+=', '+d.getUTCFullYear();return s}
function days(a,b){return Math.round((D(b)-D(a))/864e5)}
function rel(ymd,today){var n=days(today,ymd);return n===0?'today':n===1?'tomorrow':n===-1?'yesterday':n>0?'in '+n+' days':Math.abs(n)+' days ago'}
function numOf(s){s=String(s||'').trim();if(/^\d+$/.test(s))return +s;return NUMW[s]!=null?NUMW[s]:null}
function wdOf(s){s=String(s||'').toLowerCase();for(var i=0;i<7;i++){if(WDN[i].indexOf(s.slice(0,3))===0)return i}return -1}
function moOf(s){s=String(s||'').toLowerCase().slice(0,3);for(var i=0;i<12;i++){if(MONF[i].slice(0,3)===s)return i}return -1}
/* ── text clean-up: phones, emails, times, money, shorthand ── */
function norm(t){return ' '+String(t||'').toLowerCase().replace(/[’‘`]/g,"'")
  .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g,' ')
  .replace(/(\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}\b/g,' ')
  .replace(/\$\s?\d[\d,]*(\.\d+)?\s*k?\b/g,' ')
  .replace(/\b\d{1,2}:\d{2}\s*(?:[ap]\.?m\.?)?/g,' ').replace(/\b\d{1,2}\s*[ap]\.?m\b\.?/g,' ')
  .replace(/\bf\s*\/\s*u(?:p)?\b|\bfu\b|\bfollow-?up\b|\bfollowup\b/g,'follow up')
  .replace(/\b(?:tmrw|tmw|tmrow|tmrrw|tomm?orr?ow|2morr?ow|tomorow)\b/g,'tomorrow')
  .replace(/\bwks?\b/g,'weeks').replace(/\bmos\b|\bmths?\b/g,'months').replace(/\bbiz\b/g,'business')
  .replace(/\bxmas\b/g,'christmas').replace(/\bthanksgiving\b/g,'thanksgiving').replace(/\bnew years?'?s?\b/g,'new year')
  .replace(/\s+/g,' ')+' '}
var VOC=/(follow(?:ing)? up|call(?:ing|ed)? (?:\w+ )?back|callback|check(?:ing)? (?:back )?in|check back|circle back|touch base|reach (?:back )?out|try (?:again|back)|text (?:\w+ )?again|reconnect|revisit|remind(?:er)?|get back|hear back|waiting (?:on|for)|wait (?:till|until|for)|next step|reach (?:him|her|them)|ping|until|till|til|after|by|on|around)\s*$/;
var NEG=/\b(not interested|no (?:longer )?interest(?:ed)?|no follow up|don't (?:call|contact|text|reach out)|do not (?:call|contact|text)|went with (?:another|someone else|a competitor|the competition)|bought (?:elsewhere|from (?:another|someone))|chose (?:another|someone else)|lost (?:the )?(?:deal|sale|job)|cancell?ed (?:the )?(?:project|order|job|deal)?|passed away|moved away)\b/;
/* ── the parser ── */
function parse(text,today,kind){today=today||etToday();var T=D(today),y=T.getUTCFullYear(),s=norm(text),C=[],used=[];
  if(!String(text||'').trim())return{d:null,src:'empty',why:''};
  function free(a,b){for(var i=0;i<used.length;i++){if(a<used[i][1]&&b>used[i][0])return false}return true}
  function scan(rx,fn){rx.lastIndex=0;var m;while((m=rx.exec(s))){var a=m.index,b=a+m[0].length;if(!free(a,b))continue;
    var pre=s.slice(Math.max(0,a-14),a),post=s.slice(b,b+8);var r=fn(m,pre,post);if(r===undefined)continue;used.push([a,b]);if(r)C.push({i:a,d:r.d,why:m[0].trim(),weak:!!r.weak})}}
  function fut(d){return d&&S(d)>=today?{d:d}:null}
  function ymdOK(yy,mm,dd){var d=new Date(Date.UTC(yy,mm,dd));return d.getUTCMonth()===mm&&d.getUTCDate()===dd?d:null}
  function noYear(mm,dd){var d=ymdOK(y,mm,dd);if(!d)return null;if(S(d)>=today)return d;if(days(S(d),today)>60)return ymdOK(y+1,mm,dd);return null}   /* recent past date = a contact log, not a follow-up */
  function nextWd(w,from){var n=(w-from.getUTCDay()+7)%7;return add(from,n===0?7:n)}
  function nextWeekWd(w){var m=add(weekMon(T),7);return add(m,(w+6)%7)}
  function nextAnnual(mm,dd,adj){var d=new Date(Date.UTC(y,mm,dd));if(adj)d=adj(d);if(S(d)<=today){d=new Date(Date.UTC(y+1,mm,dd));if(adj)d=adj(d)}return d}
  function thanksgiving(yy){var d=new Date(Date.UTC(yy,10,1)),n=(4-d.getUTCDay()+7)%7;return add(d,n+21)}
  /* holidays and seasons */
  scan(/\b(?:after|past|once|post)\s+(?:the\s+)?holidays?\b|\bafter\s+(?:the\s+)?new year\b|\bin\s+the\s+new year\b|\bnext year\b|\bafter\s+(?:the\s+)?first of the year\b/g,function(){return{d:nextAnnual(0,4,onOrAfterMon)}});
  scan(/\bafter\s+thanksgiving\b/g,function(){var d=add(thanksgiving(y),4);if(S(d)<=today)d=add(thanksgiving(y+1),4);return{d:d}});
  scan(/\bafter\s+christmas\b/g,function(){return{d:nextAnnual(11,26,onOrAfterMon)}});
  scan(/\bafter\s+halloween\b/g,function(){return{d:nextAnnual(10,1,onOrAfterMon)}});
  scan(/\b(?:after\s+)?(?:labor day)\b/g,function(){var d=onOrAfterMon(new Date(Date.UTC(y,8,1)));if(S(d)<=today)d=onOrAfterMon(new Date(Date.UTC(y+1,8,1)));return{d:add(d,1)}});
  scan(/\b(?:(early|late|mid|in|this|next|by|until|till|after)\s+(?:the\s+)?)(spring|summer|fall|autumn|winter)\b|\b(spring|summer|winter)time\b/g,function(m){var q=m[1]||'',z=m[2]||m[3];
    var st={spring:[2,20],summer:[5,1],fall:[8,8],autumn:[8,8],winter:[11,1]}[z];if(q==='early')st=[st[0],1];if(q==='late')st=[st[0]+2,1];if(q==='after')st={spring:[5,1],summer:[8,8],fall:[11,1],autumn:[11,1],winter:[2,20]}[z];
    var d=new Date(Date.UTC(y,st[0],st[1]));if(S(d)<=today)d=new Date(Date.UTC(y+1,st[0],st[1]));return{d:wkday(d)}});
  scan(/\b(?:end of (?:the )?year|year end|eoy)\b/g,function(){var d=new Date(Date.UTC(y,11,31));return{d:S(d)>today?d:new Date(Date.UTC(y+1,11,31))}});
  /* relative days */
  scan(/\bday after tomorrow\b/g,function(){return{d:add(T,2)}});
  scan(/\btomorrow\b/g,function(){return{d:add(T,1)}});
  scan(/\b(?:tonight|later today|this (?:afternoon|evening)|end of (?:the )?day|eod|asap|right away)\b/g,function(){return{d:T}});
  scan(/\byesterday\b|\blast (?:night|week|month|year)\b/g,function(){return null});
  scan(/\btoday\b/g,function(){return{d:T,weak:true}});
  /* weeks / months */
  scan(/\b(?:end of (?:the |this )?week|eow)\b/g,function(){var w=T.getUTCDay();return{d:w>=5?add(T,(12-w)%7||7):add(T,5-w)}});
  scan(/\bnext weekend\b/g,function(){return{d:nextWeekWd(6)}});
  scan(/\b(?:this|the|over the) weekend\b/g,function(){return{d:T.getUTCDay()===6?add(T,7):nextWd(6,T)}});
  scan(/\bweek after next\b/g,function(){return{d:add(weekMon(T),14)}});
  scan(/\b(?:later )?this week\b/g,function(){var w=T.getUTCDay();if(w===0)return{d:add(T,4)};return{d:w>=4?add(T,1):add(T,4-w)}});
  scan(/\bnext week\b/g,function(){return{d:add(weekMon(T),7)}});
  scan(new RegExp('\\b(end|beginning|start|first|middle|mid|early|late)\\s+(?:of\\s+)?(?:the\\s+)?(next\\s+month|this\\s+month|month|'+MON_RX+')\\b','g'),function(m){var q=m[1],w=m[2];
    var base;if(/next/.test(w))base=new Date(Date.UTC(y,T.getUTCMonth()+1,1));else if(/month/.test(w))base=new Date(Date.UTC(y,T.getUTCMonth(),1));
    else{var mo=moOf(w);if(mo<0)return undefined;base=new Date(Date.UTC(mo<T.getUTCMonth()?y+1:y,mo,1))}
    var mm=base.getUTCMonth(),yy=base.getUTCFullYear(),d;
    if(q==='end')d=new Date(Date.UTC(yy,mm+1,0));else if(q==='middle'||q==='mid')d=new Date(Date.UTC(yy,mm,15));else if(q==='late')d=new Date(Date.UTC(yy,mm,24));else d=wkday(new Date(Date.UTC(yy,mm,1)));
    if(S(d)<today||(q==='end'&&S(d)===today&&/month$/.test(w)&&!/next/.test(w)))d=q==='end'?new Date(Date.UTC(yy,mm+2,0)):addM(d,/month/.test(w)?1:12);
    return{d:d}});
  scan(/\b(?:eom|month end)\b/g,function(){var d=new Date(Date.UTC(y,T.getUTCMonth()+1,0));return{d:S(d)>today?d:new Date(Date.UTC(y,T.getUTCMonth()+2,0))}});
  scan(/\bnext month\b/g,function(){return{d:wkday(new Date(Date.UTC(y,T.getUTCMonth()+1,1)))}});
  /* explicit dates: Oct 30, October 30th, 30th of October, 10/30, 10/30/26, 2026-10-30 */
  scan(/\b(\d{4})-(\d{1,2})-(\d{1,2})\b/g,function(m){return fut(ymdOK(+m[1],+m[2]-1,+m[3]))});
  scan(new RegExp('\\b('+MON_RX+')\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?\\b(?:,?\\s*(\\d{4}))?','g'),function(m,pre){var mo=moOf(m[1]);if(mo<0)return undefined;if(/^may$/.test(m[1])&&!/(on|by|until|till|after|in|of)\s*$/.test(pre)&&+m[2]>31)return undefined;
    return m[3]?fut(ymdOK(+m[3],mo,+m[2])):{d:noYear(mo,+m[2])}});
  scan(new RegExp('\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?('+MON_RX+')\\b','g'),function(m){var mo=moOf(m[2]);if(mo<0)return undefined;return{d:noYear(mo,+m[1])}});
  scan(/(^|[^\d\/.$])(\d{1,2})\/(\d{1,2})(?:\/(\d{2}|\d{4}))?(?![\d\/])/g,function(m){var mm=+m[2]-1,dd=+m[3];if(mm<0||mm>11)return undefined;
    if(m[4]){var yy=+m[4];if(yy<100)yy+=2000;return fut(ymdOK(yy,mm,dd))}var d=noYear(mm,dd);return d?{d:d}:null});
  scan(/\b(?:on )?the (\d{1,2})(?:st|nd|rd|th)\b/g,function(m){var dd=+m[1];if(dd<1||dd>31)return undefined;var d=ymdOK(y,T.getUTCMonth(),dd);
    if(!d||S(d)<=today){d=null;for(var k=1;k<4&&!d;k++)d=ymdOK(new Date(Date.UTC(y,T.getUTCMonth()+k,1)).getUTCFullYear(),(T.getUTCMonth()+k)%12,dd)}return{d:d}});
  /* weekdays: Friday, this Fri, next Tues, Monday after next */
  scan(new RegExp('\\b(?:(next|this|this coming|coming|on|by|until|till|til|before|last)\\s+)?('+WD_RX+')\\b(\\s+after next)?','g'),function(m,pre){var q=m[1]||'',w=wdOf(m[2]);if(w<0)return undefined;
    if(/^(sun|mon|sat|wed)$/.test(m[2])&&!q)return undefined;                                       /* bare "sat" / "sun" / "mon" / "wed" are too often other words */
    if(q==='last'||/\b(?:last|since|past)\s*$/.test(pre))return null;
    var d=q==='next'?nextWeekWd(w):nextWd(w,T);if(m[3])d=add(d,7);return{d:d}});
  /* month alone: in November, by January, after December */
  scan(new RegExp('\\b(in|by|until|till|after|around|early|before)\\s+('+MON_RX+')\\b(?!\\s*\\d)','g'),function(m){var mo=moOf(m[2]);if(mo<0)return undefined;if(m[2]==='may'&&m[1]!=='in'&&m[1]!=='after'&&m[1]!=='by')return undefined;
    var cm=T.getUTCMonth(),yy=mo<cm?y+1:y;if(m[1]==='after')mo+=1;if(mo===cm&&yy===y&&m[1]!=='after')return null;
    return{d:wkday(new Date(Date.UTC(yy,mo,1)))}});
  /* N days / weeks / months: in 3 days, after 2 weeks, couple weeks, a month from now, 3 business days, 2-3 weeks */
  scan(new RegExp('\\b(?:(in|after|within|about|around|another|wait|give (?:it|her|him|them))\\s+)?('+NUM_RX+')(?:\\s*(?:-|to|or)\\s*(?:\\d{1,3}|two|three|four|five|six))?\\s+(?:more\\s+)?(business\\s+|working\\s+)?(days?|weeks?|months?|years?)\\b(\\s+ago)?','g'),function(m,pre){
    if(m[5])return null;if(/\b(?:once|twice|per|every|each|times|last|past|for the last|for the past)\s*$/.test(pre)&&!m[1])return null;
    var n=numOf(m[2]);if(n==null||n<=0||n>400)return undefined;var u=m[4].replace(/s$/,''),d;
    if(u==='day')d=m[3]?bdays(T,n):add(T,n);else if(u==='week')d=add(T,7*n);else if(u==='month')d=addM(T,n);else d=addM(T,12*n);return{d:noSun(d)}});
  /* choose: a date tied to follow-up words wins, else the first firm date; "today" alone is how it went, not when to call */
  var best=null,why='';
  C.forEach(function(c){if(!c.d)return;var pre=s.slice(Math.max(0,c.i-48),c.i);c.vo=VOC.test(pre)||/(follow up|call back|callback|check in|check back|circle back|touch base|reach out|waiting on|reconnect|remind)\b[^.!?;]{0,40}$/.test(pre)});
  var ok=C.filter(function(c){return c.d&&S(c.d)>=today});
  var linked=ok.filter(function(c){return c.vo&&!(c.weak&&!/(follow up|call back|callback|check in|reach out|try again|text again|ping)\b[^.!?;]{0,20}$/.test(s.slice(Math.max(0,c.i-30),c.i)))});
  best=linked[0]||ok.filter(function(c){return !c.weak})[0]||null;
  if(best)return{d:S(best.d),src:'parsed',why:best.why};
  if(NEG.test(s))return{d:null,src:'none',why:'sounds like no follow-up'};
  return dflt(today,kind)}
function dflt(today,kind){var T=D(today||etToday());return kind==='pc'?{d:S(noSun(add(T,30))),src:'default',why:'30 days (past client default)'}:{d:S(bdays(T,3)),src:'default',why:'3 business days (open quote default)'}}
/* chips: [label, key] -> date */
var CHIPS=[['Tomorrow','1d'],['3 days','3d'],['1 week','1w'],['2 weeks','2w'],['1 month','1m'],['No date','none']];
function chip(key,today){var T=D(today||etToday());if(key==='none')return null;var n=parseInt(key,10),u=key.slice(-1);return S(noSun(u==='d'?add(T,n):u==='w'?add(T,7*n):addM(T,n)))}
/* row note text + reading it back */
function pad(n){return String(n).padStart(2,'0')}
function hms(d){return pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())}
function note(kind,ref,fu,text,at){return (kind==='pc'?'[pc] Past client #':'[deal] Opp #')+ref+' - note [fu '+(fu||'none')+']: '+String(text||'').replace(/\s+/g,' ').trim()+' ('+hms(at||new Date())+')'}
function read(n){var m=RX.exec(n||'');if(m)return{k:m[1].toLowerCase(),ref:m[2],f:m[3]==='none'?'':m[3],n:m[4],h:m[5]};
  var z=DET_RX.exec(n||'');if(z)return{k:z[1].toLowerCase(),ref:z[2],f:null,n:z[3],h:z[4],legacy:1};return null}
function tap(n){var m=TAP_RX.exec(n||'');return m?{k:m[1].toLowerCase(),ref:m[2],a:m[3],h:m[4]}:null}
function status(f,today){if(!f)return'';return f<today?'over':f===today?'due':'later'}
return{parse:parse,dflt:dflt,CHIPS:CHIPS,chip:chip,note:note,read:read,tap:tap,status:status,label:label,rel:rel,days:days,etToday:etToday,hms:hms,RX:RX,DET_RX:DET_RX}})();
if(typeof module!=='undefined')module.exports=FU;
