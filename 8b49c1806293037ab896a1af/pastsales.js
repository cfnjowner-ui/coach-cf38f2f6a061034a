/* My past Sales (Andrew, Oct 29, 2026). A button on each designer's page opens a modal: every sale the designer made (ClosetWare,
   read-only: Sold (Final) / Sold (Designer), Sales Board amounts and dates, all history) with client name, phone, email, address and
   $, a period selector (Past 3 months / 6 months / Past year / Last year / All) with count + total, sort by newest or $, and a map
   (Leaflet + markercluster, vendored in vendor/, OSM tiles) to spot clusters of sales by development/town.
   The records (x.ps) exist ONLY inside that designer's own encrypted bundle (pastsales.py). DNC clients are listed but marked, with
   no phone/email/street and an approximate (~1 km) map dot. Nothing here logs, sends or stores anything. */
var PS={per:'1y',sort:'d',tab:'list',map:null,cl:null,mk:{},x:null,lib:null};
var PS_PER=[['3m','Past 3 months'],['6m','Past 6 months'],['1y','Past year'],['ly','Last year'],['all','All']];
function psBtn(x){return '<button type="button" class="psbtn" id="psBtn" aria-haspopup="dialog">📍 My past Sales</button>'}
function psLoadLib(cb){if(window.L&&L.markerClusterGroup)return cb();if(PS.lib){PS.lib.push(cb);return}PS.lib=[cb];
  var V='vendor/',css=[V+'leaflet-1.9.4/leaflet.css',V+'markercluster-1.5.3/MarkerCluster.css',V+'markercluster-1.5.3/MarkerCluster.Default.css'],js=[V+'leaflet-1.9.4/leaflet.js',V+'markercluster-1.5.3/leaflet.markercluster.js'];
  css.forEach(function(h){var l=document.createElement('link');l.rel='stylesheet';l.href=h;document.head.appendChild(l)});
  (function next(i){if(i>=js.length){var q=PS.lib;PS.lib=null;q.forEach(function(f){f()});return}var s=document.createElement('script');s.src=js[i];s.onload=function(){next(i+1)};
    s.onerror=function(){var q=PS.lib;PS.lib=null;q.forEach(function(f){f('Map could not load. The list still works.')})};document.head.appendChild(s)})(0)}
function psCut(per){var t=new Date(((D.meta&&D.meta.today)||new Date().toISOString().slice(0,10))+'T12:00:00'),f=function(m){var z=new Date(t);z.setMonth(z.getMonth()-m);return z.toISOString().slice(0,10)};
  return per==='3m'?f(3):per==='6m'?f(6):per==='1y'?f(12):null}
function psRows(){var x=PS.x,L=x.ps||[],ly=String((x.ps_meta&&x.ps_meta.ly)||(+((D.meta&&D.meta.today)||'').slice(0,4)-1)),c=psCut(PS.per);
  var r=L.filter(function(s){return PS.per==='all'?true:PS.per==='ly'?String(s.d).slice(0,4)===ly:s.d>=c});
  r.sort(PS.sort==='a'?function(a,b){return b.a-a.a||(b.d<a.d?-1:1)}:function(a,b){return a.d<b.d?1:a.d>b.d?-1:b.a-a.a});return r}
function psDate(d){d=String(d||'');return d.length>=10?d.slice(5,7)+'/'+d.slice(8,10)+'/'+d.slice(0,4):d}
function psAddr(s){return [s.st,s.ci,[s.sa,s.zp].filter(Boolean).join(' ')].filter(Boolean).join(', ')}
function psRow(s,i){var tags=(s.nc?'<span class="chip r">Do not contact</span>':'')+(s.pd?'<span class="chip a" title="Sold (Designer): not yet Sold (Final)">pending final</span>':'')+(s.sf?'<span class="chip">staff</span>':'');
  var ct=s.nc?'<span class="ctn">Client asked not to be contacted: phone, email and street hidden.</span>':s.sf?'':ctLine(s,true);
  return '<li class="psr'+(s.nc?' psnc':'')+'" data-i="'+i+'" tabindex="0"><div class="pst"><b class="psn">'+esc(s.name||'(no name)')+'</b><b class="psa">'+m0(s.a)+'</b></div>'+
    '<div class="psm"><span>'+psDate(s.d)+'</span>'+tags+(s.la!=null?'<span class="psgo" title="Show on map">📍</span>':'<span class="ctn" title="No usable address/coordinates">not on map</span>')+'</div>'+
    '<div class="psad">'+esc(psAddr(s)||'no address on file')+'</div>'+(ct?'<div class="psct">'+ct+'</div>':'')+'</li>'}
function psOpen(x){PS.x=x;var M=document.getElementById('psModal');if(M)M.remove();
  var own=D.kind==='owner',has=!!(x.ps&&x.ps.length),ow=own&&D.owner&&D.owner.ps&&(D.owner.ps.designers||[]).find(function(z){return z.slug===x.slug});
  M=document.createElement('div');M.id='psModal';M.className='psmod';M.setAttribute('role','dialog');M.setAttribute('aria-modal','true');M.setAttribute('aria-label','My past Sales');
  M.innerHTML='<div class="psbox"><div class="pshd"><div><b class="psttl">My past Sales</b><div class="fine" id="psSub"></div></div><button type="button" class="psx" id="psX" aria-label="Close">✕</button></div>'+
    (has?'<div class="psbar"><div class="psper" role="group" aria-label="Period">'+PS_PER.map(function(p){return '<button type="button" data-p="'+p[0]+'">'+(p[0]==='ly'?'Last year ('+esc((x.ps_meta&&x.ps_meta.ly)||'')+')':p[1])+'</button>'}).join('')+'</div>'+
      '<div class="pssum" id="psSum" aria-live="polite"></div><div class="pssrt"><span class="fine">Sort</span><button type="button" data-s="d">Newest</button><button type="button" data-s="a">$ high→low</button></div>'+
      '<div class="pstabs" role="tablist"><button type="button" data-t="list">List</button><button type="button" data-t="map">Map</button></div></div>'+
      '<div class="psbody"><ul class="pslist" id="psList"></ul><div class="psmapw"><div id="psMap" class="psmap"></div><div class="fine psmn" id="psMn"></div></div></div>'
    :'<div class="psbody psempty"><p>'+(own?'Client-level past sales are only inside each designer\'s own page (encrypted with their code), not in the owner bundle.'+(ow?' '+esc(x.name)+': '+ow.n+' sales on record, '+ow.mapped+' on the map, '+ow.y12+' in the past year.':''):'No sales on record yet. Your sales will show here once they are Sold in ClosetWare.')+'</p></div>')+'</div>';
  document.body.appendChild(M);document.body.classList.add('psopen');
  var close=function(){M.remove();document.body.classList.remove('psopen');document.removeEventListener('keydown',esck);if(PS.map){PS.map.remove();PS.map=null}var b=document.getElementById('psBtn');if(b)b.focus()};
  var esck=function(e){if(e.key==='Escape')close()};document.addEventListener('keydown',esck);
  M.querySelector('#psX').onclick=close;M.onclick=function(e){if(e.target===M)close()};M.querySelector('#psX').focus();
  if(!has)return;
  var pm=x.ps_meta||{};M.querySelector('#psSub').textContent=(x.ps.length+' sales since '+psDate(pm.first)+' · ClosetWare, read-only · as of '+psDate(pm.asof));
  M.querySelectorAll('.psper button').forEach(function(b){b.onclick=function(){PS.per=b.dataset.p;psDraw()}});
  M.querySelectorAll('.pssrt button').forEach(function(b){b.onclick=function(){PS.sort=b.dataset.s;psDraw()}});
  M.querySelectorAll('.pstabs button').forEach(function(b){b.onclick=function(){psTab(b.dataset.t)}});
  M.querySelector('#psList').onclick=function(e){if(e.target.closest('a'))return;var li=e.target.closest('.psr');if(li)psGo(+li.dataset.i)};
  M.querySelector('#psList').onkeydown=function(e){if(e.key==='Enter'){var li=e.target.closest('.psr');if(li)psGo(+li.dataset.i)}};
  psTab(PS.tab);psDraw();
  psLoadLib(function(err){if(!document.getElementById('psMap'))return;if(err){M.querySelector('#psMn').textContent=err;return}psMapInit();psDraw()})}
function psTab(t){PS.tab=t;var M=document.getElementById('psModal');if(!M)return;M.querySelector('.psbox').setAttribute('data-tab',t);
  M.querySelectorAll('.pstabs button').forEach(function(b){b.classList.toggle('on',b.dataset.t===t);b.setAttribute('aria-selected',b.dataset.t===t)});
  if(t==='map'&&PS.map)setTimeout(function(){PS.map.invalidateSize();psFit()},30)}
function psMapInit(){var el=document.getElementById('psMap');if(!el||PS.map)return;
  PS.map=L.map(el,{zoomControl:true,preferCanvas:false}).setView([40.6,-74.4],8);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,referrerPolicy:'origin',attribution:'&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors'}).addTo(PS.map);
  PS.cl=L.markerClusterGroup({showCoverageOnHover:false,maxClusterRadius:45,spiderfyOnMaxZoom:true});PS.map.addLayer(PS.cl)}
var PS_CUR=[];
function psDraw(){var M=document.getElementById('psModal');if(!M||!PS.x.ps)return;var r=psRows(),tot=0;PS_CUR=r;r.forEach(function(s){tot+=s.a||0});
  M.querySelectorAll('.psper button').forEach(function(b){b.classList.toggle('on',b.dataset.p===PS.per);b.setAttribute('aria-pressed',b.dataset.p===PS.per)});
  M.querySelectorAll('.pssrt button').forEach(function(b){b.classList.toggle('on',b.dataset.s===PS.sort)});
  var onm=r.filter(function(s){return s.la!=null}).length;
  M.querySelector('#psSum').innerHTML='<b id="psN">'+r.length+'</b> sale'+(r.length===1?'':'s')+' · <b id="psT">'+m0(tot)+'</b>'+(r.length?' · avg '+m0(tot/r.length):'');
  M.querySelector('#psList').innerHTML=r.length?r.map(psRow).join(''):'<li class="psnone">No sales in this period.</li>';
  M.querySelector('#psMn').textContent=onm+' of '+r.length+' on the map'+(onm<r.length?' ('+(r.length-onm)+' without a usable address)':'')+(r.some(function(s){return s.nc&&s.la!=null})?' · DNC dots are approximate':'');
  if(!PS.map)return;PS.cl.clearLayers();PS.mk={};
  var ms=[];r.forEach(function(s,i){if(s.la==null)return;var m=L.circleMarker([s.la,s.lo],{radius:7,weight:2,color:'#fff',fillColor:s.nc?'#c62828':s.pd?'#b26b00':'#12263f',fillOpacity:.9});
    m.bindPopup('<b>'+esc(s.name||'(no name)')+'</b><br>'+m0(s.a)+' · '+psDate(s.d)+(s.ci?'<br><span class="fine">'+esc(s.ci)+'</span>':'')+(s.nc?'<br><span class="chip r">Do not contact</span>':''));
    m.on('click',function(){psHi(i)});PS.mk[i]=m;ms.push(m)});
  PS.cl.addLayers(ms);psFit()}
function psFit(){if(!PS.map||!PS.cl)return;var b=PS.cl.getBounds();if(b.isValid())PS.map.fitBounds(b.pad(0.08),{maxZoom:13})}
function psHi(i){var M=document.getElementById('psModal');if(!M)return;M.querySelectorAll('.psr.on').forEach(function(e){e.classList.remove('on')});var li=M.querySelector('.psr[data-i="'+i+'"]');if(li){li.classList.add('on');if(PS.tab==='list'||window.innerWidth>=760)li.scrollIntoView({block:'nearest'})}}
function psGo(i){psHi(i);var m=PS.mk[i];if(!m)return;if(window.innerWidth<760)psTab('map');
  setTimeout(function(){PS.map.invalidateSize();PS.cl.zoomToShowLayer(m,function(){PS.map.setView(m.getLatLng(),Math.max(PS.map.getZoom(),15));m.openPopup()})},window.innerWidth<760?60:0)}
function psWire(x){var b=document.getElementById('psBtn');if(b)b.onclick=function(){psOpen(x)}}
