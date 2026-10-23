const $ = id => document.getElementById(id);
const riskClass = verdict => verdict === 'High Risk' ? 'danger' : verdict === 'Suspicious' ? 'warning' : 'safe';
let currentRange = { type: 'preset', days: 7 };
let apiToken = '';

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (apiToken) headers.set('Authorization', `Bearer ${apiToken}`);
  const response = await fetch(url, { ...options, headers });
  if (response.status === 401) {
    apiToken = '';
    const gate = $('api-auth-gate');
    gate.hidden = false;
    $('api-auth-message').textContent = 'The token was rejected or revoked. Enter a valid token to reconnect.';
    $('api-token').value = '';
  }
  if (!response.ok) throw new Error(`API request failed (HTTP ${response.status})`);
  return response;
}

async function initialiseDashboard() {
  try {
    const response = await fetch('/status');
    if (!response.ok) throw new Error(`Status request failed (HTTP ${response.status})`);
    const status = await response.json();
    if (status.authentication_required) {
      $('api-auth-gate').hidden = false;
      $('api-token').focus();
      return;
    }
    loadAnalytics();
  } catch (error) {
    $('api-auth-gate').hidden = false;
    $('api-auth-message').textContent = `Could not reach the API: ${error.message}`;
  }
}

$('api-connect').addEventListener('click', async () => {
  const input = $('api-token');
  const message = $('api-auth-message');
  apiToken = input.value.trim();
  if (!apiToken) {
    message.textContent = 'Enter the API token issued for your user.';
    input.focus();
    return;
  }
  message.textContent = 'Checking token…';
  try {
    const session = await (await apiFetch('/session')).json();
    message.textContent = `Connected as ${session.user_id}. The token will be cleared when this page closes.`;
    input.value = '';
    $('api-auth-gate').hidden = true;
    loadAnalytics();
    if ($('history-list')) loadHistory();
  } catch {
    apiToken = '';
    input.value = '';
    message.textContent = 'Token validation failed. Check the token and try again.';
    input.focus();
  }
});
 $('api-token').addEventListener('keydown', event => {
  if (event.key === 'Enter') $('api-connect').click();
});

document.querySelectorAll('.nav').forEach(button => {
  button.addEventListener('click', () => showTab(button.dataset.tab));
});
document.querySelectorAll('[data-goto]').forEach(button => {
  button.addEventListener('click', () => {
    showTab(button.dataset.goto);
    if (button.dataset.openCustom) {
      const rangeBar = $('customRangeBar');
      if (rangeBar && !rangeBar.classList.contains('open')) $('customToggle').click();
    }
  });
});
function showTab(id) {
  document.querySelectorAll('.tab, .nav').forEach(element => element.classList.remove('active'));
  const page = $(id);
  if (!page) return;
  page.classList.add('active');
  document.querySelectorAll(`.nav[data-tab="${id}"]`).forEach(nav => nav.classList.add('active'));
  if (id === 'analytics' || id === 'overview') loadAnalytics();
  if (id === 'analytics') loadHistory();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function fmtBucketLabel(label,bucket){
  // label is either "YYYY-MM-DD" (day bucket) or "YYYY-MM-DDTHH" (hour bucket)
  if(bucket==='hour'){const d=new Date(label+':00:00Z');return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
  const d=new Date(label+'T00:00:00Z');return d.toLocaleDateString([],{month:'short',day:'numeric'})
}
// Catmull-Rom -> cubic bezier, so the trend line reads as a smooth curve
// instead of a jagged polyline (matches the ShadowTrace "pulse" chart style).
function smoothPath(pts){
  if(pts.length<2) return '';
  if(pts.length===2) return `M${pts[0][0]},${pts[0][1]} L${pts[1][0]},${pts[1][1]}`;
  let d=`M${pts[0][0]},${pts[0][1]}`;
  for(let i=0;i<pts.length-1;i++){
    const p0=pts[i-1]||pts[i], p1=pts[i], p2=pts[i+1], p3=pts[i+2]||p2;
    const c1x=p1[0]+(p2[0]-p0[0])/6, c1y=p1[1]+(p2[1]-p0[1])/6;
    const c2x=p2[0]-(p3[0]-p1[0])/6, c2y=p2[1]-(p3[1]-p1[1])/6;
    d+=` C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

function chart(target,series,bucket){
  bucket=bucket||'day';
  if(!series.length){target.innerHTML='<div class="chart-empty">No checks in this window yet — run a check or widen the range.</div>';return}
  const W=100,H=100,padTop=6,padBottom=18,plotH=H-padTop-padBottom;
  // Dynamic count-based y-axis (like 0/23/46/69/92) instead of a fixed
  // percentage scale -- this chart plots flagged/clear COUNTS per bucket,
  // not a 0-100% risk score, so the axis has to reflect that.
  const rawMax=Math.max(1,...series.map(x=>Math.max(x.flagged,x.clear)));
  const niceMax=Math.ceil(rawMax/4)*4||4;
  const yAt=v=>padTop+plotH-((v/niceMax)*plotH);
  const yLabels=[4,3,2,1,0].map(i=>Math.round(niceMax*i/4));
  const gridLines=[0,0.25,0.5,0.75,1].map(v=>`<line x1="0" x2="${W}" y1="${padTop+plotH-(v*plotH)}" y2="${padTop+plotH-(v*plotH)}" stroke="#2A1418" stroke-width="0.6" vector-effect="non-scaling-stroke"/>`).join('');
  // Dots are plain positioned HTML, not SVG <circle>s -- the chart is stretched
  // non-uniformly (wide, short) via preserveAspectRatio="none", which turns any
  // SVG circle into a flattened ellipse. Percent-positioned divs stay round.
  const dot=(cxPct,cyPct,label,text,cls)=>`<div class="chart-dot${cls?' '+cls:''}" style="left:${cxPct}%;top:${cyPct}%" title="${label} — ${text}"></div>`;

  if(series.length===1){
    // A single bucket isn't a trend line -- there's only one x-position, so
    // show two clearly-labeled beacons (flagged/clear) instead of faking a shape.
    const x=series[0], label=fmtBucketLabel(x.label,bucket);
    const beacons=[
      x.flagged>0?dot(46,yAt(x.flagged),label,`${x.flagged} flagged`,'pulse'):'',
      x.clear>0?dot(54,yAt(x.clear),label,`${x.clear} clear`,'pulse green'):''
    ].join('');
    target.innerHTML=`<div class="chart-yaxis">${yLabels.map(l=>`<span>${l}</span>`).join('')}</div><div class="chart-body"><div class="chart-plot"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${gridLines}</svg>${beacons}</div><div class="chart-labels"><span style="flex:1;text-align:center">${label} · ${x.flagged} flagged · ${x.clear} clear · widen the range to see a trend</span></div></div>`;
    return;
  }

  const data=series;
  const xAt=i=>i*(W/Math.max(data.length-1,1));
  const flaggedPts=data.map((x,i)=>[xAt(i),yAt(x.flagged)]);
  const clearPts=data.map((x,i)=>[xAt(i),yAt(x.clear)]);
  const flaggedCurve=smoothPath(flaggedPts);
  const clearCurve=smoothPath(clearPts);
  const areaD=`${flaggedCurve} L${flaggedPts[flaggedPts.length-1][0]},${H-padBottom} L${flaggedPts[0][0]},${H-padBottom} Z`;
  const flaggedDots=data.map((x,i)=>dot(xAt(i),yAt(x.flagged),fmtBucketLabel(x.label,bucket),`${x.flagged} flagged`,i===data.length-1?'last':'')).join('');
  const clearDots=data.map((x,i)=>dot(xAt(i),yAt(x.clear),fmtBucketLabel(x.label,bucket),`${x.clear} clear`,'green'+(i===data.length-1?' last':''))).join('');
  // show at most ~6 x-axis labels, evenly spaced, so dense hourly data doesn't overlap
  const maxLabels=6, step=Math.max(1,Math.ceil(data.length/maxLabels));
  const xLabels=data.map((x,i)=>({i,text:fmtBucketLabel(x.label,bucket)})).filter(x=>x.i%step===0||x.i===data.length-1);
  target.innerHTML=`<div class="chart-yaxis">${yLabels.map(l=>`<span>${l}</span>`).join('')}</div><div class="chart-body"><div class="chart-plot"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${gridLines}<defs><linearGradient id="fill" x1="0" x2="0" y1="0" y2="1"><stop stop-color="#FF3B5C" stop-opacity=".38"/><stop offset="1" stop-color="#FF3B5C" stop-opacity="0"/></linearGradient></defs><path d="${areaD}" fill="url(#fill)"/><path class="chart-line green" d="${clearCurve}" vector-effect="non-scaling-stroke"/><path class="chart-line" d="${flaggedCurve}" vector-effect="non-scaling-stroke"/></svg>${clearDots}${flaggedDots}</div><div class="chart-labels">${xLabels.map(l=>`<span>${l.text}</span>`).join('')}</div></div>`
}
function setDistribution(counts,total){const safe=counts.Safe||0,sus=counts.Suspicious||0,high=counts['High Risk']||0;const p1=total?safe/total*100:0,p2=total?sus/total*100:0;$('donut').style.background=`conic-gradient(#34D399 0 ${p1}%,#FBBF24 ${p1}% ${p1+p2}%,#F43F5E ${p1+p2}% 100%)`;$('donut-total').textContent=total;$('legend').innerHTML=[['Safe',safe,'green'],['Suspicious',sus,'orange'],['High Risk',high,'red']].map(x=>`<p><i class="${x[2]}"></i>${x[0]} <b>${x[1]}</b></p>`).join('');$('analytics-legend').innerHTML=[['Safe',safe,'green'],['Suspicious',sus,'orange'],['High Risk',high,'red']].map(x=>`<div><i class="${x[2]}"></i><span>${x[0]}</span><b>${x[1]} checks</b></div>`).join('')}
function rangeQuery(){return currentRange.type==='custom'?`start=${encodeURIComponent(currentRange.start)}&end=${encodeURIComponent(currentRange.end)}`:`days=${currentRange.days}`}
function fmtFull(iso){return new Date(iso).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}
async function loadAnalytics(){
  try{
    const d=await (await apiFetch(`/analytics?${rangeQuery()}`)).json();
    $('metric-total').textContent=d.total;$('metric-flagged').textContent=(d.counts['Suspicious']||0)+(d.counts['High Risk']||0);$('metric-clear').textContent=d.counts['Safe']||0;$('metric-alerts').textContent=d.counts['High Risk'];$('donut-total').textContent=d.total;
    chart($('pulse-chart'),d.series,d.bucket);chart($('analytics-chart'),d.series,d.bucket);setDistribution(d.counts,d.total);
    const windowText=`${fmtFull(d.range_start)} → ${fmtFull(d.range_end)} · bucketed by ${d.bucket}`;
    const chartLbl=$('chart-window-label'),auditLbl=$('audit-window-label');
    if(chartLbl)chartLbl.textContent=windowText; if(auditLbl)auditLbl.textContent=windowText;
  }catch{}
}
async function loadHistory(){
  try{
    const extra=currentRange.type==='custom'?`&start=${encodeURIComponent(currentRange.start)}&end=${encodeURIComponent(currentRange.end)}`:'';
    const rows=await (await apiFetch(`/history?limit=${currentRange.type==='custom'?100:12}${extra}`)).json();
    $('history-list').innerHTML=rows.length?`<div class="table"><div class="tr th"><span>VERDICT</span><span>SIGNALS USED</span><span>RISK SCORE</span><span>TIME</span></div>${rows.map(x=>`<div class="tr"><span><b class="badge ${riskClass(x.verdict)}">${x.verdict}</b></span><span>${x.modules_used.join(' · ')}</span><span>${Math.round(x.risk_score*100)}%</span><span>${fmtFull(x.created_at)}</span></div>`).join('')}</div>`:'No checks in this window. Run a message or QR check in the Android app, or widen the range.'
  }catch{}
}
function selectPreset(days){
  currentRange={type:'preset',days};
  document.querySelectorAll('[data-range]').forEach(x=>x.classList.toggle('selected',x.dataset.range==String(days)));
  const bar=$('customRangeBar'); if(bar)bar.classList.remove('open');
  loadAnalytics(); if($('history-list'))loadHistory();
}
document.querySelectorAll('[data-range]').forEach(b=>{
  if(b.dataset.range==='custom')return; // handled separately below
  b.onclick=()=>selectPreset(+b.dataset.range);
});
// --- Custom date/time range picker ---
document.querySelectorAll('#customToggle').forEach(btn=>btn.onclick=()=>{
  const bar=$('customRangeBar');
  const opening=!bar.classList.contains('open');
  bar.classList.toggle('open');
  if(opening){
    // default the pickers to the currently-active window so it's a sensible starting point
    const now=new Date(), from=new Date(now.getTime()-(currentRange.type==='preset'?currentRange.days:1)*86400000);
    const toLocalInput=dt=>new Date(dt.getTime()-dt.getTimezoneOffset()*60000).toISOString().slice(0,16);
    $('rangeFrom').value=toLocalInput(from); $('rangeTo').value=toLocalInput(now);
  }
});
$('applyCustomRange').onclick=()=>{
  const fromVal=$('rangeFrom').value, toVal=$('rangeTo').value, err=$('customRangeError');
  err.textContent='';
  if(!fromVal||!toVal){err.textContent='Pick both a start and end time.';return}
  const start=new Date(fromVal), end=new Date(toVal);
  if(start>=end){err.textContent='Start must be before end.';return}
  currentRange={type:'custom',start:start.toISOString(),end:end.toISOString()};
  document.querySelectorAll('[data-range]').forEach(x=>x.classList.toggle('selected',x.dataset.range==='custom'));
  loadAnalytics(); if($('history-list'))loadHistory();
};
$('refresh-history').onclick=()=>{loadHistory();loadAnalytics()};
initialiseDashboard();
