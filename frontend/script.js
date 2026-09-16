const $=id=>document.getElementById(id), riskClass=v=>v==='High Risk'?'danger':v==='Suspicious'?'warning':'safe';
// currentRange is either {type:'preset', days:N} or {type:'custom', start:ISO, end:ISO}
let currentRange={type:'preset',days:7};
const scenarios={safe:{message:'Hi Riya, I have sent ₹500 for dinner yesterday. Thank you!',amount:500,recipient:'riya@upi',frequency:1,newRecipient:false},warning:{message:'Your KYC expires today. Verify your UPI account immediately to avoid being blocked.',amount:2500,recipient:'helpdesk@upi',frequency:1,newRecipient:true},danger:{message:'URGENT! Your bank account is blocked. Verify your UPI PIN now to receive your refund.',url:'http://bit.ly/upi-verify-now',amount:50000,recipient:'newuser@upi',frequency:6,newRecipient:true}};
document.querySelectorAll('.nav').forEach(btn=>btn.onclick=()=>showTab(btn.dataset.tab)); document.querySelectorAll('[data-goto]').forEach(b=>b.onclick=()=>{showTab(b.dataset.goto);if(b.dataset.openCustom){const bar=$('customRangeBar');if(bar&&!bar.classList.contains('open'))$('customToggle').click();}});
function showTab(id){document.querySelectorAll('.tab,.nav').forEach(x=>x.classList.remove('active')); $(id).classList.add('active'); document.querySelectorAll(`.nav[data-tab="${id}"]`).forEach(n=>n.classList.add('active')); if(id==='analytics'||id==='overview') loadAnalytics(); if(id==='analytics')loadHistory();if(id==='flow')loadModelMetrics();window.scrollTo({top:0,behavior:'smooth'});}
function esc(v){const d=document.createElement('div');d.textContent=v;return d.innerHTML} function setScenario(name){const s=scenarios[name];$('message').value=s.message||'';$('url-qr').value=s.url||'';$('amount').value=s.amount||'';$('recipient').value=s.recipient||'';$('frequency').value=s.frequency||'';$('new-recipient').checked=s.newRecipient;showTab('analyse')}
document.querySelectorAll('.scenario').forEach(b=>b.onclick=()=>setScenario(b.dataset.scenario)); $('clear').onclick=()=>{$('risk-form').reset();};
$('qr-image').onchange=async e=>{const file=e.target.files[0],status=$('qr-status');if(!file)return;status.className='qr-status loading';status.textContent='Decoding QR image locally...';const body=new FormData();body.append('image',file);try{const r=await fetch('/scan-qr',{method:'POST',body});const d=await r.json();if(!r.ok)throw Error(d.detail||'Could not read this QR image.');$('url-qr').value=d.payload;status.className='qr-status success';status.textContent=`QR decoded · ${d.kind} · ${Math.round(d.risk_score*100)}% link/QR risk`;}catch(err){status.className='qr-status error';status.textContent=err.message||'Could not read this QR image.';}};
$('risk-form').onsubmit=async e=>{e.preventDefault();const payload={message:$('message').value,url_or_qr:$('url-qr').value,amount:$('amount').value?+$('amount').value:null,recipient:$('recipient').value,payments_last_hour:$('frequency').value?+$('frequency').value:null,is_new_recipient:$('new-recipient').checked};if(!payload.message&&!payload.url_or_qr&&payload.amount===null){$('message').focus();return}const b=$('check-btn');b.disabled=true;b.innerHTML='Analysing protection layers...';try{const r=await fetch('/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!r.ok)throw Error();showResult(await r.json());loadAnalytics(currentRange)}catch{$('result').className='panel result error';$('result').innerHTML='<p class="eyebrow">CONNECTION ERROR</p><h3>Could not complete the check</h3><p>Start the project using <code>python run_api.py</code>, then retry.</p>'}finally{b.disabled=false;b.innerHTML='Analyse payment risk <b>→</b>'}};
function shapBlock(d){
  const groups=d.shap_explanations||{};
  const labels={message:'Message model',url_qr:'Link/QR model',transaction:'Transaction model'};
  const sections=Object.entries(labels).map(([key,label])=>{
    const items=groups[key];
    if(!items||!items.length)return'';
    const rows=items.map(x=>{
      const pct=Math.round(Math.abs(x.contribution)*400); // scaled for visible bar length, SHAP values are small
      const dir=x.direction==='increased_risk'?'up':'down';
      return `<div class="shap-row ${dir}"><span>${esc(x.label)}</span><i><b style="width:${Math.min(pct,100)}%"></b></i><small>${x.direction==='increased_risk'?'+':'−'}${Math.abs(x.contribution).toFixed(3)}</small></div>`;
    }).join('');
    return `<div class="shap-group"><small>${label}</small>${rows}</div>`;
  }).filter(Boolean).join('');
  if(!sections)return'';
  return `<div class="reason-title">Model attribution (SHAP)</div><p class="shap-hint">Exactly how much each signal pushed THIS specific prediction up (red) or down (green) -- real per-prediction model math, not a general description.</p>${sections}`;
}
function showResult(d){const c=riskClass(d.verdict),score=Math.round(d.risk_score*100);$('result').className=`panel result ${c}`;$('result').innerHTML=`<p class="eyebrow">LIVE VERDICT</p><div class="verdict"><div><span class="verdict-tag ${c}">${d.verdict}</span><h2>${score}<small>/100 risk score</small></h2><p>${d.verdict==='Safe'?'No strong fraud pattern was found in the inputs supplied.':'Pause before paying and independently verify the recipient.'}</p></div><div class="score-ring" style="--p:${score}"><b>${score}</b><small>RISK</small></div></div><div class="reason-title">Why this verdict</div><ul>${d.reasons.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>${shapBlock(d)}`;$('modules').innerHTML=Object.entries(d.module_scores).map(([k,v])=>{const label=k==='url_qr'?'Link & QR':k[0].toUpperCase()+k.slice(1);const n=v===null?0:Math.round(v*100);return `<div class="module-row"><span>${label}</span><div><i><b style="width:${n}%"></b></i><strong>${v===null?'—':n+'%'}</strong></div></div>`}).join('')}
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
    const d=await (await fetch(`/analytics?${rangeQuery()}`)).json();
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
    const rows=await (await fetch(`/history?limit=${currentRange.type==='custom'?100:12}${extra}`)).json();
    $('history-list').innerHTML=rows.length?`<div class="table"><div class="tr th"><span>VERDICT</span><span>SIGNALS USED</span><span>RISK SCORE</span><span>TIME</span></div>${rows.map(x=>`<div class="tr"><span><b class="badge ${riskClass(x.verdict)}">${x.verdict}</b></span><span>${x.modules_used.join(' · ')}</span><span>${Math.round(x.risk_score*100)}%</span><span>${fmtFull(x.created_at)}</span></div>`).join('')}</div>`:'No completed checks in this window. Try a wider range or run a demo scenario.'
  }catch{}
}
async function loadModelMetrics(){const wrap=$('model-metrics-groups');const labels={nlp:'Message model',url:'URL & QR model',transaction:'Transaction model'};try{const d=await (await fetch('/model-metrics')).json();wrap.innerHTML=Object.entries(labels).map(([key,label])=>{const m=d[key];if(!m)return `<div class="model-group"><div><b>${label}</b><small>Not trained yet — run python setup.py</small></div></div>`;const strip=[['Precision',m.precision],['Recall',m.recall],['F1 score',m.f1_score],['ROC-AUC',m.roc_auc]].map(([k,v])=>`<span><small>${k}</small><b>${(v*100).toFixed(2)}%</b></span>`).join('');return `<div class="model-group"><div><b>${label}</b><small>${m.model} · ${m.test_samples.toLocaleString()} held-out samples</small></div><div class="metric-strip">${strip}</div></div>`}).join('')}catch{wrap.innerHTML='<p>Run python setup.py to generate model metrics.</p>'}}
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
loadAnalytics();
