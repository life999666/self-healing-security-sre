'use strict';
const $ = id => document.getElementById(id);
const labels = {sql_injection:'SQL injection',brute_force:'Brute force',http_flood:'HTTP flood / DDoS signal'};
let snapshot={incidents:[],rules:[],metrics:{}}, selected=null, mode='disconnected', api='', secret='', timer=null, connecting=false;
const initialDetail=$('detail').innerHTML;
const agentRoles={'Boss Agent':'Routes tasks and records the result','Detection Agent':'Validates SQL and login-failure evidence','SOC Analyst Agent':'Explains evidence and selects response','Repair Agent':'Tests SQL patches or activates login cooldown','Monitor Agent':'Verifies changes and checks health continuously'};
const esc = value => String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function message(text){$('message').textContent=text;}
function setMode(value){mode=value;const b=$('mode');b.textContent=value==='live'?'LIVE AGENT':value==='demo'?'DEMO · SAMPLE DATA':'DISCONNECTED';b.className='badge '+value;$('disconnect').hidden=value!=='live';}
function clearConnection(){clearInterval(timer);timer=null;secret='';api='';$('token').value='';}
async function request(path,options={}){
 const response=await fetch(api+path,{...options,headers:{Authorization:'Bearer '+secret,...options.headers},signal:AbortSignal.timeout(10000),cache:'no-store'});
 if(!response.ok)throw new Error(response.status===401?'Invalid admin token. Check ADMIN_TOKEN in your .env file.':`Agent returned HTTP ${response.status}.`);
 return response.json();
}
async function refresh(){
 try{snapshot=await request('/api/state');if(snapshot.mode!=='live'||!Array.isArray(snapshot.incidents))throw new Error('This address did not return a Sentinel agent.');setMode('live');render();message('Connected. Refreshing every 3 seconds. Only gateway traffic and trusted collector events are observed.');}
 catch(e){clearConnection();setMode('disconnected');message('Connection lost. Showing the last snapshot, which is no longer live. '+e.message);render();}
}
$('connect-form').addEventListener('submit',async e=>{
 e.preventDefault();if(connecting)return;connecting=true;$('connect').disabled=true;
 try{
  const u=new URL($('api-url').value);const local=['localhost','127.0.0.1','[::1]'].includes(u.hostname);
  if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw new Error('Enter only the API origin, such as http://127.0.0.1:8000.');
  if(u.protocol==='http:'&&!local)throw new Error('Use HTTPS for a remote agent.');
  if(location.protocol==='https:'&&u.protocol==='http:')throw new Error('For the local agent, open http://127.0.0.1:8000 in your browser. An HTTPS dashboard cannot reliably connect to local HTTP.');
  clearInterval(timer);api=u.origin;secret=$('token').value.trim();message('Connecting…');
  snapshot=await request('/api/state');if(snapshot.mode!=='live'||!Array.isArray(snapshot.incidents))throw new Error('This address did not return a Sentinel agent.');
  selected=null;setMode('live');render();message('Connected. Only requests through your gateway are protected.');timer=setInterval(refresh,3000);
 }catch(error){clearConnection();setMode('disconnected');message(error.message);render();}
 finally{connecting=false;$('connect').disabled=false;}
});
$('disconnect').onclick=()=>{clearConnection();setMode('disconnected');message('Disconnected. The last snapshot remains visible; gateway protections continue on the server.');render();};
$('api-url').value=['localhost','127.0.0.1'].includes(location.hostname)?location.origin:'';
function demo(){
 clearConnection();setMode('demo');const now=Date.now()/1000;
 const cases=[
 {id:'DEMO-SQL-01',label:'sql_injection',source_ip:'192.0.2.14',path:'/products',evidence:{signature:'SQL-02',request_fingerprint:'illustrative-redacted'},explanation:'A SQL syntax signature matched a request to /products. A path-scoped SQL guard was proposed. The unsafe query still requires a source fix.',kind:'sql_guard'},
 {id:'DEMO-AUTH-02',label:'brute_force',source_ip:'192.0.2.28',path:'/login',evidence:{failed_logins:5,window_seconds:60},explanation:'Five failed login responses from one source reached the threshold. A temporary login cooldown was proposed for this source.',kind:'login_cooldown'},
];
 snapshot={mode:'demo',metrics:{requests:426,blocked:67},incidents:cases.map((c,i)=>({...c,created:now-i*85,status:'mitigated',origin:'sample',llm_status:'illustrative; no model called',rule_id:'demo-rule-'+i,trace:[{node:'Boss Agent',outcome:'Sample dispatch'},{node:'Detection Agent',outcome:'Sample evidence'},{node:'SOC Analyst Agent',outcome:c.kind+' proposed'},{node:'Repair Agent',outcome:'Sample policy only; no backend change'},{node:'Monitor Agent',outcome:'Illustrative verification'},{node:'Boss Agent',outcome:'Sample result recorded'}],verification:{scope:'Illustration only. No traffic was sent and no real service was checked.'},patch:c.label==='sql_injection'?{status:'review_required',title:'Use a parameterized query',example:'cursor.execute("SELECT id, name FROM products WHERE name = ?", (user_input,))',note:'Review the actual application source. This is an example, not an applied patch.'}:null})),rules:cases.map((c,i)=>({id:'demo-rule-'+i,kind:c.kind,expires:now+120,incident_id:c.id}))};
 snapshot.agents=Object.fromEntries(Object.keys(agentRoles).map(name=>[name,{last_outcome:'Illustrative sample activity; no agent executed',last_at:now}]));
 selected=cases[0].id;render();message('Sample data only. No attacks sent, no backend connected, and no real protections applied.');return {mode,incidents:2};
}
$('demo').onclick=demo;$('filter').onchange=render;
function render(){
 $('agent-cards').innerHTML=Object.entries(agentRoles).map(([name,role])=>{const a=snapshot.agents?.[name];return `<article><strong>${esc(name)}</strong><p>${esc(role)}</p><small>${a?esc(a.last_outcome):'Waiting for a live connection'}</small><small>${a?.last_at?'Last activity: '+esc(new Date(a.last_at*1000).toLocaleTimeString()):''}</small></article>`;}).join('');
 const mon=snapshot.monitor;
 $('monitor-status').textContent=mode==='live'&&mon?.checked_at ? `Upstream ${mon.healthy?'healthy':'unavailable'} · checked ${new Date(mon.checked_at*1000).toLocaleTimeString()} · SQL source repair ${snapshot.source_repair_enabled?'enabled for configured lab':'not configured'} · ${snapshot.orchestrator}` : 'No live health verification available.';

 const m=snapshot.metrics||{};for(const [id,val] of [['requests',m.requests],['blocked',m.blocked],['incident-count',snapshot.incidents.length],['rule-count',snapshot.rules.length]])$(id).textContent=(mode==='disconnected'&&!snapshot.incidents.length&&m.requests===undefined)?'—':Number(val||0).toLocaleString();
 $('queue-number').textContent=snapshot.incidents.length;
 const list=snapshot.incidents.filter(i=>$('filter').value==='all'||i.label===$('filter').value);
 $('incident-list').innerHTML=list.length?list.map(i=>`<button class="incident ${selected===i.id?'selected':''}" data-id="${esc(i.id)}" aria-pressed="${selected===i.id}"><strong>${esc(labels[i.label]||i.label)}</strong><span class="status ${['escalated','failed','rolled_back','interrupted'].includes(i.status)?'warn':''}">${esc(i.status.replaceAll('_',' '))}</span><small>${esc(i.source_ip)} · ${esc(i.path)}</small><small>${new Date(i.created*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</small></button>`).join(''):`<div class="empty"><span class="empty-icon">⌁</span><h3>${snapshot.incidents.length?'No matching incidents':'Waiting for your first signal'}</h3><p>${mode==='live'?'Your agent is connected. Route test requests through port 8080.':'Connect your agent or explore the labeled demo cases.'}</p></div>`;
 document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>{selected=b.dataset.id;render();});
 const i=snapshot.incidents.find(i=>i.id===selected);if(!i){$('detail').innerHTML=initialDetail;return;}
 const rule=snapshot.rules.find(r=>r.id===i.rule_id);
 $('detail').innerHTML=`<div class="detail-top"><span class="eyebrow">${mode==='demo'?'SAMPLE INCIDENT':'INCIDENT DETAILS'}</span><span class="status">${esc(i.status.replaceAll('_',' '))}</span></div><h2>${esc(labels[i.label]||i.label)}</h2><p>${esc(i.explanation)}</p><div class="facts"><div><small>Source</small>${esc(i.source_ip)}</div><div><small>Protected route</small>${esc(i.path)}</div><div><small>Evidence source</small>${esc(i.origin)}</div><div><small>Local LLM</small>${esc(i.llm_status)}</div></div><div class="evidence">${esc(JSON.stringify(i.evidence,null,2))}</div><h3>Five-agent decision trail</h3><ol class="trace">${(i.trace||[]).map((t,n)=>`<li><b>${String(n+1).padStart(2,'0')}</b><div>${esc(t.node)}<small>${esc(t.outcome)}</small></div></li>`).join('')}</ol>${i.source_repair?`<details open><summary>Source repair result · ${esc(i.source_repair.status)}</summary><pre>${esc(JSON.stringify(i.source_repair,null,2))}</pre></details>`:''}${i.sre_remediation?`<details open><summary>SRE remediation · ${esc(i.sre_remediation.status)}</summary><pre>${esc(JSON.stringify(i.sre_remediation,null,2))}</pre></details>`:''}${i.verification?`<p>${esc(i.verification.scope)}</p>`:''}${i.llm_note?`<details><summary>Model explanation · advisory</summary><p>${esc(i.llm_note)}</p></details>`:''}${i.patch?`<details><summary>SQL source action · ${esc(i.patch.status)}</summary><p>${esc(i.patch.title)}</p><pre>${esc(i.patch.example)}</pre><p>${esc(i.patch.note)}</p></details>`:''}<div class="detail-actions">${rule?'<button id="rollback">'+(mode==='demo'?'Simulate rollback':'Roll back protection')+'</button>':''}<button id="export">Export incident JSON</button></div>${rule?`<p>Rule expires ${new Date(rule.expires*1000).toLocaleTimeString()}. ${mode==='demo'?'Sample expiry; no server rule exists.':''}</p>`:''}`;
 if($('rollback'))$('rollback').onclick=async()=>{
  if(mode==='disconnected'){message('Reconnect before changing a protection.');return;}
  if(mode==='demo'){snapshot.rules=snapshot.rules.filter(r=>r.id!==i.rule_id);i.status='rolled_back';i.trace.push({node:'Rollback',outcome:'Sample rule removed locally'});render();message('Demo rollback complete. No real protection was changed.');return;}
  $('rollback').disabled=true;try{await request('/api/rules/'+encodeURIComponent(i.rule_id)+'/rollback',{method:'POST'});await refresh();message('Protection rolled back. Built-in detection thresholds remain active.');}catch(e){message(e.message);render();}
 };
 $('export').onclick=()=>{const b=new Blob([JSON.stringify({mode,incident:i},null,2)],{type:'application/json'}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='sentinel-incident-'+i.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};
}
$('clock').textContent=new Date().toLocaleDateString(undefined,{day:'2-digit',month:'short',year:'numeric'});
if(document.modelContext?.registerTool){const lifecycle=new AbortController();try{Promise.resolve(document.modelContext.registerTool({name:'load_security_demo',title:'Load sample security incidents',description:'Load two labeled sample incidents in this dashboard. Disconnects any current dashboard session. Sends no traffic and changes no server protection.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:false},execute(input){if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).length)throw new Error('Expected an empty object');return demo();}},{signal:lifecycle.signal})).catch(()=>{});}catch{}window.addEventListener('pagehide',()=>lifecycle.abort(),{once:true});}
render();
