"use strict";
const $ = (id) => document.getElementById(id);
const state = {token: null, config: null, me: null, tenants: [], findings: [], registry: [], registryPage: 1, registryTotal: 0, registryPages: 0, dashboard: {}, view: "overview", tenant: ""};
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const badge = (value) => '<span class="pill '+escapeHtml(value)+'">'+escapeHtml(String(value||"unknown").replaceAll("_"," "))+'</span>';
function notify(message,error=false){const el=$("notice");el.textContent=message;el.classList.remove("hidden");el.classList.toggle("error",error);clearTimeout(notify.timer);notify.timer=setTimeout(()=>el.classList.add("hidden"),7000)}
async function request(path,options={}){
 const headers = {"Accept":"application/json",...(options.body?{"Content-Type":"application/json"}:{}),...(state.token?{"Authorization":"Bearer "+state.token}:{})};
 const response=await fetch(path,{...options,headers:{...headers,...options.headers},cache:"no-store"});
 if(response.status===401){showLogin();throw new Error("Your session has expired. Sign in again.")}
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(typeof data.detail==="string"?data.detail:"Request failed ("+response.status+")");
 return data;
}
function showLogin(){state.token=null;sessionStorage.removeItem("vt_token");$("shell").classList.add("hidden");$("login").classList.remove("hidden")}
function showShell(){$("login").classList.add("hidden");$("shell").classList.remove("hidden")}
function randomString(){const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);return Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("")}
function base64url(buffer){return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
async function signIn(){
 const c=state.config;
 if(c.dev_auth){await loadApp();return}
 if(!c.client_id||!c.authorize_url||!c.token_url){notify("OIDC login is not configured on the server.",true);return}
 const verifier=randomString(),nonce=randomString(),stateValue=randomString();
 sessionStorage.setItem("vt_pkce",JSON.stringify({verifier,nonce,state:stateValue}));
 const challenge=base64url(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier)));
 const url=new URL(c.authorize_url);
 url.searchParams.set("client_id",c.client_id);url.searchParams.set("response_type","code");
 url.searchParams.set("redirect_uri",location.origin+"/");url.searchParams.set("scope",c.scope||"openid profile");
 url.searchParams.set("code_challenge",challenge);url.searchParams.set("code_challenge_method","S256");
 url.searchParams.set("state",stateValue);url.searchParams.set("nonce",nonce);
 location.assign(url.toString());
}
async function handleCallback(){
 const query=new URLSearchParams(location.search);
 if(query.has("error")){history.replaceState(null,"","/");throw new Error("Identity provider returned: "+query.get("error"))}
 if(!query.has("code"))return;
 const saved=JSON.parse(sessionStorage.getItem("vt_pkce")||"null");
 if(!saved||saved.state!==query.get("state"))throw new Error("Invalid login state. Please try again.");
 sessionStorage.removeItem("vt_pkce");
 const c=state.config;
 const form=new URLSearchParams({grant_type:"authorization_code",code:query.get("code"),redirect_uri:location.origin+"/",client_id:c.client_id,code_verifier:saved.verifier});
 const response=await fetch("/api/auth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:form,cache:"no-store"});
 const tokens=await response.json();
 history.replaceState(null,"","/");
 if(!response.ok||!tokens.id_token)throw new Error("OIDC token exchange failed");
 const claims=JSON.parse(atob(tokens.id_token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/")));
 if(claims.nonce!==saved.nonce)throw new Error("OIDC nonce mismatch");
 // Access token remains in this browser tab only. API validates signature, issuer, audience, and expiration.
 state.token=tokens.id_token;sessionStorage.setItem("vt_token",state.token);
}
async function loadApp(){
 state.me=await request("/api/me");
 state.tenants=await request("/api/tenants");
 $("identity").textContent=state.me.subject;
 $("role").textContent=state.me.admin?"Platform administrator":"Tenant member";
 document.querySelectorAll(".admin-only").forEach(el=>el.classList.toggle("hidden",!state.me.admin));
 if(!state.me.admin&&state.view==="admin")state.view="overview";
 renderTenants();showShell();await refresh();
}
function renderTenants(){
 const previous=state.tenant;
 $("tenant-select").replaceChildren(new Option("All my tenants",""),...state.tenants.map(t=>new Option(t.name,t.id)));
 $("member-tenant").replaceChildren(...state.tenants.map(t=>new Option(t.name,t.id)));
 state.tenant=state.tenants.some(t=>t.id===previous)?previous:"";
 $("tenant-select").value=state.tenant;
}
async function refresh(){
 const suffix=state.tenant?"?tenant_id="+encodeURIComponent(state.tenant):"";
 const [dashboard,findings]=await Promise.all([
 request("/api/dashboard"+suffix),request("/api/occurrences"+suffix)]);
 state.dashboard=dashboard;state.findings=findings; await loadRegistry();
 renderOverview();renderFindings();renderRegistry();
 if(state.me.admin&&state.view==="admin")await renderImports();
 $("connection").textContent="● Connected";
}
function table(rows,columns,empty="No findings match this view."){
 if(!rows.length)return '<div class="empty">'+escapeHtml(empty)+'</div>';
 return '<div class="table-wrap"><table><thead><tr>'+columns.map(c=>'<th>'+escapeHtml(c.title)+'</th>').join("")+'</tr></thead><tbody>'+rows.map(row=>'<tr class="link-row" data-id="'+escapeHtml(row.id)+'">'+columns.map(c=>'<td>'+c.cell(row)+'</td>').join("")+'</tr>').join("")+'</tbody></table></div>';
}
const findingColumns=[
 {title:"Vulnerability",cell:r=>'<strong>'+escapeHtml(r.title)+'</strong>'+(r.is_kev?'<span class="kev">● KEV</span>':"")+'<small>'+escapeHtml(r.context||"No component context")+'</small>'},
 {title:"Severity",cell:r=>badge(r.severity)},
 {title:"Asset",cell:r=>escapeHtml(r.asset)},
 {title:"Status",cell:r=>badge(r.status)},
 {title:"Owner",cell:r=>escapeHtml(r.assignee||"Unassigned")}
];
function renderOverview(){
 const counts=state.dashboard.by_status||{};
 $("m-total").textContent=state.dashboard.total??0;
 $("m-open").textContent=(counts.open||0)+(counts.reopened||0);
 $("m-progress").textContent=counts.in_progress||0;
 $("m-kev").textContent=state.dashboard.kev_occurrences||0;
 $("recent").innerHTML=table(state.findings.slice(0,8),findingColumns,"No findings yet. Import findings to begin tracking remediation.");
}
function renderFindings(){
 const search=$("finding-search").value.trim().toLowerCase(),status=$("status-filter").value;
 const rows=state.findings.filter(f=>(!status||f.status===status)&&(!search||[f.title,f.asset,f.assignee,f.context,f.severity].some(v=>String(v||"").toLowerCase().includes(search))));
 $("finding-table").innerHTML=table(rows,findingColumns);
}
async function loadRegistry(){
 const params=new URLSearchParams({page:String(state.registryPage),page_size:"25"});
 const q=$("registry-search").value.trim(),filter=$("registry-filter").value;
 if(q)params.set("q",q);
 if(filter==="kev"||filter==="kev_findings")params.set("kev_only","true");
 if(filter==="findings"||filter==="kev_findings")params.set("has_findings","true");
 if(state.tenant)params.set("tenant_id",state.tenant);
 const data=await request("/api/vulnerabilities?"+params);
 state.registry=data.items;state.registryTotal=data.total;state.registryPages=data.pages;
 renderRegistry();
}
function renderRegistry(){
 $("registry-table").innerHTML=table(state.registry,[
 {title:"Vulnerability",cell:r=>'<strong>'+escapeHtml(r.title)+'</strong><small class="mono">'+escapeHtml(r.identifiers.join(" · "))+'</small>'},
 {title:"Severity",cell:r=>badge(r.severity)},
 {title:"Intelligence",cell:r=>r.is_kev?'<span class="kev">● CISA KEV</span>':"—"},
 {title:"Affected tenants",cell:r=>'<strong>'+r.tenant_count+'</strong><small>'+r.occurrence_count+' findings</small>'},
 {title:"Tenant impact",cell:r=>'<span class="impact-link">View affected tenants →</span>'}],"No vulnerabilities match these filters.");
 $("registry-count").textContent=state.registryTotal+" vulnerabilities";
 $("registry-prev").disabled=state.registryPage<=1;
 $("registry-next").disabled=state.registryPage>=state.registryPages;
 $("registry-page").textContent="Page "+state.registryPage+" of "+Math.max(1,state.registryPages);
}
async function openImpact(id){
 const suffix=state.tenant?"?tenant_id="+encodeURIComponent(state.tenant):"";
 const v=await request("/api/vulnerabilities/"+encodeURIComponent(id)+"/impact"+suffix);
 $("detail-title").textContent=v.title;
 const meta=Object.entries(v.kev_metadata||{}).filter(([,value])=>value).map(([key,value])=>'<dt>'+escapeHtml(key.replace(/([A-Z])/g," $1"))+'</dt><dd>'+escapeHtml(value)+'</dd>').join("");
 $("detail-body").innerHTML='<section class="drawer-section"><h3>Canonical vulnerability</h3><p>'+(v.is_kev?'<span class="kev">● CISA KEV</span>':'Not in KEV')+'</p><p class="mono">'+escapeHtml(v.identifiers.join(" · "))+'</p><p>'+badge(v.severity)+'</p>'+(meta?'<dl>'+meta+'</dl>':'')+'</section>'+
 '<section class="drawer-section"><h3>Affected tenants ('+v.tenant_count+')</h3><p>'+v.total_occurrences+' remediation occurrences within your authorized scope</p>'+
 (v.tenants.length?v.tenants.map(t=>'<details class="impact-tenant"><summary><strong>'+escapeHtml(t.name)+'</strong><span>'+t.total+' findings · '+Object.entries(t.by_status).map(([s,n])=>n+' '+s.replaceAll("_"," ")).join(", ")+'</span></summary><div class="impact-assets">'+t.assets.map(a=>'<div class="impact-asset"><div><strong>'+escapeHtml(a.name)+'</strong><small>'+escapeHtml(a.kind)+' · '+escapeHtml(a.external_id)+'</small><small>'+escapeHtml(a.context||"No component context")+'</small></div><div>'+badge(a.status)+'<small>'+escapeHtml(a.assignee||"Unassigned")+'</small><small>Due: '+escapeHtml(a.due_date||"Not set")+'</small><button class="text-button impact-open" data-occurrence="'+escapeHtml(a.occurrence_id)+'">Open remediation →</button></div></div>').join("")+'</div></details>').join(""):'<div class="empty">No affected tenants in your authorized scope.</div>')+'</section>';
 $("drawer").classList.remove("hidden");$("drawer-backdrop").classList.remove("hidden");
 $("detail-body").querySelectorAll(".impact-open").forEach(b=>b.onclick=()=>openFinding(b.dataset.occurrence).catch(err=>notify(err.message,true)));
}
async function renderImports(){
 const imports=await request("/api/admin/imports");
 $("imports").innerHTML=table(imports.map(i=>({...i,id:""})),[
 {title:"Source",cell:r=>escapeHtml(r.source)},
 {title:"Status",cell:r=>badge(r.status)},
 {title:"Processed",cell:r=>escapeHtml(r.imported)}],"No imports have been recorded.");
}
function view(name){
 if(name==="admin"&&!state.me?.admin)return;
 state.view=name;
 document.querySelectorAll(".view").forEach(el=>el.classList.toggle("hidden",el.id!==name));
 document.querySelectorAll(".nav").forEach(el=>el.classList.toggle("active",el.dataset.view===name));
 $("breadcrumb").textContent=({overview:"OVERVIEW",findings:"REMEDIATION",registry:"REGISTRY",admin:"ADMINISTRATION"})[name];
 if(name==="admin")renderImports().catch(err=>notify(err.message,true));
}
function closeDrawer(){$("drawer").classList.add("hidden");$("drawer-backdrop").classList.add("hidden")}
async function openFinding(id){
 const f=await request("/api/occurrences/"+encodeURIComponent(id)+"/detail");
 $("detail-title").textContent=f.vulnerability.title;
 const meta=[["Tenant",state.tenants.find(t=>t.id===f.tenant_id)?.name||f.tenant_id],["Asset",f.asset.name],["Asset ID",f.asset.external_id],["Component",f.context||"—"],["Severity",f.vulnerability.severity],["First seen",new Date(f.first_seen).toLocaleString()],["Last seen",new Date(f.last_seen).toLocaleString()]];
 const canWrite=state.me.admin||false; // Server performs final role checks for tenant users.
 $("detail-body").innerHTML=
 '<section class="drawer-section"><h3>Finding context</h3><dl>'+meta.map(([a,b])=>'<dt>'+escapeHtml(a)+'</dt><dd>'+escapeHtml(b)+'</dd>').join("")+'</dl>'+(f.vulnerability.is_kev?'<p class="kev">● Listed in CISA KEV</p>':"")+'</section>'+
 '<section class="drawer-section"><h3>Remediation</h3><form id="remediation-form"><label>Status<select name="status">'+["open","in_progress","reopened","remediated","risk_accepted","false_positive"].map(v=>'<option value="'+v+'" '+(f.status===v?"selected":"")+'>'+escapeHtml(v.replaceAll("_"," "))+'</option>').join("")+'</select></label><label>Assigned owner<input name="assignee" maxlength="300" value="'+escapeHtml(f.assignee)+'" placeholder="Team or user"></label><label>Due date<input name="due_date" type="date" value="'+escapeHtml(f.due_date)+'"></label><button class="primary">Save remediation</button></form></section>'+
 '<section class="drawer-section"><h3>Scanner observations ('+f.observations.length+')</h3>'+f.observations.map(o=>'<div class="note"><strong>'+escapeHtml(o.source)+'</strong><p class="mono">'+escapeHtml(o.source_finding_id)+'</p></div>').join("")+'</section>'+
 '<section class="drawer-section"><h3>Activity notes</h3><form id="note-form"><textarea name="text" required maxlength="4000" placeholder="Add remediation progress, blockers, or verification details"></textarea><button class="secondary">Add note</button></form><div>'+f.notes.map(n=>'<div class="note"><small>'+escapeHtml(n.author)+' · '+escapeHtml(new Date(n.created_at).toLocaleString())+'</small><p>'+escapeHtml(n.text)+'</p></div>').join("")+'</div></section>';
 $("drawer").classList.remove("hidden");$("drawer-backdrop").classList.remove("hidden");
 $("remediation-form").onsubmit=async e=>{e.preventDefault();const form=new FormData(e.target);try{await request("/api/occurrences/"+id,{method:"PATCH",body:JSON.stringify(Object.fromEntries(form))});notify("Remediation updated");await refresh();await openFinding(id)}catch(err){notify(err.message,true)}};
 $("note-form").onsubmit=async e=>{e.preventDefault();const form=new FormData(e.target);try{await request("/api/occurrences/"+id+"/notes",{method:"POST",body:JSON.stringify({text:form.get("text")})});notify("Note added");await openFinding(id)}catch(err){notify(err.message,true)}};
}
function bind(){
 $("sign-in").onclick=()=>signIn().catch(e=>notify(e.message,true));
 $("logout").onclick=()=>{showLogin();notify("Signed out of VulnTrack. Your identity provider session may remain active.")};
 $("refresh").onclick=()=>refresh().catch(e=>notify(e.message,true));
 $("tenant-select").onchange=e=>{state.tenant=e.target.value;refresh().catch(err=>notify(err.message,true))};
 let registryTimer;
 $("registry-search").oninput=()=>{clearTimeout(registryTimer);registryTimer=setTimeout(()=>{state.registryPage=1;loadRegistry().catch(err=>notify(err.message,true))},250)};
 $("registry-filter").onchange=()=>{state.registryPage=1;loadRegistry().catch(err=>notify(err.message,true))};
 $("registry-prev").onclick=()=>{if(state.registryPage>1){state.registryPage--;loadRegistry().catch(err=>notify(err.message,true))}};
 $("registry-next").onclick=()=>{if(state.registryPage<state.registryPages){state.registryPage++;loadRegistry().catch(err=>notify(err.message,true))}};
 $("registry-table").onclick=e=>{const row=e.target.closest("[data-id]");if(row)openImpact(row.dataset.id).catch(err=>notify(err.message,true))};
 $("finding-search").oninput=renderFindings;$("status-filter").onchange=renderFindings;
 document.querySelectorAll("[data-view]").forEach(el=>el.onclick=()=>view(el.dataset.view));
 document.querySelectorAll("[data-goto]").forEach(el=>el.onclick=()=>view(el.dataset.goto));
 $("close-drawer").onclick=closeDrawer;$("drawer-backdrop").onclick=closeDrawer;
 document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer()});
 $("recent").onclick=$("finding-table").onclick=e=>{const row=e.target.closest("[data-id]");if(row)openFinding(row.dataset.id).catch(err=>notify(err.message,true))};
 $("tenant-form").onsubmit=async e=>{e.preventDefault();try{await request("/api/tenants",{method:"POST",body:JSON.stringify({name:new FormData(e.target).get("name")})});e.target.reset();state.tenants=await request("/api/tenants");renderTenants();notify("Tenant created")}catch(err){notify(err.message,true)}};
 $("member-form").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await request("/api/tenants/"+encodeURIComponent($("member-tenant").value)+"/members",{method:"POST",body:JSON.stringify({subject:f.get("subject"),role:f.get("role")})});notify("Membership saved")}catch(err){notify(err.message,true)}};
 $("kev-sync").onclick=async e=>{e.target.disabled=true;try{const result=await request("/api/admin/kev/sync",{method:"POST"});notify("Processed "+result.processed+" KEV records");await refresh()}catch(err){notify(err.message,true)}finally{e.target.disabled=false}};
 $("import-submit").onclick=async e=>{const file=$("import-file").files[0];if(!file){notify("Choose a JSON file first.",true);return}if(file.size>5_000_000){notify("File exceeds 5 MB limit.",true);return}e.target.disabled=true;try{const payload=JSON.parse(await file.text());const result=await request("/api/ingest",{method:"POST",body:JSON.stringify(payload)});notify("Imported "+result.imported+" findings");await refresh();await renderImports()}catch(err){notify(err.message,true)}finally{e.target.disabled=false}};
}
async function boot(){
 bind();
 try{
  state.config=await request("/api/auth/config");
  await handleCallback();
  state.token=state.token||sessionStorage.getItem("vt_token");
  if(state.token||state.config.dev_auth){try{await loadApp();return}catch(err){if(!state.config.dev_auth)sessionStorage.removeItem("vt_token");notify(err.message,true)}}
  $("login-hint").textContent=state.config.dev_auth?"Local development authentication enabled.":"Authentication is managed by your organization's identity provider.";
  showLogin();
 }catch(err){showLogin();$("login-hint").textContent=err.message}
}
boot();
