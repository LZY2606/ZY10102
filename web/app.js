let state = null;
let events = [];
let noticeTimer = null;

const $ = (selector, root=document) => root.querySelector(selector);
const $$ = (selector, root=document) => [...root.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const list = value => String(value || '').split(',').map(x => x.trim()).filter(Boolean);
function idFrom() { return 'key-' + crypto.getRandomValues(new Uint8Array(8)).reduce((a,b)=>a+b.toString(16).padStart(2,'0'),''); }
function localDateTime(d=new Date()) {
  const pad = n => String(n).padStart(2,'0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function api(path, options={}) {
  return fetch(path, {headers:{'Content-Type':'application/json'}, ...options}).then(async r => {
    const text = await r.text();
    const data = text ? JSON.parse(text) : null;
    if (!r.ok) {
      if (data?.checks) data.error += '\n' + data.checks.filter(c=>!c.ok).map(c=>`${c.name}: ${c.detail}`).join('\n');
      throw new Error(data?.error || r.statusText);
    }
    return data;
  });
}
function notice(message, ok=false) {
  const el = $('#notice');
  el.textContent = message;
  el.className = 'notice ' + (ok ? '' : 'banner');
  el.style.borderColor = ok ? '#22c55e' : '#ef4444';
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => el.classList.add('hidden'), 5000);
}
function keySpec(value) {
  if (value.startsWith('RSA-')) return {type:'RSA', bits:Number(value.slice(4))};
  if (value.startsWith('EC-')) return {type:'EC', curve:value.slice(3)};
  return {type:'Ed25519'};
}
function subjectFrom(form) {
  return {common_name:form.cn.value.trim(), organization:form.organization?.value.trim() || ''};
}
function subjectRequestFrom(form) {
  return {
    purpose: form.purpose.value,
    name: form.name.value.trim(),
    template_id: form.template_id.value,
    issuer_id: '',
    issuer_ids: $$('option:checked', form.issuer_ids).map(o=>o.value),
    subject: subjectFrom(form),
    key: keySpec(form.key_type.value),
    signature_algorithm: form.sig.value,
    not_before: form.not_before.value,
    not_after: form.not_after.value,
    dns_names: list(form.dns?.value),
    ip_addresses: list(form.ips?.value),
    email_addresses: [],
    uris: [],
    ekus: list(form.ekus?.value),
    key_usage: list(form.key_usage?.value),
    max_path_len: Number(form.path_len?.value || 0),
    name_constraints: {permitted_dns: list(form.permitted_dns?.value), excluded_dns: list(form.excluded_dns?.value), permitted_ip_net: list(form.permitted_ip?.value)}
  };
}

$('#root-form').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.currentTarget;
  const input = {
    purpose:'root', name:f.name.value, subject:subjectFrom(f), key:keySpec(f.key_type.value),
    signature_algorithm:f.sig.value, not_before:f.not_before.value, not_after:f.not_after.value,
    max_path_len:0, key_usage:['keyCertSign','cRLSign'],
    name_constraints:{permitted_dns:list(f.permitted_dns.value)}
  };
  try { await api('/api/roots',{method:'POST',body:JSON.stringify(input)}); notice('根证书已由事件原子登记',true); await load(); }
  catch(err) { notice(err.message); }
});

$('#template-form').addEventListener('submit', async e => {
  e.preventDefault(); const f=e.currentTarget;
  const input={purpose:'template',name:f.name.value,subject:subjectFrom(f),key:keySpec(f.key_type.value),
    not_before:f.not_before.value,not_after:f.not_after.value,max_path_len:Number(f.path_len.value),
    name_constraints:{permitted_dns:list(f.permitted_dns.value),excluded_dns:list(f.excluded_dns.value),permitted_ip_net:list(f.permitted_ip.value)}};
  try { await api('/api/templates',{method:'POST',body:JSON.stringify(input)}); notice('模板和本地测试密钥已登记',true); await load(); }
  catch(err){notice(err.message);}
});

$('#request-form').addEventListener('submit', async e => {
  e.preventDefault(); const f=e.currentTarget;
  const key=f.idempotency_key.value.trim() || idFrom();
  f.idempotency_key.value = key;
  try { await api('/api/requests',{method:'POST',body:JSON.stringify({idempotency_key:key,input:subjectRequestFrom(f)})}); notice('候选已生成；幂等键为 '+key,true); await load(); }
  catch(err){notice(err.message);}
});

$('#policy-form').addEventListener('submit', async e => {
  e.preventDefault(); const f=e.currentTarget;
  const policy={allowed_sig_algos:list(f.allowed_sig.value),allowed_key_types:list(f.allowed_keys.value),
    max_validity_days:Number(f.max_days.value),min_validity_hours:Number(f.min_hours.value),
    require_leaf_san:f.require_san.checked,allow_wildcard_dns:f.wildcard.checked,require_aki:f.require_aki.checked};
  try { await api('/api/policy',{method:'PUT',body:JSON.stringify(policy)}); notice('已创建新策略版本；旧流程不会被伪装重算',true); await load(); }
  catch(err){notice(err.message);}
});

async function action(path) { try { await api(path,{method:'POST',body:'{}'}); notice('动作已持久化',true); await load(); } catch(err){notice(err.message);} }
async function reject(id) {
  const reason = prompt('拒绝原因', 'operator rejected');
  if (reason === null) return;
  try { await api(`/api/requests/${encodeURIComponent(id)}/reject`,{method:'POST',body:JSON.stringify({reason})}); notice('候选已拒绝',true); await load(); } catch(err){notice(err.message);}
}
async function revoke(id) {
  const reason = prompt('吊销原因', 'key compromise');
  if (reason === null) return;
  try { await api(`/api/certificates/${encodeURIComponent(id)}/revoke`,{method:'POST',body:JSON.stringify({reason})}); notice('吊销事件已持久化',true); await load(); } catch(err){notice(err.message);}
}
async function recovery(id, act) {
  try { await api(`/api/recovery/${encodeURIComponent(id)}`,{method:'POST',body:JSON.stringify({action:act})}); notice('恢复动作已解析为事件',true); await load(); } catch(err){notice(err.message);}
}
$('#verify-form').addEventListener('submit', async e => {
  e.preventDefault(); const f=e.currentTarget;
  try {
    const report=await api('/api/verify',{method:'POST',body:JSON.stringify({cert_id:f.cert_id.value,verify_at:f.verify_at.value})});
    renderVerify(report);
  } catch(err){notice(err.message);}
});
$('#refresh').onclick=load;
$('#export').onclick=()=>{ location.href='/api/export'; };
$('#import-form').addEventListener('submit', async e => {
  e.preventDefault();
  const data=new FormData(e.currentTarget);
  try { const r=await fetch('/api/import',{method:'POST',body:data}); const body=await r.json(); if(!r.ok)throw new Error(body.error); state=body; render(); notice('导入已验证并重放',true); }
  catch(err){notice(err.message);}
});

async function load() {
  [state, events] = await Promise.all([api('/api/state'), api('/api/events')]);
  render();
}
function renderPolicy() {
  const p=state.policy; const f=$('#policy-form');
  f.allowed_sig.value=p.allowed_sig_algos.join(','); f.allowed_keys.value=p.allowed_key_types.join(',');
  f.max_days.value=p.max_validity_days; f.min_hours.value=p.min_validity_hours;
  f.require_san.checked=p.require_leaf_san; f.wildcard.checked=p.allow_wildcard_dns; f.require_aki.checked=p.require_aki;
}
function renderSelectors() {
  const roots=Object.values(state.certificates).filter(c=>c.kind==='root'&&c.status==='accepted');
  const accepted=Object.values(state.certificates).filter(c=>c.status==='accepted'&&c.kind!=='root');
  const all=Object.values(state.certificates);
  $('#request-form').template_id.innerHTML = '<option value="">（不使用）</option>' + Object.values(state.templates).map(t=>`<option value="${esc(t.id)}">${esc(t.name)} (${esc(t.id)})</option>`).join('');
  $('#request-form').issuer_ids.innerHTML = roots.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} root</option>`).join('') + accepted.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} ${esc(c.kind)}</option>`).join('');
  $('#verify-form').cert_id.innerHTML = all.map(c=>`<option value="${esc(c.id)}">${esc(c.name)} ${esc(c.status)} ${esc(c.serial)}</option>`).join('');
}
function requestCertIDs(req) { return req.candidate_cert_ids || []; }
function renderRequests() {
  const boxes={pending:[],accepted:[],rejected:[],revoked:[]};
  Object.values(state.requests).forEach(req=>{ (boxes[req.status]||boxes.pending).push(req); });
  for (const key of Object.keys(boxes)) {
    $(`[data-list="${key}"]`).innerHTML = boxes[key].map(req => `
      <div class="item"><div class="item-title">${esc(req.input.name)}</div>
      <div class="small">${esc(req.id)}</div><div><span class="badge ${esc(req.status)}">${esc(req.status)}</span><span class="small">策略 v${req.policy_version}</span></div>
      ${(req.checks||[]).length?`<table><thead><tr><th>校验</th><th>结果</th><th>详情</th></tr></thead><tbody>${req.checks.map(c=>`<tr><td>${esc(c.name)}</td><td>${c.ok?'通过':'失败'}</td><td>${esc(c.detail)}</td></tr>`).join('')}</tbody></table>`:''}
      <div class="item-actions">
        ${key==='pending'?`<button class="success" onclick="action('/api/requests/${encodeURIComponent(req.id)}/accept')">签发</button><button class="danger" onclick="reject('${esc(req.id)}')">拒绝</button>`:''}
        ${key==='accepted'?`<button class="warning" onclick="revoke('${esc(req.cert_id||req.candidate_cert_ids[0])}')">吊销</button>`:''}
      </div></div>`).join('') || '<p class="small">无</p>';
  }
  const recovery=Object.values(state.intents || {});
  $('[data-list="recovering"]').innerHTML = recovery.map(i=>`<div class="item"><div class="item-title">${esc(i.operation)}</div><div class="small">${esc(i.id)}</div><div class="item-actions"><button class="success" onclick="recovery('${esc(i.id)}','commit')">完成已提交写入</button><button class="danger" onclick="recovery('${esc(i.id)}','abort')">放弃半成品</button></div></div>`).join('') || '<p class="small">无</p>';
  const banner=$('#recover');
  if (recovery.length) { banner.classList.remove('hidden'); banner.innerHTML=`<strong>检测到 ${recovery.length} 条被中断的写入。</strong><p>旧投影仍可读取；请在“恢复中”区域选择完成或放弃。系统不会自动把未决操作显示为已接受。</p>`; }
  else banner.classList.add('hidden');
}
function diffTable(diffs) {
  if (!diffs || !diffs.length) return '<p class="small">无扩展差异</p>';
  return `<table><thead><tr><th>OID</th><th>变化</th><th>Before critical</th><th>After critical</th><th>Before DER</th><th>After DER</th></tr></thead><tbody>${diffs.map(d=>`<tr><td>${esc(d.oid)}<br><span class="small">${esc(d.name)}</span></td><td>${esc(d.change)}</td><td>${d.critical_before}</td><td>${d.critical_after}</td><td class="hex" title="${esc(d.before_hex)}">${esc(d.before_hex)}</td><td class="hex" title="${esc(d.after_hex)}">${esc(d.after_hex)}</td></tr>`).join('')}</tbody></table>`;
}
function renderCertificates() {
  const certs=Object.values(state.certificates).sort((a,b)=>a.serial.localeCompare(b.serial));
  $('#certificates').innerHTML=certs.map(c=>{
    const req=c.request_id?state.requests[c.request_id]:null;
    const diffs=req?.extension_diffs_by_cert?.[c.id]||[];
    return `<div class="item"><div class="item-title"><span class="badge ${esc(c.status)}">${esc(c.status)}</span>${esc(c.name)} <span class="small">#${esc(c.serial)}</span></div>
    <p class="small">${esc(c.kind)} / ${esc(c.signature_algorithm)} / ${esc(c.not_before)} → ${esc(c.not_after)}</p>
    <p class="small">Parent: ${esc(c.parent_id||'self')} · 本地私钥引用不持久化 · Fingerprint: ${esc(c.fingerprint.slice(0,16))}…</p>
    ${diffTable(diffs)}
    <div class="item-actions"><a href="/api/certificates/${encodeURIComponent(c.id)}/der"><button type="button" class="secondary">公开 DER</button></a>${c.status==='accepted'?`<button class="warning" onclick="revoke('${esc(c.id)}')">吊销</button>`:''}</div></div>`;
  }).join('') || '<p class="small">暂无证书；页面未写入任何示例数据。</p>';
}
function renderEvents() {
  $('#events').innerHTML=events.map(e=>`<div class="item"><div><strong>${esc(e.type)}</strong> <span class="small">${esc(e.at)}</span></div><div class="small">#${e.seq} ${esc(e.id)}</div><div class="hex">${esc(e.hash)}</div></div>`).join('');
  $('#proof-root').textContent=events.length?`${events.at(-1).id}:${events.at(-1).hash}`:'EMPTY';
}
function renderVerify(report) {
  $('#verify-result').innerHTML=`<p>${esc(report.boundary_rule)}</p>` + report.chains.map((c,i)=>`<div class="chain ${c.qualified?'qualified':'unqualified'}"><strong>${c.default?'默认链 ':''}${esc(c.id)} ${c.qualified?'合格':'不合格'}</strong><p class="small">${esc(c.reason)}</p>${c.links.map(l=>`<div>→ ${esc(l.subject)} <span class="badge ${esc(l.status)}">${esc(l.status)}</span></div>`).join('')}</div>`).join('');
}
function render() { renderPolicy(); renderSelectors(); renderRequests(); renderCertificates(); renderEvents(); }
function initTimes() { const now=new Date(); const later=new Date(now.getTime()+365*24*3600*1000); $$('input[type=datetime-local]').forEach(i=>{ if(!i.value)i.value=localDateTime(i.form.id==='root-form'||i.form.id==='template-form'?later:now);}); }
initTimes();
load().catch(err=>notice(err.message));
