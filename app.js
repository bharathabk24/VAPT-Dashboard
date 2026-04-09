'use strict';

// ═══════════════════════════════════════════════════════════════
//  SUPABASE CLIENT  — fixed pagination (no header conflict)
// ═══════════════════════════════════════════════════════════════
const sb = {
  // Base headers — NO 'Prefer' here; set it per-call
  baseHdr() {
    return {
      'apikey':        SUPABASE_KEY,
      'Authorization': 'Bearer ' + SUPABASE_KEY,
      'Content-Type':  'application/json'
    };
  },

  // Fetch one page using Range header — bypasses Supabase's project-level 1000-row cap
  async fetchPage(table, cols, orderCol, from, to) {
    const url = `${SUPABASE_URL}/rest/v1/${table}?select=${cols}&order=${orderCol}.asc`;
    const res = await fetch(url, {
      headers: {
        ...this.baseHdr(),
        'Range-Unit': 'items',
        'Range':      `${from}-${to}`,
        'Prefer':     'count=exact'
      }
    });
    // 206 = partial content (more rows exist), 200 = last page
    if (res.status !== 200 && res.status !== 206) {
      const txt = await res.text();
      throw new Error(`Supabase ${res.status}: ${txt}`);
    }
    const data = await res.json();
    // content-range: items 0-999/52341  → total = 52341
    const cr    = res.headers.get('content-range') || '';
    const total = parseInt((cr.split('/')[1]) || '0') || null;
    return { data, total, done: res.status === 200 };
  },

  // Load ALL rows — uses Range paging which always works regardless of project settings
  async loadAll(table, cols, orderCol, onProgress) {
    const PAGE = 1000;
    let all = [], from = 0;
    while (true) {
      const { data, total, done } = await this.fetchPage(table, cols, orderCol, from, from + PAGE - 1);
      if (!Array.isArray(data)) throw new Error('Unexpected response: ' + JSON.stringify(data));
      all = all.concat(data);
      if (onProgress) onProgress(all.length, total);
      if (data.length < PAGE || done) break;
      from += PAGE;
    }
    return all;
  },

  // Delete all rows for a given upload_date (used before re-uploading a day)
  async deleteByDate(dateVal) {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/vulnerabilities?upload_date=eq.${dateVal}`,
      { method: 'DELETE', headers: this.baseHdr() }
    );
    if (!res.ok) throw new Error(await res.text());
  },

  // Check how many vuln rows exist for a date
  async countDate(dateVal) {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/vulnerabilities?upload_date=eq.${dateVal}&select=id&limit=1`,
      { headers: { ...this.baseHdr(), 'Prefer': 'count=exact', 'Range-Unit': 'items', 'Range': '0-0' } }
    );
    const cr = res.headers.get('content-range') || '';
    return parseInt(cr.split('/')[1] || '0');
  },

  // Insert rows in batches of BATCH_SIZE
  async insertBatch(table, rows) {
    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const chunk = rows.slice(i, i + BATCH_SIZE);
      const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
        method: 'POST',
        headers: { ...this.baseHdr(), 'Prefer': 'return=minimal' },
        body: JSON.stringify(chunk)
      });
      if (!res.ok) throw new Error(await res.text());
    }
  }
};

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════
let dayStore     = {};   // { "2025-01-10": [...rows] }
let resData      = [];
let currentDay   = null;
let filteredData = [];
let currentPage  = 1;
let resPage      = 1;
const PAGE_SIZE  = 25;
let charts       = {};

const SEV      = { Critical:'#e05c5c', Important:'#e0984a', Moderate:'#5b9cf6', Low:'#6b8f6b' };
const SEV_KEYS = ['Critical','Important','Moderate','Low'];
const RES_COLORS = {
  'Succeeded':'#4caf81','Yet To Apply':'#f0e04a','In Progress':'#5b9cf6',
  'Retry In Progress':'#e0984a','Failed':'#e05c5c','Not Applicable':'#555b66','Overridden':'#e07a30'
};

// ═══════════════════════════════════════════════════════════════
//  UTILS
// ═══════════════════════════════════════════════════════════════
const fmt     = n   => Number(n).toLocaleString();
const pct     = (n,t) => t ? (n/t*100).toFixed(1)+'%' : '—';
const short   = s   => (s||'').replace('Windows ','Win ').replace('Single Language','SL')
                       .replace('Professional','Pro').replace('Enterprise','Ent')
                       .replace('Ultimate','Ult').replace('Edition','').replace(/\s+/g,' ').trim();
const countBy = (arr,k) => arr.reduce((a,r)=>{ const v=r[k]||'Unknown'; a[v]=(a[v]||0)+1; return a; },{});
const topN    = (obj,n) => Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,n);
const rowKey  = r => (r['Computer Name']||'')+'|||'+(r['Vulnerabilities']||r['Vulnerability']||'');

function destroyChart(k){ if(charts[k]){ try{ charts[k].destroy(); }catch(e){} charts[k]=null; } }

function showLoading(txt='Loading…'){
  document.getElementById('loadingText').textContent = txt;
  document.getElementById('loadingOverlay').classList.add('show');
}
function hideLoading(){ document.getElementById('loadingOverlay').classList.remove('show'); }
function sortedDays(){ return Object.keys(dayStore).sort(); }

function parseDateStr(s){
  if(!s) return null;
  const str = String(s).trim();
  if(/^\d{4}-\d{2}-\d{2}/.test(str)) return str.slice(0,10);
  const d = new Date(str);
  if(!isNaN(d)) return d.toISOString().slice(0,10);
  return null;
}

function dateFromFilename(name){
  // YYYY-MM-DD or YYYY_MM_DD anywhere in filename
  const m = name.match(/(\d{4}[-_]\d{2}[-_]\d{2})/);
  if(m) return m[1].replace(/_/g,'-');
  // DD-MM-YYYY or DD_MM_YYYY
  const m2 = name.match(/(\d{2}[-_]\d{2}[-_]\d{4})/);
  if(m2){ const p=m2[1].split(/[-_]/); return `${p[2]}-${p[1]}-${p[0]}`; }
  return null;
}

// ═══════════════════════════════════════════════════════════════
//  LOAD ALL DATA FROM SUPABASE
// ═══════════════════════════════════════════════════════════════
async function loadFromSupabase(){
  showLoading('Connecting to database…');
  try {
    // Load vulnerabilities — all rows via pagination
    showLoading('Loading vulnerability data (this may take a moment for large datasets)…');
    const vulnRows = await sb.loadAll(
      'vulnerabilities',
      'upload_date,vulnerability_name,severity,computer_name,operating_system,remote_office,cvss_score,discovered_date',
      'upload_date',
      (n, total) => showLoading(`Loading vulnerability data… ${n.toLocaleString()}${total ? ' / ' + total.toLocaleString() : ''} rows`)
    );

    // Group rows by date
    dayStore = {};
    vulnRows.forEach(r => {
      const d = r.upload_date;
      if(!dayStore[d]) dayStore[d] = [];
      dayStore[d].push(dbRowToVuln(r));
    });

    // Load resolutions
    showLoading('Loading resolution data…');
    const resRows = await sb.loadAll(
      'resolutions',
      'computer_name,vulnerability_name,status,date,office,notes',
      'date',
      (n, total) => showLoading(`Loading resolution data… ${n.toLocaleString()}${total ? ' / ' + total.toLocaleString() : ''} rows`)
    );
    resData = resRows.map(dbRowToRes);

    // Render everything
    const days = sortedDays();
    const totalVulns = vulnRows.length;

    if(days.length){
      currentDay = days[days.length - 1];
      rebuildDayDropdowns();
      populateGlobalDropdowns();
      switchDay(currentDay);
      rebuildTrend();
      rebuildResolution();
      document.getElementById('fileInfo').textContent =
        days.length + ' day(s)  |  ' + totalVulns.toLocaleString() + ' total vuln rows  |  Latest: ' + days[days.length-1];
    } else {
      document.getElementById('fileInfo').textContent = 'No data yet — use Admin Upload.';
      document.getElementById('last-updated').textContent = 'No data loaded';
      document.getElementById('day-select').innerHTML = '<option value="">— no data —</option>';
    }
  } catch(err){
    document.getElementById('fileInfo').textContent = '⚠ Error: ' + err.message;
    document.getElementById('last-updated').textContent = 'Failed to load — check console';
    console.error('loadFromSupabase error:', err);
  }
  hideLoading();
}

function dbRowToVuln(r){
  return {
    'Vulnerabilities':  r.vulnerability_name,
    'Severity':         r.severity,
    'Computer Name':    r.computer_name,
    'Operating System': r.operating_system,
    'Remote Office':    r.remote_office,
    'CVSS 3.0 Score':   r.cvss_score,
    'Discovered Date':  r.discovered_date,
  };
}
function dbRowToRes(r){
  return {
    'Computer Name': r.computer_name,
    'Vulnerability': r.vulnerability_name,
    'Status':        r.status,
    'Date':          r.date,
    'Office':        r.office,
    'Notes':         r.notes,
  };
}

// ═══════════════════════════════════════════════════════════════
//  ADMIN MODAL
// ═══════════════════════════════════════════════════════════════
function openAdminModal(){
  document.getElementById('adminPasswordInput').value = '';
  document.getElementById('adminLoginError').style.display = 'none';
  document.getElementById('adminModal').classList.add('open');
  setTimeout(()=>document.getElementById('adminPasswordInput').focus(), 100);
}
function closeAdminModal(){ document.getElementById('adminModal').classList.remove('open'); }
function verifyAdminPassword(){
  if(document.getElementById('adminPasswordInput').value === ADMIN_PASSWORD){
    closeAdminModal(); openUploadModal();
  } else {
    document.getElementById('adminLoginError').style.display = 'block';
    document.getElementById('adminPasswordInput').value = '';
    document.getElementById('adminPasswordInput').focus();
  }
}
document.getElementById('adminPasswordInput').addEventListener('keydown', e=>{
  if(e.key==='Enter') verifyAdminPassword();
});

// ═══════════════════════════════════════════════════════════════
//  UPLOAD MODAL
// ═══════════════════════════════════════════════════════════════
let pendingVulnFiles = [], pendingResFiles = [];

function openUploadModal(){
  pendingVulnFiles = [];
  pendingResFiles  = [];
  document.getElementById('vulnFileNames').textContent = 'No files selected';
  document.getElementById('resFileNames').textContent  = 'No files selected';
  // Default to yesterday to avoid accidental today uploads
  const d = new Date(); d.setDate(d.getDate()-1);
  document.getElementById('batchDateInput').value = d.toISOString().slice(0,10);
  document.getElementById('uploadProgress').classList.remove('show');
  document.getElementById('progressLog').textContent = '';
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('progressLabel').textContent = 'Ready to upload';
  document.getElementById('uploadBtn').disabled = false;
  document.getElementById('replaceCheckbox').checked = false;
  document.getElementById('uploadModal').classList.add('open');
}
function closeUploadModal(){ document.getElementById('uploadModal').classList.remove('open'); }

document.getElementById('vulnFileInput').addEventListener('change', e=>{
  pendingVulnFiles = Array.from(e.target.files);
  document.getElementById('vulnFileNames').textContent =
    pendingVulnFiles.length ? pendingVulnFiles.map(f=>f.name).join('\n') : 'No files selected';
  // Try to auto-detect date from first filename
  const detected = dateFromFilename(pendingVulnFiles[0]?.name || '');
  if(detected){
    document.getElementById('batchDateInput').value = detected;
    logProgress('📅 Date auto-detected from filename: ' + detected);
  }
  e.target.value = '';
});
document.getElementById('resFileInput').addEventListener('change', e=>{
  pendingResFiles = Array.from(e.target.files);
  document.getElementById('resFileNames').textContent =
    pendingResFiles.length ? pendingResFiles.map(f=>f.name).join('\n') : 'No files selected';
  e.target.value = '';
});

function logProgress(msg){
  const el = document.getElementById('progressLog');
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
}
function setProgressBar(p){
  document.getElementById('progressBar').style.width = p + '%';
  document.getElementById('progressLabel').textContent = p + '% complete';
}

async function startUpload(){
  if(!pendingVulnFiles.length && !pendingResFiles.length){
    alert('Please select at least one file.'); return;
  }
  const batchDate = document.getElementById('batchDateInput').value;
  if(!batchDate){ alert('Please set the upload date.'); return; }
  const replaceExisting = document.getElementById('replaceCheckbox').checked;

  document.getElementById('uploadBtn').disabled = true;
  document.getElementById('uploadProgress').classList.add('show');

  const totalSteps = pendingVulnFiles.length + pendingResFiles.length;
  let stepsDone = 0;

  // ── Group all vuln files by their date ──
  // Files with a date in the filename use that date.
  // Files without use the batchDate picker.
  const byDate = {}; // { "2025-01-10": [rows, ...] }

  for(const file of pendingVulnFiles){
    try{
      logProgress('📄 Parsing: ' + file.name);
      const rows = await parseFile(file);
      const fileDate = dateFromFilename(file.name) || batchDate;
      if(!byDate[fileDate]) byDate[fileDate] = [];
      byDate[fileDate].push(...rows);
      logProgress(`   → ${rows.length.toLocaleString()} rows  |  date: ${fileDate}`);
    } catch(err){
      logProgress('❌ Parse error – ' + file.name + ': ' + err.message);
    }
    stepsDone++;
    setProgressBar(Math.round(stepsDone / totalSteps * 60));
  }

  // ── Save to DB per date ──
  const dateKeys = Object.keys(byDate);
  for(let i = 0; i < dateKeys.length; i++){
    const date  = dateKeys[i];
    const rows  = byDate[date];
    try{
      if(replaceExisting){
        logProgress(`🗑 Removing existing data for ${date}…`);
        await sb.deleteByDate(date);
        logProgress(`   → Cleared`);
      } else {
        const existing = await sb.countDate(date);
        if(existing > 0){
          logProgress(`⚠ ${date} already has ${existing.toLocaleString()} rows. Check "Replace" to overwrite, or pick a different date.`);
          continue;
        }
      }
      logProgress(`💾 Saving ${rows.length.toLocaleString()} rows for ${date}…`);
      const dbRows = rows.map(r => vulnRowToDb(r, date));
      await sb.insertBatch('vulnerabilities', dbRows);
      logProgress(`✅ ${date} — saved ${rows.length.toLocaleString()} rows`);
    } catch(err){
      logProgress('❌ DB error for ' + date + ': ' + err.message);
    }
    setProgressBar(Math.round(60 + (i+1)/dateKeys.length * 30));
  }

  // ── Resolution files ──
  for(const file of pendingResFiles){
    try{
      logProgress('\n📄 Parsing resolution: ' + file.name);
      const rows = await parseFile(file);
      const dbRows = rows.map(r => resRowToDb(normaliseResRow(r)));
      logProgress(`💾 Saving ${dbRows.length.toLocaleString()} resolution rows…`);
      await sb.insertBatch('resolutions', dbRows);
      logProgress('✅ ' + file.name + ' saved');
    } catch(err){
      logProgress('❌ Error – ' + file.name + ': ' + err.message);
    }
    stepsDone++;
    setProgressBar(Math.round(stepsDone / totalSteps * 100));
  }

  setProgressBar(100);
  logProgress('\n🎉 Upload complete! Reloading dashboard…');
  setTimeout(async()=>{ closeUploadModal(); await loadFromSupabase(); }, 2000);
}

// ── Map to DB columns ──
function vulnRowToDb(r, dateKey){
  return {
    upload_date:        dateKey,
    vulnerability_name: (r['Vulnerabilities'] || r['Vulnerability'] || '').slice(0, 500),
    severity:            r['Severity'] || '',
    computer_name:      (r['Computer Name'] || '').slice(0, 200),
    operating_system:   (r['Operating System'] || '').slice(0, 200),
    remote_office:      (r['Remote Office'] || '').slice(0, 200),
    cvss_score:         (r['CVSS 3.0 Score'] != null && r['CVSS 3.0 Score'] !== '')
                          ? parseFloat(r['CVSS 3.0 Score']) || null : null,
    discovered_date:    parseDateStr(r['Discovered Date']) || null,
  };
}
function resRowToDb(r){
  return {
    computer_name:      (r['Computer Name'] || '').slice(0, 200),
    vulnerability_name: (r['Vulnerability'] || '').slice(0, 500),
    status:              r['Status'] || '',
    date:                parseDateStr(r['Date']) || null,
    office:              r['Office'] || '',
    notes:              (r['Notes'] || '').slice(0, 500),
  };
}
function normaliseResRow(r){
  const colMap = k => {
    const kl = k.toLowerCase();
    if(/computer/.test(kl))        return 'Computer Name';
    if(/vuln|patch|fix/.test(kl))  return 'Vulnerability';
    if(/status/.test(kl))          return 'Status';
    if(/date|resolved/.test(kl))   return 'Date';
    if(/office/.test(kl))          return 'Office';
    if(/note/.test(kl))            return 'Notes';
    return k;
  };
  const out = {};
  Object.entries(r).forEach(([k,v])=>{ out[colMap(k)] = v; });
  return out;
}

// ═══════════════════════════════════════════════════════════════
//  FILE PARSING
// ═══════════════════════════════════════════════════════════════
function parseFile(file){
  return new Promise((resolve, reject)=>{
    const reader = new FileReader();
    reader.onload = e => {
      try{
        const wb = XLSX.read(e.target.result, { type:'array' });
        const ws = wb.Sheets[wb.SheetNames[0]];
        resolve(XLSX.utils.sheet_to_json(ws, { defval:'' }));
      } catch(err){ reject(err); }
    };
    reader.onerror = () => reject(new Error('File read failed'));
    reader.readAsArrayBuffer(file);
  });
}

// ═══════════════════════════════════════════════════════════════
//  DAY NAVIGATION
// ═══════════════════════════════════════════════════════════════
function rebuildDayDropdowns(){
  const days = sortedDays();
  const opts = days.map(d=>`<option value="${d}">${d}</option>`).join('');
  document.getElementById('day-select').innerHTML = opts;
  document.getElementById('day-select').value = currentDay;

  document.getElementById('diff-day-a').innerHTML = '<option value="">— Day A —</option>' + opts;
  document.getElementById('diff-day-b').innerHTML = '<option value="">— Day B —</option>' + opts;
  if(days.length >= 2){
    document.getElementById('diff-day-a').value = days[days.length-2];
    document.getElementById('diff-day-b').value = days[days.length-1];
  }

  const allOff = [...new Set(
    Object.values(dayStore).flat().map(r=>r['Remote Office']).filter(Boolean)
  )].sort();
  document.getElementById('trend-office-filter').innerHTML =
    '<option value="">All offices</option>' +
    allOff.map(o=>`<option value="${o}">${o}</option>`).join('');

  updateDayNavLabel();
}

function updateDayNavLabel(){
  document.getElementById('day-nav-label').textContent = currentDay || '—';
  const days = sortedDays(), idx = days.indexOf(currentDay);
  document.getElementById('day-prev').disabled = idx <= 0;
  document.getElementById('day-next').disabled = idx < 0 || idx >= days.length-1;
}

function switchDay(dateKey){
  currentDay = dateKey;
  document.getElementById('day-select').value = dateKey;
  const count = (dayStore[dateKey]||[]).length;
  document.getElementById('last-updated').textContent =
    'Viewing: ' + dateKey + '  (' + fmt(count) + ' vulnerabilities)';
  updateDayNavLabel();
  populateGlobalDropdowns();
  applyFilters();
}

function populateGlobalDropdowns(){
  const rows = dayStore[currentDay] || [];
  const offices = [...new Set(rows.map(r=>r['Remote Office']).filter(Boolean))].sort();
  const oses    = [...new Set(rows.map(r=>r['Operating System']).filter(Boolean))].sort();
  ['f-office-global','f-office'].forEach(id=>{
    const prev = document.getElementById(id).value;
    document.getElementById(id).innerHTML =
      '<option value="">All offices</option>' +
      offices.map(o=>`<option value="${o}">${o}</option>`).join('');
    if(offices.includes(prev)) document.getElementById(id).value = prev;
  });
  document.getElementById('f-os-global').innerHTML =
    '<option value="">All OS</option>' +
    oses.map(o=>`<option value="${o}">${o}</option>`).join('');
}

// ═══════════════════════════════════════════════════════════════
//  FILTERS & OVERVIEW
// ═══════════════════════════════════════════════════════════════
function getFilters(){
  return {
    severity: document.getElementById('f-severity').value,
    office:   document.getElementById('f-office').value || document.getElementById('f-office-global').value,
    os:       document.getElementById('f-os-global').value,
    search:  (document.getElementById('search-input').value || '').toLowerCase()
  };
}

function applyFilters(){
  const rows = dayStore[currentDay] || [], f = getFilters();
  filteredData = rows.filter(r=>{
    if(f.severity && r.Severity !== f.severity) return false;
    if(f.office   && r['Remote Office'] !== f.office) return false;
    if(f.os       && r['Operating System'] !== f.os) return false;
    if(f.search   && !(r.Vulnerabilities||'').toLowerCase().includes(f.search) &&
                     !(r['Computer Name']||'').toLowerCase().includes(f.search)) return false;
    return true;
  });
  currentPage = 1;

  const days = sortedDays(), idx = days.indexOf(currentDay);
  const prevRows = idx > 0 ? (dayStore[days[idx-1]] || []) : null;
  const sev      = countBy(filteredData, 'Severity');
  const devices  = new Set(filteredData.map(r=>r['Computer Name'])).size;

  renderMetrics(filteredData.length, sev, devices,
    prevRows ? countBy(prevRows,'Severity') : null, prevRows ? prevRows.length : null);
  renderSevChart(sev);
  renderOfficeChart(countBy(filteredData, 'Remote Office'));
  renderOSBars(countBy(filteredData, 'Operating System'));
  renderTimeline(filteredData);
  renderTable();
  renderOfficeCards(filteredData);
}

// ═══════════════════════════════════════════════════════════════
//  METRICS
// ═══════════════════════════════════════════════════════════════
function renderMetrics(total, sev, devices, prevSev, prevTotal){
  document.getElementById('m-total').textContent     = fmt(total);
  document.getElementById('m-critical').textContent  = fmt(sev.Critical||0);
  document.getElementById('m-important').textContent = fmt(sev.Important||0);
  const ml = (sev.Moderate||0) + (sev.Low||0);
  document.getElementById('m-moderate').textContent  = fmt(ml);
  document.getElementById('m-crit-pct').textContent  = pct(sev.Critical||0, total) + ' of total';
  document.getElementById('m-imp-pct').textContent   = pct(sev.Important||0, total) + ' of total';
  document.getElementById('m-mod-pct').textContent   = pct(ml, total) + ' of total';
  document.getElementById('m-devices').textContent   = devices > 0 ? devices + ' unique devices' : '';
  if(prevTotal !== null){
    renderDelta('d-total',    total,           prevTotal);
    renderDelta('d-critical', sev.Critical||0, prevSev.Critical||0);
    renderDelta('d-important',sev.Important||0,prevSev.Important||0);
    renderDelta('d-moderate', ml,             (prevSev.Moderate||0)+(prevSev.Low||0));
  } else {
    ['d-total','d-critical','d-important','d-moderate'].forEach(id=>{
      document.getElementById(id).textContent = '';
      document.getElementById(id).className = 'metric-delta';
    });
  }
}
function renderDelta(id, curr, prev){
  const el = document.getElementById(id), diff = curr - prev;
  if(diff === 0){ el.textContent='±0';          el.className='metric-delta delta-same'; }
  else if(diff>0){ el.textContent='+'+fmt(diff); el.className='metric-delta delta-up';   }
  else           { el.textContent=fmt(diff);     el.className='metric-delta delta-down'; }
}

// ═══════════════════════════════════════════════════════════════
//  CHART HELPERS
// ═══════════════════════════════════════════════════════════════
const mkChart = (k,id,cfg) => { destroyChart(k); charts[k] = new Chart(document.getElementById(id), cfg); };
const gc = 'rgba(255,255,255,0.05)', tc = '#555b66', tf = {size:11};
const kf = v => v >= 1000 ? (v/1000).toFixed(0)+'k' : v;

function renderSevChart(sev){
  const labels = SEV_KEYS.filter(k=>sev[k]);
  const data   = labels.map(k=>sev[k]||0), colors = labels.map(k=>SEV[k]);
  document.getElementById('sev-legend').innerHTML = labels.map((l,i)=>
    `<span><span class="legend-dot" style="background:${colors[i]}"></span>${l}: ${fmt(data[i])}</span>`
  ).join('');
  mkChart('sevChart','sevChart',{type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${fmt(ctx.parsed)}`}}}}
  });
}
function renderOfficeChart(oc){
  const top = topN(oc,8), labels = top.map(([k])=>k.length>22?k.slice(0,20)+'…':k), data = top.map(([,v])=>v);
  document.getElementById('office-chart-wrap').style.height = Math.max(240,top.length*38+50)+'px';
  mkChart('officeChart','officeChart',{type:'bar',
    data:{labels,datasets:[{data,backgroundColor:'rgba(91,156,246,0.55)',borderRadius:4,borderSkipped:false}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+fmt(ctx.parsed.x)}}},
      scales:{x:{grid:{color:gc},ticks:{color:tc,font:tf,callback:kf}},y:{grid:{display:false},ticks:{color:'#8b909a',font:tf}}}}
  });
}
function renderOSBars(oc){
  const top = topN(oc,10), max = top[0]?top[0][1]:1;
  document.getElementById('os-bars').innerHTML = top.map(([os,count])=>`
    <div class="os-bar-row">
      <div class="os-bar-label" title="${os}">${short(os)}</div>
      <div class="os-bar-track"><div class="os-bar-fill" style="width:${Math.round(count/max*100)}%"></div></div>
      <div class="os-bar-count">${fmt(count)}</div>
    </div>`).join('');
}
function renderTimeline(data){
  const mm = {};
  data.forEach(r=>{
    const raw=r['Discovered Date']; if(!raw) return;
    const d=new Date(raw); if(isNaN(d)) return;
    const k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');
    if(!mm[k]) mm[k]={Critical:0,Important:0,Moderate:0,Low:0};
    const s=r.Severity; if(SEV_KEYS.includes(s)) mm[k][s]++;
  });
  const keys = Object.keys(mm).sort().slice(-18);
  mkChart('timelineChart','timelineChart',{type:'bar',
    data:{labels:keys,datasets:SEV_KEYS.map(s=>({
      label:s,data:keys.map(k=>mm[k]?.[s]||0),backgroundColor:SEV[s]+'99',borderRadius:2,borderSkipped:false
    }))},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false}},
      scales:{x:{stacked:true,grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:12}},
              y:{stacked:true,grid:{color:gc},ticks:{color:tc,font:{size:10},callback:kf}}}}
  });
}

// ═══════════════════════════════════════════════════════════════
//  RECORDS TABLE
// ═══════════════════════════════════════════════════════════════
function buildResLookup(){
  const map = {};
  resData.forEach(r=>{
    const k = (r['Computer Name']||'').toLowerCase()+'|||'+(r['Vulnerability']||'').toLowerCase();
    map[k] = r['Status']||'';
  });
  return map;
}
function renderTable(){
  const resLookup = buildResLookup();
  const start = (currentPage-1)*PAGE_SIZE;
  const page  = filteredData.slice(start, start+PAGE_SIZE);
  const tbody = document.getElementById('table-body');
  if(!filteredData.length){
    tbody.innerHTML=`<tr><td colspan="8"><div class="empty-state"><p>No records match your filters</p></div></td></tr>`;
    document.getElementById('page-info').textContent='';
    document.getElementById('prev-btn').disabled=true;
    document.getElementById('next-btn').disabled=true;
    document.getElementById('records-count').textContent='0 records';
    return;
  }
  tbody.innerHTML = page.map(row=>{
    const sev=row.Severity||'Low', vuln=row.Vulnerabilities||'', os=row['Operating System']||'';
    const cvss=row['CVSS 3.0 Score'];
    const rk=(row['Computer Name']||'').toLowerCase()+'|||'+vuln.toLowerCase();
    const rs=resLookup[rk]||'—';
    const rbadge=rs!=='—'?`<span class="badge badge-${rs.replace(/ /g,'')}">${rs}</span>`:'<span style="color:var(--text-3)">—</span>';
    return `<tr>
      <td><div class="vuln-name" title="${vuln}">${vuln}</div></td>
      <td><span class="badge badge-${sev}">${sev}</span></td>
      <td><span class="comp-name">${row['Computer Name']||'—'}</span></td>
      <td><div class="os-name" title="${os}">${short(os)}</div></td>
      <td>${row['Remote Office']||'—'}</td>
      <td class="cvss-val">${cvss!=null&&cvss!==''?parseFloat(cvss).toFixed(1):'—'}</td>
      <td class="disc-date">${row['Discovered Date']||'—'}</td>
      <td>${rbadge}</td>
    </tr>`;
  }).join('');
  const total=filteredData.length, tp=Math.ceil(total/PAGE_SIZE);
  document.getElementById('page-info').textContent=`${currentPage} / ${tp}  (${fmt(total)} records)`;
  document.getElementById('records-count').textContent=fmt(total)+' records';
  document.getElementById('prev-btn').disabled=currentPage===1;
  document.getElementById('next-btn').disabled=currentPage>=tp;
}

// ═══════════════════════════════════════════════════════════════
//  OFFICE CARDS
// ═══════════════════════════════════════════════════════════════
function renderOfficeCards(data){
  const byOffice={};
  data.forEach(r=>{const o=r['Remote Office']||'Unknown';if(!byOffice[o])byOffice[o]=[];byOffice[o].push(r);});
  const sorted=Object.entries(byOffice).sort((a,b)=>b[1].length-a[1].length);
  if(!sorted.length){document.getElementById('office-cards').innerHTML='<div class="empty-state" style="grid-column:1/-1"><p>No data</p></div>';return;}
  document.getElementById('office-cards').innerHTML=sorted.map(([name,rows])=>{
    const sev=countBy(rows,'Severity'),total=rows.length;
    const segs=SEV_KEYS.map(s=>{
      const w=sev[s]?Math.round(sev[s]/total*100):0;
      return w>0?`<div class="office-bar-seg-fill" style="flex:${w};background:${SEV[s]}88;"></div>`:'';
    }).join('');
    return `<div class="office-card">
      <div class="office-name" title="${name}">${name}</div>
      <div class="office-stat-row"><span class="office-stat-label">Total</span><span class="office-stat-val">${fmt(total)}</span></div>
      <div class="office-stat-row"><span class="office-stat-label">Critical</span><span class="office-stat-val" style="color:#e07070">${fmt(sev.Critical||0)}</span></div>
      <div class="office-stat-row"><span class="office-stat-label">Important</span><span class="office-stat-val" style="color:#e0a860">${fmt(sev.Important||0)}</span></div>
      <div class="office-stat-row"><span class="office-stat-label">Moderate</span><span class="office-stat-val" style="color:#7aabf7">${fmt(sev.Moderate||0)}</span></div>
      <div class="office-bar-seg">${segs}</div>
    </div>`;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════
//  DAY DIFF
// ═══════════════════════════════════════════════════════════════
function rebuildDiff(){
  const dayA=document.getElementById('diff-day-a').value;
  const dayB=document.getElementById('diff-day-b').value;
  if(!dayA||!dayB||dayA===dayB){
    document.getElementById('diff-summary').innerHTML=
      `<div style="color:var(--text-3);font-size:13px;padding:20px 0;grid-column:1/-1;">
        Select two different days above to compare.
        <br><span style="font-size:11px;opacity:0.6;">You have ${sortedDays().length} day(s) loaded.</span>
      </div>`;
    return;
  }
  document.getElementById('diff-subtitle').textContent = dayA + ' → ' + dayB;
  const rowsA=dayStore[dayA]||[], rowsB=dayStore[dayB]||[];
  const setA=new Set(rowsA.map(rowKey)), setB=new Set(rowsB.map(rowKey));
  const newRows      = rowsB.filter(r=>!setA.has(rowKey(r)));
  const resolvedRows = rowsA.filter(r=>!setB.has(rowKey(r)));
  const persisted    = rowsB.filter(r=>setA.has(rowKey(r)));
  const sevA=countBy(rowsA,'Severity'), sevB=countBy(rowsB,'Severity');
  const delta=rowsB.length-rowsA.length;

  const cards=[
    {label:'Day A total',      val:fmt(rowsA.length),          color:''},
    {label:'Day B total',      val:fmt(rowsB.length),          color:''},
    {label:'Net change',       val:(delta>=0?'+':'')+fmt(delta),color:delta>0?'var(--red)':delta<0?'var(--green)':'var(--text-3)'},
    {label:'New in Day B',     val:fmt(newRows.length),        color:'var(--red)'},
    {label:'Fixed / Gone',     val:fmt(resolvedRows.length),   color:'var(--green)'},
    {label:'Still present',    val:fmt(persisted.length),      color:'var(--text-2)'},
  ];
  document.getElementById('diff-summary').innerHTML = cards.map(c=>`
    <div class="diff-card">
      <div class="diff-card-label">${c.label}</div>
      <div class="diff-card-val" style="${c.color?'color:'+c.color:''}">${c.val}</div>
    </div>`).join('');

  mkChart('diffSevChart','diffSevChart',{type:'bar',
    data:{labels:SEV_KEYS,datasets:[
      {label:'Day A ('+dayA+')',data:SEV_KEYS.map(k=>sevA[k]||0),backgroundColor:SEV_KEYS.map(k=>SEV[k]+'88'),borderRadius:3,borderSkipped:false},
      {label:'Day B ('+dayB+')',data:SEV_KEYS.map(k=>sevB[k]||0),backgroundColor:SEV_KEYS.map(k=>SEV[k]),borderRadius:3,borderSkipped:false}
    ]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{x:{grid:{display:false},ticks:{color:tc,font:tf}},y:{grid:{color:gc},ticks:{color:tc,font:tf,callback:kf}}}}
  });

  const allOff=[...new Set([...rowsA,...rowsB].map(r=>r['Remote Office']).filter(Boolean))];
  const offA=countBy(rowsA,'Remote Office'), offB=countBy(rowsB,'Remote Office');
  const deltas=allOff.map(o=>({o,d:(offB[o]||0)-(offA[o]||0)}))
    .sort((a,b)=>Math.abs(b.d)-Math.abs(a.d)).slice(0,12);
  document.getElementById('diff-office-wrap').style.height=Math.max(280,deltas.length*38+60)+'px';
  mkChart('diffOfficeChart','diffOfficeChart',{type:'bar',
    data:{labels:deltas.map(x=>x.o.length>20?x.o.slice(0,18)+'…':x.o),
          datasets:[{data:deltas.map(x=>x.d),
            backgroundColor:deltas.map(x=>x.d>0?'rgba(224,92,92,0.7)':x.d<0?'rgba(76,175,129,0.7)':'rgba(255,255,255,0.15)'),
            borderRadius:3,borderSkipped:false}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>(ctx.parsed.x>=0?'+':'')+fmt(ctx.parsed.x)}}},
      scales:{x:{grid:{color:gc},ticks:{color:tc,font:tf,callback:v=>(v>=0?'+':'')+kf(v)}},
              y:{grid:{display:false},ticks:{color:'#8b909a',font:tf}}}}
  });

  const diffTbl = rows => {
    if(!rows.length) return '<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:16px;">None</td></tr>';
    return rows.slice(0,150).map(r=>`<tr>
      <td><div class="vuln-name" title="${r.Vulnerabilities||''}">${r.Vulnerabilities||''}</div></td>
      <td><span class="badge badge-${r.Severity||'Low'}">${r.Severity||'—'}</span></td>
      <td><span class="comp-name">${r['Computer Name']||'—'}</span></td>
      <td>${r['Remote Office']||'—'}</td>
      <td class="cvss-val">${r['CVSS 3.0 Score']!=null&&r['CVSS 3.0 Score']!==''?parseFloat(r['CVSS 3.0 Score']).toFixed(1):'—'}</td>
    </tr>`).join('');
  };
  document.getElementById('new-vuln-count').textContent      = fmt(newRows.length);
  document.getElementById('resolved-vuln-count').textContent = fmt(resolvedRows.length);
  document.getElementById('diff-new-body').innerHTML      = diffTbl(newRows);
  document.getElementById('diff-resolved-body').innerHTML = diffTbl(resolvedRows);
}

// ═══════════════════════════════════════════════════════════════
//  RESOLUTION MODULE
// ═══════════════════════════════════════════════════════════════
function rebuildResolution(){
  const dates   = [...new Set(resData.map(r=>parseDateStr(r['Date'])).filter(Boolean))].sort();
  const offices = [...new Set(resData.map(r=>r['Office']).filter(Boolean))].sort();
  document.getElementById('res-day-filter').innerHTML =
    '<option value="">All days (' + dates.length + ')</option>' +
    dates.map(d=>`<option value="${d}">${d}</option>`).join('');
  document.getElementById('res-office-filter').innerHTML =
    '<option value="">All offices</option>' +
    offices.map(o=>`<option value="${o}">${o}</option>`).join('');
  renderResolution();
}

function getResFilters(){
  return {
    day:    document.getElementById('res-day-filter').value,
    status: document.getElementById('res-status-filter').value,
    office: document.getElementById('res-office-filter').value,
    search:(document.getElementById('res-search').value||'').toLowerCase(),
  };
}

function renderResolution(){
  const f = getResFilters();
  const data = resData.filter(r=>{
    if(f.status && (r['Status']||'') !== f.status) return false;
    if(f.day){ const d=parseDateStr(r['Date']); if(d!==f.day) return false; }
    if(f.office && (r['Office']||'') !== f.office) return false;
    if(f.search && !(r['Vulnerability']||'').toLowerCase().includes(f.search) &&
                   !(r['Computer Name']||'').toLowerCase().includes(f.search)) return false;
    return true;
  });
  const total = data.length;
  const sc    = countBy(data,'Status');
  const succeeded = sc['Succeeded']||0;
  const pending   = (sc['Yet To Apply']||0)+(sc['In Progress']||0)+(sc['Retry In Progress']||0)+(sc['Overridden']||0);
  const failed    = sc['Failed']||0;
  const na        = sc['Not Applicable']||0;
  const resRate   = total ? Math.round(succeeded/total*100) : 0;

  document.getElementById('r-total').textContent        = fmt(total);
  document.getElementById('r-resolved').textContent     = fmt(succeeded);
  document.getElementById('r-pending').textContent      = fmt(pending);
  document.getElementById('r-failed').textContent       = fmt(failed);
  document.getElementById('r-na').textContent           = fmt(na);
  document.getElementById('r-resolved-pct').textContent = pct(succeeded,total)+' succeeded';
  document.getElementById('r-pending-pct').textContent  = pct(pending,total)+' pending';
  document.getElementById('r-failed-pct').textContent   = pct(failed,total)+' failed';
  document.getElementById('r-na-pct').textContent       = pct(na,total)+' N/A';
  document.getElementById('res-subtitle').textContent   = fmt(total)+' records  |  '+resRate+'% success rate';

  // Ring
  const ring = document.getElementById('res-ring-fill');
  if(ring){
    const circ = 2*Math.PI*54;
    ring.style.strokeDasharray  = circ;
    ring.style.strokeDashoffset = circ*(1-resRate/100);
    document.getElementById('res-ring-pct').textContent = resRate+'%';
  }

  // Donut
  const rL=Object.keys(RES_COLORS), rV=rL.map(k=>sc[k]||0);
  document.getElementById('res-legend').innerHTML = rL.map((l,i)=>
    `<span><span class="legend-dot" style="background:${Object.values(RES_COLORS)[i]}"></span>${l}: ${fmt(rV[i])}</span>`
  ).join('');
  mkChart('resDonutChart','resDonutChart',{type:'doughnut',
    data:{labels:rL,datasets:[{data:rV,backgroundColor:Object.values(RES_COLORS),borderWidth:0,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'62%',
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${fmt(ctx.parsed)}`}}}}
  });

  // Trend over time
  const byDate={};
  resData.forEach(r=>{
    const d=parseDateStr(r['Date']); if(!d) return;
    if(!byDate[d]) byDate[d]={total:0,succeeded:0,failed:0,pending:0};
    byDate[d].total++;
    const s=r['Status']||'';
    if(s==='Succeeded') byDate[d].succeeded++;
    else if(s==='Failed') byDate[d].failed++;
    else byDate[d].pending++;
  });
  const tKeys=Object.keys(byDate).sort();
  mkChart('resTrendChart','resTrendChart',{type:'line',
    data:{labels:tKeys,datasets:[
      {label:'Succeeded %',data:tKeys.map(k=>Math.round(byDate[k].succeeded/byDate[k].total*100)),
       borderColor:'#4caf81',backgroundColor:'rgba(76,175,129,0.08)',fill:true,tension:0.3,pointRadius:3},
      {label:'Failed %',   data:tKeys.map(k=>Math.round(byDate[k].failed/byDate[k].total*100)),
       borderColor:'#e05c5c',fill:false,tension:0.3,pointRadius:3},
      {label:'Total patches',data:tKeys.map(k=>byDate[k].total),
       borderColor:'#5b9cf6',fill:false,tension:0.3,pointRadius:3,yAxisID:'y2'}
    ]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45}},
        y:{grid:{color:gc},ticks:{color:tc,font:{size:10},callback:v=>v+'%'},min:0,max:100},
        y2:{position:'right',grid:{display:false},ticks:{color:tc,font:{size:10},callback:kf}}
      }}
  });

  // Office resolution bar
  const byOff={};
  resData.forEach(r=>{
    const o=r['Office']||'Unknown';
    if(!byOff[o]) byOff[o]={succeeded:0,failed:0,pending:0,total:0};
    byOff[o].total++;
    const s=r['Status']||'';
    if(s==='Succeeded') byOff[o].succeeded++;
    else if(s==='Failed') byOff[o].failed++;
    else byOff[o].pending++;
  });
  const topOff=Object.entries(byOff).sort((a,b)=>b[1].total-a[1].total).slice(0,10);
  mkChart('resOfficeChart','resOfficeChart',{type:'bar',
    data:{
      labels:topOff.map(([o])=>o.length>20?o.slice(0,18)+'…':o),
      datasets:[
        {label:'Succeeded',data:topOff.map(([,v])=>v.succeeded),backgroundColor:'#4caf81aa',borderRadius:2,borderSkipped:false},
        {label:'Pending',  data:topOff.map(([,v])=>v.pending),  backgroundColor:'#e0984aaa',borderRadius:2,borderSkipped:false},
        {label:'Failed',   data:topOff.map(([,v])=>v.failed),   backgroundColor:'#e05c5caa',borderRadius:2,borderSkipped:false},
      ]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{stacked:true,grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45}},
        y:{stacked:true,grid:{color:gc},ticks:{color:tc,font:{size:10},callback:kf}}
      }}
  });

  resPage = 1;
  renderResTable(data);
}

function renderResTable(data){
  const start=(resPage-1)*PAGE_SIZE, page=data.slice(start,start+PAGE_SIZE);
  const tbody=document.getElementById('res-table-body');
  if(!data.length){
    tbody.innerHTML='<tr><td colspan="6"><div class="empty-state"><p>No resolution records match filters.</p></div></td></tr>';
    document.getElementById('res-page-info').textContent='';
    document.getElementById('res-prev-btn').disabled=true;
    document.getElementById('res-next-btn').disabled=true;
    return;
  }
  tbody.innerHTML=page.map(r=>{
    const st=r['Status']||'—';
    const bc=st==='Succeeded'?'badge-Succeeded':st==='Yet To Apply'?'badge-YetToApply':
             st==='In Progress'?'badge-InProgress':st==='Retry In Progress'?'badge-RetryInProgress':
             st==='Failed'?'badge-Failed':st==='Not Applicable'?'badge-NotApplicable':
             st==='Overridden'?'badge-Overridden':'';
    return `<tr>
      <td><span class="comp-name">${r['Computer Name']||'—'}</span></td>
      <td><div class="vuln-name" title="${r['Vulnerability']||''}">${r['Vulnerability']||'—'}</div></td>
      <td><span class="badge ${bc}">${st}</span></td>
      <td class="disc-date">${r['Date']||'—'}</td>
      <td>${r['Office']||'—'}</td>
      <td style="font-size:11px;color:var(--text-3);">${r['Notes']||'—'}</td>
    </tr>`;
  }).join('');
  const tp=Math.ceil(data.length/PAGE_SIZE);
  document.getElementById('res-page-info').textContent=`${resPage} / ${tp}  (${fmt(data.length)} records)`;
  document.getElementById('res-prev-btn').disabled=resPage===1;
  document.getElementById('res-next-btn').disabled=resPage>=tp;
}

// ═══════════════════════════════════════════════════════════════
//  TREND
// ═══════════════════════════════════════════════════════════════
function rebuildTrend(){
  const days = sortedDays();
  if(!days.length) return;
  const el = document.getElementById('trend-days-info');
  if(el) el.textContent = days.length + ' days in database';

  const officeFilter = document.getElementById('trend-office-filter').value;
  const getRows = day => {
    const rows = dayStore[day]||[];
    return officeFilter ? rows.filter(r=>r['Remote Office']===officeFilter) : rows;
  };

  mkChart('trendTotalChart','trendTotalChart',{type:'line',
    data:{labels:days,datasets:[{label:'Total vulns',data:days.map(d=>getRows(d).length),
      borderColor:'#5b9cf6',backgroundColor:'rgba(91,156,246,0.08)',fill:true,tension:0.3,pointRadius:4}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false,callbacks:{label:ctx=>'Total: '+fmt(ctx.parsed.y)}}},
      scales:{x:{grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:20}},
              y:{grid:{color:gc},ticks:{color:tc,font:{size:10},callback:kf}}}}
  });

  mkChart('trendSevChart','trendSevChart',{type:'bar',
    data:{labels:days,datasets:SEV_KEYS.map(s=>({
      label:s,data:days.map(d=>countBy(getRows(d),'Severity')[s]||0),
      backgroundColor:SEV[s]+'aa',borderRadius:2,borderSkipped:false
    }))},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{x:{stacked:true,grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:20}},
              y:{stacked:true,grid:{color:gc},ticks:{color:tc,font:{size:10},callback:kf}}}}
  });

  mkChart('trendCritChart','trendCritChart',{type:'line',
    data:{labels:days,datasets:[
      {label:'Critical', data:days.map(d=>countBy(getRows(d),'Severity')['Critical']||0),
       borderColor:'#e05c5c',backgroundColor:'rgba(224,92,92,0.08)',fill:true,tension:0.3,pointRadius:3},
      {label:'Important',data:days.map(d=>countBy(getRows(d),'Severity')['Important']||0),
       borderColor:'#e0984a',fill:false,tension:0.3,pointRadius:3},
    ]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{x:{grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:20}},
              y:{grid:{color:gc},ticks:{color:tc,font:{size:10},callback:kf}}}}
  });

  const byDate={};
  resData.forEach(r=>{
    const d=parseDateStr(r['Date']); if(!d) return;
    if(!byDate[d]) byDate[d]={total:0,resolved:0};
    byDate[d].total++;
    if((r['Status']||'')==='Succeeded') byDate[d].resolved++;
  });
  mkChart('trendResChart','trendResChart',{type:'line',
    data:{labels:days,datasets:[{label:'Resolution %',data:days.map(d=>byDate[d]?Math.round(byDate[d].resolved/byDate[d].total*100):null),
      borderColor:'#4caf81',backgroundColor:'rgba(76,175,129,0.08)',fill:true,tension:0.3,pointRadius:4,spanGaps:true}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>ctx.parsed.y!==null?ctx.parsed.y+'%':'No data'}}},
      scales:{x:{grid:{display:false},ticks:{color:tc,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:20}},
              y:{grid:{color:gc},ticks:{color:tc,font:{size:10},callback:v=>v+'%'},min:0,max:100}}}
  });
}

// ═══════════════════════════════════════════════════════════════
//  EVENTS
// ═══════════════════════════════════════════════════════════════
document.getElementById('day-select').addEventListener('change',e=>{ if(e.target.value) switchDay(e.target.value); });
document.getElementById('day-prev').addEventListener('click',()=>{
  const days=sortedDays(),idx=days.indexOf(currentDay); if(idx>0) switchDay(days[idx-1]);
});
document.getElementById('day-next').addEventListener('click',()=>{
  const days=sortedDays(),idx=days.indexOf(currentDay); if(idx<days.length-1) switchDay(days[idx+1]);
});

document.querySelectorAll('.nav-item').forEach(item=>{
  item.addEventListener('click',()=>{
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('tab-'+item.dataset.tab).classList.add('active');
    if(item.dataset.tab==='diff')       rebuildDiff();
    if(item.dataset.tab==='trend')      rebuildTrend();
    if(item.dataset.tab==='resolution') rebuildResolution();
  });
});

['f-severity','f-office','f-office-global','f-os-global'].forEach(id=>{
  document.getElementById(id).addEventListener('change', applyFilters);
});
let st;
document.getElementById('search-input').addEventListener('input',()=>{ clearTimeout(st); st=setTimeout(applyFilters,250); });
document.getElementById('prev-btn').addEventListener('click',()=>{ currentPage--; renderTable(); });
document.getElementById('next-btn').addEventListener('click',()=>{ currentPage++; renderTable(); });
document.getElementById('res-prev-btn').addEventListener('click',()=>{ resPage--; renderResolution(); });
document.getElementById('res-next-btn').addEventListener('click',()=>{ resPage++; renderResolution(); });
['res-day-filter','res-status-filter','res-office-filter'].forEach(id=>{
  document.getElementById(id).addEventListener('change',()=>{ resPage=1; renderResolution(); });
});
let rst;
document.getElementById('res-search').addEventListener('input',()=>{ clearTimeout(rst); rst=setTimeout(()=>{ resPage=1; renderResolution(); },250); });
document.getElementById('diff-day-a').addEventListener('change', rebuildDiff);
document.getElementById('diff-day-b').addEventListener('change', rebuildDiff);
document.getElementById('trend-office-filter').addEventListener('change', rebuildTrend);

// Boot
loadFromSupabase();
