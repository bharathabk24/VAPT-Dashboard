'use strict';

// ═══════════════════════════════════════════════════════════════
//  SUPABASE CLIENT  (lightweight fetch-based, no SDK needed)
// ═══════════════════════════════════════════════════════════════
const sb = {
  headers: {
    'apikey': SUPABASE_KEY,
    'Authorization': 'Bearer ' + SUPABASE_KEY,
    'Content-Type': 'application/json',
    'Prefer': 'return=minimal'
  },

  // SELECT with optional filters & ordering
  async select(table, params = '') {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?${params}`, {
      headers: { ...this.headers, 'Prefer': 'count=exact' }
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  // INSERT rows in batches
  async insertBatch(table, rows) {
    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const chunk = rows.slice(i, i + BATCH_SIZE);
      const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(chunk)
      });
      if (!res.ok) throw new Error(await res.text());
    }
  },

  // Check if rows for a date already exist
  async countForDate(table, dateCol, dateVal) {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/${table}?${dateCol}=eq.${dateVal}&select=id&limit=1`,
      { headers: { ...this.headers, 'Prefer': 'count=exact' } }
    );
    const count = parseInt(res.headers.get('content-range')?.split('/')[1] || '0');
    return count;
  }
};

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════
let dayStore    = {};
let resData     = [];
let currentDay  = null;
let filteredData = [];
let currentPage = 1, resPage = 1;
const PAGE_SIZE = 25;
let charts = {};

const SEV = { Critical:'#e05c5c', Important:'#e0984a', Moderate:'#5b9cf6', Low:'#6b8f6b' };
const SEV_KEYS = ['Critical','Important','Moderate','Low'];
const RES_COLORS = {
  'Succeeded':'#4caf81','Yet To Apply':'#f0e04a','In Progress':'#5b9cf6',
  'Retry In Progress':'#e0984a','Failed':'#e05c5c','Not Applicable':'#555b66','Overridden':'#e07a30'
};

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════
const fmt   = n  => Number(n).toLocaleString();
const pct   = (n,t) => t ? (n/t*100).toFixed(1)+'%' : '—';
const short = s  => (s||'').replace('Windows ','Win ').replace('Single Language','SL')
                   .replace('Professional','Pro').replace('Enterprise','Ent')
                   .replace('Ultimate','Ult').replace('Edition','').replace(/\s+/g,' ').trim();
const countBy = (arr,k) => arr.reduce((a,r)=>{ const v=r[k]||'Unknown'; a[v]=(a[v]||0)+1; return a; },{});
const topN    = (obj,n) => Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,n);

function destroyChart(key) {
  if (charts[key]) { try{ charts[key].destroy(); }catch(e){} charts[key]=null; }
}
function rowKey(r) {
  return (r['Computer Name']||'') + '|||' + (r['Vulnerabilities']||r['Vulnerability']||'');
}

function showLoading(text = 'Loading data from database…') {
  document.getElementById('loadingText').textContent = text;
  document.getElementById('loadingOverlay').classList.add('show');
}
function hideLoading() {
  document.getElementById('loadingOverlay').classList.remove('show');
}

// ═══════════════════════════════════════════════════════════════
//  LOAD DATA FROM SUPABASE ON PAGE OPEN
// ═══════════════════════════════════════════════════════════════
async function loadFromSupabase() {
  showLoading('Loading vulnerability data…');
  try {
    // Load all vuln rows — ordered by date
    const vulnRows = await sb.select('vulnerabilities', 'select=*&order=upload_date.asc');
    dayStore = {};
    vulnRows.forEach(r => {
      const d = r.upload_date;
      if (!dayStore[d]) dayStore[d] = [];
      dayStore[d].push(dbRowToVuln(r));
    });

    showLoading('Loading resolution data…');
    const resRows = await sb.select('resolutions', 'select=*&order=date.asc');
    resData = resRows.map(dbRowToRes);

    const days = sortedDays();
    if (days.length) {
      currentDay = days[days.length - 1];
      rebuildDayDropdowns();
      populateGlobalDropdowns();
      switchDay(currentDay);
      rebuildTrend();
      document.getElementById('fileInfo').textContent =
        days.length + ' day(s) in database. Last: ' + days[days.length-1];
      if (resData.length) rebuildResolution();
    } else {
      document.getElementById('fileInfo').textContent = 'No data in database yet. Use Admin Upload.';
      document.getElementById('last-updated').textContent = 'No data loaded';
      document.getElementById('day-select').innerHTML = '<option value="">— no data —</option>';
    }
  } catch (err) {
    document.getElementById('fileInfo').textContent = '⚠ DB error: ' + err.message;
    console.error(err);
  }
  hideLoading();
}

// Map DB columns → app row format
function dbRowToVuln(r) {
  return {
    'Vulnerabilities':     r.vulnerability_name,
    'Severity':            r.severity,
    'Computer Name':       r.computer_name,
    'Operating System':    r.operating_system,
    'Remote Office':       r.remote_office,
    'CVSS 3.0 Score':      r.cvss_score,
    'Discovered Date':     r.discovered_date,
  };
}
function dbRowToRes(r) {
  return {
    'Computer Name':  r.computer_name,
    'Vulnerability':  r.vulnerability_name,
    'Status':         r.status,
    'Date':           r.date,
    'Office':         r.office,
    'Notes':          r.notes,
  };
}

// ═══════════════════════════════════════════════════════════════
//  ADMIN MODAL
// ═══════════════════════════════════════════════════════════════
function openAdminModal() {
  document.getElementById('adminPasswordInput').value = '';
  document.getElementById('adminLoginError').style.display = 'none';
  document.getElementById('adminModal').classList.add('open');
  setTimeout(() => document.getElementById('adminPasswordInput').focus(), 100);
}
function closeAdminModal() {
  document.getElementById('adminModal').classList.remove('open');
}
function verifyAdminPassword() {
  const val = document.getElementById('adminPasswordInput').value;
  if (val === ADMIN_PASSWORD) {
    closeAdminModal();
    openUploadModal();
  } else {
    document.getElementById('adminLoginError').style.display = 'block';
    document.getElementById('adminPasswordInput').value = '';
    document.getElementById('adminPasswordInput').focus();
  }
}
document.getElementById('adminPasswordInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') verifyAdminPassword();
});

// ═══════════════════════════════════════════════════════════════
//  UPLOAD MODAL
// ═══════════════════════════════════════════════════════════════
let pendingVulnFiles = [];
let pendingResFiles  = [];

function openUploadModal() {
  pendingVulnFiles = [];
  pendingResFiles  = [];
  document.getElementById('vulnFileNames').textContent = '';
  document.getElementById('resFileNames').textContent  = '';
  document.getElementById('uploadProgress').classList.remove('show');
  document.getElementById('progressLog').textContent = '';
  document.getElementById('uploadBtn').disabled = false;
  document.getElementById('uploadModal').classList.add('open');
}
function closeUploadModal() {
  document.getElementById('uploadModal').classList.remove('open');
}

document.getElementById('vulnFileInput').addEventListener('change', e => {
  pendingVulnFiles = Array.from(e.target.files);
  document.getElementById('vulnFileNames').textContent =
    pendingVulnFiles.length ? pendingVulnFiles.map(f=>f.name).join(', ') : '';
  e.target.value = '';
});
document.getElementById('resFileInput').addEventListener('change', e => {
  pendingResFiles = Array.from(e.target.files);
  document.getElementById('resFileNames').textContent =
    pendingResFiles.length ? pendingResFiles.map(f=>f.name).join(', ') : '';
  e.target.value = '';
});

function logProgress(msg) {
  const el = document.getElementById('progressLog');
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
}
function setProgressBar(pct) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressLabel').textContent = pct + '% complete';
}

async function startUpload() {
  if (!pendingVulnFiles.length && !pendingResFiles.length) {
    alert('Please select at least one file to upload.');
    return;
  }

  document.getElementById('uploadBtn').disabled = true;
  document.getElementById('uploadProgress').classList.add('show');
  document.getElementById('progressLog').textContent = '';
  setProgressBar(0);

  const total = pendingVulnFiles.length + pendingResFiles.length;
  let done = 0;

  // ── Upload vuln files ──
  for (const file of pendingVulnFiles) {
    try {
      logProgress('📄 Parsing: ' + file.name);
      const rows = await parseFile(file);
      const dateKey = dateFromFilename(file.name);
      logProgress('📅 Date detected: ' + dateKey + ' (' + rows.length + ' rows)');

      // Check for duplicates
      const existing = await sb.countForDate('vulnerabilities', 'upload_date', dateKey);
      if (existing > 0) {
        logProgress('⚠ Skipping ' + file.name + ' — date ' + dateKey + ' already in DB (' + existing + ' rows exist)');
        done++; setProgressBar(Math.round(done/total*100));
        continue;
      }

      const dbRows = rows.map(r => vulnRowToDb(r, dateKey));
      logProgress('💾 Saving ' + dbRows.length + ' rows to database…');
      await sb.insertBatch('vulnerabilities', dbRows);
      logProgress('✅ Done: ' + file.name);
    } catch (err) {
      logProgress('❌ Error on ' + file.name + ': ' + err.message);
    }
    done++; setProgressBar(Math.round(done/total*100));
  }

  // ── Upload resolution files ──
  for (const file of pendingResFiles) {
    try {
      logProgress('📄 Parsing: ' + file.name);
      const rows = await parseFile(file);
      const dbRows = rows.map(r => resRowToDb(normaliseResRow(r)));
      logProgress('💾 Saving ' + dbRows.length + ' resolution rows…');
      await sb.insertBatch('resolutions', dbRows);
      logProgress('✅ Done: ' + file.name);
    } catch (err) {
      logProgress('❌ Error on ' + file.name + ': ' + err.message);
    }
    done++; setProgressBar(Math.round(done/total*100));
  }

  setProgressBar(100);
  logProgress('🎉 All done! Reloading dashboard…');

  setTimeout(async () => {
    closeUploadModal();
    await loadFromSupabase();
  }, 1500);
}

// Map app row → DB columns
function vulnRowToDb(r, dateKey) {
  return {
    upload_date:       dateKey,
    vulnerability_name: r['Vulnerabilities'] || r['Vulnerability'] || '',
    severity:          r['Severity'] || '',
    computer_name:     r['Computer Name'] || '',
    operating_system:  r['Operating System'] || '',
    remote_office:     r['Remote Office'] || '',
    cvss_score:        r['CVSS 3.0 Score'] != null && r['CVSS 3.0 Score'] !== '' ? parseFloat(r['CVSS 3.0 Score']) : null,
    discovered_date:   r['Discovered Date'] || null,
  };
}
function resRowToDb(r) {
  return {
    computer_name:     r['Computer Name'] || '',
    vulnerability_name: r['Vulnerability'] || '',
    status:            r['Status'] || '',
    date:              parseDateStr(r['Date']) || null,
    office:            r['Office'] || '',
    notes:             r['Notes'] || '',
  };
}

// ═══════════════════════════════════════════════════════════════
//  PARSE XLSX / CSV
// ═══════════════════════════════════════════════════════════════
function parseFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const wb = XLSX.read(e.target.result, { type:'array' });
        const ws = wb.Sheets[wb.SheetNames[0]];
        resolve(XLSX.utils.sheet_to_json(ws, { defval:'' }));
      } catch(err) { reject(err); }
    };
    reader.onerror = () => reject(new Error('File read failed'));
    reader.readAsArrayBuffer(file);
  });
}

function dateFromFilename(name) {
  const m = name.match(/(\d{4}[-_]\d{2}[-_]\d{2})/);
  if (m) return m[1].replace(/_/g,'-');
  const m2 = name.match(/(\d{2}[-_]\d{2}[-_]\d{4})/);
  if (m2) {
    const parts = m2[1].split(/[-_]/);
    return `${parts[2]}-${parts[1]}-${parts[0]}`;
  }
  const entered = prompt(
    `No date found in filename "${name}".\nEnter date for this file (YYYY-MM-DD):`,
    new Date().toISOString().slice(0,10)
  );
  return entered ? entered.trim() : new Date().toISOString().slice(0,10);
}

function parseDateStr(s) {
  if (!s) return null;
  const str = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(str)) return str.slice(0,10);
  const d = new Date(str);
  if (!isNaN(d)) return d.toISOString().slice(0,10);
  return null;
}

function normaliseResRow(r) {
  const colMap = k => {
    const kl = k.toLowerCase();
    if (/computer/.test(kl)) return 'Computer Name';
    if (/vuln|patch|fix/.test(kl)) return 'Vulnerability';
    if (/status/.test(kl)) return 'Status';
    if (/date|resolved/.test(kl)) return 'Date';
    if (/office/.test(kl)) return 'Office';
    if (/note/.test(kl)) return 'Notes';
    return k;
  };
  const out = {};
  Object.entries(r).forEach(([k,v])=>{ out[colMap(k)]=v; });
  return out;
}

// ═══════════════════════════════════════════════════════════════
//  DAY NAVIGATION
// ═══════════════════════════════════════════════════════════════
function sortedDays() {
  return Object.keys(dayStore).sort();
}

function rebuildDayDropdowns() {
  const days = sortedDays();
  const opts = days.map(d=>`<option value="${d}">${d}</option>`).join('');
  document.getElementById('day-select').innerHTML = opts;
  document.getElementById('day-select').value = currentDay;
  document.getElementById('diff-day-a').innerHTML = '<option value="">Day A</option>'+opts;
  document.getElementById('diff-day-b').innerHTML = '<option value="">Day B (later)</option>'+opts;
  if (days.length >= 2) {
    document.getElementById('diff-day-a').value = days[days.length-2];
    document.getElementById('diff-day-b').value = days[days.length-1];
  }
  document.getElementById('trend-office-filter').innerHTML =
    '<option value="">All offices</option>' +
    [...new Set(Object.values(dayStore).flat().map(r=>r['Remote Office']).filter(Boolean))].sort()
      .map(o=>`<option value="${o}">${o}</option>`).join('');
  updateDayNavLabel();
}

function updateDayNavLabel() {
  document.getElementById('day-nav-label').textContent = currentDay || '—';
  const days = sortedDays();
  const idx = days.indexOf(currentDay);
  document.getElementById('day-prev').disabled = idx <= 0;
  document.getElementById('day-next').disabled = idx < 0 || idx >= days.length-1;
}

function switchDay(dateKey) {
  currentDay = dateKey;
  document.getElementById('day-select').value = dateKey;
  document.getElementById('last-updated').textContent = 'Viewing: ' + dateKey;
  updateDayNavLabel();
  populateGlobalDropdowns();
  applyFilters();
}

function populateGlobalDropdowns() {
  const rows = dayStore[currentDay] || [];
  const offices = [...new Set(rows.map(r=>r['Remote Office']).filter(Boolean))].sort();
  const oses    = [...new Set(rows.map(r=>r['Operating System']).filter(Boolean))].sort();
  ['f-office-global','f-office'].forEach(id=>{
    const prev = document.getElementById(id).value;
    document.getElementById(id).innerHTML =
      '<option value="">All offices</option>' +
      offices.map(o=>`<option value="${o}">${o}</option>`).join('');
    if (offices.includes(prev)) document.getElementById(id).value = prev;
  });
  document.getElementById('f-os-global').innerHTML =
    '<option value="">All OS</option>' +
    oses.map(o=>`<option value="${o}">${o}</option>`).join('');
}

// ═══════════════════════════════════════════════════════════════
//  FILTERS & OVERVIEW RENDER
// ═══════════════════════════════════════════════════════════════
function getFilters() {
  return {
    severity: document.getElementById('f-severity').value,
    office:   document.getElementById('f-office').value || document.getElementById('f-office-global').value,
    os:       document.getElementById('f-os-global').value,
    search:  (document.getElementById('search-input').value||'').toLowerCase()
  };
}

function applyFilters() {
  const rows = dayStore[currentDay] || [];
  const f = getFilters();
  filteredData = rows.filter(r=>{
    if (f.severity && r.Severity !== f.severity) return false;
    if (f.office   && r['Remote Office'] !== f.office) return false;
    if (f.os       && r['Operating System'] !== f.os) return false;
    if (f.search   && !(r.Vulnerabilities||'').toLowerCase().includes(f.search) &&
                      !(r['Computer Name']||'').toLowerCase().includes(f.search)) return false;
    return true;
  });
  currentPage = 1;

  const days = sortedDays();
  const idx  = days.indexOf(currentDay);
  const prevRows = idx > 0 ? (dayStore[days[idx-1]]||[]) : null;

  const sev     = countBy(filteredData,'Severity');
  const offices = countBy(filteredData,'Remote Office');
  const oses    = countBy(filteredData,'Operating System');
  const devices = new Set(filteredData.map(r=>r['Computer Name'])).size;

  renderMetrics(filteredData.length, sev, devices, prevRows ? buildSevSummary(prevRows) : null, prevRows ? prevRows.length : null);
  renderSevChart(sev);
  renderOfficeChart(offices);
  renderOSBars(oses);
  renderTimeline(filteredData);
  renderTable();
  renderOfficeCards(filteredData);
}

function buildSevSummary(rows) { return countBy(rows,'Severity'); }

// ═══════════════════════════════════════════════════════════════
//  METRICS
// ═══════════════════════════════════════════════════════════════
function renderMetrics(total, sev, devices, prevSev, prevTotal) {
  document.getElementById('m-total').textContent    = fmt(total);
  document.getElementById('m-critical').textContent = fmt(sev.Critical||0);
  document.getElementById('m-important').textContent= fmt(sev.Important||0);
  const ml = (sev.Moderate||0)+(sev.Low||0);
  document.getElementById('m-moderate').textContent = fmt(ml);
  document.getElementById('m-crit-pct').textContent = pct(sev.Critical||0,total)+' of total';
  document.getElementById('m-imp-pct').textContent  = pct(sev.Important||0,total)+' of total';
  document.getElementById('m-mod-pct').textContent  = pct(ml,total)+' of total';
  document.getElementById('m-devices').textContent  = devices>0?devices+' unique devices':'';

  if (prevTotal !== null) {
    renderDelta('d-total', total, prevTotal);
    renderDelta('d-critical', sev.Critical||0, prevSev.Critical||0);
    renderDelta('d-important', sev.Important||0, prevSev.Important||0);
    renderDelta('d-moderate', ml, (prevSev.Moderate||0)+(prevSev.Low||0));
  } else {
    ['d-total','d-critical','d-important','d-moderate'].forEach(id=>{
      document.getElementById(id).textContent=''; document.getElementById(id).className='metric-delta';
    });
  }
}

function renderDelta(id, curr, prev) {
  const el = document.getElementById(id);
  const diff = curr - prev;
  if (diff === 0) { el.textContent='±0'; el.className='metric-delta delta-same'; }
  else if (diff > 0) { el.textContent='+'+fmt(diff); el.className='metric-delta delta-up'; }
  else { el.textContent=fmt(diff); el.className='metric-delta delta-down'; }
}

// ═══════════════════════════════════════════════════════════════
//  CHARTS
// ═══════════════════════════════════════════════════════════════
function mkChart(key, canvasId, config) {
  destroyChart(key);
  charts[key] = new Chart(document.getElementById(canvasId), config);
}

const gridColor  = 'rgba(255,255,255,0.05)';
const tickColor  = '#555b66';
const tickFont   = { size:11 };
const kFormatter = v => v>=1000?(v/1000).toFixed(0)+'k':v;

function renderSevChart(sev) {
  const labels = SEV_KEYS.filter(k=>sev[k]);
  const data   = labels.map(k=>sev[k]||0);
  const colors = labels.map(k=>SEV[k]);
  document.getElementById('sev-legend').innerHTML = labels.map((l,i)=>
    `<span><span class="legend-dot" style="background:${colors[i]}"></span>${l}: ${fmt(data[i])}</span>`
  ).join('');
  mkChart('sevChart','sevChart',{
    type:'doughnut',
    data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${fmt(ctx.parsed)}`}}},
      cutout:'62%'}
  });
}

function renderOfficeChart(officeCounts) {
  const top    = topN(officeCounts,8);
  const labels = top.map(([k])=>k.length>22?k.slice(0,20)+'…':k);
  const data   = top.map(([,v])=>v);
  const h      = Math.max(240,top.length*38+50);
  document.getElementById('office-chart-wrap').style.height=h+'px';
  mkChart('officeChart','officeChart',{
    type:'bar',
    data:{labels,datasets:[{data,backgroundColor:'rgba(91,156,246,0.55)',borderRadius:4,borderSkipped:false}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+fmt(ctx.parsed.x)}}},
      scales:{
        x:{grid:{color:gridColor},ticks:{color:tickColor,font:tickFont,callback:kFormatter}},
        y:{grid:{display:false},ticks:{color:'#8b909a',font:tickFont}}
      }}
  });
}

function renderOSBars(osCounts) {
  const top = topN(osCounts,10);
  const max = top[0]?top[0][1]:1;
  document.getElementById('os-bars').innerHTML = top.map(([os,count])=>`
    <div class="os-bar-row">
      <div class="os-bar-label" title="${os}">${short(os)}</div>
      <div class="os-bar-track"><div class="os-bar-fill" style="width:${Math.round(count/max*100)}%"></div></div>
      <div class="os-bar-count">${fmt(count)}</div>
    </div>`).join('');
}

function renderTimeline(data) {
  const mm = {};
  data.forEach(r=>{
    const raw = r['Discovered Date']; if(!raw) return;
    const d = new Date(raw); if(isNaN(d)) return;
    const k = d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');
    if(!mm[k]) mm[k]={Critical:0,Important:0,Moderate:0,Low:0};
    const s=r.Severity; if(SEV_KEYS.includes(s)) mm[k][s]++;
  });
  const keys = Object.keys(mm).sort().slice(-18);
  mkChart('timelineChart','timelineChart',{
    type:'bar',
    data:{labels:keys,datasets:SEV_KEYS.map(s=>({
      label:s,data:keys.map(k=>mm[k]?.[s]||0),
      backgroundColor:SEV[s]+'99',borderRadius:2,borderSkipped:false
    }))},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{stacked:true,grid:{display:false},ticks:{color:tickColor,font:{size:10},maxRotation:45,autoSkip:true,maxTicksLimit:12}},
        y:{stacked:true,grid:{color:gridColor},ticks:{color:tickColor,font:{size:10},callback:kFormatter}}
      }}
  });
}

// ═══════════════════════════════════════════════════════════════
//  TABLE
// ═══════════════════════════════════════════════════════════════
function buildResLookup() {
  const map = {};
  resData.forEach(r => {
    const k = (r['Computer Name']||'').toLowerCase()+'|||'+
              (r['Vulnerability']||'').toLowerCase();
    map[k] = r['Status']||'';
  });
  return map;
}

function renderTable() {
  const resLookup = buildResLookup();
  const start = (currentPage-1)*PAGE_SIZE;
  const page  = filteredData.slice(start,start+PAGE_SIZE);
  const tbody = document.getElementById('table-body');
  if (!filteredData.length) {
    tbody.innerHTML=`<tr><td colspan="8"><div class="empty-state"><p>No records match your filters</p></div></td></tr>`;
    document.getElementById('page-info').textContent='';
    document.getElementById('prev-btn').disabled=true;
    document.getElementById('next-btn').disabled=true;
    document.getElementById('records-count').textContent='0 records';
    return;
  }
  tbody.innerHTML = page.map(row=>{
    const sev   = row.Severity||'Low';
    const cvss  = row['CVSS 3.0 Score'];
    const vuln  = row.Vulnerabilities||'';
    const os    = row['Operating System']||'';
    const rk    = (row['Computer Name']||'').toLowerCase()+'|||'+(vuln).toLowerCase();
    const rs    = resLookup[rk]||'—';
    const rbadge = rs!=='—' ? `<span class="badge badge-${rs.replace(/ /g,'')}">${rs}</span>` : '<span style="color:var(--text-3)">—</span>';
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
  const total=filteredData.length, totalPages=Math.ceil(total/PAGE_SIZE);
  document.getElementById('page-info').textContent=`${currentPage} / ${totalPages}  (${fmt(total)} records)`;
  document.getElementById('records-count').textContent=fmt(total)+' records';
  document.getElementById('prev-btn').disabled=currentPage===1;
  document.getElementById('next-btn').disabled=currentPage>=totalPages;
}

// ═══════════════════════════════════════════════════════════════
//  OFFICE CARDS
// ═══════════════════════════════════════════════════════════════
function renderOfficeCards(data) {
  const byOffice = {};
  data.forEach(r=>{ const o=r['Remote Office']||'Unknown'; if(!byOffice[o])byOffice[o]=[]; byOffice[o].push(r); });
  const sorted = Object.entries(byOffice).sort((a,b)=>b[1].length-a[1].length);
  if(!sorted.length){ document.getElementById('office-cards').innerHTML='<div class="empty-state" style="grid-column:1/-1"><p>No data</p></div>'; return; }
  document.getElementById('office-cards').innerHTML = sorted.map(([name,rows])=>{
    const sev=countBy(rows,'Severity'); const total=rows.length;
    const segs = SEV_KEYS.map(s=>{
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
function rebuildDiff() {
  const dayA = document.getElementById('diff-day-a').value;
  const dayB = document.getElementById('diff-day-b').value;
  if (!dayA || !dayB || dayA===dayB) {
    document.getElementById('diff-summary').innerHTML='<p style="color:var(--text-3);font-size:13px;">Select two different days above.</p>';
    return;
  }
  document.getElementById('diff-subtitle').textContent = dayA+' → '+dayB;
  const rowsA = dayStore[dayA]||[];
  const rowsB = dayStore[dayB]||[];
  const setA  = new Set(rowsA.map(rowKey));
  const setB  = new Set(rowsB.map(rowKey));
  const newRows      = rowsB.filter(r=>!setA.has(rowKey(r)));
  const resolvedRows = rowsA.filter(r=>!setB.has(rowKey(r)));
  const sevA = countBy(rowsA,'Severity');
  const sevB = countBy(rowsB,'Severity');
  const deltaTotal = rowsB.length-rowsA.length;

  const cards = [
    {label:'Day A total', val:fmt(rowsA.length), delta:null},
    {label:'Day B total', val:fmt(rowsB.length), delta:deltaTotal},
    {label:'New vulns',   val:fmt(newRows.length), delta:null, color:'var(--red)'},
    {label:'Resolved',    val:fmt(resolvedRows.length), delta:null, color:'var(--green)'},
    {label:'Net change',  val:(deltaTotal>=0?'+':'')+fmt(deltaTotal), delta:null, color:deltaTotal>0?'var(--red)':deltaTotal<0?'var(--green)':'var(--text-3)'}
  ];
  document.getElementById('diff-summary').innerHTML = cards.map(c=>`
    <div class="diff-card">
      <div class="diff-card-label">${c.label}</div>
      <div class="diff-card-val" style="${c.color?'color:'+c.color:''}">${c.val}</div>
      ${c.delta!==null?`<div class="diff-card-delta ${c.delta>0?'diff-pos':c.delta<0?'diff-neg':'diff-zero'}">${c.delta>0?'+':''}${fmt(c.delta)} vs prev</div>`:''}
    </div>`).join('');

  mkChart('diffSevChart','diffSevChart',{
    type:'bar',
    data:{
      labels:SEV_KEYS,
      datasets:[
        {label:'Day A ('+dayA+')',data:SEV_KEYS.map(k=>sevA[k]||0),backgroundColor:SEV_KEYS.map(k=>SEV[k]+'88'),borderRadius:3,borderSkipped:false},
        {label:'Day B ('+dayB+')',data:SEV_KEYS.map(k=>sevB[k]||0),backgroundColor:SEV_KEYS.map(k=>SEV[k]),borderRadius:3,borderSkipped:false}
      ]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{grid:{display:false},ticks:{color:tickColor,font:tickFont}},
        y:{grid:{color:gridColor},ticks:{color:tickColor,font:tickFont,callback:kFormatter}}
      }}
  });

  const allOffices = [...new Set([...rowsA.map(r=>r['Remote Office']),...rowsB.map(r=>r['Remote Office'])].filter(Boolean))];
  const offA = countBy(rowsA,'Remote Office');
  const offB = countBy(rowsB,'Remote Office');
  const deltas = allOffices.map(o=>({ o, d:(offB[o]||0)-(offA[o]||0) }))
    .sort((a,b)=>Math.abs(b.d)-Math.abs(a.d)).slice(0,10);
  const dLabels = deltas.map(x=>x.o.length>18?x.o.slice(0,16)+'…':x.o);
  const dData   = deltas.map(x=>x.d);
  const dColors = dData.map(v=>v>0?'rgba(224,92,92,0.7)':v<0?'rgba(76,175,129,0.7)':'rgba(255,255,255,0.15)');
  const dh = Math.max(260,deltas.length*38+50);
  document.getElementById('diff-office-wrap').style.height=dh+'px';
  mkChart('diffOfficeChart','diffOfficeChart',{
    type:'bar',
    data:{labels:dLabels,datasets:[{data:dData,backgroundColor:dColors,borderRadius:3,borderSkipped:false}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>(ctx.parsed.x>=0?'+':'')+fmt(ctx.parsed.x)}}},
      scales:{
        x:{grid:{color:gridColor},ticks:{color:tickColor,font:tickFont,callback:v=>(v>=0?'+':'')+kFormatter(v)}},
        y:{grid:{display:false},ticks:{color:'#8b909a',font:tickFont}}
      }}
  });

  function diffTableRows(rows) {
    if(!rows.length) return '<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:16px;">None</td></tr>';
    return rows.slice(0,100).map(r=>`<tr>
      <td><div class="vuln-name" title="${r.Vulnerabilities||''}">${r.Vulnerabilities||''}</div></td>
      <td><span class="badge badge-${r.Severity||'Low'}">${r.Severity||'—'}</span></td>
      <td><span class="comp-name">${r['Computer Name']||'—'}</span></td>
      <td>${r['Remote Office']||'—'}</td>
      <td class="cvss-val">${r['CVSS 3.0 Score']!=null&&r['CVSS 3.0 Score']!==''?parseFloat(r['CVSS 3.0 Score']).toFixed(1):'—'}</td>
    </tr>`).join('');
  }
  document.getElementById('new-vuln-count').textContent      = fmt(newRows.length);
  document.getElementById('resolved-vuln-count').textContent = fmt(resolvedRows.length);
  document.getElementById('diff-new-body').innerHTML      = diffTableRows(newRows);
  document.getElementById('diff-resolved-body').innerHTML = diffTableRows(resolvedRows);
}

// ═══════════════════════════════════════════════════════════════
//  RESOLUTION
// ═══════════════════════════════════════════════════════════════
function rebuildResolution() {
  const dates = [...new Set(resData.map(r=>{
    const d=parseDateStr(r['Date']); return d||null;
  }).filter(Boolean))].sort();
  document.getElementById('res-day-filter').innerHTML =
    '<option value="">All days</option>' + dates.map(d=>`<option value="${d}">${d}</option>`).join('');
  renderResolution();
}

function renderResolution() {
  const f = getResFilters();
  let data = resData.filter(r=>{
    if(f.status && (r['Status']||'')!==f.status) return false;
    if(f.day){ const d=parseDateStr(r['Date']); if(d!==f.day) return false; }
    return true;
  });
  const total = data.length;
  const statusCount = countBy(data,'Status');
  const succeeded  = statusCount['Succeeded']||0;
  const pending    = (statusCount['Yet To Apply']||0)+(statusCount['In Progress']||0)+(statusCount['Retry In Progress']||0)+(statusCount['Overridden']||0);
  const failed     = statusCount['Failed']||0;

  document.getElementById('r-total').textContent        = fmt(total);
  document.getElementById('r-resolved').textContent     = fmt(succeeded);
  document.getElementById('r-pending').textContent      = fmt(pending);
  document.getElementById('r-na').textContent           = fmt(failed);
  document.getElementById('r-resolved-pct').textContent = pct(succeeded,total)+' succeeded';
  document.getElementById('r-pending-pct').textContent  = pct(pending,total)+' pending/in-progress';
  document.getElementById('r-na-pct').textContent       = pct(failed,total)+' failed';
  document.getElementById('res-subtitle').textContent   = fmt(total)+' resolution records';

  const resLabels = Object.keys(RES_COLORS);
  const resVals   = resLabels.map(k=>statusCount[k]||0);
  document.getElementById('res-legend').innerHTML = resLabels.map((l,i)=>
    `<span><span class="legend-dot" style="background:${Object.values(RES_COLORS)[i]}"></span>${l}: ${fmt(resVals[i])}</span>`
  ).join('');
  mkChart('resDonutChart','resDonutChart',{
    type:'doughnut',
    data:{labels:resLabels,datasets:[{data:resVals,backgroundColor:Object.values(RES_COLORS),borderWidth:0,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${fmt(ctx.parsed)}`}}},
      cutout:'62%'}
  });

  const byDate = {};
  resData.forEach(r=>{
    const d=parseDateStr(r['Date']); if(!d)return;
    if(!byDate[d]) byDate[d]={total:0,resolved:0};
    byDate[d].total++;
    if((r['Status']||'')==='Succeeded') byDate[d].resolved++;
  });
  const tKeys = Object.keys(byDate).sort();
  mkChart('resTrendChart','resTrendChart',{
    type:'line',
    data:{labels:tKeys,datasets:[
      {label:'Succeeded %',data:tKeys.map(k=>Math.round(byDate[k].resolved/byDate[k].total*100)),
       borderColor:'#4caf81',backgroundColor:'rgba(76,175,129,0.08)',fill:true,tension:0.3,pointRadius:3},
      {label:'Total patches',data:tKeys.map(k=>byDate[k].total),
       borderColor:'#5b9cf6',backgroundColor:'rgba(91,156,246,0.05)',fill:false,tension:0.3,pointRadius:3,yAxisID:'y2'}
    ]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{grid:{display:false},ticks:{color:tickColor,font:{size:10},maxRotation:45}},
        y:{grid:{color:gridColor},ticks:{color:tickColor,font:{size:10},callback:v=>v+'%'},min:0,max:100,title:{display:true,text:'Succeeded %',color:tickColor,font:{size:10}}},
        y2:{position:'right',grid:{display:false},ticks:{color:tickColor,font:{size:10},callback:kFormatter},title:{display:true,text:'# Patches',color:tickColor,font:{size:10}}}
      }}
  });

  const start = (resPage-1)*PAGE_SIZE;
  const page  = data.slice(start,start+PAGE_SIZE);
  const tbody = document.getElementById('res-table-body');
  if(!data.length){
    tbody.innerHTML='<tr><td colspan="6"><div class="empty-state"><p>No resolution records in database.</p></div></td></tr>';
    document.getElementById('res-page-info').textContent='';
    document.getElementById('res-prev-btn').disabled=true;
    document.getElementById('res-next-btn').disabled=true;
    return;
  }
  tbody.innerHTML = page.map(r=>{
    const st = r['Status']||'—';
    const bc = st==='Succeeded'?'badge-Succeeded':st==='Yet To Apply'?'badge-YetToApply':st==='In Progress'?'badge-InProgress':st==='Retry In Progress'?'badge-RetryInProgress':st==='Failed'?'badge-Failed':st==='Not Applicable'?'badge-NotApplicable':st==='Overridden'?'badge-Overridden':'';
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

function getResFilters() {
  return {
    day:    document.getElementById('res-day-filter').value,
    status: document.getElementById('res-status-filter').value
  };
}

// ═══════════════════════════════════════════════════════════════
//  TREND (multi-day)
// ═══════════════════════════════════════════════════════════════
function rebuildTrend() {
  const days = sortedDays();
  if(!days.length) return;
  const officeFilter = document.getElementById('trend-office-filter').value;
  const getRows = day => {
    const rows = dayStore[day]||[];
    return officeFilter ? rows.filter(r=>r['Remote Office']===officeFilter) : rows;
  };

  const totals = days.map(d=>getRows(d).length);
  mkChart('trendTotalChart','trendTotalChart',{
    type:'line',
    data:{labels:days,datasets:[{
      label:'Total vulns',data:totals,
      borderColor:'#5b9cf6',backgroundColor:'rgba(91,156,246,0.08)',fill:true,tension:0.3,pointRadius:4
    }]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{grid:{display:false},ticks:{color:tickColor,font:{size:10},maxRotation:45}},
        y:{grid:{color:gridColor},ticks:{color:tickColor,font:{size:10},callback:kFormatter}}
      }}
  });

  mkChart('trendSevChart','trendSevChart',{
    type:'bar',
    data:{labels:days,datasets:SEV_KEYS.map(s=>({
      label:s,
      data:days.map(d=>{const r=getRows(d);return countBy(r,'Severity')[s]||0;}),
      backgroundColor:SEV[s]+'aa',borderRadius:2,borderSkipped:false
    }))},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#8b909a',font:{size:11}}},tooltip:{mode:'index',intersect:false}},
      scales:{
        x:{stacked:true,grid:{display:false},ticks:{color:tickColor,font:{size:10},maxRotation:45}},
        y:{stacked:true,grid:{color:gridColor},ticks:{color:tickColor,font:{size:10},callback:kFormatter}}
      }}
  });

  const byDate = {};
  resData.forEach(r=>{
    const d=parseDateStr(r['Date']); if(!d)return;
    if(!byDate[d]) byDate[d]={total:0,resolved:0};
    byDate[d].total++;
    if((r['Status']||'')==='Succeeded') byDate[d].resolved++;
  });
  const rateData = days.map(d=>byDate[d]?Math.round(byDate[d].resolved/byDate[d].total*100):null);
  mkChart('trendResChart','trendResChart',{
    type:'line',
    data:{labels:days,datasets:[{
      label:'Succeeded rate %',data:rateData,
      borderColor:'#4caf81',backgroundColor:'rgba(76,175,129,0.08)',fill:true,tension:0.3,
      pointRadius:4,spanGaps:true
    }]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>ctx.parsed.y!==null?ctx.parsed.y+'%':'No data'}}},
      scales:{
        x:{grid:{display:false},ticks:{color:tickColor,font:{size:10},maxRotation:45}},
        y:{grid:{color:gridColor},ticks:{color:tickColor,font:{size:10},callback:v=>v+'%'},min:0,max:100}
      }}
  });
}

// ═══════════════════════════════════════════════════════════════
//  EVENTS
// ═══════════════════════════════════════════════════════════════
document.getElementById('day-select').addEventListener('change', e=>{ if(e.target.value) switchDay(e.target.value); });
document.getElementById('day-prev').addEventListener('click', ()=>{
  const days=sortedDays(), idx=days.indexOf(currentDay);
  if(idx>0) switchDay(days[idx-1]);
});
document.getElementById('day-next').addEventListener('click', ()=>{
  const days=sortedDays(), idx=days.indexOf(currentDay);
  if(idx<days.length-1) switchDay(days[idx+1]);
});

document.querySelectorAll('.nav-item').forEach(item=>{
  item.addEventListener('click', ()=>{
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('tab-'+item.dataset.tab).classList.add('active');
    if (item.dataset.tab === 'diff') rebuildDiff();
    if (item.dataset.tab === 'trend') rebuildTrend();
    if (item.dataset.tab === 'resolution') { rebuildResolution(); }
  });
});

['f-severity','f-office','f-office-global','f-os-global'].forEach(id=>{
  document.getElementById(id).addEventListener('change', applyFilters);
});
let st;
document.getElementById('search-input').addEventListener('input', ()=>{ clearTimeout(st); st=setTimeout(applyFilters,250); });

document.getElementById('prev-btn').addEventListener('click', ()=>{ currentPage--; renderTable(); });
document.getElementById('next-btn').addEventListener('click', ()=>{ currentPage++; renderTable(); });

document.getElementById('res-prev-btn').addEventListener('click', ()=>{ resPage--; renderResolution(); });
document.getElementById('res-next-btn').addEventListener('click', ()=>{ resPage++; renderResolution(); });

document.getElementById('res-day-filter').addEventListener('change', ()=>{ resPage=1; renderResolution(); });
document.getElementById('res-status-filter').addEventListener('change', ()=>{ resPage=1; renderResolution(); });

document.getElementById('diff-day-a').addEventListener('change', rebuildDiff);
document.getElementById('diff-day-b').addEventListener('change', rebuildDiff);
document.getElementById('trend-office-filter').addEventListener('change', rebuildTrend);

// ── Kick off DB load ──
loadFromSupabase();
