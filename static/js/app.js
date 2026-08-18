// CodeAlpha Task 1 Sniffer Controller
let isStreaming = true;
let pktId = 103;

function toggleStream() {
  isStreaming = !isStreaming;
  document.getElementById('lbl-stream').innerText = isStreaming ? 'Live Capture Active' : 'Capture Paused';
  document.getElementById('icon-stream').className = isStreaming ? 'fa-solid fa-play' : 'fa-solid fa-pause';
}

function clearPackets() {
  document.getElementById('packet-tbody').innerHTML = '';
  document.getElementById('stat-count').innerText = '0';
  document.getElementById('stat-alerts').innerText = '0';
}

function injectPacket() {
  const type = document.getElementById('inj-type').value;
  const src = document.getElementById('inj-src').value;
  const dst = document.getElementById('inj-dst').value;
  const tbody = document.getElementById('packet-tbody');

  let proto = 'TCP';
  let summary = 'Custom injected packet payload';
  let alertMsg = '<span class="text-slate-500">Clean</span>';
  let rowBg = 'border-b border-slate-800/60 hover:bg-slate-800/40';

  if (type === 'SQLi') {
    proto = 'HTTP';
    summary = "POST /api/login payload: UNION SELECT username,password FROM users";
    alertMsg = '<span class="px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 font-bold">SQL Injection</span>';
    rowBg += ' bg-rose-950/20';
    const alertsEl = document.getElementById('stat-alerts');
    alertsEl.innerText = parseInt(alertsEl.innerText) + 1;
  } else if (type === 'SYN') {
    proto = 'TCP';
    summary = 'SYN Flood Burst [SYN] seq=92817281';
    alertMsg = '<span class="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 font-bold">DoS Anomaly</span>';
    rowBg += ' bg-amber-950/20';
  } else if (type === 'DNS') {
    proto = 'DNS';
    summary = 'Standard query A exfil-data.c2-server.xyz';
    alertMsg = '<span class="px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800 font-bold">DNS Tunnel</span>';
    rowBg += ' bg-purple-950/20';
  } else if (type === 'ICMP') {
    proto = 'ICMP';
    summary = 'Echo (ping) request ttl=64 id=0x4a1b';
  }

  const tr = document.createElement('tr');
  tr.className = rowBg;
  tr.innerHTML = `
    <td class="py-2.5 px-3 text-cyan-400 font-bold">#${pktId++}</td>
    <td class="py-2.5 px-3">${src}</td>
    <td class="py-2.5 px-3">${dst}</td>
    <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">${proto}</span></td>
    <td class="py-2.5 px-3 text-slate-300">${summary}</td>
    <td class="py-2.5 px-3">${alertMsg}</td>
  `;
  tbody.prepend(tr);

  const countEl = document.getElementById('stat-count');
  countEl.innerText = parseInt(countEl.innerText) + 1;
}

function filterPackets() {
  const query = document.getElementById('search-input').value.toLowerCase();
  const rows = document.querySelectorAll('#packet-tbody tr');
  rows.forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(query) ? '' : 'none';
  });
}
