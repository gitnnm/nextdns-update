// update-dns.js
// Скрипт для обновления IP-адресов в NextDNS через Comss DNS
// + фиксированные IP для Deezer и Google AI (без запроса к Comss)
// ИСПРАВЛЕНО: NextDNS Rewrites не поддерживает PATCH, используется DELETE + POST

const NEXTDNS_API_KEY = process.env.NEXTDNS_API_KEY;
const NEXTDNS_PROFILE_ID = process.env.NEXTDNS_PROFILE_ID;

if (!NEXTDNS_API_KEY || !NEXTDNS_PROFILE_ID) {
  console.error('Ошибка: не заданы переменные окружения NEXTDNS_API_KEY или NEXTDNS_PROFILE_ID');
  process.exit(1);
}

// === Фиксированные IP (не запрашиваем Comss) ===
const FIXED_IP = '193.233.112.68';

const fixedIps = {
  // Deezer
  'deezer.com': FIXED_IP,
  'www.deezer.com': FIXED_IP,
  'payment.deezer.com': FIXED_IP,

  // Google AI (все домены из блока "Google AI")
  'gemini.google.com': FIXED_IP,
  'gemini.google': FIXED_IP,
  'aistudio.google.com': FIXED_IP,
  'generativelanguage.googleapis.com': FIXED_IP,
  'generativeai.google': FIXED_IP,
  'ai.google.dev': FIXED_IP,
  'alkalicore-pa.clients6.google.com': FIXED_IP,
  'alkalimakersuite-pa.clients6.google.com': FIXED_IP,
  'alkalimining-pa.googleapis.com': FIXED_IP,
  'aisandbox-pa.googleapis.com': FIXED_IP,
  'aitestkitchen.withgoogle.com': FIXED_IP,
  'apis.google.com': FIXED_IP,
  'appcatalyst.pa.googleapis.com': FIXED_IP,
  'assistant-s3-pa.googleapis.com': FIXED_IP,
  'bard.google.com': FIXED_IP,
  'daily-cloudcode-pa.googleapis.com': FIXED_IP,
  'datastudio.google.com': FIXED_IP,
  'deepmind.com': FIXED_IP,
  'deepmind.google': FIXED_IP,
  'developerprofiles-pa.googleapis.com': FIXED_IP,
  'geller-pa.googleapis.com': FIXED_IP,
  'jules.google': FIXED_IP,
  'jules.google.com': FIXED_IP,
  'labs.google': FIXED_IP,
  'labs.google.com': FIXED_IP,
  'lookerstudio.google.com': FIXED_IP,
  'makersuite.google.com': FIXED_IP,
  'notebook.google': FIXED_IP,
  'notebook.google.com': FIXED_IP,
  'notebook-pa.googleapis.com': FIXED_IP,
  'notebooklm.google': FIXED_IP,
  'notebooklm.google.com': FIXED_IP,
  'notebooklm-pa.googleapis.com': FIXED_IP,
  'o.pki.goog': FIXED_IP,
  'opal.google': FIXED_IP,
  'opal.google.com': FIXED_IP,
  'opal.withgoogle.com': FIXED_IP,
  'people-pa.clients6.google.com': FIXED_IP,
  'proactivebackend-pa.googleapis.com': FIXED_IP,
  'robinfrontend-pa.googleapis.com': FIXED_IP,
  'signaler-pa.clients6.google.com': FIXED_IP,
  'stitch.withgoogle.com': FIXED_IP,
  'suggestqueries.google.com': FIXED_IP,
  'waa-pa.clients6.google.com': FIXED_IP,
  'webchannel-alkalimakersuite-pa.clients6.google.com': FIXED_IP,
  'antigravity.google': FIXED_IP,
  'www.antigravity.google': FIXED_IP,
  'flow.google': FIXED_IP,
  'www.flow.google': FIXED_IP,
  'flowmusic.app': FIXED_IP,
  'www.flowmusic.app': FIXED_IP,
};

// === Домены, для которых IP берём у Comss ===
const comssDomains = [
  // ChatGPT / OpenAI
  "chatgpt.com", "www.chatgpt.com", "chatgpt.site", "www.chatgpt.site",
  "ab.chatgpt.com", "webrtc.chatgpt.com", "ws.chatgpt.com",
  "tcr9i.chat.openai.com", "auth.openai.com", "auth0.openai.com",
  "platform.openai.com", "api.openai.com", "cdn.oaistatic.com",
  "cdn.platform.openai.com", "files.oaiusercontent.com", "oaiusercontent.com",
  "www.oaiusercontent.com", "oaistatic.com", "www.oaistatic.com",
  "ios.chat.openai.com", "android.chat.openai.com", "operator.chatgpt.com",
  "videos.openai.com", "developers.openai.com", "openai.com", "www.openai.com",
  "sdmntprukwest.oaiusercontent.com", "sdmntpritalynorth.oaiusercontent.com",
  "sdmntprpolandcentral.oaiusercontent.com", "sdmntprnortheu.oaiusercontent.com",
  // Claude / Anthropic
  "anthropic.com", "api.anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
  // Grok / xAI
  "x.ai", "grok.com", "api.x.ai", "accounts.x.ai",
  // Microsoft Copilot
  "auth.xboxlive.com", "copilot.microsoft.com", "designer.microsoft.com",
  "ecs.office.com", "edgeservices.bing.com", "gssv-play-prod.xboxlive.com",
  "rewards.bing.com", "sydney.bing.com", "titlestorage.xboxlive.com",
  "xboxdesignlab.xbox.com", "xgpuweb.gssv-play-prod.xboxlive.com",
  "xgpuwebf2p.gssv-play-prod.xboxlive.com", "xsts.auth.xboxlive.com"
];

const allDomains = [...Object.keys(fixedIps), ...comssDomains];

function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function buildDnsQuery(domain) {
  const labels = domain.split('.');
  const parts = [];
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  parts.push(header);
  for (const label of labels) {
    const lb = Buffer.from(label, 'utf8');
    parts.push(Buffer.from([lb.length]), lb);
  }
  parts.push(Buffer.from([0x00]));
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0);
  qtype.writeUInt16BE(1, 2);
  parts.push(qtype);
  return Buffer.concat(parts);
}

function parseDnsResponse(buffer) {
  try {
    if (buffer.length < 12) return null;
    let offset = 12;
    const qnameEnd = Math.min(offset + 255, buffer.length);
    while (offset < qnameEnd && buffer[offset] !== 0) offset += buffer[offset] + 1;
    offset += 1 + 4;
    while (offset + 12 <= buffer.length) {
      if ((buffer[offset] & 0xc0) === 0xc0) { offset += 2; }
      else {
        while (offset < buffer.length && buffer[offset] !== 0) offset += buffer[offset] + 1;
        offset += 1;
      }
      if (offset + 10 > buffer.length) break;
      const type = buffer.readUInt16BE(offset);
      offset += 2;
      const rdlength = buffer.readUInt16BE(offset + 6);
      offset += 8;
      if (type === 1 && rdlength === 4 && offset + 4 <= buffer.length) {
        return `${buffer[offset]}.${buffer[offset+1]}.${buffer[offset+2]}.${buffer[offset+3]}`;
      }
      offset += rdlength;
    }
    return null;
  } catch { return null; }
}

async function getComssIp(domain) {
  const query = base64UrlEncode(buildDnsQuery(domain));
  const res = await fetch(`https://dns.comss.one/dns-query?dns=${query}`, {
    headers: { 'Accept': 'application/dns-message' },
    signal: AbortSignal.timeout(10_000)
  });
  if (!res.ok) throw new Error(`DoH ошибка: ${res.status}`);
  const ip = parseDnsResponse(Buffer.from(await res.arrayBuffer()));
  if (!ip) throw new Error('no A record');
  return ip;
}

async function fetchWithoutOrigin(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.delete('Origin');
  return fetch(url, { method: options.method || 'GET', headers, body: options.body });
}

// ИСПРАВЛЕНО: DELETE + POST, так как PATCH не поддерживается
async function upsertNextDns(domain, newIp) {
  const baseUrl = `https://api.nextdns.io/profiles/${NEXTDNS_PROFILE_ID}/rewrites`;
  const headers = {
    'X-Api-Key': NEXTDNS_API_KEY,
    'Content-Type': 'application/json'
  };

  // 1. Получаем список текущих правил
  const listResp = await fetchWithoutOrigin(baseUrl, { headers });
  if (!listResp.ok) throw new Error(`list: ${listResp.status}`);
  const existing = (await listResp.json()).data?.find(r => r.name === domain);

  // 2. IP не изменился — пропускаем
  if (existing && existing.content === newIp) return 'unchanged';

  // 3. Если правило существует — удаляем (PATCH не работает)
  if (existing) {
    const delResp = await fetchWithoutOrigin(`${baseUrl}/${existing.id}`, {
      method: 'DELETE',
      headers
    });
    if (!delResp.ok) {
      throw new Error(`delete: ${delResp.status} - ${await delResp.text()}`);
    }
  }

  // 4. Создаём новое правило
  const createResp = await fetchWithoutOrigin(baseUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: domain, content: newIp })
  });
  if (!createResp.ok) {
    throw new Error(`create: ${createResp.status} - ${await createResp.text()}`);
  }
  return existing ? 'updated' : 'created';
}

async function main() {
  console.log(`Начинаю обновление ${allDomains.length} доменов...`);
  console.log(`Время запуска: ${new Date().toISOString()}`);

  const results = [];
  for (const domain of allDomains) {
    try {
      let newIp;
      if (fixedIps[domain]) {
        newIp = fixedIps[domain];
        console.log(`Обработка: ${domain} → фиксированный ${newIp}`);
      } else {
        newIp = await getComssIp(domain);
        console.log(`Обработка: ${domain} → Comss ${newIp}`);
      }

      const status = await upsertNextDns(domain, newIp);
      console.log(`  ${status === 'unchanged' ? 'Без изменений' : status === 'created' ? 'Создано' : 'Обновлено'}`);
      results.push({ domain, status, ip: newIp });

      if (!fixedIps[domain]) await new Promise(r => setTimeout(r, 2000));
    } catch (e) {
      const msg = e.message || String(e);
      const isNoRecord = /no A record/i.test(msg);
      console.error(`  ${isNoRecord ? 'Пропущено' : 'Ошибка'}: ${msg}`);
      results.push({ domain, status: isNoRecord ? 'skipped' : 'error', error: msg });
    }
  }

  const count = s => results.filter(r => r.status === s).length;
  console.log('\n=== ИТОГИ ===');
  console.log(`Создано:       ${count('created')}`);
  console.log(`Обновлено:     ${count('updated')}`);
  console.log(`Без изменений: ${count('unchanged')}`);
  console.log(`Пропущено:     ${count('skipped')}`);
  console.log(`Ошибок:        ${count('error')}`);

  if (count('error') > 0) process.exit(1);
}

main().catch(e => { console.error('Критическая ошибка:', e); process.exit(1); });
