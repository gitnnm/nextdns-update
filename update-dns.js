// update-dns.js
// Скрипт для обновления IP-адресов в NextDNS через Comss DNS

const NEXTDNS_API_KEY = process.env.NEXTDNS_API_KEY;
const NEXTDNS_PROFILE_ID = process.env.NEXTDNS_PROFILE_ID;

if (!NEXTDNS_API_KEY || !NEXTDNS_PROFILE_ID) {
  console.error('Ошибка: не заданы переменные окружения NEXTDNS_API_KEY или NEXTDNS_PROFILE_ID');
  process.exit(1);
}

// Полный список доменов
const domains = [
  // ChatGPT / OpenAI
  "chatgpt.com", "ab.chatgpt.com", "webrtc.chatgpt.com",
  "tcr9i.chat.openai.com", "auth.openai.com", "auth0.openai.com",
  "platform.openai.com", "api.openai.com", "cdn.oaistatic.com",
  "files.oaiusercontent.com",
  // Claude / Anthropic
  "anthropic.com", "api.anthropic.com", "claude.ai", "claude.com",
  "claudeusercontent.com",
  // Google AI (полный список из GeoHide)
"gemini.google.com",
"gemini.google",
"aistudio.google.com",
"generativelanguage.googleapis.com",
"generativeai.google",
"ai.google.dev",
"alkalicore-pa.clients6.google.com",
"alkalimakersuite-pa.clients6.google.com",
"alkalimining-pa.googleapis.com",
"aisandbox-pa.googleapis.com",
"aitestkitchen.withgoogle.com",
"apis.google.com",
"appcatalyst.pa.googleapis.com",
"assistant-s3-pa.googleapis.com",
"bard.google.com",
"daily-cloudcode-pa.googleapis.com",
"datastudio.google.com",
"deepmind.com",
"deepmind.google",
"developerprofiles-pa.googleapis.com",
"geller-pa.googleapis.com",
"jules.google",
"jules.google.com",
"labs.google",
"labs.google.com",
"lookerstudio.google.com",
"makersuite.google.com",
"notebook.google",
"notebook.google.com",
"notebook-pa.googleapis.com",
"notebooklm.google",
"notebooklm.google.com",
"notebooklm-pa.googleapis.com",
"o.pki.goog",
"opal.google",
"opal.google.com",
"opal.withgoogle.com",
"people-pa.clients6.google.com",
"proactivebackend-pa.googleapis.com",
"robinfrontend-pa.googleapis.com",
"signaler-pa.clients6.google.com",
"stitch.withgoogle.com",
"suggestqueries.google.com",
"waa-pa.clients6.google.com",
"webchannel-alkalimakersuite-pa.clients6.google.com",
"antigravity.google",
"www.antigravity.google",
"flow.google",
"www.flow.google",
"flowmusic.app",
"www.flowmusic.app",
  // Grok / xAI
  "x.ai", "grok.com", "api.x.ai", "accounts.x.ai",
  // Microsoft Copilot
  "copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com",
  "login.live.com", "login.microsoftonline.com"
];

// === Вспомогательные функции ===

/**
 * Кодирует ArrayBuffer в base64url
 */
function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Строит DNS-запрос в wire format для A-записи
 */
function buildDnsQuery(domain) {
  const labels = domain.split('.');
  const parts = [];
  
  // Header
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0, 0);      // ID
  header.writeUInt16BE(0x0100, 2); // Flags
  header.writeUInt16BE(1, 4);      // QDCOUNT
  header.writeUInt16BE(0, 6);      // ANCOUNT
  header.writeUInt16BE(0, 8);      // NSCOUNT
  header.writeUInt16BE(0, 10);     // ARCOUNT
  parts.push(header);
  
  // QNAME
  for (const label of labels) {
    const labelBytes = Buffer.from(label, 'utf8');
    parts.push(Buffer.from([labelBytes.length]));
    parts.push(labelBytes);
  }
  parts.push(Buffer.from([0x00])); // конец QNAME
  
  // QTYPE + QCLASS
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0); // A
  qtype.writeUInt16BE(1, 2); // IN
  parts.push(qtype);
  
  return Buffer.concat(parts);
}

/**
 * Парсит DNS-ответ в wire format и извлекает первый IPv4
 */
function parseDnsResponse(buffer) {
  try {
    if (buffer.length < 12) return null;
    
    let offset = 12;
    
    // Пропускаем QNAME
    while (offset < buffer.length && buffer[offset] !== 0) {
      offset += buffer[offset] + 1;
    }
    offset += 1; // null byte
    offset += 4; // QTYPE + QCLASS
    
    // Читаем Answer Section
    while (offset + 12 <= buffer.length) {
      // Имя ответа (pointer или метки)
      if ((buffer[offset] & 0xc0) === 0xc0) {
        offset += 2;
      } else {
        while (offset < buffer.length && buffer[offset] !== 0) {
          offset += buffer[offset] + 1;
        }
        offset += 1;
      }
      
      if (offset + 10 > buffer.length) break;
      
      const type = buffer.readUInt16BE(offset);
      offset += 2;
      
      const rdlength = buffer.readUInt16BE(offset + 6);
      offset += 8; // CLASS + TTL + RDLENGTH
      
      if (type === 1 && rdlength === 4 && offset + 4 <= buffer.length) {
        return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
      }
      
      offset += rdlength;
    }
    
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Запрашивает IP у Comss DNS
 */
async function getComssIp(domain) {
  const query = buildDnsQuery(domain);
  const base64Query = base64UrlEncode(query);
  const url = `https://dns.comss.one/dns-query?dns=${base64Query}`;
  
  const response = await fetch(url, {
    headers: { 'Accept': 'application/dns-message' }
  });
  
  if (!response.ok) {
    throw new Error(`DoH ошибка: ${response.status}`);
  }
  
  const buffer = Buffer.from(await response.arrayBuffer());
  const ip = parseDnsResponse(buffer);
  
  if (!ip) {
    throw new Error('IP не найден в ответе');
  }
  
  return ip;
}

/**
 * Удаляет заголовок Origin из запроса (обход authRequired)
 */
async function fetchWithoutOrigin(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.delete('Origin');
  
  return fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body
  });
}

/**
 * Обновляет правило в NextDNS
 */
async function updateNextDns(domain, newIp) {
  const baseUrl = `https://api.nextdns.io/profiles/${NEXTDNS_PROFILE_ID}/rewrites`;
  const headers = {
    'X-Api-Key': NEXTDNS_API_KEY,
    'Content-Type': 'application/json'
  };
  
  // 1. Получаем список текущих правил
  const listResp = await fetchWithoutOrigin(baseUrl, { headers });
  if (!listResp.ok) {
    throw new Error(`Не удалось получить список правил: ${listResp.status}`);
  }
  
  const listData = await listResp.json();
  const existingRule = listData.data?.find(r => r.name === domain);
  
  // 2. Удаляем старое правило, если есть
  if (existingRule) {
    await fetchWithoutOrigin(`${baseUrl}/${existingRule.id}`, {
      method: 'DELETE',
      headers
    });
  }
  
  // 3. Создаём новое правило
  const createResp = await fetchWithoutOrigin(baseUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: domain, content: newIp })
  });
  
  if (!createResp.ok) {
    const error = await createResp.text();
    throw new Error(`Не удалось создать правило: ${createResp.status} - ${error}`);
  }
}

// === Основная логика ===

async function main() {
  console.log(`Начинаю обновление ${domains.length} доменов...`);
  console.log(`Время запуска: ${new Date().toISOString()}`);
  
  const results = [];
  
  for (const domain of domains) {
    try {
      console.log(`Обработка: ${domain}`);
      
      // Получаем IP от Comss
      const newIp = await getComssIp(domain);
      console.log(`  Comss вернул IP: ${newIp}`);
      
      // Обновляем NextDNS
      await updateNextDns(domain, newIp);
      console.log(`  Обновлено в NextDNS`);
      
      results.push({ domain, status: 'updated', ip: newIp });
      
      // Небольшая пауза между доменами, чтобы не перегружать API
      await new Promise(resolve => setTimeout(resolve, 2000));
      
    } catch (e) {
      console.error(`  Ошибка: ${e.message}`);
      results.push({ domain, status: 'error', error: e.message });
    }
  }
  
  // Итоги  
  const updated = results.filter(r => r.status === 'updated').length;
  const errors = results.filter(r => r.status === 'error').length;
  
  console.log('\n=== ИТОГИ ===');
  console.log(`Обновлено: ${updated}`);
  console.log(`Ошибок: ${errors}`);
  
  if (errors > 0) {
    console.log('\nДомены с ошибками:');
    results.filter(r => r.status === 'error').forEach(r => {
      console.log(`  ${r.domain}: ${r.error}`);
    });
    process.exit(1);
  }
}

main().catch(e => {
  console.error('Критическая ошибка:', e);
  process.exit(1);
});
