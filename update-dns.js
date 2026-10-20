// update-dns.js
// Скрипт для обновления IP-адресов в NextDNS через Comss DNS
// + фиксированные IP для Deezer (без запроса к Comss)

const NEXTDNS_API_KEY = process.env.NEXTDNS_API_KEY;
const NEXTDNS_PROFILE_ID = process.env.NEXTDNS_PROFILE_ID;

if (!NEXTDNS_API_KEY || !NEXTDNS_PROFILE_ID) {
  console.error('Ошибка: не заданы переменные окружения NEXTDNS_API_KEY или NEXTDNS_PROFILE_ID');
  process.exit(1);
}

// === Фиксированные IP (не запрашиваем Comss) ===
// NextDNS Rewrites поддерживает только 1 IP на домен,
// поэтому выбираем по одному адресу для каждого домена.
const fixedIps = {
  'deezer.com': '159.194.200.33',
  'www.deezer.com': '159.194.200.33',
  'payment.deezer.com': '159.194.200.33',
};

// === Домены, для которых IP берём у Comss ===
const comssDomains = [
  // ChatGPT / OpenAI
  "chatgpt.com",
  "www.chatgpt.com",
  "chatgpt.site",
  "www.chatgpt.site",
  "ab.chatgpt.com",
  "webrtc.chatgpt.com",
  "ws.chatgpt.com",
  "tcr9i.chat.openai.com",
  "auth.openai.com",
  "auth0.openai.com",
  "platform.openai.com",
  "api.openai.com",
  "cdn.oaistatic.com",
  "cdn.platform.openai.com",
  "files.oaiusercontent.com",
  "oaiusercontent.com",
  "www.oaiusercontent.com",
  "oaistatic.com",
  "www.oaistatic.com",
  "ios.chat.openai.com",
  "android.chat.openai.com",
  "operator.chatgpt.com",
  "videos.openai.com",
  "developers.openai.com",
  "openai.com",
  "www.openai.com",
  "sdmntprukwest.oaiusercontent.com",
  "sdmntpritalynorth.oaiusercontent.com",
  "sdmntprpolandcentral.oaiusercontent.com",
  "sdmntprnortheu.oaiusercontent.com",

  // Claude / Anthropic
  "anthropic.com", "api.anthropic.com", "claude.ai", "claude.com",
  "claudeusercontent.com",

  // Google AI
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
  "auth.xboxlive.com",
  "copilot.microsoft.com",
  "designer.microsoft.com",
  "ecs.office.com",
  "edgeservices.bing.com",
  "gssv-play-prod.xboxlive.com",
  "rewards.bing.com",
  "sydney.bing.com",
  "titlestorage.xboxlive.com",
  "xboxdesignlab.xbox.com",
  "xgpuweb.gssv-play-prod.xboxlive.com",
  "xgpuwebf2p.gssv-play-prod.xboxlive.com",
  "xsts.auth.xboxlive.com"
];

// Объединяем все домены в один список (чтобы обойти за один проход)
const allDomains = [...Object.keys(fixedIps), ...comssDomains];

// === Вспомогательные функции ===

function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function buildDnsQuery(domain) {
  const labels = domain.split('.');
  const parts = [];

  const header = Buffer.alloc(12);
  header.writeUInt16BE(0, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  parts.push(header);

  for (const label of labels) {
    const labelBytes = Buffer.from(label, 'utf8');
    parts.push(Buffer.from([labelBytes.length]));
    parts.push(labelBytes);
  }
  parts.push(Buffer.from([0x00]));

  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0); // A
  qtype.writeUInt16BE(1, 2); // IN
  parts.push(qtype);

  return Buffer.concat(parts);
}

function parseDnsResponse(buffer) {
  try {
    if (buffer.length < 12) return null;

    let offset = 12;

    // QNAME (в секции вопроса указатели обычно не встречаются)
    const qnameEnd = Math.min(offset + 255, buffer.length);
    while (offset < qnameEnd && buffer[offset] !== 0) {
      offset += buffer[offset] + 1;
    }
    offset += 1; // null byte
    offset += 4; // QTYPE + QCLASS

    // Answer Section
    while (offset + 12 <= buffer.length) {
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
      offset += 8; // CLASS(2) + TTL(4) + RDLENGTH(2)

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

async function getComssIp(domain) {
  const query = buildDnsQuery(domain);
  const base64Query = base64UrlEncode(query);
  const url = `https://dns.comss.one/dns-query?dns=${base64Query}`;

  const response = await fetch(url, {
    headers: { 'Accept': 'application/dns-message' },
    signal: AbortSignal.timeout(10_000)
  });

  if (!response.ok) {
    throw new Error(`DoH ошибка: ${response.status}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  const ip = parseDnsResponse(buffer);

  if (!ip) {
    throw new Error('no A record');
  }

  return ip;
}

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
 * Обновляет/создаёт правило в NextDNS.
 * Возвращает статус: 'created' | 'updated' | 'unchanged'.
 */
async function upsertNextDns(domain, newIp) {
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

  // 2. Если IP не изменился — пропускаем
  if (existingRule && existingRule.content === newIp) {
    return 'unchanged';
  }

  // 3. Обновляем существующее правило через PATCH
  if (existingRule) {
    const patchResp = await fetchWithoutOrigin(`${baseUrl}/${existingRule.id}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ content: newIp })
    });
    if (!patchResp.ok) {
      const error = await patchResp.text();
      throw new Error(`Не удалось обновить правило: ${patchResp.status} - ${error}`);
    }
    return 'updated';
  }

  // 4. Создаём новое правило
  const createResp = await fetchWithoutOrigin(baseUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: domain, content: newIp })
  });

  if (!createResp.ok) {
    const error = await createResp.text();
    throw new Error(`Не удалось создать правило: ${createResp.status} - ${error}`);
  }
  return 'created';
}

// === Основная логика ===

async function main() {
  console.log(`Начинаю обновление ${allDomains.length} доменов...`);
  console.log(`  - фиксированных IP (Deezer): ${Object.keys(fixedIps).length}`);
  console.log(`  - через Comss: ${comssDomains.length}`);
  console.log(`Время запуска: ${new Date().toISOString()}`);

  const results = [];

  for (const domain of allDomains) {
    try {
      console.log(`Обработка: ${domain}`);

      let newIp;
      if (fixedIps[domain]) {
        newIp = fixedIps[domain];
        console.log(`  Фиксированный IP: ${newIp}`);
      } else {
        newIp = await getComssIp(domain);
        console.log(`  Comss вернул IP: ${newIp}`);
      }

      const status = await upsertNextDns(domain, newIp);
      if (status === 'unchanged') {
        console.log(`  Без изменений (уже ${newIp})`);
      } else {
        console.log(`  ${status === 'created' ? 'Создано' : 'Обновлено'} в NextDNS`);
      }

      results.push({ domain, status, ip: newIp });

      // Пауза только для запросов к Comss (фиксированные IP не нагружают внешний API)
      if (!fixedIps[domain]) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }

    } catch (e) {
      const msg = e.message || String(e);
      // "no A record" — не критично, помечаем как skipped
      const isNoRecord = /no A record/i.test(msg);
      const status = isNoRecord ? 'skipped' : 'error';
      console.error(`  ${isNoRecord ? 'Пропущено' : 'Ошибка'}: ${msg}`);
      results.push({ domain, status, error: msg });
    }
  }

  // === Итоги ===
  const created   = results.filter(r => r.status === 'created').length;
  const updated   = results.filter(r => r.status === 'updated').length;
  const unchanged = results.filter(r => r.status === 'unchanged').length;
  const skipped   = results.filter(r => r.status === 'skipped').length;
  const errors    = results.filter(r => r.status === 'error').length;

  console.log('\n=== ИТОГИ ===');
  console.log(`Создано:        ${created}`);
  console.log(`Обновлено:      ${updated}`);
  console.log(`Без изменений:  ${unchanged}`);
  console.log(`Пропущено:      ${skipped}`);
  console.log(`Ошибок:         ${errors}`);

  if (skipped > 0) {
    console.log('\nПропущенные домены (нет A-записи):');
    results.filter(r => r.status === 'skipped').forEach(r => {
      console.log(`  ${r.domain}`);
    });
  }

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
