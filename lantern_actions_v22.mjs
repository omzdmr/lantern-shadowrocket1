import fs from 'node:fs';
import worker from './lantern_worker_v19.js';

const response = await worker.fetch(new Request('https://lantern.local/nodes.json'));
const body = await response.text();
if (!response.ok) {
  console.error(body);
  process.exit(1);
}

const nodes = JSON.parse(body);
if (!Array.isArray(nodes) || nodes.length === 0) {
  throw new Error('Lantern node listesi bos');
}

function pctPassword(s) {
  // Match Shadowrocket's Lua exporter closely enough for the credential payload.
  // The outer payload is base64, so only characters that can confuse its inner
  // userinfo parser need escaping here.
  return String(s)
    .replace(/%/g, '%25')
    .replace(/\//g, '%2F')
    .replace(/@/g, '%40')
    .replace(/:/g, '%3A');
}

function luaShareLink(node, index) {
  if (!node.user || !node.password || !node.host || !node.port || !node.path) {
    throw new Error(`Eksik Lua node alani index=${index}`);
  }

  // Shadowrocket's Lua share-link payload is a base64-wrapped
  // user:password@host:port string. Its own exporter currently duplicates the
  // password into the user slot for our custom node, so we generate the link
  // ourselves and preserve the real settings.user required by the Lantern Lua
  // backend.
  const inner = `${node.user}:${pctPassword(node.password)}@${node.host}:${node.port}`;
  const payload = Buffer.from(inner, 'utf8').toString('base64').replace(/=+$/g, '');
  const title = `Lantern Auto v22 ${String(node.title || '').replace(/^Lantern Auto v19\s*/, '') || `Node ${index}`}`;

  return `lua://${payload}` +
    `?path=${encodeURIComponent(node.path)}` +
    `&remarks=${encodeURIComponent(title)}` +
    `&allowInsecure=${node.allowInsecure ? 1 : 0}` +
    `&method=${encodeURIComponent(node.method || 'aes-256-cfb')}`;
}

const links = nodes.map(luaShareLink);
const plainSubscription = links.join('\n') + '\n';
const base64Subscription = Buffer.from(plainSubscription, 'utf8').toString('base64') + '\n';

fs.writeFileSync('nodes.json', JSON.stringify(nodes, null, 2) + '\n');
fs.writeFileSync('subscription.txt', plainSubscription);
fs.writeFileSync('subscription.b64', base64Subscription);

console.log(`Generated ${nodes.length} Lantern nodes`);
for (const n of nodes) console.log(`${n.host}:${n.port} ${n.title}`);
console.log('Generated subscription.txt and subscription.b64');
