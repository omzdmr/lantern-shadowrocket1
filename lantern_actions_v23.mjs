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

  // Shadowrocket's Lua share URL does not reliably serialize the DLWServer
  // `user` field. Keep the currently accepted credential payload so password,
  // host and port import normally, and carry the missing user material in the
  // temporary remark. A per-subscription script restores $server.user and then
  // replaces this temporary remark with a clean display name.
  const inner = `${node.user}:${pctPassword(node.password)}@${node.host}:${node.port}`;
  const payload = Buffer.from(inner, 'utf8').toString('base64').replace(/=+$/g, '');
  const repairRemark = `L23|${node.user}`;

  return `lua://${payload}` +
    `?path=${encodeURIComponent(node.path)}` +
    `&remarks=${encodeURIComponent(repairRemark)}` +
    `&allowInsecure=${node.allowInsecure ? 1 : 0}` +
    `&method=${encodeURIComponent(node.method || 'aes-256-cfb')}`;
}

const links = nodes.map(luaShareLink);
const plainSubscription = links.join('\n') + '\n';
const base64Subscription = Buffer.from(plainSubscription, 'utf8').toString('base64') + '\n';

fs.writeFileSync('nodes.json', JSON.stringify(nodes, null, 2) + '\n');
fs.writeFileSync('subscription-v23.txt', plainSubscription);
fs.writeFileSync('subscription-v23.b64', base64Subscription);

console.log(`Generated ${nodes.length} Lantern v23 nodes`);
for (const n of nodes) console.log(`${n.host}:${n.port} ${n.title}`);
console.log('Generated subscription-v23.txt and subscription-v23.b64');
