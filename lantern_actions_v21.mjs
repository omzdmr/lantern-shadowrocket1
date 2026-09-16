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

fs.writeFileSync('nodes.json', JSON.stringify(nodes, null, 2) + '\n');
console.log(`Generated ${nodes.length} Lantern nodes`);
for (const n of nodes) console.log(`${n.host}:${n.port} ${n.title}`);
