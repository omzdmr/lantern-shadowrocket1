// Lantern v23 Shadowrocket subscription repair script.
// Paste this into: Subscription -> Edit -> Script
// The v23 subscription temporarily stores the Lua backend's missing `user`
// material in the node title as: L23|<sni>|<ticketBase64>.
// Shadowrocket's subscription script runs once per imported node. Restore the
// real DLWServer user field, then replace the temporary carrier title.

const PREFIX = 'L23|';

if (!$server || typeof $server.title !== 'string') {
  return true;
}

if (!$server.title.startsWith(PREFIX)) {
  return true;
}

const packedUser = $server.title.slice(PREFIX.length);
const sep = packedUser.indexOf('|');
if (sep <= 0 || sep === packedUser.length - 1) {
  return false;
}

const sni = packedUser.slice(0, sep);
$server.user = packedUser;
$server.title = `Lantern Auto v23 ${sni}`;
return true;
