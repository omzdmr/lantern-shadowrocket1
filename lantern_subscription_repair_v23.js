// Lantern v23 Shadowrocket subscription repair script.
// Paste into: Subscription -> Edit -> Script
// The v23 subscription temporarily stores the missing Lua `user` material in
// the node title as: L23|<sni>|<sessionTicketBase64>.

var PREFIX = 'L23|';

if (!$server || typeof $server.title !== 'string') {
  return true;
}

if ($server.title.indexOf(PREFIX) !== 0) {
  return true;
}

var packedUser = $server.title.substring(PREFIX.length);
var sep = packedUser.indexOf('|');
if (sep <= 0 || sep === packedUser.length - 1) {
  return false;
}

var sni = packedUser.substring(0, sep);
$server.user = packedUser;
$server.title = 'Lantern Auto v23 ' + sni;
return true;
