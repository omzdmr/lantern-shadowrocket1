// Lantern v25 Shadowrocket subscription repair + native mux probe.
// Paste into the subscription's Filter/Script field.
// The v23/v25 subscription carries the missing Lua `user` material in title as:
// L23|<sni>|<sessionTicketBase64>

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

// Restore the custom Lua backend material that Shadowrocket's Lua share-link
// importer otherwise drops.
$server.user = packedUser;

// Important v25 experiment: set Shadowrocket's internal mux property through
// the subscription filter. The URI-level mux=1 parameter was ignored in prior
// tests, so this deliberately exercises the internal server object instead.
$server.mux = 1;

$server.title = 'Lantern Auto v25 ' + sni;
return true;
