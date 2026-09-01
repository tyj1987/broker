// broker-test/test-headers.js — debug Headers access
const r = new Response('', { status: 401, headers: { 'www-authenticate': 'Bearer realm="x"' } });
console.log('bracket:', JSON.stringify(r.headers['www-authenticate']));
console.log('get:', JSON.stringify(r.headers.get('www-authenticate')));
console.log('bracket-lower:', JSON.stringify(r.headers['WWW-Authenticate']));
