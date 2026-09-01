// broker-test/test-docker-debug.js — debug docker test
const mockFetch = async (url) => {
  console.log('mockFetch called with:', url);
  if (url.endsWith('/v2/')) {
    return new Response('', {
      status: 401,
      headers: { 'www-authenticate': 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"' },
    });
  }
  return new Response('', { status: 404 });
};

import('../broker/signing/docker-registry.js').then(async ({ getDockerRegistryToken }) => {
  try {
    const tok = await getDockerRegistryToken({ registry: 'https://registry-1.docker.io', fetchImpl: mockFetch });
    console.log('OK token:', tok);
  } catch (e) {
    console.log('FAIL:', e.message);
    console.log('stack:', e.stack);
  }
});
