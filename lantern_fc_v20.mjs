import worker from './lantern_worker_v19.js';

export const handler = async (event, context) => {
  try {
    const evt = JSON.parse(event.toString());
    const path = evt.rawPath || evt?.requestContext?.http?.path || '/';
    const method = evt?.requestContext?.http?.method || 'GET';
    const host = evt?.requestContext?.domainName || 'localhost';

    const req = new Request(`https://${host}${path}`, { method });
    const res = await worker.fetch(req);
    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      if (k.toLowerCase() === 'content-disposition') continue;
      headers[k] = v;
    }

    return {
      statusCode: res.status,
      headers,
      body: await res.text(),
      isBase64Encoded: false
    };
  } catch (e) {
    return {
      statusCode: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
      body: 'Lantern FC v20 ERROR\n' + (e?.message || String(e)),
      isBase64Encoded: false
    };
  }
};
