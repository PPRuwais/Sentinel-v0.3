
import { createOSVService } from './lib/osv.mjs';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { AIError, createAIService } from './lib/ai.mjs';

const isRender = process.env.RENDER === 'true';
const publicApiToken = process.env.SENTINEL_API_TOKEN || '';

const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/application-ui.js', ['application-ui.js', 'text/javascript; charset=utf-8']],
  ['/application-core.mjs', ['application-core.mjs', 'text/javascript; charset=utf-8']],
  ['/ai-ui.js', ['ai-ui.js', 'text/javascript; charset=utf-8']],
  ['/sentinel.mjs', ['sentinel.mjs', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);

const send = (res, status, data) => {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(data));
};

function secureTokenEquals(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function checkRequest(req, port) {
  const path = (req.url || '/').split('?')[0];
  const apiPath = path.startsWith('/api/');

  // Local development: allow only the local Sentinel origin.
  if (!isRender) {
    const allowedHosts = new Set([
      `localhost:${port}`,
      `127.0.0.1:${port}`,
    ]);

    if (!allowedHosts.has(req.headers.host)) {
      throw new AIError('Use the local Sentinel address shown in the terminal.', 403, 'invalid_host');
    }

    const origin = req.headers.origin;
    if (origin && origin !== `http://${req.headers.host}`) {
      throw new AIError('Cross-origin requests are not allowed.', 403, 'invalid_origin');
    }

    if (req.headers['sec-fetch-site'] === 'cross-site') {
      throw new AIError('Cross-site requests are not allowed.', 403, 'invalid_origin');
    }

    if (
      req.method === 'POST' &&
      (!origin || !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || ''))
    ) {
      throw new AIError('Requests must use same-origin JSON.', 403, 'invalid_origin');
    }

    return;
  }

  // Public deployment: APIs stay disabled unless a token is configured.
  // The public dashboard can still load, but its privileged APIs are protected.
  if (apiPath) {
    if (!publicApiToken) {
      throw new AIError(
        'API access is disabled on this public deployment.',
        503,
        'public_api_disabled',
      );
    }

    const suppliedToken = req.headers['x-sentinel-token'];
    if (
      typeof suppliedToken !== 'string' ||
      !secureTokenEquals(suppliedToken, publicApiToken)
    ) {
      throw new AIError('API authentication required.', 401, 'unauthorized');
    }

    const origin = req.headers.origin;
    if (origin) {
      let originUrl;
      try {
        originUrl = new URL(origin);
      } catch {
        throw new AIError('Invalid request origin.', 403, 'invalid_origin');
      }

      const requestHost = String(req.headers.host || '').toLowerCase();
      if (
        originUrl.host.toLowerCase() !== requestHost ||
        !['https:', 'http:'].includes(originUrl.protocol)
      ) {
        throw new AIError('Cross-origin requests are not allowed.', 403, 'invalid_origin');
      }
    }

    if (
      req.method === 'POST' &&
      !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')
    ) {
      throw new AIError('Requests must use JSON.', 415, 'invalid_content_type');
    }
  }
}

async function readJSON(req) {
  const maxBytes = 40000;
  const declaredLength = Number(req.headers['content-length'] || 0);

  if (declaredLength > maxBytes) {
    throw new AIError('Request is too large.', 413, 'payload_too_large');
  }

  let size = 0;
  const chunks = [];

  for await (const chunk of req) {
    size += chunk.length;

    if (size > maxBytes) {
      throw new AIError('Request is too large.', 413, 'payload_too_large');
    }

    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new AIError('Request body is not valid JSON.');
  }
}

export function createHandler({
  port = 3000,
  ai = createAIService(),
  osv = createOSVService(),
} = {}) {
  let aiBusy = false;
  let osvBusy = false;

  return async (req, res) => {
    try {
      checkRequest(req, port);

      const path = (req.url || '/').split('?')[0];

      if (path === '/health' && req.method === 'GET') {
        send(res, 200, {
          status: 'ok',
          mode: isRender ? 'public-demo' : 'local',
        });
        return;
      }

      if (path === '/api/ai/status' && req.method === 'GET') {
        send(res, 200, await ai.status());
        return;
      }

      if (path === '/api/dependencies/check' && req.method === 'POST') {
        if (osvBusy) {
          throw new AIError(
            'Another dependency lookup is running. Wait for it to finish.',
            429,
            'lookup_busy',
          );
        }

        osvBusy = true;
        try {
          send(res, 200, await osv.lookup(await readJSON(req)));
        } finally {
          osvBusy = false;
        }
        return;
      }

      if (
        ['/api/ai/analyze', '/api/ai/application'].includes(path) &&
        req.method === 'POST'
      ) {
        if (aiBusy) {
          throw new AIError(
            'Another AI review is running. Wait for it to finish.',
            429,
            'model_busy',
          );
        }

        aiBusy = true;
        try {
          const input = await readJSON(req);
          const result = path === '/api/ai/application'
            ? await ai.review(input)
            : await ai.analyze(input);

          send(res, 200, result);
        } finally {
          aiBusy = false;
        }
        return;
      }

      if (!['GET', 'HEAD'].includes(req.method)) {
        res.writeHead(405, { Allow: 'GET, HEAD' });
        res.end('Method not allowed');
        return;
      }

      const asset = assets.get(path);
      if (!asset) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const bytes = await readFile(
        new URL(`./dist/${asset[0]}`, import.meta.url),
      );

      res.writeHead(200, {
        'Content-Type': asset[1],
        'Content-Length': bytes.length,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      });

      res.end(req.method === 'HEAD' ? undefined : bytes);
    } catch (error) {
      if (res.destroyed || res.writableEnded) return;

      send(
        res,
        error instanceof AIError ? error.status : 500,
        {
          error: error instanceof AIError
            ? error.message
            : 'Could not complete the request. Check the server logs.',
          code: error instanceof AIError
            ? error.code
            : 'internal_error',
        },
      );
    }
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const port = Number(process.env.PORT || 3000);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('PORT must be an integer between 1 and 65535.');
    process.exit(1);
  }

  const host = isRender ? '0.0.0.0' : '127.0.0.1';
  const server = http.createServer(createHandler({ port }));

  server.requestTimeout = 300000;

  server.on('error', (error) => {
    console.error(
      error.code === 'EADDRINUSE'
        ? `Port ${port} is already in use. Stop the old Sentinel server, then retry.`
        : `Could not start Sentinel: ${error.message}`,
    );
    process.exitCode = 1;
  });

  server.listen(port, host, () => {
    console.log(`Sentinel server listening on ${host}:${port}`);

    if (isRender) {
      console.log('Public demo mode: privileged APIs are disabled unless SENTINEL_API_TOKEN is configured.');
      console.log('Local Ollama is not automatically available on Render.');
    } else {
      console.log(`Open Sentinel at http://localhost:${port}`);
      console.log('Optional local AI: install Ollama and pull qwen2.5-coder:3b.');
      console.log('Keep this terminal open. Press Ctrl+C to stop.');
    }
  });
}
