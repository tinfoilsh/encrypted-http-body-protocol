// Browser conformance runner. Batch adapter: reads fixtures as JSONL on stdin,
// runs each in a real browser page via Playwright, writes results as JSONL.
//
//   node runner.mjs --browser=chromium < fixtures.jsonl
//
// The page (page.html) holds the operation dispatch; this driver only serves the
// page + browser bundle over http and shuttles fixtures in and results out.

import http from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, firefox } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const engine = (process.argv.find((a) => a.startsWith('--browser=')) || '').split('=')[1] || 'chromium';
const oracle = process.env.ORACLE_URL || '';

const pageHtml = readFileSync(join(here, 'page.html'));
const bundle = readFileSync(join(here, '../../../js/dist/browser.js'));

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.setHeader('Content-Type', 'text/html'); res.end(pageHtml);
  } else if (req.url.startsWith('/browser.js')) {
    res.setHeader('Content-Type', 'text/javascript'); res.end(bundle);
  } else {
    res.statusCode = 404; res.end();
  }
});

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function main() {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const pageUrl = `http://127.0.0.1:${server.address().port}/`;

  const browser = await (engine === 'firefox' ? firefox : chromium).launch();
  const page = await browser.newPage();
  await page.goto(pageUrl);
  await page.waitForFunction('window.__ready === true');

  const input = await readStdin();
  const out = [];
  for (const line of input.split('\n')) {
    if (!line.trim()) continue;
    const fx = JSON.parse(line);
    let res;
    try {
      res = await page.evaluate(({ fx, oracle }) => window.runFixture(fx, oracle), { fx, oracle });
    } catch (err) {
      res = { fixture_id: fx.id, outcome: 'error', error_code: 'ADAPTER_CRASH',
              native_error: String(err) };
    }
    res.runner = `js-browser:${engine}`;
    out.push(JSON.stringify(res));
  }
  process.stdout.write(out.join('\n') + '\n');

  await browser.close();
  server.close();
}

main().catch((err) => { console.error(err); process.exit(2); });
