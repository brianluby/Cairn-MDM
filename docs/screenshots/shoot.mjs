// Signs in to a local demo server with headless Chrome (DevTools protocol, no
// packages to install) and saves one PNG per page. See README.md here.
//
//   DEMO_PW=... node shoot.mjs <outdir> name=/path ['name=/path#From..To' ...]
//
// "#From..To" keeps only the part of the page between two headings.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const base = 'http://127.0.0.1:8459';
const out = process.argv[2];
const pages = process.argv.slice(3).map(a => a.split('='));
const scheme = process.env.SCHEME || 'light';
const width = +(process.env.WIDTH || 1280), height = +(process.env.HEIGHT || 800);
const port = 9333;

const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
  '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'cairn-shots-'))}`,
  '--no-first-run', '--hide-scrollbars', 'about:blank',
], { stdio: 'ignore' });

const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === 'page'); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let seq = 0; const waiting = new Map(); const listeners = [];
ws.addEventListener('message', m => {
  const d = JSON.parse(m.data);
  if (d.id && waiting.has(d.id)) { waiting.get(d.id)(d); waiting.delete(d.id); }
  else listeners.forEach(l => l(d));
});
const send = (method, params = {}) => new Promise(r => { const id = ++seq; waiting.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
const loaded = () => new Promise(r => { const l = d => { if (d.method === 'Page.loadEventFired') { listeners.splice(listeners.indexOf(l), 1); r(); } }; listeners.push(l); });
const go = async url => { const p = loaded(); await send('Page.navigate', { url }); await p; await sleep(300); };
const evaluate = async expression => (await send('Runtime.evaluate', { expression, returnByValue: true })).result?.result?.value;

await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: false });
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });

await go(base + '/login');
if (pages.some(([n]) => n === 'login')) {
  const { data } = (await send('Page.captureScreenshot', { format: 'png' })).result;
  writeFileSync(join(out, 'login.png'), Buffer.from(data, 'base64'));
}
const p = loaded();
await evaluate(`document.getElementById('username').value='admin';document.getElementById('password').value=${JSON.stringify(process.env.DEMO_PW)};document.querySelector('form').submit()`);
await p; await sleep(300);
console.log('after login:', await evaluate('location.pathname'));

for (const [name, spec] of pages) {
  if (name === 'login') continue;
  // path#From..To clips between the headings with that text (To may be empty).
  const [path, range] = spec.split('#');
  await go(base + path);
  let y = 0, h = Math.min(await evaluate('document.documentElement.scrollHeight'), +(process.env.MAXH || 1500));
  if (range) {
    const [from, to] = range.split('..').map(decodeURIComponent);
    const top = t => evaluate(`(()=>{const e=[...document.querySelectorAll('h1,h2')].find(e=>e.textContent.trim()===${JSON.stringify(t)});return e?e.getBoundingClientRect().top+scrollY:-1})()`);
    const end = to ? await top(to) - 28 : h;
    y = from ? Math.max(0, await top(from) - 28) : 0;
    h = end - y;
  } else h = Math.max(h, height);
  const { data } = (await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y, width, height: h, scale: 1 } })).result;
  writeFileSync(join(out, name + '.png'), Buffer.from(data, 'base64'));
  console.log(name, await evaluate('document.title'), y, h);
}
ws.close(); chrome.kill();
