// Test end-to-end de secrets-scanner.
import path from 'node:path';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const packageDir = path.resolve(import.meta.dirname, '..');
const tmpDir = path.join(packageDir, 'test', 'tmp');
rmSync(tmpDir, { recursive: true, force: true });
const home = path.join(tmpDir, 'dsh-home');
const project = path.join(tmpDir, 'proj');
mkdirSync(path.join(home, 'secrets-scanner'), { recursive: true });
mkdirSync(path.join(project, 'src'), { recursive: true });
mkdirSync(path.join(project, 'node_modules', 'lib'), { recursive: true });
writeFileSync(path.join(home, 'secrets-scanner', 'config.json'), JSON.stringify({ allowedPaths: [project] }), 'utf8');
writeFileSync(path.join(project, 'src', 'config.js'), 'const api_key = "sk-abcdefghijklmnopqrstuvwxyz123456";\nconsole.log("ok");\n', 'utf8');
writeFileSync(path.join(project, '.env'), 'PASSWORD=supersecreto123\nPORT=3000\n', 'utf8');
writeFileSync(path.join(project, 'src', 'clean.js'), 'const saludo = "hola";\n', 'utf8');
writeFileSync(path.join(project, 'node_modules', 'lib', 'x.js'), 'const token = "ghp_abcdefghijklmnopqrstuvwxyz0123";\n', 'utf8');

function makeClient() {
  const entry = process.env.SECRETS_SERVER ? path.resolve(process.env.SECRETS_SERVER) : path.join(packageDir, 'server.mjs');
  const transport = new StdioClientTransport({ command: process.execPath, args: [entry], env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows', PATH: process.env.PATH, USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME || process.env.USERPROFILE, TEMP: process.env.TEMP, TMP: process.env.TMP, DSH_HOME: home }, stderr: 'pipe' });
  transport.stderr?.on('data', (c) => process.stderr.write(`[server] ${c}`));
  const client = new Client({ name: 'secrets-test', version: '1.0.0' }, { capabilities: {}, versionNegotiation: { mode: 'auto' } });
  return client.connect(transport).then(() => ({ client, transport }));
}
const textOf = (r) => (r.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n');

const { client, transport } = await makeClient();
console.log('tools:', (await client.listTools()).tools.map((t) => t.name).join(', '));
console.log('--- status ---'); console.log(textOf(await client.callTool({ name: 'status', arguments: {} })));
console.log('--- patterns ---'); console.log(textOf(await client.callTool({ name: 'patterns', arguments: {} })));
const scan = textOf(await client.callTool({ name: 'scan', arguments: {} }));
console.log('--- scan ---'); console.log(scan);
console.log('detecta api key y password:', scan.includes('openai-key') && scan.includes('env-secret'));
console.log('no escanea node_modules:', !scan.includes('node_modules'));
console.log('enmascara secreto:', scan.includes('sk-a***') && !scan.includes('sk-abcdefghijklmnopqrstuvwxyz123456'));
const high = textOf(await client.callTool({ name: 'scan', arguments: { severity: 'high' } }));
console.log('filtra high:', high.includes('openai-key') && !high.includes('env-secret'));
const outside = await client.callTool({ name: 'scan', arguments: { path: 'C:\\Windows' } });
console.log('ruta fuera isError:', outside.isError === true);
const empty = textOf(await client.callTool({ name: 'scan', arguments: { path: path.join(project, 'src', 'clean.js') } }));
console.log('archivo no dir isError:', empty.includes('no es un directorio') || empty.includes('Error'));
await client.close(); try { await transport.close?.(); } catch {}
console.log('OK');
