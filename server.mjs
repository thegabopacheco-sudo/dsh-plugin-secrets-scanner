#!/usr/bin/env node
// dsh-plugin-secrets-scanner — escanea secretos en un proyecto local.
// Tools: status, patterns, scan.

import path from 'node:path';
import os from 'node:os';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const VERSION = '0.1.0';
const DSH_HOME = (() => {
  const v = process.env.DSH_HOME && process.env.DSH_HOME.trim();
  return v || path.join(process.env.USERPROFILE || process.env.HOME || os.homedir(), '.dsh');
})();
const CONFIG_FILE = path.join(DSH_HOME, 'secrets-scanner', 'config.json');
const CACHE_DIR = path.join(DSH_HOME, 'cache', 'secrets-scanner');
const MAX_FILES = 5000;
const MAX_FILE_BYTES = 300 * 1024;
const MAX_DEPTH = 8;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.venv', 'venv', '__pycache__', '.cache', 'target', 'coverage', '.idea', '.vscode', 'vendor', 'bin', 'obj']);
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.md', '.txt', '.env', '.sh', '.ps1', '.bat', '.py', '.rb', '.go', '.rs', '.java', '.php', '.cs', '.sql', '.xml', '.properties', '.gitignore', '.npmrc', '.pypirc']);
const PATTERNS = [
  { id: 'aws-key', label: 'AWS Access Key', severity: 'high', regex: /AKIA[0-9A-Z]{16}/ },
  { id: 'github-token', label: 'GitHub token', severity: 'high', regex: /gh[pousr]_[A-Za-z0-9_]{20,}/ },
  { id: 'openai-key', label: 'API key (sk-)', severity: 'high', regex: /sk-[A-Za-z0-9]{20,}/ },
  { id: 'private-key', label: 'Private key', severity: 'high', regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { id: 'jwt', label: 'JWT', severity: 'medium', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: 'assignment', label: 'Asignación de secreto', severity: 'medium', regex: /(api[_-]?key|secret|token|passwd|password|bearer)\s*[:=]\s*['"]?[A-Za-z0-9_\-/.]{8,}/i },
  { id: 'env-secret', label: 'Variable .env sensible', severity: 'medium', regex: /^(?:export\s+)?(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)\s*=\s*\S{6,}/im },
];
const log = (m) => process.stderr.write(`[secrets] ${m}\n`);

function loadConfig() {
  try { if (existsSync(CONFIG_FILE)) return { allowedPaths: [], ...(JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) || {}) }; } catch { /* defaults */ }
  return { allowedPaths: [] };
}
function allowedRoots() { const configured = loadConfig().allowedPaths; return (Array.isArray(configured) && configured.length ? configured : [process.env.USERPROFILE || process.env.HOME || os.homedir()]).map((item) => path.resolve(item)); }
function isAllowed(target) { const resolved = path.resolve(target); return allowedRoots().some((root) => resolved === root || resolved.startsWith(root + path.sep)); }
function mask(secret) { const text = String(secret); if (text.length <= 6) return '***'; return `${text.slice(0, 4)}***${text.slice(-2)}`; }

function scanProject(rootInner) {
  const root = path.resolve(rootInner);
  if (!existsSync(root)) throw new Error(`la ruta no existe: ${root}`);
  if (!statSync(root).isDirectory()) throw new Error(`no es un directorio: ${root}`);
  if (!isAllowed(root)) throw new Error(`ruta no permitida: ${root} (revisa allowedPaths)`);
  const findings = [];
  let files = 0;
  const walk = (dir, depth) => {
    if (depth > MAX_DEPTH || files >= MAX_FILES) return;
    let entries = [];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (files >= MAX_FILES) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) walk(full, depth + 1); continue; }
      const ext = path.extname(entry.name).toLowerCase();
      const isDotEnv = /^\.env/.test(entry.name) || entry.name === '.npmrc' || entry.name === '.pypirc';
      if (!TEXT_EXTENSIONS.has(ext) && !isDotEnv) continue;
      let stat = null;
      try { stat = statSync(full); } catch { continue; }
      if (stat.size > MAX_FILE_BYTES) continue;
      let text = '';
      try { text = readFileSync(full, 'utf8'); } catch { continue; }
      files++;
      const lines = text.split('\n');
      for (let index = 0; index < lines.length; index++) {
        for (const pattern of PATTERNS) {
          const match = lines[index].match(pattern.regex);
          if (!match) continue;
          findings.push({ file: path.relative(root, full), line: index + 1, rule: pattern.id, label: pattern.label, severity: pattern.severity, preview: mask(match[0]) });
        }
      }
    }
  };
  walk(root, 1);
  return { root, files, findings };
}
function textResult(text) { return { content: [{ type: 'text', text }] }; }

function buildInstructions() {
  return [
    'Secrets Scanner: busca credenciales en un proyecto local.',
    '',
    'Herramientas: status, patterns, scan.',
    '',
    'Reglas:',
    '- Solo lectura: nunca muestra el secreto completo, solo una vista enmascarada.',
    '- Respeta allowedPaths y omite node_modules/.git/build.',
    '- Reporta hallazgos reales con archivo y línea; no inventes.',
    '- No copia secretos a logs ni a la salida.',
  ].join('\n');
}

function buildServer() {
  const server = new McpServer({ name: 'dsh-plugin-secrets-scanner', version: VERSION }, { capabilities: { tools: {} }, instructions: buildInstructions() });

  server.registerTool(
    'status',
    { title: 'Estado', description: 'Rutas permitidas, reglas y límites.', inputSchema: z.object({}) },
    async () => textResult([`Rutas permitidas: ${allowedRoots().join(', ')}`, `Reglas: ${PATTERNS.length}`, `Límites: ${MAX_FILES} archivos · ${MAX_FILE_BYTES / 1024} KB/archivo · profundidad ${MAX_DEPTH}`, 'Modo: solo lectura'].join('\n')),
  );

  server.registerTool(
    'patterns',
    { title: 'Patrones', description: 'Lista las reglas de detección.', inputSchema: z.object({}) },
    async () => textResult(PATTERNS.map((pattern) => `- [${pattern.severity}] ${pattern.id}: ${pattern.label}`).join('\n')),
  );

  server.registerTool(
    'scan',
    { title: 'Escanear secretos', description: 'Escanea un proyecto (o la primera ruta permitida) y devuelve hallazgos enmascarados.', inputSchema: z.object({ path: z.string().min(2).optional(), severity: z.enum(['high', 'medium']).optional(), limit: z.number().int().min(1).max(200).optional() }) },
    async (args) => {
      const result = scanProject(args.path || allowedRoots()[0]);
      let findings = result.findings;
      if (args.severity) findings = findings.filter((finding) => finding.severity === args.severity);
      findings = findings.slice(0, args.limit ?? 100);
      if (findings.length === 0) return textResult(`Sin secretos detectados en ${result.files} archivos de ${result.root}.`);
      const high = findings.filter((finding) => finding.severity === 'high').length;
      return textResult([
        `Hallazgos: ${findings.length} (high: ${high}) · archivos escaneados: ${result.files}`,
        '',
        ...findings.map((finding) => `${finding.severity === 'high' ? '🔴' : '🟠'} [${finding.rule}] ${finding.file}:${finding.line} · ${finding.label} · ${finding.preview}`),
      ].join('\n'));
    },
  );

  return server;
}

try { mkdirSync(CACHE_DIR, { recursive: true }); } catch { /* ignora */ }
log('scanner listo');
serveStdio(buildServer, { onerror: (e) => log(`serveStdio: ${e.message}`) });
process.on('uncaughtException', (e) => log(`excepción: ${e.message}`));
process.on('unhandledRejection', (e) => log(`rechazo: ${e && e.message ? e.message : String(e)}`));
