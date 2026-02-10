#!/usr/bin/env node
'use strict';

/**
 * Simple pipeline runner.
 * - Executes skills from pipeline.json in order.
 * - Collects JSONL records from stdout.
 * - Sends records to Faraday when configured.
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { loadEnv } = require('../lib/load-env');
const { ingestRecord, buildPayload } = require('../lib/faraday');
const { normalizeRecord } = require('../lib/schema');
const { loadScopeFile, targetInScope } = require('../lib/scope');

loadEnv();

function parseArgs(argv) {
  const args = { targets: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key === '--pipeline' && val) {
      args.pipeline = val;
      i += 1;
      continue;
    }
    if (key === '--target' && val) {
      args.targets.push(val);
      i += 1;
      continue;
    }
    if (key === '--out-dir' && val) {
      args.outDir = val;
      i += 1;
      continue;
    }
    if (key === '--scope-file' && val) {
      args.scopeFile = val;
      i += 1;
      continue;
    }
    if (key === '--rate' && val) {
      args.rate = val;
      i += 1;
      continue;
    }
    if (key === '--timeout' && val) {
      args.timeout = val;
      i += 1;
      continue;
    }
    if (key === '--max-targets' && val) {
      args.maxTargets = val;
      i += 1;
      continue;
    }
    if (key === '--allow-exploit') {
      args.allowExploit = true;
      continue;
    }
    if (key === '--allow-vuln') {
      args.allowVuln = true;
      continue;
    }
    if (key === '--confirm' && val) {
      args.confirm = val;
      i += 1;
      continue;
    }
    if (key === '--stage' && val) {
      args.stage = val;
      i += 1;
      continue;
    }
    if (key === '--workspace' && val) {
      args.workspace = val;
      i += 1;
      continue;
    }
    if (key === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (key === '--strict') {
      args.strict = true;
      continue;
    }
  }
  return args;
}

function detectRunner(skillPath) {
  if (skillPath.endsWith('.js')) return { kind: 'node', path: skillPath };
  if (skillPath.endsWith('.py')) return { kind: 'python', path: skillPath };
  if (skillPath.endsWith('.sh')) return { kind: 'shell', path: skillPath };
  return { kind: 'raw', path: skillPath };
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function nowStamp() {
  // Filesystem-safe UTC timestamp: 20260209T072812Z
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  const mm = pad(d.getUTCMonth() + 1);
  const dd = pad(d.getUTCDate());
  const hh = pad(d.getUTCHours());
  const mi = pad(d.getUTCMinutes());
  const ss = pad(d.getUTCSeconds());
  return `${yyyy}${mm}${dd}T${hh}${mi}${ss}Z`;
}

function readJsonlLines(chunk, buffer) {
  const data = buffer + chunk;
  const lines = data.split('\n');
  const rest = lines.pop() || '';
  return { lines: lines.filter((l) => l.trim().length > 0), rest };
}

function safeJsonParse(line) {
  try {
    return { ok: true, value: JSON.parse(line) };
  } catch (_err) {
    return { ok: false, value: null };
  }
}

async function runNodeSkillInProcess(skillPath, target, opts) {
  const abs = path.resolve(skillPath);
  // eslint-disable-next-line global-require, import/no-dynamic-require
  const mod = require(abs);
  const run = mod && mod.run;
  if (typeof run !== 'function') {
    process.stderr.write(`[runner] node skill has no exported run(): ${skillPath}\n`);
    return { ok: false, code: 1, emitted: 0, parseErrors: 0, stderr: 'missing_run' };
  }

  let emitted = 0;
  function emitRecord(raw) {
    const normalized = normalizeRecord(raw, {
      stage: opts.stage || 'unknown',
      tool: opts.tool || opts.sourceFallback || skillPath,
      target
    });
    const record = buildPayload({
      ...normalized,
      source: normalized.source || opts.sourceFallback || skillPath,
      workspace: normalized.workspace || opts.workspace
    });

    emitted += 1;
    process.stdout.write(`${JSON.stringify(record)}\n`);
    if (opts.recordsStream) opts.recordsStream.write(`${JSON.stringify(record)}\n`);
    if (typeof opts.onRecord === 'function') opts.onRecord(record);
    if (!opts.dryRun) void ingestRecord(record);
  }

  try {
    const runPromise = Promise.resolve(run({
      target,
      emit: emitRecord,
      outDir: opts.outDir,
      scopeFile: opts.scopeFile,
      rate: opts.rate,
      timeout: opts.timeout,
      allowExploit: opts.allowExploit,
      runTs: opts.runTs
    }));

    const t = Number(opts.timeout || process.env.TIMEOUT || 0);
    if (Number.isFinite(t) && t > 0) {
      await Promise.race([
        runPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error(`runner-timeout: ${t}s`)), t * 1000))
      ]);
    } else {
      await runPromise;
    }

    return { ok: true, code: 0, emitted, parseErrors: 0, stderr: '' };
  } catch (err) {
    const msg = err && err.stack ? err.stack : String(err);
    process.stderr.write(`[runner] node skill failed: ${skillPath}: ${msg}\n`);

    if (String(msg).includes('runner-timeout:')) {
      const t = Number(opts.timeout || process.env.TIMEOUT || 0);
      const record = buildPayload({
        type: 'note',
        tool: 'runner-timeout',
        stage: opts.stage || 'unknown',
        target,
        severity: 'info',
        evidence: [],
        data: { timed_out: true, timeout_sec: t, kind: 'node_in_process' },
        source: 'src/bin/run-pipeline.js',
        workspace: opts.workspace
      });
      process.stdout.write(`${JSON.stringify(record)}\n`);
      if (opts.recordsStream) opts.recordsStream.write(`${JSON.stringify(record)}\n`);
      if (!opts.dryRun) void ingestRecord(record);
    }

    return { ok: false, code: 1, emitted, parseErrors: 0, stderr: msg };
  }
}

async function runSkillOnce(skillPath, target, opts) {
  const runner = detectRunner(skillPath);

  if (runner.kind === 'node') {
    return runNodeSkillInProcess(skillPath, target, opts);
  }

  let cmd = '';
  let argv = [];
  if (runner.kind === 'python') {
    cmd = 'python3';
    argv = [runner.path, '--target', target];
  } else if (runner.kind === 'shell') {
    cmd = 'bash';
    argv = [runner.path, '--target', target];
  } else {
    cmd = runner.path;
    argv = ['--target', target];
  }

  if (opts.outDir) argv.push('--out-dir', String(opts.outDir));
  if (opts.scopeFile) argv.push('--scope-file', String(opts.scopeFile));
  if (opts.rate) argv.push('--rate', String(opts.rate));
  if (opts.timeout) argv.push('--timeout', String(opts.timeout));
  if (opts.allowExploit) argv.push('--allow-exploit');

  const child = spawn(cmd, argv, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      RUN_TS: opts.runTs || process.env.RUN_TS || '',
      OUT_DIR: opts.outDir || process.env.OUT_DIR || '',
      SCOPE_FILE: opts.scopeFile || process.env.SCOPE_FILE || '',
      CONFIRM: opts.confirm || process.env.CONFIRM || '',
      ALLOW_VULN: opts.allowVuln ? '1' : (process.env.ALLOW_VULN || '')
    }
  });

  // Runner-level timeout guard to avoid hanging tools.
  const killAfterSecs = Number(opts.timeout || process.env.TIMEOUT || 0);
  let killedByTimeout = false;
  let killTimer = null;
  if (Number.isFinite(killAfterSecs) && killAfterSecs > 0) {
    killTimer = setTimeout(() => {
      killedByTimeout = true;
      try { child.kill('SIGTERM'); } catch (_e) { /* ignore */ }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch (_e2) { /* ignore */ } }, 500);
    }, killAfterSecs * 1000);
  }

  let outBuf = '';
  let errBuf = '';
  let parseErrors = 0;
  let emitted = 0;

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');

  child.stdout.on('data', (chunk) => {
    const res = readJsonlLines(chunk, outBuf);
    outBuf = res.rest;

    for (const line of res.lines) {
      const parsed = safeJsonParse(line);
      if (!parsed.ok) {
        parseErrors += 1;
        if (opts.strict) {
          process.stderr.write(`[runner] invalid jsonl from ${skillPath}: ${line}\n`);
        }
        continue;
      }

      const normalized = normalizeRecord(parsed.value, {
        stage: opts.stage || 'unknown',
        tool: opts.tool || opts.sourceFallback || skillPath,
        target
      });
      const record = buildPayload({
        ...normalized,
        source: normalized.source || opts.sourceFallback || skillPath,
        workspace: normalized.workspace || opts.workspace
      });

      emitted += 1;
      process.stdout.write(`${JSON.stringify(record)}\n`);
      if (opts.recordsStream) opts.recordsStream.write(`${JSON.stringify(record)}\n`);
      if (typeof opts.onRecord === 'function') opts.onRecord(record);
      if (!opts.dryRun) void ingestRecord(record);
    }
  });

  child.stderr.on('data', (chunk) => {
    errBuf += chunk;
    // Keep stderr streaming for interactive visibility.
    process.stderr.write(chunk);
  });

  const code = await new Promise((resolve) => child.on('close', resolve));

  if (killTimer) clearTimeout(killTimer);

  if (killedByTimeout) {
    const record = buildPayload({
      type: 'note',
      tool: 'runner-timeout',
      stage: opts.stage || 'unknown',
      target,
      severity: 'info',
      evidence: [],
      data: { timed_out: true, timeout_sec: killAfterSecs, cmd, argv },
      source: 'src/bin/run-pipeline.js',
      workspace: opts.workspace
    });
    process.stdout.write(`${JSON.stringify(record)}\n`);
    if (opts.recordsStream) opts.recordsStream.write(`${JSON.stringify(record)}\n`);
    if (!opts.dryRun) void ingestRecord(record);
    return { ok: false, code: code || 124, emitted, parseErrors, stderr: (errBuf || 'timeout') };
  }

  if (outBuf.trim().length > 0) {
    const parsed = safeJsonParse(outBuf.trim());
    if (parsed.ok) {
      const normalized = normalizeRecord(parsed.value, {
        stage: opts.stage || 'unknown',
        tool: opts.tool || opts.sourceFallback || skillPath,
        target
      });
      const record = buildPayload({
        ...normalized,
        source: normalized.source || opts.sourceFallback || skillPath,
        workspace: normalized.workspace || opts.workspace
      });
      emitted += 1;
      process.stdout.write(`${JSON.stringify(record)}\n`);
      if (opts.recordsStream) opts.recordsStream.write(`${JSON.stringify(record)}\n`);
      if (typeof opts.onRecord === 'function') opts.onRecord(record);
      if (!opts.dryRun) void ingestRecord(record);
    } else {
      parseErrors += 1;
      if (opts.strict) {
        process.stderr.write(`[runner] invalid jsonl trailing from ${skillPath}: ${outBuf.trim()}\n`);
      }
    }
  }

  return { ok: code === 0, code, emitted, parseErrors, stderr: errBuf };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const pipelinePath = args.pipeline || 'pipeline.json';

  if (args.targets.length === 0) {
    process.stderr.write('Usage: run-pipeline --target <t> [--target <t2>] [--stage recon] [--workspace ws] [--pipeline pipeline.json] [--out-dir dir] [--scope-file file] [--rate n] [--timeout sec] [--max-targets n] [--allow-exploit] [--confirm str] [--dry-run] [--strict]\n');
    process.exit(1);
  }

  const runTs = nowStamp();
  const outDir = args.outDir ? path.resolve(args.outDir) : path.resolve('data', 'runs', runTs);
  ensureDir(outDir);
  const recordsPath = path.join(outDir, 'records.jsonl');
  const recordsStream = fs.createWriteStream(recordsPath, { flags: 'a' });

  const abs = path.resolve(pipelinePath);
  const pipelineDir = path.dirname(abs);
  const pipeline = JSON.parse(fs.readFileSync(abs, 'utf8'));
  const stages = Array.isArray(pipeline.stages) ? pipeline.stages : [];

  const selectedStages = args.stage
    ? stages.filter((s) => s && s.name === args.stage)
    : stages;

  if (selectedStages.length === 0) {
    process.stderr.write(`[runner] no stages to run (stage filter: ${args.stage || 'none'})\n`);
    process.exit(1);
  }

  function extractTargets(record) {
    if (!record || record.type !== 'asset') return [];
    const out = [];
    if (record.target) out.push(record.target);
    const data = record.data || {};
    if (typeof data.ip === 'string' && data.ip) out.push(data.ip);
    if (Array.isArray(data.hostnames)) out.push(...data.hostnames.filter(Boolean));
    return out;
  }

  const propagateAssets = Boolean(pipeline.options && pipeline.options.propagate_assets);
  const maxTargets = Number(args.maxTargets || process.env.MAX_TARGETS || 0);
  const scope = loadScopeFile(args.scopeFile).entries;
  function inScopeOrAllowAll(t) {
    if (!args.scopeFile) return true;
    return targetInScope(t, scope);
  }

  let stageTargets = [...args.targets].filter((t) => inScopeOrAllowAll(t));
  const initialFiltered = args.targets.filter((t) => !inScopeOrAllowAll(t));
  if (initialFiltered.length > 0) {
    process.stderr.write(`[runner] scope blocked ${initialFiltered.length} initial target(s)\n`);
  }

  for (const stage of selectedStages) {
    if (stage && stage.name === 'exploit') {
      const okGate = Boolean(args.allowExploit);
      if (!okGate) {
        const record = buildPayload({
          type: 'note',
          tool: 'intrusive-gate',
          stage: stage.name,
          target: stageTargets[0] || args.targets[0] || '',
          severity: 'info',
          evidence: [],
          data: { intrusive_actions: 'blocked', required: '--allow-exploit' },
          source: 'src/bin/run-pipeline.js',
          workspace: args.workspace
        });
        process.stdout.write(`${JSON.stringify(record)}\n`);
        recordsStream.write(`${JSON.stringify(record)}\n`);
        if (!args.dryRun) void ingestRecord(record);
        process.stderr.write('[runner] exploit stage blocked (missing --allow-exploit)\n');
        continue;
      }
    }

    const skills = Array.isArray(stage.skills) ? stage.skills : [];
    const discovered = new Set();
    const onRecord = (rec) => {
      extractTargets(rec).forEach((t) => discovered.add(t));
    };

    for (const skillRef of skills) {
      const skillPath = path.isAbsolute(skillRef) ? skillRef : path.resolve(pipelineDir, skillRef);
      for (const target of stageTargets) {
        process.stderr.write(`[runner] stage=${stage.name} skill=${skillRef} target=${target}\n`);
        // eslint-disable-next-line no-await-in-loop
        const res = await runSkillOnce(skillPath, target, {
          dryRun: args.dryRun,
          strict: args.strict,
          workspace: args.workspace,
          sourceFallback: skillRef,
          stage: stage.name,
          tool: path.basename(skillRef),
          onRecord,
          outDir,
          scopeFile: args.scopeFile,
          rate: args.rate,
          timeout: args.timeout,
          allowExploit: args.allowExploit,
          allowVuln: args.allowVuln,
          confirm: args.confirm,
          runTs,
          recordsStream
        });
        if (!res.ok && pipeline.options && pipeline.options.stop_on_error) {
          process.stderr.write(`[runner] stopping on error: ${skillRef} (code ${res.code})\n`);
          process.exit(res.code || 1);
        }
      }
    }

    if (propagateAssets && discovered.size > 0) {
      const next = new Set(stageTargets);
      discovered.forEach((t) => {
        if (inScopeOrAllowAll(t)) next.add(t);
      });
      stageTargets = Array.from(next);

      if (maxTargets > 0 && stageTargets.length > maxTargets) {
        process.stderr.write(`[runner] max-targets cap: ${stageTargets.length} -> ${maxTargets}\n`);
        stageTargets = stageTargets.slice(0, maxTargets);
      }
    }
  }

  recordsStream.end();
  process.stderr.write(`[runner] outDir=${outDir}\n`);
  process.stderr.write(`[runner] records=${recordsPath}\n`);
}

main().catch((err) => {
  process.stderr.write(`[runner] fatal: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1);
});
