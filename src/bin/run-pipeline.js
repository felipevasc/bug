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
const { ingestRecord, buildPayload } = require('../lib/faraday');

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
    const record = buildPayload({
      ...raw,
      target: raw && raw.target ? raw.target : target,
      source: raw && raw.source ? raw.source : (opts.sourceFallback || skillPath),
      workspace: raw && raw.workspace ? raw.workspace : opts.workspace
    });

    emitted += 1;
    process.stdout.write(`${JSON.stringify(record)}\n`);
    if (typeof opts.onRecord === 'function') opts.onRecord(record);
    if (!opts.dryRun) void ingestRecord(record);
  }

  try {
    await Promise.resolve(run({ target, emit: emitRecord }));
    return { ok: true, code: 0, emitted, parseErrors: 0, stderr: '' };
  } catch (err) {
    const msg = err && err.stack ? err.stack : String(err);
    process.stderr.write(`[runner] node skill failed: ${skillPath}: ${msg}\n`);
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

  const child = spawn(cmd, argv, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env
  });

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

      const record = buildPayload({
        ...parsed.value,
        target: parsed.value.target || target,
        source: parsed.value.source || opts.sourceFallback || skillPath,
        workspace: parsed.value.workspace || opts.workspace
      });

      emitted += 1;
      process.stdout.write(`${JSON.stringify(record)}\n`);
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

  if (outBuf.trim().length > 0) {
    const parsed = safeJsonParse(outBuf.trim());
    if (parsed.ok) {
      const record = buildPayload({
        ...parsed.value,
        target: parsed.value.target || target,
        source: parsed.value.source || opts.sourceFallback || skillPath,
        workspace: parsed.value.workspace || opts.workspace
      });
      emitted += 1;
      process.stdout.write(`${JSON.stringify(record)}\n`);
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
    process.stderr.write('Usage: run-pipeline --target <t> [--target <t2>] [--stage recon] [--workspace ws] [--pipeline pipeline.json] [--dry-run] [--strict]\n');
    process.exit(1);
  }

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
  let stageTargets = [...args.targets];

  for (const stage of selectedStages) {
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
        const res = await runSkillOnce(skillPath, target, { dryRun: args.dryRun, strict: args.strict, workspace: args.workspace, sourceFallback: skillRef, onRecord });
        if (!res.ok && pipeline.options && pipeline.options.stop_on_error) {
          process.stderr.write(`[runner] stopping on error: ${skillRef} (code ${res.code})\n`);
          process.exit(res.code || 1);
        }
      }
    }

    if (propagateAssets && discovered.size > 0) {
      const next = new Set(stageTargets);
      discovered.forEach((t) => next.add(t));
      stageTargets = Array.from(next);
    }
  }
}

main().catch((err) => {
  process.stderr.write(`[runner] fatal: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1);
});
