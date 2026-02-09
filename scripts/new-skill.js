#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const val = argv[i + 1];
    if (key && key.startsWith('--') && val && !val.startsWith('--')) {
      args[key.slice(2)] = val;
      i += 1;
    }
  }
  return args;
}

function slugify(value) {
  return (value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function inferLang(tech, provided) {
  if (provided) return provided;
  if (tech === 'nodejs') return 'node';
  if (tech === 'python') return 'python';
  if (tech === 'shell') return 'shell';
  return 'node';
}

function extForLang(lang) {
  if (lang === 'node') return 'js';
  if (lang === 'python') return 'py';
  if (lang === 'shell') return 'sh';
  return 'js';
}

function shebangForLang(lang) {
  if (lang === 'node') return '#!/usr/bin/env node';
  if (lang === 'python') return '#!/usr/bin/env python3';
  if (lang === 'shell') return '#!/usr/bin/env bash';
  return '#!/usr/bin/env node';
}

function normalizePath(p) {
  return String(p).split(path.sep).join('/');
}

function templateFor({ tech, stage, name, lang, sourcePath }) {
  const skillId = `${tech}/${stage}/${slugify(name)}`;
  const commonMeta = `@skill: ${skillId}\n@inputs: target\n@outputs: asset|finding|note\n@tools: toolname`;
  const shellMeta = commonMeta.split('\n').map((l) => `# ${l}`).join('\n');

  if (lang === 'python') {
    return `${shebangForLang(lang)}\n\"\"\"\n${commonMeta}\n\"\"\"\n\nimport argparse\nimport json\nimport sys\nfrom datetime import datetime, timezone\n\n\ndef now_iso():\n    return datetime.now(timezone.utc).isoformat().replace(\"+00:00\", \"Z\")\n\n\ndef emit(record):\n    if \"timestamp\" not in record:\n        record[\"timestamp\"] = now_iso()\n    sys.stdout.write(json.dumps(record, separators=(\",\", \":\")) + \"\\n\")\n\n\ndef main():\n    parser = argparse.ArgumentParser()\n    parser.add_argument(\"--target\", required=True)\n    args = parser.parse_args()\n\n    emit({\n        \"type\": \"asset\",\n        \"target\": args.target,\n        \"data\": {\"notes\": \"placeholder\"},\n        \"source\": \"${sourcePath}\"\n    })\n\n\nif __name__ == \"__main__\":\n    main()\n`;
  }

  if (lang === 'shell') {
    return `${shebangForLang(lang)}\nset -euo pipefail\n\n${shellMeta}\n\nTARGET=\"\"\nwhile [[ $# -gt 0 ]]; do\n  case \"$1\" in\n    --target)\n      if [[ $# -lt 2 ]]; then\n        echo \"Missing value for --target\" >&2\n        exit 1\n      fi\n      TARGET=\"$2\"\n      shift 2\n      ;;\n    *)\n      if [[ -z \"$TARGET\" ]]; then\n        TARGET=\"$1\"\n      fi\n      shift\n      ;;\n  esac\ndone\n\nif [[ -z \"$TARGET\" ]]; then\n  echo \"Usage: $0 --target <target> (or positional <target>)\" >&2\n  exit 1\nfi\n\nTS=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"\nJSON=$(printf '{\"type\":\"asset\",\"target\":\"%s\",\"data\":{\"notes\":\"placeholder\"},\"timestamp\":\"%s\",\"source\":\"${sourcePath}\"}\\n' \"$TARGET\" \"$TS\")\n\necho \"$JSON\"\n`;
  }

  return `${shebangForLang(lang)}\n'use strict';\n\n/**\n * ${commonMeta}\n */\n\nfunction recordForTarget(target) {\n  return {\n    type: 'asset',\n    target,\n    data: {\n      notes: 'placeholder'\n    },\n    source: '${sourcePath}'\n  };\n}\n\nasync function run({ target, emit }) {\n  emit(recordForTarget(target));\n}\n\nfunction getArg(name) {\n  const idx = process.argv.indexOf(name);\n  return idx > -1 ? process.argv[idx + 1] : null;\n}\n\nfunction defaultEmit(record) {\n  if (!record.timestamp) record.timestamp = new Date().toISOString();\n  process.stdout.write(JSON.stringify(record) + '\\n');\n}\n\nasync function main() {\n  const target = getArg('--target');\n  if (!target) {\n    process.stderr.write('Usage: --target <host>\\n');\n    process.exit(1);\n  }\n\n  await run({ target, emit: defaultEmit });\n}\n\nmodule.exports = { run };\n\nif (require.main === module) {\n  void main();\n}\n`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const tech = args.tech;
  const stage = args.stage;
  const name = args.name;

  if (!tech || !stage || !name) {
    process.stderr.write('Usage: --tech <tech> --stage <stage> --name "Skill Name" [--order 01] [--lang node|python|shell] [--out-dir src/skills] [--force true]\n');
    process.exit(1);
  }

  const order = args.order || '01';
  const lang = inferLang(tech, args.lang);
  const ext = extForLang(lang);
  const slug = slugify(name);
  const filename = `${order}-${slug}.${ext}`;

  const outDir = args['out-dir'] || path.join('src', 'skills');
  const dir = path.join(outDir, tech, stage);
  const filePath = path.join(dir, filename);

  fs.mkdirSync(dir, { recursive: true });

  if (fs.existsSync(filePath) && args.force !== 'true') {
    process.stderr.write(`File already exists: ${filePath}. Use --force true to overwrite.\n`);
    process.exit(1);
  }

  const sourcePath = normalizePath(path.join(dir, filename));
  const content = templateFor({ tech, stage, name, lang, sourcePath });

  fs.writeFileSync(filePath, content, 'utf8');
  fs.chmodSync(filePath, 0o755);
  process.stdout.write(`Created ${filePath}\n`);
}

main();
