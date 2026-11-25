// Copies the Dafny-generated event core (dafny/gen-events/js/ehbp.js) into the given
// directories as ehbp.cjs: src/gen for type resolution and the browser bundle,
// dist/*/gen for the published builds.
const fs = require('node:fs');
const path = require('node:path');
const src = path.join(__dirname, '..', '..', 'dafny', 'gen-events', 'js', 'ehbp.js');
for (const dir of process.argv.slice(2)) {
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(src, path.join(dir, 'ehbp.cjs'));
}
