#!/usr/bin/env node
/**
 * REAL-BUILD-RUNTIME-ISOLATION-GUARD-1
 *
 * Empêche un build rehearsal/test d'écraser silencieusement frontend/dist pendant que
 * le cabinet réel (port 8005) le sert, et empêche un build "real" explicite tant que ce
 * process n'a pas été arrêté volontairement.
 *
 * Modes :
 *   safe      (npm run build)            -> dist, refuse si :8005 est actif
 *   rehearsal (npm run build:rehearsal)   -> dist-rehearsal, toujours autorisé
 *   real      (npm run build:real)        -> dist, nécessite CONFIRM_REAL_BUILD=yes
 *                                             ET refuse si :8005 est actif
 */
import { execSync } from 'node:child_process';
import { createConnection } from 'node:net';
import { writeFileSync, mkdirSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const REAL_CABINET_PORT = 8005;
const MODE = process.argv[2] || 'safe';

const OUT_DIRS = {
  safe: 'dist',
  rehearsal: 'dist-rehearsal',
  real: 'dist',
  test: 'dist-test',
};

function isPortListening(port, host = '127.0.0.1', timeoutMs = 800) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ port, host });
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => { socket.destroy(); reject(new Error('workstation port probe timed out')); });
    socket.once('error', (error) => {
      if (error.code === 'ECONNREFUSED') done(false);
      else { socket.destroy(); reject(new Error('workstation port probe inconclusive')); }
    });
  });
}

function fail(message) {
  console.error(`\n[build-guard] REFUS — ${message}\n`);
  process.exit(1);
}

async function main() {
  if (!Object.hasOwn(OUT_DIRS, MODE)) {
    fail(`mode inconnu "${MODE}" (attendu: safe | rehearsal | real | test)`);
  }

  const outDir = OUT_DIRS[MODE];
  // An isolated build never needs to inspect or modify the real cabinet.
  const realCabinetLive = (MODE === 'safe' || MODE === 'real') ? await isPortListening(REAL_CABINET_PORT) : false;
  try {
    const existing = lstatSync(path.join(ROOT, outDir));
    if (existing.isSymbolicLink() || !existing.isDirectory()) fail('output directory is not an ordinary directory');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  console.log(`[build-guard] mode=${MODE} outDir=${outDir} port8005Live=${realCabinetLive}`);

  if (MODE === 'safe' && realCabinetLive) {
    fail(
      `le port ${REAL_CABINET_PORT} (cabinet réel) est actif. "npm run build" n'écrit plus dans ` +
      `frontend/dist tant que ce process tourne, pour ne jamais écraser silencieusement le build ` +
      `servi en réel. Utilise "npm run build:rehearsal" pour un build isolé, ou arrête le process ` +
      `réel puis "npm run build:real" pour une activation explicite.`
    );
  }

  if (MODE === 'real') {
    if (realCabinetLive) {
      fail(
        `le port ${REAL_CABINET_PORT} est actif — arrête-le volontairement avant un build réel ` +
        `explicite (ordre attendu : arrêt maîtrisé du runtime -> build réel -> redémarrage).`
      );
    }
    if (process.env.CONFIRM_REAL_BUILD !== 'yes') {
      fail(
        `build réel explicite refusé sans confirmation. Relance avec ` +
        `CONFIRM_REAL_BUILD=yes npm run build:real`
      );
    }
  }

  // rehearsal/test : jamais de vérification de port, ils n'écrivent jamais dans dist réel.

  console.log(`[build-guard] OK — build autorisé vers ${outDir}`);

  execSync('tsc -b', { stdio: 'inherit', cwd: ROOT });
  // Real release uses runtime origin rather than a baked-in development API.
  const buildEnv = MODE === 'real' ? { ...process.env, VITE_API_URL: '' } : process.env;
  execSync(`vite build --outDir ${outDir}`, { stdio: 'inherit', cwd: ROOT, env: buildEnv });

  writeManifest(outDir, MODE);
}

function writeManifest(outDir, mode) {
  const absOutDir = path.join(ROOT, outDir);
  let commit = 'unknown';
  try {
    commit = execSync('git rev-parse HEAD', { cwd: ROOT }).toString().trim();
  } catch {
    // pas de repo git accessible depuis ce contexte — non bloquant
  }

  const manifest = {
    environment: mode,
    commit,
    buildDate: new Date().toISOString(),
    mode,
    outputDir: outDir,
  };

  mkdirSync(absOutDir, { recursive: true });
  writeFileSync(path.join(absOutDir, 'build-manifest.json'), JSON.stringify(manifest, null, 2));
  console.log(`[build-guard] manifest écrit : ${outDir}/build-manifest.json`);
  console.log(JSON.stringify(manifest, null, 2));
}

main().catch(error => fail(error.message));
