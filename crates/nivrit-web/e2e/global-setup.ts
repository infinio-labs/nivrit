import { execSync } from 'node:child_process';
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '../..', '..');
const COMPOSE = `docker compose --env-file ${join(ROOT, '.env.docker')} -f ${join(ROOT, 'docker-compose.yml')}`;
const API_BASE = 'http://localhost:4000';
const SUFFIX = Date.now().toString();
const HOME_DIR = '/tmp/nivrit-web-test';
const ALICE_EMAIL = `alice-web-${SUFFIX}@example.com`;
const BOB_EMAIL = `bob-web-${SUFFIX}@example.com`;
// Must satisfy the shared password policy in nivrit-crypto: at least 12
// characters, and not derived from the account email.
const PASSWORD = 'web-test-glacier-tuesday';

function run(cmd: string): string {
  return execSync(cmd, { cwd: ROOT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'inherit'] }).trim();
}

// Passes the master password through NIVRIT_PASSWORD rather than --password,
// which the CLI warns about because a flag lands in shell history and `ps`.
// The tests should model the way we tell users to do it.
function cli(home: string, ...args: string[]): string {
  const cmd = `${COMPOSE} exec -T -e HOME=${home} -e NIVRIT_PASSWORD=${PASSWORD} api niv ${args.join(' ')}`;
  return run(cmd);
}

export default async function globalSetup() {
  // Ensure the stack is running.
  try {
    run(`curl -sf ${API_BASE}/health`);
  } catch {
    run(`${COMPOSE} up -d --wait`);
    for (let i = 0; i < 30; i++) {
      try {
        run(`curl -sf ${API_BASE}/health`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
  }

  // Start each test run with clean CLI home directories.
  run(`docker compose --env-file ${join(ROOT, '.env.docker')} -f ${join(ROOT, 'docker-compose.yml')} exec -T api rm -rf ${HOME_DIR}-alice ${HOME_DIR}-bob`);

  // Seed two registered users. The E2E spec itself exercises org/project/env
  // creation and member invitation through the web UI.
  cli(`${HOME_DIR}-alice`, 'register', `--email ${ALICE_EMAIL}`, '--name AliceWeb');
  cli(`${HOME_DIR}-bob`, 'register', `--email ${BOB_EMAIL}`, '--name BobWeb');

  const stateDir = join(import.meta.dirname, '.state');
  if (!existsSync(stateDir)) mkdirSync(stateDir, { recursive: true });
  writeFileSync(
    join(stateDir, 'test-state.json'),
    JSON.stringify({ aliceEmail: ALICE_EMAIL, bobEmail: BOB_EMAIL, password: PASSWORD }, null, 2)
  );
}
