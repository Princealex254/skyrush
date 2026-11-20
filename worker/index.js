import { DurableObject } from 'cloudflare:workers';

const ROUND_WAIT_MS = 1500;
const BETTING_DURATION_MS = 6000;
const GROWTH_RATE_PPM_PER_SECOND = 80000;
const HOUSE_EDGE_DENOMINATOR = 33;
const MAX_MULTIPLIER_MILLI = 1000000000;
const MIN_STAKE_MINOR = 1000;
const MAX_STAKE_MINOR = 5000000;
const FAIRNESS_ALGORITHM = 'skyrush-hmac-sha256-v1';

const TWO_TO_52 = 1n << 52n;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const encoder = new TextEncoder();

function databaseErrorDetails(error) {
  const details = { name: error?.name || 'Error' };
  if (typeof error?.message === 'string') details.message = error.message.slice(0, 500);
  if (typeof error?.code === 'string' || Number.isInteger(error?.code)) details.code = error.code;
  if (typeof error?.cause?.message === 'string') {
    details.cause = error.cause.message.slice(0, 500);
  }
  return details;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    throw new TypeError('Expected an even-length hexadecimal value.');
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function generateServerSeed() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

async function commitServerSeed(seedHex) {
  const digest = await crypto.subtle.digest('SHA-256', hexToBytes(seedHex));
  return bytesToHex(new Uint8Array(digest));
}

async function getCrashMultiplierMilli(seedHex, roundNonce) {
  if (!Number.isSafeInteger(roundNonce) || roundNonce < 1) {
    throw new TypeError('Round nonce must be a positive safe integer.');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(seedHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const digest = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${FAIRNESS_ALGORITHM}:${roundNonce}`)
  );
  const first52Bits = BigInt(`0x${bytesToHex(new Uint8Array(digest)).slice(0, 13)}`);
  if (first52Bits % BigInt(HOUSE_EDGE_DENOMINATOR) === 0n) return 1000;

  const cents = (100n * TWO_TO_52 - first52Bits) / (TWO_TO_52 - first52Bits);
  const multiplierMilli = cents * 10n;
  return Number(multiplierMilli > BigInt(MAX_MULTIPLIER_MILLI)
    ? BigInt(MAX_MULTIPLIER_MILLI)
    : multiplierMilli);
}

function getMultiplierMilliAt(startAtMs, atMs, ratePpmPerSecond = GROWTH_RATE_PPM_PER_SECOND) {
  if (!Number.isSafeInteger(startAtMs) || !Number.isSafeInteger(atMs) ||
      !Number.isSafeInteger(ratePpmPerSecond) || ratePpmPerSecond < 1) {
    throw new TypeError('Invalid multiplier timing parameters.');
  }
  if (atMs <= startAtMs) return 1000;
  const exponent = (ratePpmPerSecond * (atMs - startAtMs)) / 1_000_000_000;
  const multiplier = Math.floor(1000 * Math.exp(Math.min(exponent, 700)));
  return Math.min(Number.MAX_SAFE_INTEGER, multiplier);
}

function getMultiplierDeadlineMs(startAtMs, multiplierMilli, ratePpmPerSecond = GROWTH_RATE_PPM_PER_SECOND) {
  if (!Number.isSafeInteger(startAtMs) || !Number.isSafeInteger(multiplierMilli) ||
      multiplierMilli < 1000 || !Number.isSafeInteger(ratePpmPerSecond) || ratePpmPerSecond < 1) {
    throw new TypeError('Invalid crash timing parameters.');
  }
  const durationMs = Math.ceil(
    Math.log(multiplierMilli / 1000) * 1_000_000_000 / ratePpmPerSecond
  );
  const deadline = startAtMs + durationMs;
  if (!Number.isSafeInteger(deadline)) throw new RangeError('Crash deadline exceeds safe timestamp range.');
  return deadline;
}

function getAutoCashoutAtMs(startAtMs, multiplierMilli, ratePpmPerSecond = GROWTH_RATE_PPM_PER_SECOND) {
  if (multiplierMilli <= 1000) throw new TypeError('Auto cashout must be greater than 1.00x.');
  return getMultiplierDeadlineMs(startAtMs, multiplierMilli, ratePpmPerSecond);
}

function calculatePayoutMinor(amountMinor, multiplierMilli) {
  if (!Number.isSafeInteger(amountMinor) || amountMinor < 1 ||
      !Number.isSafeInteger(multiplierMilli) || multiplierMilli < 1000) {
    throw new TypeError('Invalid payout inputs.');
  }
  const payout = (BigInt(amountMinor) * BigInt(multiplierMilli)) / 1000n;
  if (payout > MAX_SAFE_BIGINT) throw new RangeError('Payout exceeds the safe integer range.');
  return Number(payout);
}

async function verifyFairness({ seed, commitment, roundNonce, crashMultiplierMilli }) {
  if (await commitServerSeed(seed) !== commitment) return false;
  return await getCrashMultiplierMilli(seed, roundNonce) === crashMultiplierMilli;
}

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_BET_IDEMPOTENCY_LENGTH = 100;
const ROUND_RESTART_DELAY_MS = 3500;

class GameError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'GameError';
    this.status = status;
    this.code = code;
  }
}

function gameJsonResponse(data, status = 200) {
  return new Response(JSON.stringify(
    status >= 400
      ? { ok: false, error: data }
      : { ok: true, data }
  ), {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

function readHexSecret(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new GameError(503, 'SEED_ENCRYPTION_NOT_CONFIGURED', 'The game engine is not configured.');
  }
  return hexToBytes(value);
}

function readIdempotencyKey(request) {
  const key = request.headers.get('Idempotency-Key') || '';
  if (!/^[A-Za-z0-9_-]{16,100}$/.test(key)) {
    throw new GameError(400, 'INVALID_IDEMPOTENCY_KEY', 'A valid idempotency key is required.');
  }
  return key;
}

function safeNumber(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new GameError(400, 'INVALID_REQUEST', `${name} must be a safe integer.`);
  }
  return parsed;
}

function statePhase(round, schedulerPaused) {
  if (!round || round.engineStatus === 'SETTLED') return schedulerPaused ? 'PAUSED' : 'WAITING';
  return round.engineStatus;
}

export class GlobalGame extends DurableObject {
  constructor(state, env) {
    super(state, env);
    this.serial = Promise.resolve();
    this.activeNetworkRequest = null;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS game_engine_state (
        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
        snapshot_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      )
    `);
    this.snapshot = { schedulerPaused: false, round: null, eventSequence: 0 };
    this.ready = this.ctx.blockConcurrencyWhile(async () => {
      await this.restore();
      await this.advance(Date.now());
    });
  }

  enqueue(operation) {
    const result = this.serial.then(operation, operation);
    this.serial = result.catch(() => {});
    return result;
  }

  async fetch(request) {
    try {
      await this.ready;
      return await this.enqueue(() => this.handleRequest(request, Date.now()));
    } catch (error) {
      return this.errorResponse(error);
    }
  }

  async alarm() {
    try {
      await this.ready;
      await this.enqueue(() => this.advance(Date.now()));
    } catch (error) {
      console.error('Game alarm failed', { name: error?.name || 'Error' });
      await this.ctx.storage.setAlarm(Date.now() + 5000);
      throw error;
    }
  }

  async webSocketMessage(socket, message) {
    try {
      await this.ready;
      await this.enqueue(async () => {
        if (typeof message === 'string' && message === 'PING') {
          socket.send(JSON.stringify({ type: 'PONG', id: String(Date.now()) }));
          return;
        }
        socket.send(JSON.stringify({
          type: 'ERROR',
          id: String(Date.now()),
          data: { code: 'HTTP_ACTION_REQUIRED', message: 'Submit player actions through the authenticated API.' }
        }));
      });
    } catch {
      try { socket.close(1011, 'Game state unavailable.'); } catch {}
    }
  }

  async webSocketClose() {}

  async webSocketError() {}

  async handleRequest(request, receivedAtMs) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') {
      const state = await this.publicState(receivedAtMs);
      return gameJsonResponse({
        initialized: true,
        status: state.status,
        roundNumber: state.round?.number ?? null,
        schedulerPaused: state.schedulerPaused,
        serverTimeMs: state.serverTimeMs
      });
    }
    if ((url.pathname === '/socket' || url.pathname === '/api/v1/game/live') &&
        request.method === 'GET') {
      return this.openSocket(request, receivedAtMs);
    }
    if (request.method === 'GET' && url.pathname === '/state') {
      await this.advance(receivedAtMs);
      return gameJsonResponse(await this.publicState(receivedAtMs));
    }
    if (request.method === 'POST' && url.pathname === '/bet') {
      const body = await this.readBody(request);
      const uid = request.headers.get('X-Game-Actor');
      const idempotencyKey = readIdempotencyKey(request);
      const bet = await this.placeBet(uid, body, idempotencyKey, receivedAtMs);
      return gameJsonResponse(bet, 201);
    }
    if (request.method === 'POST' && url.pathname === '/cashout') {
      const body = await this.readBody(request);
      const uid = request.headers.get('X-Game-Actor');
      const idempotencyKey = readIdempotencyKey(request);
      const result = await this.cashout(uid, body.betId, idempotencyKey, receivedAtMs);
      return gameJsonResponse(result);
    }
    if (request.method === 'POST' && url.pathname === '/admin/pause') {
      const actorUid = request.headers.get('X-Game-Actor');
      if (request.headers.get('X-Game-Admin') !== 'true') {
        throw new GameError(403, 'ADMIN_REQUIRED', 'Administrator permission is required.');
      }
      await this.setSchedulerPaused(true, actorUid);
      return gameJsonResponse({ schedulerPaused: true });
    }
    if (request.method === 'POST' && url.pathname === '/admin/resume') {
      const actorUid = request.headers.get('X-Game-Actor');
      if (request.headers.get('X-Game-Admin') !== 'true') {
        throw new GameError(403, 'ADMIN_REQUIRED', 'Administrator permission is required.');
      }
      await this.setSchedulerPaused(false, actorUid);
      return gameJsonResponse({ schedulerPaused: false });
    }
    throw new GameError(404, 'NOT_FOUND', 'The requested game operation does not exist.');
  }

  errorResponse(error) {
    if (error instanceof GameError) {
      return gameJsonResponse({ code: error.code, message: error.message }, error.status);
    }
    console.error('Durable game operation failed', { name: error?.name || 'Error' });
    return gameJsonResponse({ code: 'GAME_UNAVAILABLE', message: 'The game service is temporarily unavailable.' }, 503);
  }

  async readBody(request) {
    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      throw new GameError(415, 'JSON_REQUIRED', 'Send a JSON request body.');
    }
    const text = await request.text();
    if (text.length > 4096) throw new GameError(413, 'REQUEST_TOO_LARGE', 'The request body is too large.');
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new GameError(400, 'INVALID_JSON', 'The request body must be valid JSON.');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new GameError(400, 'INVALID_BODY', 'The request body must be a JSON object.');
    }
    return body;
  }

  async dbFirst(sql, ...values) {
    if (!this.env.DB || typeof this.env.DB.prepare !== 'function') {
      throw new GameError(503, 'D1_NOT_CONFIGURED', 'The game database is not available.');
    }
    try {
      return await this.env.DB.prepare(sql).bind(...values).first();
    } catch (error) {
      console.error('Game D1 read failed', databaseErrorDetails(error));
      throw new GameError(503, 'DATABASE_UNAVAILABLE', 'The game database is temporarily unavailable.');
    }
  }

  async dbAll(sql, ...values) {
    if (!this.env.DB || typeof this.env.DB.prepare !== 'function') {
      throw new GameError(503, 'D1_NOT_CONFIGURED', 'The game database is not available.');
    }
    try {
      const result = await this.env.DB.prepare(sql).bind(...values).all();
      return result.results || [];
    } catch (error) {
      console.error('Game D1 read failed', databaseErrorDetails(error));
      throw new GameError(503, 'DATABASE_UNAVAILABLE', 'The game database is temporarily unavailable.');
    }
  }

  async dbRun(sql, ...values) {
    if (!this.env.DB || typeof this.env.DB.prepare !== 'function') {
      throw new GameError(503, 'D1_NOT_CONFIGURED', 'The game database is not available.');
    }
    try {
      return await this.env.DB.prepare(sql).bind(...values).run();
    } catch (error) {
      console.error('Game D1 write failed', databaseErrorDetails(error));
      throw new GameError(503, 'DATABASE_UNAVAILABLE', 'The game database is temporarily unavailable.');
    }
  }

  async dbBatch(statements) {
    if (!this.env.DB || typeof this.env.DB.batch !== 'function') {
      throw new GameError(503, 'D1_NOT_CONFIGURED', 'The game database is not available.');
    }
    try {
      return await this.env.DB.batch(statements);
    } catch (error) {
      console.error('Game D1 transaction failed', databaseErrorDetails(error));
      throw new GameError(503, 'DATABASE_UNAVAILABLE', 'The game database is temporarily unavailable.');
    }
  }

  async encryptSeed(seedHex) {
    const keyBytes = readHexSecret(this.env.GAME_SEED_ENCRYPTION_KEY);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt('AES-GCM', key, hexToBytes(seedHex));
    return {
      ciphertext: Array.from(new Uint8Array(ciphertext), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      iv: Array.from(iv, (byte) => byte.toString(16).padStart(2, '0')).join('')
    };
  }

  async decryptSeed(ciphertextHex, ivHex) {
    const keyBytes = readHexSecret(this.env.GAME_SEED_ENCRYPTION_KEY);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    try {
      const plaintext = await crypto.subtle.decrypt(
        'AES-GCM',
        key,
        hexToBytes(ivHex),
        hexToBytes(ciphertextHex)
      );
      return Array.from(new Uint8Array(plaintext), (byte) => byte.toString(16).padStart(2, '0')).join('');
    } catch {
      throw new GameError(503, 'SEED_DECRYPTION_FAILED', 'The game is paused because a round seed could not be recovered.');
    }
  }

  async persistSnapshot() {
    this.ctx.storage.sql.exec(`
      INSERT INTO game_engine_state (singleton_id, snapshot_json, updated_at_ms)
      VALUES (1, ?, ?)
      ON CONFLICT(singleton_id) DO UPDATE SET
        snapshot_json = excluded.snapshot_json,
        updated_at_ms = excluded.updated_at_ms
    `, JSON.stringify(this.snapshot), Date.now());
  }

  async restore() {
    const stored = this.ctx.storage.sql.exec(
      'SELECT snapshot_json FROM game_engine_state WHERE singleton_id = 1'
    ).toArray()[0];
    if (stored) {
      try {
        this.snapshot = JSON.parse(stored.snapshot_json);
      } catch {
        this.snapshot = { schedulerPaused: false, round: null, eventSequence: 0 };
      }
    }

    const config = await this.dbFirst(`
      SELECT scheduler_paused FROM game_engine_config WHERE singleton_id = 1
    `);
    this.snapshot.schedulerPaused = Boolean(config && Number(config.scheduler_paused) === 1);

    const active = await this.dbFirst(`
      SELECT round_id, round_number, engine_status, created_at,
             betting_open_at_ms, betting_closes_at_ms, official_start_at_ms,
             crash_deadline_at_ms, official_crash_at_ms, settled_at_ms,
             current_multiplier_milli, crash_multiplier_milli, seed_commitment,
             seed_reveal, seed_ciphertext, seed_iv, growth_rate_ppm_per_second,
             max_multiplier_milli
      FROM game_rounds
      WHERE engine_status <> 'SETTLED'
      ORDER BY round_number DESC
      LIMIT 1
    `);
    if (active) {
      this.snapshot.round = this.roundFromRow(active);
    } else {
      const latest = await this.dbFirst(`
        SELECT round_id, round_number, engine_status, created_at,
               betting_open_at_ms, betting_closes_at_ms, official_start_at_ms,
               crash_deadline_at_ms, official_crash_at_ms, settled_at_ms,
               current_multiplier_milli, crash_multiplier_milli, seed_commitment,
               seed_reveal, seed_ciphertext, seed_iv, growth_rate_ppm_per_second,
               max_multiplier_milli
        FROM game_rounds
        ORDER BY round_number DESC
        LIMIT 1
      `);
      this.snapshot.round = latest ? this.roundFromRow(latest) : null;
    }
    if (!Number.isSafeInteger(this.snapshot.eventSequence)) this.snapshot.eventSequence = 0;
    await this.persistSnapshot();
  }

  roundFromRow(row) {
    const settledAtMs = Number(row.settled_at_ms) || null;
    return {
      id: row.round_id,
      number: Number(row.round_number),
      engineStatus: row.engine_status,
      createdAtMs: Number(row.created_at) * 1000,
      bettingOpenAtMs: Number(row.betting_open_at_ms) || null,
      bettingClosesAtMs: Number(row.betting_closes_at_ms) || null,
      startedAtMs: Number(row.official_start_at_ms) || null,
      crashDeadlineAtMs: Number(row.crash_deadline_at_ms) || null,
      crashedAtMs: Number(row.official_crash_at_ms) || null,
      settledAtMs,
      nextRoundAtMs: settledAtMs ? settledAtMs + ROUND_RESTART_DELAY_MS : null,
      currentMultiplierMilli: Number(row.current_multiplier_milli) || 1000,
      crashMultiplierMilli: row.crash_multiplier_milli == null ? null : Number(row.crash_multiplier_milli),
      seedCommitment: row.seed_commitment,
      seedReveal: row.seed_reveal || null,
      seedCiphertext: row.seed_ciphertext || null,
      seedIv: row.seed_iv || null,
      growthRatePpmPerSecond: Number(row.growth_rate_ppm_per_second) || GROWTH_RATE_PPM_PER_SECOND,
      maxMultiplierMilli: Number(row.max_multiplier_milli) || MAX_MULTIPLIER_MILLI
    };
  }

  async createRound(nowMs) {
    if (this.snapshot.schedulerPaused) {
      this.snapshot.round = null;
      await this.persistSnapshot();
      await this.ctx.storage.deleteAlarm();
      return;
    }
    readHexSecret(this.env.GAME_SEED_ENCRYPTION_KEY);
    const row = await this.dbFirst('SELECT COALESCE(MAX(round_number), 0) + 1 AS next_number FROM game_rounds');
    const roundNumber = Number(row?.next_number);
    if (!Number.isSafeInteger(roundNumber) || roundNumber < 1) {
      throw new GameError(503, 'ROUND_SEQUENCE_UNAVAILABLE', 'The next round could not be created.');
    }
    const seed = generateServerSeed();
    const [commitment, crashMultiplierMilli, encrypted] = await Promise.all([
      commitServerSeed(seed),
      getCrashMultiplierMilli(seed, roundNumber),
      this.encryptSeed(seed)
    ]);
    const roundId = crypto.randomUUID();
    const round = {
      id: roundId,
      number: roundNumber,
      engineStatus: 'WAITING',
      createdAtMs: nowMs,
      bettingOpenAtMs: nowMs + ROUND_WAIT_MS,
      bettingClosesAtMs: nowMs + ROUND_WAIT_MS + BETTING_DURATION_MS,
      startedAtMs: null,
      crashDeadlineAtMs: null,
      crashedAtMs: null,
      settledAtMs: null,
      nextRoundAtMs: null,
      currentMultiplierMilli: 1000,
      crashMultiplierMilli,
      seedCommitment: commitment,
      seedReveal: null,
      seedCiphertext: encrypted.ciphertext,
      seedIv: encrypted.iv,
      growthRatePpmPerSecond: GROWTH_RATE_PPM_PER_SECOND,
      maxMultiplierMilli: MAX_MULTIPLIER_MILLI
    };
    await this.dbRun(`
      INSERT INTO game_rounds (
        round_id, round_number, status, current_multiplier_milli,
        crash_multiplier_milli, seed_commitment, seed_reveal, created_at,
        engine_status, betting_open_at_ms, betting_closes_at_ms,
        growth_rate_ppm_per_second, max_multiplier_milli,
        seed_ciphertext, seed_iv, fairness_algorithm
      ) VALUES (?, ?, 'betting', 1000, ?, ?, NULL, ?, 'WAITING', ?, ?, ?, ?, ?, ?, ?)
    `,
    roundId,
    roundNumber,
    crashMultiplierMilli,
    commitment,
    Math.floor(nowMs / 1000),
    round.bettingOpenAtMs,
    round.bettingClosesAtMs,
    GROWTH_RATE_PPM_PER_SECOND,
    MAX_MULTIPLIER_MILLI,
    encrypted.ciphertext,
    encrypted.iv,
    FAIRNESS_ALGORITHM);
    this.snapshot.round = round;
    await this.persistSnapshot();
    await this.ctx.storage.setAlarm(round.bettingOpenAtMs);
    await this.emit('ROUND_CREATED', {
      roundId,
      roundNumber,
      createdAtMs: nowMs,
      bettingOpensAtMs: round.bettingOpenAtMs,
      bettingClosesAtMs: round.bettingClosesAtMs,
      seedCommitment: commitment,
      fairnessAlgorithm: FAIRNESS_ALGORITHM
    });
  }

  async updateRoundStatus(round, engineStatus, legacyStatus = null, values = []) {
    const status = legacyStatus || (engineStatus === 'RUNNING' ? 'flying'
      : engineStatus === 'CRASHED' ? 'crashed'
        : engineStatus === 'SETTLED' ? 'settled' : 'betting');
    const result = await this.dbRun(`
      UPDATE game_rounds
      SET engine_status = ?, status = ?, updated_at = ?
      WHERE round_id = ?
    `, engineStatus, status, Math.floor(Date.now() / 1000), round.id);
    if (result?.meta && Number(result.meta.changes) !== 1) {
      throw new GameError(503, 'ROUND_STATE_UNAVAILABLE', 'The active round could not be updated.');
    }
    round.engineStatus = engineStatus;
    await this.persistSnapshot();
    await this.emit(engineStatus, ...values);
  }

  async openBetting(round) {
    await this.dbRun(`
      UPDATE game_rounds
      SET engine_status = 'BETTING', betting_open_at_ms = ?
      WHERE round_id = ? AND engine_status = 'WAITING'
    `, round.bettingOpenAtMs, round.id);
    round.engineStatus = 'BETTING';
    await this.persistSnapshot();
    await this.emit('BETTING_OPEN', {
      roundId: round.id,
      roundNumber: round.number,
      bettingOpenedAtMs: round.bettingOpenAtMs,
      bettingClosesAtMs: round.bettingClosesAtMs,
      seedCommitment: round.seedCommitment
    });
  }

  async closeBetting(round) {
    await this.dbRun(`
      UPDATE game_rounds
      SET engine_status = 'BETTING_CLOSED'
      WHERE round_id = ? AND engine_status = 'BETTING'
    `, round.id);
    round.engineStatus = 'BETTING_CLOSED';
    await this.persistSnapshot();
    await this.emit('BETTING_CLOSED', {
      roundId: round.id,
      roundNumber: round.number,
      bettingClosedAtMs: round.bettingClosesAtMs
    });
  }

  async startRound(round, startAtMs) {
    const crashDeadlineAtMs = getMultiplierDeadlineMs(
      startAtMs,
      round.crashMultiplierMilli,
      round.growthRatePpmPerSecond
    );
    await this.dbRun(`
      UPDATE game_rounds
      SET engine_status = 'RUNNING', status = 'flying',
          official_start_at_ms = ?, started_at = ?
      WHERE round_id = ? AND engine_status = 'BETTING_CLOSED'
    `, startAtMs, Math.floor(startAtMs / 1000), round.id);
    round.engineStatus = 'RUNNING';
    round.startedAtMs = startAtMs;
    round.crashDeadlineAtMs = crashDeadlineAtMs;
    round.currentMultiplierMilli = 1000;
    await this.persistSnapshot();
    await this.emit('ROUND_STARTED', {
      roundId: round.id,
      roundNumber: round.number,
      startedAtMs: startAtMs,
      serverTimeMs: Date.now(),
      growthRatePpmPerSecond: round.growthRatePpmPerSecond,
      currentMultiplierMilli: 1000
    });
    await this.scheduleRunningAlarm(round, startAtMs);
  }

  async scheduleRunningAlarm(round, nowMs) {
    const autoRows = await this.dbAll(`
      SELECT bet_id, auto_cashout_multiplier_milli
      FROM bets
      WHERE round_id = ? AND status = 'open'
        AND auto_cashout_multiplier_milli IS NOT NULL
    `, round.id);
    let nextAlarmAtMs = round.crashDeadlineAtMs;
    for (const bet of autoRows) {
      const targetAtMs = getAutoCashoutAtMs(
        round.startedAtMs,
        Number(bet.auto_cashout_multiplier_milli),
        round.growthRatePpmPerSecond
      );
      if (targetAtMs < round.crashDeadlineAtMs && targetAtMs > nowMs) {
        nextAlarmAtMs = Math.min(nextAlarmAtMs, targetAtMs);
      }
    }
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, nextAlarmAtMs));
  }

  async processDueAutoCashouts(round, atMs) {
    const autoRows = await this.dbAll(`
      SELECT bet_id, firebase_uid, auto_cashout_multiplier_milli
      FROM bets
      WHERE round_id = ? AND status = 'open'
        AND auto_cashout_multiplier_milli IS NOT NULL
    `, round.id);
    for (const bet of autoRows) {
      const multiplierMilli = Number(bet.auto_cashout_multiplier_milli);
      const targetAtMs = getAutoCashoutAtMs(round.startedAtMs, multiplierMilli, round.growthRatePpmPerSecond);
      if (targetAtMs <= atMs && targetAtMs < round.crashDeadlineAtMs) {
        await this.cashout(
          bet.firebase_uid,
          bet.bet_id,
          `auto_${bet.bet_id.replace(/-/g, '')}`.slice(0, MAX_BET_IDEMPOTENCY_LENGTH),
          targetAtMs,
          multiplierMilli,
          true
        );
      }
    }
  }

  async crashRound(round, crashedAtMs) {
    await this.dbRun(`
      UPDATE game_rounds
      SET engine_status = 'CRASHED', status = 'crashed',
          official_crash_at_ms = ?, crashed_at = ?
      WHERE round_id = ? AND engine_status = 'RUNNING'
    `, crashedAtMs, Math.floor(crashedAtMs / 1000), round.id);
    round.engineStatus = 'CRASHED';
    round.crashedAtMs = crashedAtMs;
    await this.persistSnapshot();
    await this.emit('ROUND_CRASHED', {
      roundId: round.id,
      roundNumber: round.number,
      officialCrashAtMs: crashedAtMs,
      crashMultiplierMilli: round.crashMultiplierMilli
    });
    await this.settleRound(round, crashedAtMs);
  }

  async settleRound(round, settledAtMs) {
    const seed = await this.decryptSeed(round.seedCiphertext, round.seedIv);
    const valid = await commitServerSeed(seed) === round.seedCommitment &&
      await getCrashMultiplierMilli(seed, round.number) === round.crashMultiplierMilli;
    if (!valid) throw new GameError(503, 'FAIRNESS_VERIFICATION_FAILED', 'The round could not be settled safely.');

    round.engineStatus = 'SETTLING';
    await this.persistSnapshot();
    const totals = await this.dbFirst(`
      SELECT COUNT(*) AS accepted_count,
             SUM(CASE WHEN status = 'cashed_out' THEN 1 ELSE 0 END) AS cashed_count,
             SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS lost_count,
             COALESCE(SUM(amount_minor), 0) AS stakes_minor,
             COALESCE(SUM(CASE WHEN status = 'cashed_out' THEN payout_minor ELSE 0 END), 0) AS payouts_minor
      FROM bets
      WHERE round_id = ?
    `, round.id);
    const transactionResults = await this.dbBatch([
      this.env.DB.prepare(`
        UPDATE bets
        SET status = 'lost', settled_at = ?
        WHERE round_id = ? AND status = 'open'
      `).bind(Math.floor(settledAtMs / 1000), round.id),
      this.env.DB.prepare(`
        UPDATE game_rounds
        SET engine_status = 'SETTLED', status = 'settled',
            seed_reveal = ?, seed_ciphertext = NULL, seed_iv = NULL,
            settled_at = ?, settled_at_ms = ?
        WHERE round_id = ? AND engine_status IN ('CRASHED', 'SETTLING')
      `).bind(seed, Math.floor(settledAtMs / 1000), settledAtMs, round.id),
      this.env.DB.prepare(`
        INSERT OR IGNORE INTO round_settlements (
          round_id, round_number, crash_multiplier_milli,
          accepted_bet_count, cashed_out_bet_count, lost_bet_count,
          total_stakes_minor, total_payouts_minor, settled_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        round.id,
        round.number,
        round.crashMultiplierMilli,
        Number(totals?.accepted_count || 0),
        Number(totals?.cashed_count || 0),
        Number(totals?.lost_count || 0),
        Number(totals?.stakes_minor || 0),
        Number(totals?.payouts_minor || 0),
        settledAtMs
      ),
      this.env.DB.prepare(`
        INSERT OR IGNORE INTO game_fairness_records (
          round_id, algorithm, commitment, revealed_seed, round_nonce,
          house_edge_denominator, max_multiplier_milli, verified_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        round.id,
        FAIRNESS_ALGORITHM,
        round.seedCommitment,
        seed,
        round.number,
        HOUSE_EDGE_DENOMINATOR,
        round.maxMultiplierMilli,
        settledAtMs
      )
    ]);
    if (!transactionResults || transactionResults.length !== 4) {
      throw new GameError(503, 'SETTLEMENT_FAILED', 'The round settlement could not be confirmed.');
    }
    round.engineStatus = 'SETTLED';
    round.seedReveal = seed;
    round.seedCiphertext = null;
    round.seedIv = null;
    round.settledAtMs = settledAtMs;
    round.nextRoundAtMs = settledAtMs + ROUND_RESTART_DELAY_MS;
    await this.persistSnapshot();
    await this.emit('ROUND_SETTLED', {
      roundId: round.id,
      roundNumber: round.number,
      crashMultiplierMilli: round.crashMultiplierMilli,
      seedCommitment: round.seedCommitment,
      revealedSeed: seed,
      settledAtMs
    });
    if (!this.snapshot.schedulerPaused) {
      await this.ctx.storage.setAlarm(round.nextRoundAtMs);
    } else {
      await this.ctx.storage.deleteAlarm();
    }
  }

  async advance(nowMs) {
    if (!this.snapshot.round) {
      await this.createRound(nowMs);
      return;
    }
    const round = this.snapshot.round;
    if (round.engineStatus === 'INITIALIZING' || round.engineStatus === 'RECOVERY') {
      await this.dbRun(`
        UPDATE game_rounds
        SET engine_status = 'WAITING'
        WHERE round_id = ? AND engine_status IN ('INITIALIZING', 'RECOVERY')
      `, round.id);
      round.engineStatus = 'WAITING';
      await this.persistSnapshot();
    }
    if (round.engineStatus === 'WAITING' && nowMs >= round.bettingOpenAtMs) {
      await this.openBetting(round);
    }
    if (round.engineStatus === 'BETTING' && nowMs >= round.bettingClosesAtMs) {
      await this.closeBetting(round);
    }
    if (round.engineStatus === 'BETTING_CLOSED') {
      await this.startRound(round, Math.max(nowMs, round.bettingClosesAtMs));
    }
    if (round.engineStatus === 'RUNNING') {
      await this.processDueAutoCashouts(round, nowMs);
      if (nowMs >= round.crashDeadlineAtMs) {
        await this.processDueAutoCashouts(round, round.crashDeadlineAtMs);
        await this.crashRound(round, round.crashDeadlineAtMs);
      } else {
        round.currentMultiplierMilli = Math.min(
          round.crashMultiplierMilli - 1,
          getMultiplierMilliAt(round.startedAtMs, nowMs, round.growthRatePpmPerSecond)
        );
        await this.persistSnapshot();
        await this.scheduleRunningAlarm(round, nowMs);
      }
    } else if (round.engineStatus === 'CRASHED' || round.engineStatus === 'SETTLING') {
      await this.settleRound(round, nowMs);
    } else if (round.engineStatus === 'SETTLED') {
      if (this.snapshot.schedulerPaused) {
        await this.ctx.storage.deleteAlarm();
      } else if (round.nextRoundAtMs && nowMs >= round.nextRoundAtMs) {
        await this.createRound(nowMs);
      } else if (round.nextRoundAtMs) {
        await this.ctx.storage.setAlarm(round.nextRoundAtMs);
      } else if (!this.snapshot.schedulerPaused) {
        await this.createRound(nowMs);
      }
    } else if (round.engineStatus === 'WAITING') {
      await this.ctx.storage.setAlarm(round.bettingOpenAtMs);
    } else if (round.engineStatus === 'BETTING') {
      await this.ctx.storage.setAlarm(round.bettingClosesAtMs);
    }
  }

  async publicState(serverTimeMs = Date.now()) {
    const round = this.snapshot.round;
    if (!round) {
      return {
        status: this.snapshot.schedulerPaused ? 'PAUSED' : 'INITIALIZING',
        schedulerPaused: this.snapshot.schedulerPaused,
        round: null,
        serverTimeMs
      };
    }
    let currentMultiplierMilli = round.currentMultiplierMilli;
    if (round.engineStatus === 'RUNNING') {
      currentMultiplierMilli = Math.min(
        round.crashMultiplierMilli - 1,
        getMultiplierMilliAt(round.startedAtMs, serverTimeMs, round.growthRatePpmPerSecond)
      );
    }
    const settled = round.engineStatus === 'SETTLED';
    return {
      status: statePhase(round, this.snapshot.schedulerPaused),
      schedulerPaused: this.snapshot.schedulerPaused,
      serverTimeMs,
      round: {
        id: round.id,
        number: round.number,
        status: round.engineStatus,
        createdAtMs: round.createdAtMs,
        bettingOpenAtMs: round.bettingOpenAtMs,
        bettingClosesAtMs: round.bettingClosesAtMs,
        startedAtMs: round.startedAtMs,
        currentMultiplierMilli,
        growthRatePpmPerSecond: round.growthRatePpmPerSecond,
        seedCommitment: round.seedCommitment,
        crashMultiplierMilli: settled || round.engineStatus === 'CRASHED'
          ? round.crashMultiplierMilli : null,
        officialCrashAtMs: settled || round.engineStatus === 'CRASHED'
          ? round.crashedAtMs : null,
        revealedSeed: settled ? round.seedReveal : null
      }
    };
  }

  async openSocket(request, receivedAtMs) {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      throw new GameError(426, 'WEBSOCKET_REQUIRED', 'A WebSocket connection is required.');
    }
    await this.advance(receivedAtMs);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.serializeAttachment({ connectedAtMs: receivedAtMs });
    this.ctx.acceptWebSocket(server, ['global-game']);
    server.send(JSON.stringify({
      type: 'ROUND_RECOVERED',
      id: `snapshot-${this.snapshot.round?.number || 0}-${this.snapshot.eventSequence}`,
      data: await this.publicState(receivedAtMs)
    }));
    return new Response(null, { status: 101, webSocket: client });
  }

  async emit(type, data) {
    this.snapshot.eventSequence += 1;
    await this.persistSnapshot();
    const event = JSON.stringify({
      type,
      id: String(this.snapshot.eventSequence),
      serverTimeMs: Date.now(),
      data
    });
    for (const socket of this.ctx.getWebSockets('global-game')) {
      try {
        if (socket.readyState === WebSocket.OPEN) socket.send(event);
      } catch {
        try { socket.close(1011, 'Broadcast failed.'); } catch {}
      }
    }
  }

  async placeBet(uid, body, idempotencyKey, receivedAtMs) {
    if (typeof uid !== 'string' || uid.length < 1 || uid.length > 128) {
      throw new GameError(401, 'AUTH_REQUIRED', 'Sign in to place demo bets.');
    }
    const allowedKeys = ['roundId', 'slot', 'amountMinor', 'autoCashoutMultiplierMilli'];
    if (Object.keys(body).some((key) => !allowedKeys.includes(key))) {
      throw new GameError(400, 'INVALID_BET', 'The bet request contains unsupported fields.');
    }
    const round = this.snapshot.round;
    if (!round || body.roundId !== round.id || round.engineStatus !== 'BETTING' ||
        this.snapshot.schedulerPaused || receivedAtMs >= round.bettingClosesAtMs) {
      throw new GameError(409, 'BETTING_CLOSED', 'This round is not accepting demo bets.');
    }
    const slot = safeNumber(body.slot, 'Bet slot');
    const amountMinor = safeNumber(body.amountMinor, 'Bet amount');
    const autoCashoutMultiplierMilli = body.autoCashoutMultiplierMilli == null
      ? null : safeNumber(body.autoCashoutMultiplierMilli, 'Auto cashout multiplier');
    if (![0, 1].includes(slot) || amountMinor < MIN_STAKE_MINOR || amountMinor > MAX_STAKE_MINOR ||
        (autoCashoutMultiplierMilli !== null &&
          (autoCashoutMultiplierMilli <= 1000 || autoCashoutMultiplierMilli > MAX_MULTIPLIER_MILLI))) {
      throw new GameError(400, 'INVALID_BET', 'The demo bet is outside the permitted limits.');
    }

    const existing = await this.dbFirst(`
      SELECT bet_id, round_id, slot_index, amount_minor, status,
             cashout_multiplier_milli, payout_minor
      FROM bets WHERE firebase_uid = ? AND idempotency_key = ?
    `, uid, idempotencyKey);
    if (existing) return this.mapBet(existing);

    const betId = crypto.randomUUID();
    const debitKey = `bet:${idempotencyKey}`;
    const statements = [
      this.env.DB.prepare(`
        UPDATE demo_wallets
        SET balance_minor = balance_minor - ?, updated_at = ?
        WHERE firebase_uid = ? AND balance_minor >= ?
          AND EXISTS (
            SELECT 1 FROM game_rounds
            WHERE round_id = ? AND engine_status = 'BETTING'
              AND betting_closes_at_ms > ?
          )
      `).bind(
        amountMinor, Math.floor(receivedAtMs / 1000), uid, amountMinor,
        round.id, receivedAtMs
      ),
      this.env.DB.prepare(`
        INSERT INTO bets (
          bet_id, round_id, firebase_uid, slot_index, amount_minor,
          auto_cashout_multiplier_milli, status, idempotency_key,
          accepted_at, settled_at, accepted_at_ms
        )
        SELECT ?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL, ?
        WHERE changes() = 1
      `).bind(
        betId, round.id, uid, slot, amountMinor,
        autoCashoutMultiplierMilli, idempotencyKey,
        Math.floor(receivedAtMs / 1000), receivedAtMs
      ),
      this.env.DB.prepare(`
        INSERT INTO demo_wallet_transactions (
          transaction_id, firebase_uid, transaction_type, amount_minor,
          balance_after_minor, reference_type, reference_id,
          idempotency_key, created_at
        )
        SELECT ?, ?, 'bet_debit', ?, w.balance_minor, 'bet', ?, ?, ?
        FROM demo_wallets w
        JOIN bets b ON b.bet_id = ?
        WHERE w.firebase_uid = ? AND changes() = 1
      `).bind(
        crypto.randomUUID(), uid, amountMinor, betId, debitKey,
        Math.floor(receivedAtMs / 1000), betId, uid
      )
    ];
    const batch = await this.dbBatch(statements);
    if (Number(batch?.[0]?.meta?.changes || 0) !== 1) {
      const wallet = await this.dbFirst(
        'SELECT balance_minor FROM demo_wallets WHERE firebase_uid = ?',
        uid
      );
      if (!wallet) throw new GameError(404, 'DEMO_WALLET_NOT_FOUND', 'Create your player profile before betting.');
      if (Number(wallet.balance_minor) < amountMinor) {
        throw new GameError(409, 'INSUFFICIENT_DEMO_CREDITS', 'Your demo balance is too low for this bet.');
      }
      throw new GameError(409, 'BETTING_CLOSED', 'The round no longer accepts demo bets.');
    }
    const accepted = await this.dbFirst(`
      SELECT b.bet_id, b.round_id, b.slot_index, b.amount_minor, b.status,
             b.cashout_multiplier_milli, b.payout_minor, p.display_name,
             w.balance_minor
      FROM bets b
      JOIN players p ON p.firebase_uid = b.firebase_uid
      JOIN demo_wallets w ON w.firebase_uid = b.firebase_uid
      WHERE b.bet_id = ?
    `, betId);
    if (!accepted) throw new GameError(503, 'BET_UNAVAILABLE', 'The accepted bet could not be confirmed.');
    await this.emit('BET_ACCEPTED', {
      roundId: round.id,
      betId,
      displayName: accepted.display_name,
      slot,
      amountMinor,
      autoCashoutMultiplierMilli
    });
    return {
      ...this.mapBet(accepted),
      demoBalanceMinor: Number(accepted.balance_minor)
    };
  }

  mapBet(row) {
    return {
      id: row.bet_id,
      roundId: row.round_id,
      slot: Number(row.slot_index),
      amountMinor: Number(row.amount_minor),
      status: row.status,
      cashoutMultiplierMilli: row.cashout_multiplier_milli == null
        ? null : Number(row.cashout_multiplier_milli),
      payoutMinor: row.payout_minor == null ? null : Number(row.payout_minor)
    };
  }

  async cashout(uid, betId, idempotencyKey, receivedAtMs, autoMultiplierMilli = null, isAutomatic = false) {
    if (typeof uid !== 'string' || uid.length < 1 || uid.length > 128) {
      throw new GameError(401, 'AUTH_REQUIRED', 'Sign in to cash out a demo bet.');
    }
    if (typeof betId !== 'string' || betId.length < 1 || betId.length > 128) {
      throw new GameError(400, 'INVALID_BET_ID', 'A valid bet identifier is required.');
    }
    const existing = await this.dbFirst(`
      SELECT bet_id, round_id, slot_index, amount_minor, status,
             cashout_multiplier_milli, payout_minor
      FROM bets
      WHERE firebase_uid = ? AND cashout_idempotency_key = ?
    `, uid, idempotencyKey);
    if (existing) return this.mapBet(existing);

    const round = this.snapshot.round;
    if (!round || round.engineStatus !== 'RUNNING' || receivedAtMs >= round.crashDeadlineAtMs) {
      throw new GameError(409, 'CASHOUT_TOO_LATE', 'The cashout arrived at or after the official crash deadline.');
    }
    const bet = await this.dbFirst(`
      SELECT bet_id, round_id, firebase_uid, amount_minor, status,
             auto_cashout_multiplier_milli
      FROM bets WHERE bet_id = ? AND firebase_uid = ?
    `, betId, uid);
    if (!bet) throw new GameError(404, 'BET_NOT_FOUND', 'This demo bet was not found.');
    if (bet.round_id !== round.id) throw new GameError(409, 'BET_ROUND_MISMATCH', 'This bet is not part of the active round.');
    if (bet.status !== 'open') throw new GameError(409, 'BET_NOT_OPEN', 'This demo bet can no longer be cashed out.');

    const multiplierMilli = autoMultiplierMilli == null
      ? Math.min(
        round.crashMultiplierMilli - 1,
        getMultiplierMilliAt(round.startedAtMs, receivedAtMs, round.growthRatePpmPerSecond)
      )
      : safeNumber(autoMultiplierMilli, 'Auto cashout multiplier');
    const payoutMinor = calculatePayoutMinor(Number(bet.amount_minor), multiplierMilli);
    const wallet = await this.dbFirst(
      'SELECT balance_minor FROM demo_wallets WHERE firebase_uid = ?',
      uid
    );
    if (!wallet || Number(wallet.balance_minor) > MAX_SAFE_INTEGER - payoutMinor) {
      throw new GameError(503, 'WALLET_LIMIT', 'The demo wallet could not safely receive this payout.');
    }
    const ledgerKey = `cashout:${idempotencyKey}`;
    const result = await this.dbBatch([
      this.env.DB.prepare(`
        UPDATE demo_wallets
        SET balance_minor = balance_minor + ?, updated_at = ?
        WHERE firebase_uid = ? AND balance_minor <= ?
          AND EXISTS (
            SELECT 1 FROM bets b
            JOIN game_rounds r ON r.round_id = b.round_id
            WHERE b.bet_id = ? AND b.firebase_uid = ? AND b.status = 'open'
              AND r.engine_status = 'RUNNING'
              AND ? < r.crash_deadline_at_ms
          )
      `).bind(
        payoutMinor, Math.floor(receivedAtMs / 1000), uid,
        MAX_SAFE_INTEGER - payoutMinor, betId, uid, receivedAtMs
      ),
      this.env.DB.prepare(`
        UPDATE bets
        SET status = 'cashed_out', cashout_multiplier_milli = ?,
            payout_minor = ?, cashout_received_at_ms = ?,
            cashout_idempotency_key = ?, settled_at = ?
        WHERE bet_id = ? AND firebase_uid = ? AND status = 'open'
          AND changes() = 1
          AND EXISTS (
            SELECT 1 FROM game_rounds r
            WHERE r.round_id = bets.round_id AND r.engine_status = 'RUNNING'
              AND ? < r.crash_deadline_at_ms
          )
      `).bind(
        multiplierMilli, payoutMinor, receivedAtMs,
        idempotencyKey, Math.floor(receivedAtMs / 1000),
        betId, uid, receivedAtMs
      ),
      this.env.DB.prepare(`
        INSERT INTO demo_wallet_transactions (
          transaction_id, firebase_uid, transaction_type, amount_minor,
          balance_after_minor, reference_type, reference_id,
          idempotency_key, created_at
        )
        SELECT ?, ?, 'win_credit', ?, w.balance_minor, 'bet', ?, ?, ?
        FROM demo_wallets w
        JOIN bets b ON b.firebase_uid = w.firebase_uid
        WHERE w.firebase_uid = ? AND b.bet_id = ?
          AND b.cashout_idempotency_key = ? AND changes() = 1
      `).bind(
        crypto.randomUUID(), uid, payoutMinor, betId, ledgerKey,
        Math.floor(receivedAtMs / 1000), uid, betId, idempotencyKey
      )
    ]);
    if (Number(result?.[0]?.meta?.changes || 0) !== 1) {
      const latest = await this.dbFirst(
        'SELECT status FROM bets WHERE bet_id = ? AND firebase_uid = ?',
        betId,
        uid
      );
      if (!latest) throw new GameError(404, 'BET_NOT_FOUND', 'This demo bet was not found.');
      throw new GameError(409, 'CASHOUT_TOO_LATE', 'The cashout could not be accepted before the official crash deadline.');
    }
    const updated = await this.dbFirst(`
      SELECT b.bet_id, b.round_id, b.slot_index, b.amount_minor, b.status,
             b.cashout_multiplier_milli, b.payout_minor, w.balance_minor,
             p.display_name
      FROM bets b JOIN demo_wallets w ON w.firebase_uid = b.firebase_uid
      JOIN players p ON p.firebase_uid = b.firebase_uid
      WHERE b.bet_id = ? AND b.firebase_uid = ?
    `, betId, uid);
    if (!updated) throw new GameError(503, 'CASHOUT_UNAVAILABLE', 'The cashout could not be confirmed.');
    const resultPayload = {
      ...this.mapBet(updated),
      demoBalanceMinor: Number(updated.balance_minor),
      automatic: isAutomatic
    };
    await this.emit('PLAYER_CASHED_OUT', {
      roundId: round.id,
      betId,
      displayName: updated.display_name,
      cashoutMultiplierMilli: multiplierMilli,
      payoutMinor,
      automatic: isAutomatic
    });
    return resultPayload;
  }

  async setSchedulerPaused(paused, actorUid) {
    if (typeof actorUid !== 'string' || actorUid.length < 1 || actorUid.length > 128) {
      throw new GameError(401, 'AUTH_REQUIRED', 'Administrator identity is required.');
    }
    const nowMs = Date.now();
    await this.dbBatch([
      this.env.DB.prepare(`
        UPDATE game_engine_config
        SET scheduler_paused = ?, updated_at_ms = ?
        WHERE singleton_id = 1
      `).bind(paused ? 1 : 0, nowMs),
      this.env.DB.prepare(`
        INSERT INTO game_audit_logs (
          audit_id, actor_uid, action, round_id, detail_json, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(),
        actorUid,
        paused ? 'pause' : 'resume',
        this.snapshot.round?.id || null,
        JSON.stringify({ schedulerPaused: paused }),
        nowMs
      )
    ]);
    this.snapshot.schedulerPaused = paused;
    await this.persistSnapshot();
    await this.emit(paused ? 'GAME_PAUSED' : 'GAME_RESUMED', {
      schedulerPaused: paused,
      currentRoundId: this.snapshot.round?.id || null
    });
    if (!paused) await this.advance(nowMs);
    else if (!this.snapshot.round || this.snapshot.round.engineStatus === 'SETTLED') {
      await this.ctx.storage.deleteAlarm();
    }
  }
}

const FIREBASE_PROJECT_ID = 'skyrush-2ac7f';
const FIREBASE_CERTS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const INITIAL_DEMO_BALANCE_MINOR = 1000000;
const RATE_WINDOW_SECONDS = 60;
const LOCAL_DEVELOPMENT_ORIGIN = 'http://127.0.0.1:5500';

let firebaseCertificates = null;
let firebaseCertificatesExpireAt = 0;
let firebasePublicKeys = new Map();
let lastRateLimitCleanupAt = 0;

class WorkerError extends Error {
  constructor(status, code, message, headers = {}) {
    super(message);
    this.name = 'WorkerError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

function jsonResponse(request, env, status, payload, extraHeaders = {}) {
  const headers = new Headers({
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff'
  });
  const origin = request.headers.get('Origin');
  if (origin && isAllowedOrigin(origin, env)) {
    headers.set('Access-Control-Allow-Origin', origin);
  }
  for (const [name, value] of Object.entries(extraHeaders)) {
    headers.set(name, value);
  }
  return new Response(JSON.stringify(payload), { status, headers });
}

function success(request, env, data, status = 200, headers = {}) {
  return jsonResponse(request, env, status, { ok: true, data }, headers);
}

function failure(request, env, status, code, message, headers = {}) {
  return jsonResponse(request, env, status, {
    ok: false,
    error: { code, message }
  }, headers);
}

function isAllowedOrigin(origin, env) {
  if (!origin) return true;
  if (origin === LOCAL_DEVELOPMENT_ORIGIN) return true;
  const configuredOrigin = env.FRONTEND_ORIGIN;
  if (typeof configuredOrigin !== 'string' || configuredOrigin.length === 0) return false;
  try {
    const parsed = new URL(configuredOrigin);
    return parsed.origin === configuredOrigin && origin === configuredOrigin;
  } catch {
    return false;
  }
}

function corsPreflight(request, env) {
  const origin = request.headers.get('Origin');
  const headers = new Headers({
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, Idempotency-Key',
    'Access-Control-Max-Age': '600',
    'Cache-Control': 'no-store',
    'Vary': 'Origin'
  });
  if (origin) headers.set('Access-Control-Allow-Origin', origin);
  return new Response(null, { status: 204, headers });
}

function requireDatabase(env) {
  if (!env.DB || typeof env.DB.prepare !== 'function') {
    throw new WorkerError(503, 'D1_NOT_CONFIGURED', 'The database is not available.');
  }
  return env.DB;
}

async function withDatabase(env, operation) {
  const db = requireDatabase(env);
  try {
    return await operation(db);
  } catch (error) {
    if (error instanceof WorkerError) throw error;
    console.error('D1 operation failed', databaseErrorDetails(error));
    throw new WorkerError(503, 'DATABASE_UNAVAILABLE', 'The database is temporarily unavailable.');
  }
}

function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - value.length % 4) % 4);
  try {
    const decoded = atob(base64);
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
}

function decodeJsonSegment(segment) {
  if (segment.length > 12000) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64Url(segment)));
  } catch {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
}

function readDerElement(bytes, offset) {
  if (offset >= bytes.length) throw new Error('Invalid certificate encoding.');
  const headerStart = offset;
  const tag = bytes[offset++];
  if ((tag & 0x1f) === 0x1f || offset >= bytes.length) {
    throw new Error('Unsupported certificate encoding.');
  }

  const firstLengthByte = bytes[offset++];
  let length = 0;
  if (firstLengthByte < 0x80) {
    length = firstLengthByte;
  } else {
    const byteCount = firstLengthByte & 0x7f;
    if (byteCount === 0 || byteCount > 4 || offset + byteCount > bytes.length) {
      throw new Error('Invalid certificate length.');
    }
    for (let index = 0; index < byteCount; index += 1) {
      length = length * 256 + bytes[offset++];
    }
  }

  const end = offset + length;
  if (end > bytes.length) throw new Error('Truncated certificate.');
  return { tag, headerStart, start: offset, end };
}

function certificateSubjectPublicKeyInfo(pem) {
  const encoded = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  const der = decodeBase64Url(encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''));
  const certificate = readDerElement(der, 0);
  if (certificate.tag !== 0x30 || certificate.end !== der.length) {
    throw new Error('Invalid X.509 certificate.');
  }
  const tbsCertificate = readDerElement(der, certificate.start);
  if (tbsCertificate.tag !== 0x30) throw new Error('Invalid X.509 certificate.');

  let offset = tbsCertificate.start;
  let element = readDerElement(der, offset);
  if (element.tag === 0xa0) {
    offset = element.end;
  }

  for (let index = 0; index < 6; index += 1) {
    element = readDerElement(der, offset);
    if (element.end > tbsCertificate.end) throw new Error('Invalid certificate structure.');
    offset = element.end;
    if (index === 5) {
      if (element.tag !== 0x30) throw new Error('Missing certificate public key.');
      return der.slice(element.headerStart, element.end);
    }
  }
  throw new Error('Missing certificate public key.');
}

function cacheMaxAge(response) {
  const cacheControl = response.headers.get('Cache-Control') || '';
  const match = cacheControl.match(/(?:^|,)\s*max-age=(\d+)/i);
  return match ? Number(match[1]) : 0;
}

async function loadFirebaseCertificates(forceRefresh = false) {
  if (!forceRefresh && firebaseCertificates && Date.now() < firebaseCertificatesExpireAt) {
    return firebaseCertificates;
  }

  let response;
  try {
    response = await fetch(FIREBASE_CERTS_URL, {
      headers: { 'Cache-Control': 'no-cache' }
    });
  } catch {
    throw new WorkerError(503, 'TOKEN_VERIFICATION_UNAVAILABLE', 'Sign-in verification is temporarily unavailable.');
  }
  if (!response.ok) {
    throw new WorkerError(503, 'TOKEN_VERIFICATION_UNAVAILABLE', 'Sign-in verification is temporarily unavailable.');
  }

  let certificates;
  try {
    certificates = await response.json();
  } catch {
    throw new WorkerError(503, 'TOKEN_VERIFICATION_UNAVAILABLE', 'Sign-in verification is temporarily unavailable.');
  }
  if (!certificates || typeof certificates !== 'object' || Array.isArray(certificates)) {
    throw new WorkerError(503, 'TOKEN_VERIFICATION_UNAVAILABLE', 'Sign-in verification is temporarily unavailable.');
  }

  const maxAge = Math.min(cacheMaxAge(response), 86400);
  firebaseCertificates = certificates;
  firebaseCertificatesExpireAt = Date.now() + maxAge * 1000;
  firebasePublicKeys = new Map();
  return certificates;
}

async function getFirebasePublicKey(keyId) {
  if (firebaseCertificates && Date.now() >= firebaseCertificatesExpireAt) {
    firebaseCertificates = null;
    firebasePublicKeys = new Map();
  }
  if (firebasePublicKeys.has(keyId)) return firebasePublicKeys.get(keyId);

  let certificates = await loadFirebaseCertificates();
  let certificate = certificates[keyId];
  if (typeof certificate !== 'string') {
    certificates = await loadFirebaseCertificates(true);
    certificate = certificates[keyId];
  }
  if (typeof certificate !== 'string') {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }

  try {
    const spki = certificateSubjectPublicKeyInfo(certificate);
    const key = await crypto.subtle.importKey(
      'spki',
      spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    firebasePublicKeys.set(keyId, key);
    return key;
  } catch (error) {
    if (error instanceof WorkerError) throw error;
    console.error('Firebase signing key could not be imported', { name: error?.name || 'Error' });
    throw new WorkerError(503, 'TOKEN_VERIFICATION_UNAVAILABLE', 'Sign-in verification is temporarily unavailable.');
  }
}

async function verifyFirebaseIdToken(token) {
  if (typeof token !== 'string' || token.length > 16384) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }

  const header = decodeJsonSegment(segments[0]);
  const claims = decodeJsonSegment(segments[1]);
  if (!header || header.alg !== 'RS256' || typeof header.kid !== 'string' ||
      (header.typ && header.typ !== 'JWT')) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }

  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== FIREBASE_PROJECT_ID ||
      claims.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}` ||
      typeof claims.sub !== 'string' || claims.sub.length < 1 || claims.sub.length > 128 ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= now ||
      !Number.isSafeInteger(claims.iat) || claims.iat > now + 60 ||
      (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now))) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }

  const key = await getFirebasePublicKey(header.kid);
  let signatureIsValid = false;
  try {
    signatureIsValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      decodeBase64Url(segments[2]),
      new TextEncoder().encode(`${segments[0]}.${segments[1]}`)
    );
  } catch {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }
  if (!signatureIsValid) {
    throw new WorkerError(401, 'INVALID_TOKEN', 'A valid sign-in token is required.');
  }

  return { uid: claims.sub, isAdmin: claims.admin === true };
}

function clientAddress(request) {
  return request.headers.get('CF-Connecting-IP') || 'unavailable';
}

async function hashKey(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function scheduleRateLimitCleanup(env, context, now) {
  if (!context || now - lastRateLimitCleanupAt < 600) return;
  lastRateLimitCleanupAt = now;
  const db = requireDatabase(env);
  context.waitUntil(
    db.prepare('DELETE FROM api_rate_limits WHERE updated_at < ?')
      .bind(now - 86400)
      .run()
      .catch((error) => {
        console.error('Rate-limit cleanup failed', { name: error?.name || 'Error' });
      })
  );
}

async function enforceRateLimit(env, context, actor, route, limit) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / RATE_WINDOW_SECONDS) * RATE_WINDOW_SECONDS;
  const actorHash = await hashKey(`skyrush-rate-v1:${actor}`);
  const row = await withDatabase(env, (db) => db.prepare(`
    INSERT INTO api_rate_limits (actor_hash, route_key, window_start, request_count, updated_at)
    VALUES (?, ?, ?, 1, ?)
    ON CONFLICT(actor_hash, route_key) DO UPDATE SET
      request_count = CASE
        WHEN api_rate_limits.window_start = excluded.window_start
          THEN api_rate_limits.request_count + 1
        ELSE 1
      END,
      window_start = excluded.window_start,
      updated_at = excluded.updated_at
    RETURNING request_count
  `).bind(actorHash, route, windowStart, now).first());

  if (!row || !Number.isSafeInteger(Number(row.request_count))) {
    throw new WorkerError(503, 'RATE_LIMIT_UNAVAILABLE', 'Request protection is temporarily unavailable.');
  }
  scheduleRateLimitCleanup(env, context, now);
  if (Number(row.request_count) > limit) {
    const retryAfter = RATE_WINDOW_SECONDS - (now % RATE_WINDOW_SECONDS);
    throw new WorkerError(429, 'RATE_LIMITED', 'Too many requests. Please try again shortly.', {
      'Retry-After': String(retryAfter)
    });
  }
}

async function authenticateRequest(request, env, context, route, userLimit) {
  await enforceRateLimit(env, context, `ip:${clientAddress(request)}`, `${route}:token`, 20);
  const authorization = request.headers.get('Authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9._~-]+)$/);
  if (!match) {
    throw new WorkerError(401, 'AUTH_REQUIRED', 'Sign in to access this resource.');
  }
  const player = await verifyFirebaseIdToken(match[1]);
  await enforceRateLimit(env, context, `uid:${player.uid}`, route, userLimit);
  return player;
}

async function limitPublicRequest(request, env, context, route, limit = 120) {
  await enforceRateLimit(env, context, `ip:${clientAddress(request)}`, route, limit);
}

async function readJsonObject(request) {
  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new WorkerError(415, 'JSON_REQUIRED', 'Send a JSON request body.');
  }
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 4096) {
    throw new WorkerError(413, 'REQUEST_TOO_LARGE', 'The request body is too large.');
  }

  let text;
  try {
    text = await request.text();
  } catch {
    throw new WorkerError(400, 'INVALID_JSON', 'The request body must be valid JSON.');
  }
  if (text.length > 4096) {
    throw new WorkerError(413, 'REQUEST_TOO_LARGE', 'The request body is too large.');
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new WorkerError(400, 'INVALID_JSON', 'The request body must be valid JSON.');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new WorkerError(400, 'INVALID_BODY', 'The request body must be a JSON object.');
  }
  return body;
}

function validateDisplayName(value) {
  if (typeof value !== 'string') {
    throw new WorkerError(400, 'INVALID_PROFILE', 'A display name is required.');
  }
  const displayName = value.trim().normalize('NFC');
  if (displayName.length < 1 || displayName.length > 32 || /[\u0000-\u001f\u007f]/.test(displayName)) {
    throw new WorkerError(400, 'INVALID_PROFILE', 'Display name must be 1 to 32 characters.');
  }
  return displayName;
}

function mapProfile(row) {
  return {
    displayName: row.display_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function getProfile(request, env, context) {
  const player = await authenticateRequest(request, env, context, 'profile:get', 60);
  return withDatabase(env, async (db) => {
    const row = await db.prepare(`
      SELECT display_name, created_at, updated_at
      FROM players
      WHERE firebase_uid = ?
    `).bind(player.uid).first();
    if (!row) throw new WorkerError(404, 'PROFILE_NOT_FOUND', 'Create your player profile to continue.');
    return success(request, env, mapProfile(row));
  });
}

async function postProfile(request, env, context) {
  const player = await authenticateRequest(request, env, context, 'profile:post', 10);
  const body = await readJsonObject(request);
  if (Object.keys(body).some((key) => key !== 'displayName')) {
    throw new WorkerError(400, 'INVALID_PROFILE', 'Only the displayName field can be changed.');
  }
  const displayName = validateDisplayName(body.displayName);
  const now = Math.floor(Date.now() / 1000);
  const transactionId = crypto.randomUUID();

  return withDatabase(env, async (db) => {
    await db.batch([
      db.prepare(`
        INSERT INTO players (firebase_uid, display_name, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(firebase_uid) DO UPDATE SET
          display_name = excluded.display_name,
          updated_at = excluded.updated_at
      `).bind(player.uid, displayName, now, now),
      db.prepare(`
        INSERT INTO demo_wallets (firebase_uid, balance_minor, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(firebase_uid) DO NOTHING
      `).bind(player.uid, INITIAL_DEMO_BALANCE_MINOR, now, now),
      // D1 batch is atomic; only ledger an initial credit when the wallet insert actually added a row.
      db.prepare(`
        INSERT INTO demo_wallet_transactions (
          transaction_id, firebase_uid, transaction_type, amount_minor,
          balance_after_minor, reference_type, reference_id, idempotency_key, created_at
        )
        SELECT ?, ?, 'initial_credit', ?, ?, 'profile_init', NULL, 'profile-initial-credit-v1', ?
        WHERE changes() = 1
        ON CONFLICT(firebase_uid, idempotency_key) DO NOTHING
      `).bind(
        transactionId,
        player.uid,
        INITIAL_DEMO_BALANCE_MINOR,
        INITIAL_DEMO_BALANCE_MINOR,
        now
      )
    ]);

    const row = await db.prepare(`
      SELECT display_name, created_at, updated_at
      FROM players
      WHERE firebase_uid = ?
    `).bind(player.uid).first();
    if (!row) throw new WorkerError(503, 'PROFILE_UNAVAILABLE', 'The player profile could not be saved.');
    return success(request, env, mapProfile(row));
  });
}

async function getDemoWallet(request, env, context) {
  const player = await authenticateRequest(request, env, context, 'wallet:demo:get', 60);
  return withDatabase(env, async (db) => {
    const [wallet, transactions] = await Promise.all([
      db.prepare(`
        SELECT balance_minor, updated_at
        FROM demo_wallets
        WHERE firebase_uid = ?
      `).bind(player.uid).first(),
      db.prepare(`
        SELECT transaction_id, transaction_type, amount_minor, balance_after_minor, created_at
        FROM demo_wallet_transactions
        WHERE firebase_uid = ?
        ORDER BY created_at DESC, transaction_id DESC
        LIMIT 25
      `).bind(player.uid).all()
    ]);
    if (!wallet) {
      throw new WorkerError(404, 'DEMO_WALLET_NOT_FOUND', 'Create your player profile to initialize a demo wallet.');
    }
    if (!Number.isSafeInteger(Number(wallet.balance_minor))) {
      throw new WorkerError(503, 'INVALID_WALLET_DATA', 'The demo wallet is temporarily unavailable.');
    }
    return success(request, env, {
      demoBalanceMinor: Number(wallet.balance_minor),
      currency: 'DEMO_CR',
      updatedAt: wallet.updated_at,
      transactions: (transactions.results || []).map((row) => ({
        id: row.transaction_id,
        type: row.transaction_type,
        amountMinor: Number(row.amount_minor),
        balanceAfterMinor: Number(row.balance_after_minor),
        createdAt: row.created_at
      }))
    });
  });
}

async function getGameStatus(request, env, context) {
  await limitPublicRequest(request, env, context, 'game:status:get');
  return withDatabase(env, async (db) => {
    const row = await db.prepare(`
      SELECT round_id, round_number, status, current_multiplier_milli, created_at, started_at
      FROM game_rounds
      WHERE status IN ('betting', 'flying')
      ORDER BY round_number DESC
      LIMIT 1
    `).first();
    return success(request, env, {
      round: row ? {
        id: row.round_id,
        number: row.round_number,
        status: row.status,
        currentMultiplierMilli: row.current_multiplier_milli,
        createdAt: row.created_at,
        startedAt: row.started_at
      } : null,
      authority: row ? 'd1_snapshot' : 'durable_object_pending',
      realMoneyEnabled: false
    });
  });
}

async function getGameHistory(request, env, context) {
  await limitPublicRequest(request, env, context, 'game:history:get');
  const url = new URL(request.url);
  const requestedLimit = Number(url.searchParams.get('limit') || 20);
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 50) {
    throw new WorkerError(400, 'INVALID_LIMIT', 'History limit must be from 1 to 50.');
  }
  return withDatabase(env, async (db) => {
    const result = await db.prepare(`
      SELECT round_id, round_number, crash_multiplier_milli, seed_commitment,
             started_at, crashed_at, settled_at, settled_at_ms
      FROM game_rounds
      WHERE status = 'settled' AND crash_multiplier_milli IS NOT NULL
      ORDER BY settled_at DESC, round_number DESC
      LIMIT ?
    `).bind(requestedLimit).all();
    return success(request, env, {
      rounds: (result.results || []).map((row) => ({
        id: row.round_id,
        number: row.round_number,
        crashMultiplierMilli: row.crash_multiplier_milli,
        seedCommitment: row.seed_commitment,
        startedAt: row.started_at,
        crashedAt: row.crashed_at,
        settledAt: row.settled_at,
        settledAtMs: row.settled_at_ms
      }))
    });
  });
}

function getGameStub(env) {
  if (!env.GAME) {
    throw new WorkerError(503, 'GAME_NOT_CONFIGURED', 'The authoritative game engine is not available.');
  }
  if (typeof env.GAME.getByName === 'function') return env.GAME.getByName('global-game');
  if (typeof env.GAME.idFromName === 'function' && typeof env.GAME.get === 'function') {
    return env.GAME.get(env.GAME.idFromName('global-game'));
  }
  throw new WorkerError(503, 'GAME_NOT_CONFIGURED', 'The authoritative game engine is not available.');
}

async function callGame(env, path, {
  method = 'GET',
  body,
  actor,
  admin = false,
  idempotencyKey,
  websocketRequest
} = {}) {
  const headers = new Headers({ Accept: 'application/json' });
  if (actor) headers.set('X-Game-Actor', actor);
  if (admin) headers.set('X-Game-Admin', 'true');
  if (idempotencyKey) headers.set('Idempotency-Key', idempotencyKey);
  if (body !== undefined) headers.set('Content-Type', 'application/json');

  let response;
  try {
    const gameRequest = websocketRequest
      ? new Request(`https://game.internal${path}`, websocketRequest)
      : new Request(`https://game.internal${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    response = await getGameStub(env).fetch(gameRequest);
  } catch (error) {
    console.error('Durable game request failed', {
      ...databaseErrorDetails(error),
      path
    });
    throw new WorkerError(503, 'GAME_UNAVAILABLE', 'The game service is temporarily unavailable.');
  }
  if (response.status === 101) return response;

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new WorkerError(503, 'GAME_INVALID_RESPONSE', 'The game service returned an invalid response.');
  }
  if (!response.ok || !payload || payload.ok !== true ||
      !Object.prototype.hasOwnProperty.call(payload, 'data')) {
    const error = payload?.error;
    throw new WorkerError(
      response.status >= 400 ? response.status : 503,
      typeof error?.code === 'string' ? error.code : 'GAME_UNAVAILABLE',
      typeof error?.message === 'string' ? error.message : 'The game service could not complete the request.'
    );
  }
  return payload.data;
}

async function getGameRound(request, env, context, roundId) {
  await limitPublicRequest(request, env, context, 'game:round:get');
  return withDatabase(env, async (db) => {
    const row = await db.prepare(`
      SELECT round_id, round_number, engine_status, status, created_at,
             betting_open_at_ms, betting_closes_at_ms, official_start_at_ms,
             official_crash_at_ms, crash_deadline_at_ms, current_multiplier_milli,
             crash_multiplier_milli, seed_commitment, seed_reveal, settled_at_ms
      FROM game_rounds
      WHERE round_id = ?
    `).bind(roundId).first();
    if (!row) throw new WorkerError(404, 'ROUND_NOT_FOUND', 'The requested round was not found.');
    const isSettled = row.engine_status === 'SETTLED';
    const hasCrashed = row.engine_status === 'CRASHED' || isSettled;
    return success(request, env, {
      id: row.round_id,
      number: Number(row.round_number),
      status: row.engine_status,
      createdAtMs: Number(row.created_at) * 1000,
      bettingOpenedAtMs: row.betting_open_at_ms,
      bettingClosesAtMs: row.betting_closes_at_ms,
      startedAtMs: row.official_start_at_ms,
      currentMultiplierMilli: row.current_multiplier_milli,
      officialCrashAtMs: hasCrashed ? row.official_crash_at_ms : null,
      crashMultiplierMilli: hasCrashed ? row.crash_multiplier_milli : null,
      seedCommitment: row.seed_commitment,
      revealedSeed: isSettled ? row.seed_reveal : null,
      settledAtMs: row.settled_at_ms
    });
  });
}

async function getGameFairness(request, env, context, roundId) {
  await limitPublicRequest(request, env, context, 'game:fairness:get');
  return withDatabase(env, async (db) => {
    const row = await db.prepare(`
      SELECT r.round_id, r.round_number, r.engine_status, r.seed_commitment,
             r.crash_multiplier_milli, r.seed_reveal, r.max_multiplier_milli,
             f.algorithm, f.house_edge_denominator
      FROM game_rounds r
      LEFT JOIN game_fairness_records f ON f.round_id = r.round_id
      WHERE r.round_id = ?
    `).bind(roundId).first();
    if (!row) throw new WorkerError(404, 'ROUND_NOT_FOUND', 'The requested round was not found.');
    const settled = row.engine_status === 'SETTLED' && typeof row.seed_reveal === 'string';
    return success(request, env, {
      roundId: row.round_id,
      roundNumber: Number(row.round_number),
      algorithm: row.algorithm || 'skyrush-hmac-sha256-v1',
      seedCommitment: row.seed_commitment,
      revealedSeed: settled ? row.seed_reveal : null,
      crashMultiplierMilli: settled ? row.crash_multiplier_milli : null,
      houseEdgeDenominator: row.house_edge_denominator || 33,
      maxMultiplierMilli: row.max_multiplier_milli,
      verified: settled
    });
  });
}

async function getPlayerBets(request, env, player, betId = null) {
  return withDatabase(env, async (db) => {
    const query = betId ? db.prepare(`
      SELECT bet_id, round_id, slot_index, amount_minor, auto_cashout_multiplier_milli,
             status, cashout_multiplier_milli, payout_minor, accepted_at_ms,
             cashout_received_at_ms, settled_at
      FROM bets
      WHERE firebase_uid = ? AND bet_id = ?
    `).bind(player.uid, betId) : db.prepare(`
      SELECT bet_id, round_id, slot_index, amount_minor, auto_cashout_multiplier_milli,
             status, cashout_multiplier_milli, payout_minor, accepted_at_ms,
             cashout_received_at_ms, settled_at
      FROM bets
      WHERE firebase_uid = ?
      ORDER BY accepted_at DESC, bet_id DESC
      LIMIT 50
    `).bind(player.uid);
    const rows = betId ? [await query.first()].filter(Boolean) : (await query.all()).results || [];
    if (betId && rows.length === 0) {
      throw new WorkerError(404, 'BET_NOT_FOUND', 'The requested bet was not found.');
    }
    return success(request, env, betId ? mapPlayerBet(rows[0]) : { bets: rows.map(mapPlayerBet) });
  });
}

function mapPlayerBet(row) {
  return {
    id: row.bet_id,
    roundId: row.round_id,
    slot: Number(row.slot_index),
    amountMinor: Number(row.amount_minor),
    autoCashoutMultiplierMilli: row.auto_cashout_multiplier_milli == null
      ? null : Number(row.auto_cashout_multiplier_milli),
    status: row.status,
    cashoutMultiplierMilli: row.cashout_multiplier_milli == null
      ? null : Number(row.cashout_multiplier_milli),
    payoutMinor: row.payout_minor == null ? null : Number(row.payout_minor),
    acceptedAtMs: row.accepted_at_ms,
    cashoutReceivedAtMs: row.cashout_received_at_ms,
    settledAt: row.settled_at
  };
}

async function handleRequest(request, env, context) {
  const url = new URL(request.url);
  const path = url.pathname;
  const liveBetCashout = path.match(/^\/api\/v1\/bets\/([^/]+)\/cashout$/);
  const playerBetPath = path.match(/^\/api\/v1\/player\/bets\/([^/]+)$/);
  const gameRoundPath = path.match(/^\/api\/v1\/game\/round\/([^/]+)$/);
  const fairnessPath = path.match(/^\/api\/v1\/game\/fairness\/([^/]+)$/);

  if (request.method === 'GET' && (path === '/api/v1/game/status' ||
      path === '/api/v1/game/round/current')) {
    await limitPublicRequest(request, env, context, 'game:state:get');
    const data = await callGame(env, '/state');
    return success(request, env, data);
  }
  if (request.method === 'GET' && path === '/api/v1/game/live') {
    await limitPublicRequest(request, env, context, 'game:live:get', 60);
    return callGame(env, '/socket', { method: 'GET', websocketRequest: request });
  }
  if (request.method === 'GET' && gameRoundPath && gameRoundPath[1] !== 'current') {
    let roundId;
    try { roundId = decodeURIComponent(gameRoundPath[1]); } catch {
      throw new WorkerError(400, 'INVALID_ROUND_ID', 'The round identifier is invalid.');
    }
    return getGameRound(request, env, context, roundId);
  }
  if (request.method === 'GET' && fairnessPath) {
    let roundId;
    try { roundId = decodeURIComponent(fairnessPath[1]); } catch {
      throw new WorkerError(400, 'INVALID_ROUND_ID', 'The round identifier is invalid.');
    }
    return getGameFairness(request, env, context, roundId);
  }
  if (request.method === 'POST' && path === '/api/v1/bets') {
    const player = await authenticateRequest(request, env, context, 'bets:post', 20);
    const body = await readJsonObject(request);
    const idempotencyKey = request.headers.get('Idempotency-Key') || '';
    if (!/^[A-Za-z0-9_-]{16,100}$/.test(idempotencyKey)) {
      throw new WorkerError(400, 'INVALID_IDEMPOTENCY_KEY', 'A valid idempotency key is required.');
    }
    const data = await callGame(env, '/bet', {
      method: 'POST',
      body,
      actor: player.uid,
      idempotencyKey
    });
    return success(request, env, data, 201);
  }
  if (request.method === 'POST' && liveBetCashout) {
    const player = await authenticateRequest(request, env, context, 'cashout:post', 30);
    const body = await readJsonObject(request);
    if (Object.keys(body).length !== 0) {
      throw new WorkerError(400, 'INVALID_CASHOUT', 'Cashout requests cannot specify a multiplier or payout.');
    }
    let betId;
    try { betId = decodeURIComponent(liveBetCashout[1]); } catch {
      throw new WorkerError(400, 'INVALID_BET_ID', 'The bet identifier is invalid.');
    }
    const idempotencyKey = request.headers.get('Idempotency-Key') || '';
    if (!/^[A-Za-z0-9_-]{16,100}$/.test(idempotencyKey)) {
      throw new WorkerError(400, 'INVALID_IDEMPOTENCY_KEY', 'A valid idempotency key is required.');
    }
    const data = await callGame(env, '/cashout', {
      method: 'POST',
      body: { betId },
      actor: player.uid,
      idempotencyKey
    });
    return success(request, env, data);
  }
  if (request.method === 'GET' && path === '/api/v1/player/bets') {
    const player = await authenticateRequest(request, env, context, 'player:bets:list', 60);
    return getPlayerBets(request, env, player);
  }
  if (request.method === 'GET' && playerBetPath) {
    const player = await authenticateRequest(request, env, context, 'player:bets:get', 60);
    let betId;
    try { betId = decodeURIComponent(playerBetPath[1]); } catch {
      throw new WorkerError(400, 'INVALID_BET_ID', 'The bet identifier is invalid.');
    }
    return getPlayerBets(request, env, player, betId);
  }
  if (request.method === 'POST' &&
      (path === '/api/v1/admin/game/pause' || path === '/api/v1/admin/game/resume')) {
    const player = await authenticateRequest(request, env, context, 'admin:game', 10);
    if (!player.isAdmin) throw new WorkerError(403, 'ADMIN_REQUIRED', 'Administrator permission is required.');
    const body = await readJsonObject(request);
    if (Object.keys(body).length !== 0) {
      throw new WorkerError(400, 'INVALID_ADMIN_REQUEST', 'The request body must be empty.');
    }
    const action = path.endsWith('/pause') ? 'pause' : 'resume';
    const data = await callGame(env, `/admin/${action}`, {
      method: 'POST',
      body: {},
      actor: player.uid,
      admin: true
    });
    return success(request, env, data);
  }
  if (request.method === 'GET' && path === '/api/v1/admin/game/health') {
    const player = await authenticateRequest(request, env, context, 'admin:game:health', 20);
    if (!player.isAdmin) {
      throw new WorkerError(403, 'ADMIN_REQUIRED', 'Administrator permission is required.');
    }
    const game = await callGame(env, '/health');
    return success(request, env, {
      durableObjectBinding: 'configured',
      ...game
    });
  }

  if (request.method === 'GET' && path === '/') {
    return success(request, env, {
      name: 'SkyRush API',
      version: 'v1',
      worker: 'skyrush-api',
      realMoneyEnabled: false
    });
  }
  if (request.method === 'GET' && path === '/health') {
    return success(request, env, { worker: 'ok', database: 'not_checked' });
  }
  if (request.method === 'GET' && path === '/db-health') {
    return withDatabase(env, async (db) => {
      const row = await db.prepare('SELECT 1 AS connected').first();
      if (!row || Number(row.connected) !== 1) {
        throw new WorkerError(503, 'D1_UNAVAILABLE', 'The database health check failed.');
      }
      return success(request, env, { d1: 'connected' });
    });
  }
  if (request.method === 'GET' && path === '/api/v1/game/status') {
    return getGameStatus(request, env, context);
  }
  if (request.method === 'GET' && path === '/api/v1/game/history') {
    return getGameHistory(request, env, context);
  }
  if (request.method === 'GET' && path === '/api/v1/player/profile') {
    return getProfile(request, env, context);
  }
  if (request.method === 'POST' && path === '/api/v1/player/profile') {
    return postProfile(request, env, context);
  }
  if (request.method === 'GET' && path === '/api/v1/wallet/demo') {
    return getDemoWallet(request, env, context);
  }
  const methodsByPath = {
    '/': ['GET'],
    '/health': ['GET'],
    '/db-health': ['GET'],
    '/api/v1/game/status': ['GET'],
    '/api/v1/game/history': ['GET'],
    '/api/v1/player/profile': ['GET', 'POST'],
    '/api/v1/wallet/demo': ['GET'],
    '/api/v1/game/round/current': ['GET'],
    '/api/v1/game/live': ['GET'],
    '/api/v1/bets': ['POST'],
    '/api/v1/player/bets': ['GET'],
    '/api/v1/admin/game/pause': ['POST'],
    '/api/v1/admin/game/resume': ['POST'],
    '/api/v1/admin/game/health': ['GET']
  };
  if (methodsByPath[path] || liveBetCashout || playerBetPath || gameRoundPath || fairnessPath) {
    throw new WorkerError(405, 'METHOD_NOT_ALLOWED', 'This method is not allowed for the endpoint.', {
      Allow: `${(methodsByPath[path] || (liveBetCashout ? ['POST'] :
        playerBetPath || gameRoundPath || fairnessPath ? ['GET'] : [])).join(', ')}, OPTIONS`
    });
  }
  throw new WorkerError(404, 'NOT_FOUND', 'The requested endpoint does not exist.');
}

export default {
  async fetch(request, env, context) {
    const origin = request.headers.get('Origin');
    if (!isAllowedOrigin(origin, env)) {
      return failure(request, env, 403, 'ORIGIN_NOT_ALLOWED', 'This website is not allowed to access the API.');
    }
    if (request.method === 'OPTIONS') return corsPreflight(request, env);

    try {
      return await handleRequest(request, env, context);
    } catch (error) {
      if (error instanceof WorkerError) {
        return failure(request, env, error.status, error.code, error.message, error.headers);
      }
      console.error('Unhandled Worker request error', {
        path: new URL(request.url).pathname,
        name: error?.name || 'Error'
      });
      return failure(request, env, 500, 'INTERNAL_ERROR', 'The request could not be completed.');
    }
  }
};

