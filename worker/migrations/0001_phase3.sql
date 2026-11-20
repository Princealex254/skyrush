-- Complete SkyRush D1 schema for new databases, including the authoritative game engine.
-- All balances and transaction amounts are demo-credit minor units (1 credit = 100 units).
-- Multipliers are stored in thousandths (1.25x = 1250).
-- This schema contains no real-money wallet or payment tables.

CREATE TABLE IF NOT EXISTS players (
  firebase_uid TEXT PRIMARY KEY NOT NULL
    CHECK (length(firebase_uid) BETWEEN 1 AND 128),
  display_name TEXT NOT NULL
    CHECK (length(display_name) BETWEEN 1 AND 32),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
);

CREATE TABLE IF NOT EXISTS demo_wallets (
  firebase_uid TEXT PRIMARY KEY NOT NULL,
  balance_minor INTEGER NOT NULL
    CHECK (typeof(balance_minor) = 'integer' AND balance_minor BETWEEN 0 AND 9007199254740991),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  FOREIGN KEY (firebase_uid) REFERENCES players(firebase_uid) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS demo_wallet_transactions (
  transaction_id TEXT PRIMARY KEY NOT NULL,
  firebase_uid TEXT NOT NULL,
  transaction_type TEXT NOT NULL CHECK (
    transaction_type IN (
      'initial_credit',
      'bet_debit',
      'win_credit',
      'refund',
      'adjustment',
      'daily_bonus'
    )
  ),
  amount_minor INTEGER NOT NULL
    CHECK (typeof(amount_minor) = 'integer' AND amount_minor BETWEEN 1 AND 9007199254740991),
  balance_after_minor INTEGER NOT NULL
    CHECK (typeof(balance_after_minor) = 'integer' AND balance_after_minor BETWEEN 0 AND 9007199254740991),
  reference_type TEXT NOT NULL CHECK (
    reference_type IN ('profile_init', 'bet', 'round', 'bonus', 'admin')
  ),
  reference_id TEXT,
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  FOREIGN KEY (firebase_uid) REFERENCES demo_wallets(firebase_uid) ON DELETE RESTRICT,
  UNIQUE (firebase_uid, idempotency_key)
);

CREATE TABLE IF NOT EXISTS game_rounds (
  round_id TEXT PRIMARY KEY NOT NULL,
  round_number INTEGER NOT NULL UNIQUE
    CHECK (typeof(round_number) = 'integer' AND round_number > 0),
  status TEXT NOT NULL CHECK (status IN ('betting', 'flying', 'crashed', 'settled')),
  current_multiplier_milli INTEGER NOT NULL DEFAULT 1000
    CHECK (
      typeof(current_multiplier_milli) = 'integer' AND
      current_multiplier_milli BETWEEN 1000 AND 9007199254740991
    ),
  crash_multiplier_milli INTEGER
    CHECK (
      crash_multiplier_milli IS NULL OR
      (typeof(crash_multiplier_milli) = 'integer' AND
       crash_multiplier_milli BETWEEN 1000 AND 9007199254740991)
    ),
  seed_commitment TEXT,
  seed_reveal TEXT,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER CHECK (updated_at >= 0),
  started_at INTEGER,
  crashed_at INTEGER,
  settled_at INTEGER,
  engine_status TEXT NOT NULL DEFAULT 'SETTLED'
    CHECK (engine_status IN (
      'INITIALIZING', 'WAITING', 'BETTING', 'BETTING_CLOSED', 'RUNNING',
      'CRASHED', 'SETTLING', 'SETTLED', 'PAUSED', 'RECOVERY'
    )),
  betting_open_at_ms INTEGER
    CHECK (betting_open_at_ms IS NULL OR (typeof(betting_open_at_ms) = 'integer' AND betting_open_at_ms >= 0)),
  betting_closes_at_ms INTEGER
    CHECK (betting_closes_at_ms IS NULL OR (typeof(betting_closes_at_ms) = 'integer' AND betting_closes_at_ms >= 0)),
  official_start_at_ms INTEGER
    CHECK (official_start_at_ms IS NULL OR (typeof(official_start_at_ms) = 'integer' AND official_start_at_ms >= 0)),
  crash_deadline_at_ms INTEGER
    CHECK (crash_deadline_at_ms IS NULL OR (typeof(crash_deadline_at_ms) = 'integer' AND crash_deadline_at_ms >= 0)),
  official_crash_at_ms INTEGER
    CHECK (official_crash_at_ms IS NULL OR (typeof(official_crash_at_ms) = 'integer' AND official_crash_at_ms >= 0)),
  settled_at_ms INTEGER
    CHECK (settled_at_ms IS NULL OR (typeof(settled_at_ms) = 'integer' AND settled_at_ms >= 0)),
  growth_rate_ppm_per_second INTEGER NOT NULL DEFAULT 80000
    CHECK (typeof(growth_rate_ppm_per_second) = 'integer' AND growth_rate_ppm_per_second BETWEEN 1 AND 1000000),
  max_multiplier_milli INTEGER NOT NULL DEFAULT 1000000000
    CHECK (typeof(max_multiplier_milli) = 'integer' AND max_multiplier_milli BETWEEN 1000 AND 9007199254740991),
  seed_ciphertext TEXT,
  seed_iv TEXT,
  fairness_algorithm TEXT NOT NULL DEFAULT 'skyrush-hmac-sha256-v1'
    CHECK (fairness_algorithm = 'skyrush-hmac-sha256-v1'),
  CHECK (started_at IS NULL OR started_at >= created_at),
  CHECK (crashed_at IS NULL OR started_at IS NOT NULL),
  CHECK (settled_at IS NULL OR crashed_at IS NOT NULL),
  CHECK (status NOT IN ('crashed', 'settled') OR crash_multiplier_milli IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS bets (
  bet_id TEXT PRIMARY KEY NOT NULL,
  round_id TEXT NOT NULL,
  firebase_uid TEXT NOT NULL,
  slot_index INTEGER NOT NULL CHECK (typeof(slot_index) = 'integer' AND slot_index IN (0, 1)),
  amount_minor INTEGER NOT NULL
    CHECK (typeof(amount_minor) = 'integer' AND amount_minor BETWEEN 1 AND 9007199254740991),
  auto_cashout_multiplier_milli INTEGER
    CHECK (
      auto_cashout_multiplier_milli IS NULL OR
      (typeof(auto_cashout_multiplier_milli) = 'integer' AND
       auto_cashout_multiplier_milli BETWEEN 1001 AND 9007199254740991)
    ),
  status TEXT NOT NULL CHECK (status IN ('open', 'cashed_out', 'lost', 'cancelled')),
  cashout_multiplier_milli INTEGER
    CHECK (
      cashout_multiplier_milli IS NULL OR
      (typeof(cashout_multiplier_milli) = 'integer' AND
       cashout_multiplier_milli BETWEEN 1000 AND 9007199254740991)
    ),
  payout_minor INTEGER
    CHECK (
      payout_minor IS NULL OR
      (typeof(payout_minor) = 'integer' AND payout_minor BETWEEN 0 AND 9007199254740991)
    ),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  accepted_at INTEGER NOT NULL CHECK (accepted_at >= 0),
  accepted_at_ms INTEGER
    CHECK (accepted_at_ms IS NULL OR (typeof(accepted_at_ms) = 'integer' AND accepted_at_ms >= 0)),
  cashout_received_at_ms INTEGER
    CHECK (cashout_received_at_ms IS NULL OR (typeof(cashout_received_at_ms) = 'integer' AND cashout_received_at_ms >= 0)),
  cashout_idempotency_key TEXT
    CHECK (cashout_idempotency_key IS NULL OR length(cashout_idempotency_key) BETWEEN 1 AND 128),
  settled_at INTEGER,
  FOREIGN KEY (round_id) REFERENCES game_rounds(round_id) ON DELETE RESTRICT,
  FOREIGN KEY (firebase_uid) REFERENCES players(firebase_uid) ON DELETE RESTRICT,
  UNIQUE (firebase_uid, idempotency_key),
  UNIQUE (round_id, firebase_uid, slot_index),
  CHECK (
    (status = 'cashed_out' AND cashout_multiplier_milli IS NOT NULL AND payout_minor IS NOT NULL)
    OR
    (status <> 'cashed_out' AND cashout_multiplier_milli IS NULL AND payout_minor IS NULL)
  ),
  CHECK (settled_at IS NULL OR settled_at >= accepted_at)
);

-- D1-backed fixed-window request counters. Actor identifiers are SHA-256 hashed in the Worker.
CREATE TABLE IF NOT EXISTS api_rate_limits (
  actor_hash TEXT NOT NULL CHECK (length(actor_hash) = 64),
  route_key TEXT NOT NULL CHECK (length(route_key) BETWEEN 1 AND 64),
  window_start INTEGER NOT NULL CHECK (window_start >= 0),
  request_count INTEGER NOT NULL CHECK (request_count > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  PRIMARY KEY (actor_hash, route_key)
);

CREATE TABLE IF NOT EXISTS game_engine_config (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  scheduler_paused INTEGER NOT NULL DEFAULT 0 CHECK (scheduler_paused IN (0, 1)),
  updated_at_ms INTEGER NOT NULL CHECK (typeof(updated_at_ms) = 'integer' AND updated_at_ms >= 0)
);

INSERT OR IGNORE INTO game_engine_config (singleton_id, scheduler_paused, updated_at_ms)
VALUES (1, 0, 0);

CREATE TABLE IF NOT EXISTS round_settlements (
  round_id TEXT PRIMARY KEY NOT NULL,
  round_number INTEGER NOT NULL UNIQUE CHECK (typeof(round_number) = 'integer' AND round_number > 0),
  crash_multiplier_milli INTEGER NOT NULL
    CHECK (typeof(crash_multiplier_milli) = 'integer' AND crash_multiplier_milli BETWEEN 1000 AND 9007199254740991),
  accepted_bet_count INTEGER NOT NULL CHECK (typeof(accepted_bet_count) = 'integer' AND accepted_bet_count >= 0),
  cashed_out_bet_count INTEGER NOT NULL CHECK (typeof(cashed_out_bet_count) = 'integer' AND cashed_out_bet_count >= 0),
  lost_bet_count INTEGER NOT NULL CHECK (typeof(lost_bet_count) = 'integer' AND lost_bet_count >= 0),
  total_stakes_minor INTEGER NOT NULL
    CHECK (typeof(total_stakes_minor) = 'integer' AND total_stakes_minor BETWEEN 0 AND 9007199254740991),
  total_payouts_minor INTEGER NOT NULL
    CHECK (typeof(total_payouts_minor) = 'integer' AND total_payouts_minor BETWEEN 0 AND 9007199254740991),
  settled_at_ms INTEGER NOT NULL CHECK (typeof(settled_at_ms) = 'integer' AND settled_at_ms >= 0),
  FOREIGN KEY (round_id) REFERENCES game_rounds(round_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS game_audit_logs (
  audit_id TEXT PRIMARY KEY NOT NULL,
  actor_uid TEXT NOT NULL CHECK (length(actor_uid) BETWEEN 1 AND 128),
  action TEXT NOT NULL CHECK (action IN ('pause', 'resume')),
  round_id TEXT,
  detail_json TEXT NOT NULL CHECK (json_valid(detail_json)),
  created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
  FOREIGN KEY (round_id) REFERENCES game_rounds(round_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS game_fairness_records (
  round_id TEXT PRIMARY KEY NOT NULL,
  algorithm TEXT NOT NULL CHECK (algorithm = 'skyrush-hmac-sha256-v1'),
  commitment TEXT NOT NULL CHECK (length(commitment) = 64),
  revealed_seed TEXT NOT NULL CHECK (length(revealed_seed) = 64),
  round_nonce INTEGER NOT NULL CHECK (typeof(round_nonce) = 'integer' AND round_nonce > 0),
  house_edge_denominator INTEGER NOT NULL CHECK (house_edge_denominator = 33),
  max_multiplier_milli INTEGER NOT NULL
    CHECK (typeof(max_multiplier_milli) = 'integer' AND max_multiplier_milli BETWEEN 1000 AND 9007199254740991),
  verified_at_ms INTEGER NOT NULL CHECK (typeof(verified_at_ms) = 'integer' AND verified_at_ms >= 0),
  FOREIGN KEY (round_id) REFERENCES game_rounds(round_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_demo_wallet_transactions_player_time
  ON demo_wallet_transactions (firebase_uid, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_demo_wallet_transactions_reference
  ON demo_wallet_transactions (reference_type, reference_id);

CREATE INDEX IF NOT EXISTS idx_game_rounds_status_number
  ON game_rounds (status, round_number DESC);

CREATE INDEX IF NOT EXISTS idx_game_rounds_settled_time
  ON game_rounds (settled_at DESC);

CREATE INDEX IF NOT EXISTS idx_bets_round_status
  ON bets (round_id, status);

CREATE INDEX IF NOT EXISTS idx_bets_player_time
  ON bets (firebase_uid, accepted_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated
  ON api_rate_limits (updated_at);

CREATE UNIQUE INDEX IF NOT EXISTS ux_bets_player_cashout_idempotency
  ON bets (firebase_uid, cashout_idempotency_key)
  WHERE cashout_idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_game_rounds_engine_status
  ON game_rounds (engine_status, round_number DESC);

CREATE UNIQUE INDEX IF NOT EXISTS ux_game_rounds_single_active
  ON game_rounds ((1))
  WHERE engine_status <> 'SETTLED';

CREATE INDEX IF NOT EXISTS idx_game_audit_logs_created
  ON game_audit_logs (created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_game_fairness_verified
  ON game_fairness_records (verified_at_ms DESC);
