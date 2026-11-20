-- Upgrade path for databases that already applied the original Phase 3 0001 migration.
-- New databases should use the consolidated 0001_phase3.sql only; do not run this afterward.
-- Timestamps ending in _ms are Unix epoch milliseconds; existing legacy timestamps remain seconds.
-- The Worker must not accept gameplay until this migration has been applied.

ALTER TABLE game_rounds
  ADD COLUMN updated_at INTEGER
    CHECK (updated_at IS NULL OR (typeof(updated_at) = 'integer' AND updated_at >= 0));

ALTER TABLE game_rounds
  ADD COLUMN engine_status TEXT NOT NULL DEFAULT 'SETTLED'
    CHECK (engine_status IN (
      'INITIALIZING', 'WAITING', 'BETTING', 'BETTING_CLOSED', 'RUNNING',
      'CRASHED', 'SETTLING', 'SETTLED', 'PAUSED', 'RECOVERY'
    ));

ALTER TABLE game_rounds
  ADD COLUMN betting_open_at_ms INTEGER
    CHECK (betting_open_at_ms IS NULL OR (typeof(betting_open_at_ms) = 'integer' AND betting_open_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN betting_closes_at_ms INTEGER
    CHECK (betting_closes_at_ms IS NULL OR (typeof(betting_closes_at_ms) = 'integer' AND betting_closes_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN official_start_at_ms INTEGER
    CHECK (official_start_at_ms IS NULL OR (typeof(official_start_at_ms) = 'integer' AND official_start_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN crash_deadline_at_ms INTEGER
    CHECK (crash_deadline_at_ms IS NULL OR (typeof(crash_deadline_at_ms) = 'integer' AND crash_deadline_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN official_crash_at_ms INTEGER
    CHECK (official_crash_at_ms IS NULL OR (typeof(official_crash_at_ms) = 'integer' AND official_crash_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN settled_at_ms INTEGER
    CHECK (settled_at_ms IS NULL OR (typeof(settled_at_ms) = 'integer' AND settled_at_ms >= 0));

ALTER TABLE game_rounds
  ADD COLUMN growth_rate_ppm_per_second INTEGER NOT NULL DEFAULT 80000
    CHECK (typeof(growth_rate_ppm_per_second) = 'integer' AND growth_rate_ppm_per_second BETWEEN 1 AND 1000000);

ALTER TABLE game_rounds
  ADD COLUMN max_multiplier_milli INTEGER NOT NULL DEFAULT 1000000000
    CHECK (typeof(max_multiplier_milli) = 'integer' AND max_multiplier_milli BETWEEN 1000 AND 9007199254740991);

ALTER TABLE game_rounds
  ADD COLUMN seed_ciphertext TEXT;

ALTER TABLE game_rounds
  ADD COLUMN seed_iv TEXT;

ALTER TABLE game_rounds
  ADD COLUMN fairness_algorithm TEXT NOT NULL DEFAULT 'skyrush-hmac-sha256-v1'
    CHECK (fairness_algorithm = 'skyrush-hmac-sha256-v1');

ALTER TABLE bets
  ADD COLUMN accepted_at_ms INTEGER
    CHECK (accepted_at_ms IS NULL OR (typeof(accepted_at_ms) = 'integer' AND accepted_at_ms >= 0));

ALTER TABLE bets
  ADD COLUMN cashout_received_at_ms INTEGER
    CHECK (cashout_received_at_ms IS NULL OR (typeof(cashout_received_at_ms) = 'integer' AND cashout_received_at_ms >= 0));

ALTER TABLE bets
  ADD COLUMN cashout_idempotency_key TEXT
    CHECK (cashout_idempotency_key IS NULL OR length(cashout_idempotency_key) BETWEEN 1 AND 128);

CREATE UNIQUE INDEX ux_bets_player_cashout_idempotency
  ON bets (firebase_uid, cashout_idempotency_key)
  WHERE cashout_idempotency_key IS NOT NULL;

CREATE INDEX idx_game_rounds_engine_status
  ON game_rounds (engine_status, round_number DESC);

CREATE UNIQUE INDEX ux_game_rounds_single_active
  ON game_rounds ((1))
  WHERE engine_status <> 'SETTLED';

CREATE TABLE game_engine_config (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  scheduler_paused INTEGER NOT NULL DEFAULT 0 CHECK (scheduler_paused IN (0, 1)),
  updated_at_ms INTEGER NOT NULL CHECK (typeof(updated_at_ms) = 'integer' AND updated_at_ms >= 0)
);

INSERT OR IGNORE INTO game_engine_config (singleton_id, scheduler_paused, updated_at_ms)
VALUES (1, 0, 0);

CREATE TABLE round_settlements (
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

CREATE TABLE game_audit_logs (
  audit_id TEXT PRIMARY KEY NOT NULL,
  actor_uid TEXT NOT NULL CHECK (length(actor_uid) BETWEEN 1 AND 128),
  action TEXT NOT NULL CHECK (action IN ('pause', 'resume')),
  round_id TEXT,
  detail_json TEXT NOT NULL CHECK (json_valid(detail_json)),
  created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
  FOREIGN KEY (round_id) REFERENCES game_rounds(round_id) ON DELETE RESTRICT
);

CREATE INDEX idx_game_audit_logs_created
  ON game_audit_logs (created_at_ms DESC);

CREATE TABLE game_fairness_records (
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

CREATE INDEX idx_game_fairness_verified
  ON game_fairness_records (verified_at_ms DESC);
