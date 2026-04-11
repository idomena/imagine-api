-- =============================================================================
-- Migration: add_security_audit_report
-- =============================================================================
--
-- SAFETY ANALYSIS — read before applying:
--
--   ✓  No existing table is dropped
--   ✓  No existing column is altered or dropped
--   ✓  No existing index is dropped
--   ✓  The App table is NOT modified (the relation field
--       "securityAuditReport" in schema.prisma is a Prisma virtual field;
--       the foreign key lives entirely on the new SecurityAuditReport table)
--   ✓  All new columns are either NOT NULL with a default, or nullable
--   ✓  Safe to run against a live database (only CREATE / ALTER ADD statements)
--
-- Apply options:
--   A) psql "$DATABASE_URL" -f migration.sql
--   B) npx prisma db push          (safe — additive-only diff)
--   C) npx prisma generate         (after option A, to refresh the client)
-- =============================================================================

-- 1. New enum type ─────────────────────────────────────────────────────────────

CREATE TYPE "SecurityDecision" AS ENUM (
  'AUTO_PUBLISHED',
  'HELD_FOR_REVIEW',
  'AUTO_REJECTED'
);

-- 2. New table ─────────────────────────────────────────────────────────────────

CREATE TABLE "SecurityAuditReport" (
    "id"          TEXT                NOT NULL,
    "appId"       TEXT                NOT NULL,
    "createdAt"   TIMESTAMP(3)        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"   TIMESTAMP(3)        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "decision"    "SecurityDecision"  NOT NULL,
    "safetyScore" INTEGER             NOT NULL,
    "phase1"      JSONB,
    "phase2"      JSONB,
    "phase3"      JSONB,
    "threats"     JSONB,
    "warnings"    JSONB,

    CONSTRAINT "SecurityAuditReport_pkey" PRIMARY KEY ("id")
);

-- 3. Indexes ───────────────────────────────────────────────────────────────────

-- Unique: one audit report per app (upserted on every submission)
CREATE UNIQUE INDEX "SecurityAuditReport_appId_key"
    ON "SecurityAuditReport"("appId");

-- Regular index for admin queries filtering by appId
CREATE INDEX "SecurityAuditReport_appId_idx"
    ON "SecurityAuditReport"("appId");

-- 4. Foreign key to App ────────────────────────────────────────────────────────
--    CASCADE DELETE: removing an App also removes its audit report.
--    The App table itself is NOT modified in any way.

ALTER TABLE "SecurityAuditReport"
    ADD CONSTRAINT "SecurityAuditReport_appId_fkey"
    FOREIGN KEY ("appId")
    REFERENCES "App"("id")
    ON DELETE CASCADE
    ON UPDATE CASCADE;
