# Global Traffic Multiplier Implementation Plan

**Goal:** Add one global 1.00–5.00 traffic billing multiplier, applying only to subsequent traffic, with real and billed usage visible and kernel-enforced exhaustion.

**Architecture:** Keep existing direction/kernel counters in real bytes. Store billed bytes and a hundredth-byte carry per period; settle real counter increments at the current integer percentage. Guard multiplier changes with the existing freeze/checkpoint/transaction/install sequence. Derive the kernel's real-byte limit from the remaining billed budget, without rewriting past usage.

**Tech Stack:** Lua 5.1, SQLite migrations, nftables shared quotas, native LuCI JavaScript.

## Steps

1. Add exact integer billing arithmetic and schema v2 migration. Existing periods start with billed usage equal to their effective original usage; new periods start at zero. Preserve old raw counters and use a durable settings-change journal.
2. Integrate billing into checkpoint, snapshots, account projections, quota edits, authentication, rollover and summaries. Expose integer `traffic_multiplier_percent` through administrator RPC. Validate 100–500 inclusive; reject fractions and unknown arguments.
3. Add a separate billing settings panel with presets, examples and explicit confirmation. Update account, overview, traffic and portal displays to label billed and real usage consistently.
4. Add meaningful arithmetic/domain/rule tests: no retroactive billing, carry across updates/restarts, stale/duplicate readings, changed quotas, rollover, shared limits, migration and transaction failure.
5. Run Python/JavaScript checks, source Lua suites on the real MT3000 against isolated temporary databases, and build packages. Verify runtime UI if the device can be safely updated. Document any unperformed acceptance checks.

## Acceptance examples

- Default 100 preserves existing behavior.
- 20 GB at 100%, then 10 GB at 120% => real 30 GB, billed 32 GB.
- Reverting to 100% never reduces past billed usage.
- 12 GB remaining at 120% allows approximately 10 GB real traffic before the shared kernel quota stops forwarding.
- Saving billing settings changes neither account quotas nor reset dates, and requires no SSH for customers.
