# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""
kern_explorer.indexer
=====================

Background chain follower. Polls the Kern RPC for new blocks, parses each
block's transactions, materializes them into the SQLite tables, and
maintains derived state (account balances, contract storage snapshots,
attestation registry mirror, slashing log).

Design:
- Single async task started by the web app at startup
- One block at a time, in order; if the node is ahead by N blocks we
  catch up sequentially (no parallel fetch — simpler, and devnet/testnet
  block production is slow enough that this is fine)
- On RPC error, exponential backoff up to 30s, then retry
- The indexer cursor (latest_indexed_level) is persisted to the `meta`
  table, so restart resumes where it left off

Skald template detection (basic heuristic, refined in session 4):
- We pattern-match on the contract source for `contract STO...`,
  `contract QuadraticFunding...`, `contract Retroactive...`,
  `contract GenericDataOracle`, `contract DefiPriceOracle`,
  `contract SchemaMarketplaceEntry`, etc.
- Detected template name lets the web app organize contracts by
  vertical (compliance / public goods / oracle)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional

from .client import KernRpcClient, KernRpcError
from .db import (
    init_schema,
    latest_indexed_level,
    open_db,
    set_meta,
    transaction,
    upsert_account,
)


logger = logging.getLogger("heimdall.indexer")


# Detection patterns for the known Skald templates shipped with v1.1-rc.
# These let us classify contracts as they're originated, so the explorer
# can group them by vertical on the dashboards.
TEMPLATE_PATTERNS = [
    ("sto-startup-equity",     re.compile(r"contract\s+StoStartupEquity\b")),
    ("sto-institutional-fund", re.compile(r"contract\s+StoInstitutionalFund\b")),
    ("sto-real-estate",        re.compile(r"contract\s+StoRealEstate\b")),
    ("quadratic-funding",      re.compile(r"contract\s+QuadraticFundingProject\b")),
    ("retroactive-pgf",        re.compile(r"contract\s+RetroactivePgfNomination\b")),
    ("generic-data-oracle",    re.compile(r"contract\s+GenericDataOracle\b")),
    ("defi-price-oracle",      re.compile(r"contract\s+DefiPriceOracle\b")),
    ("schema-marketplace",     re.compile(r"contract\s+SchemaMarketplaceEntry\b")),
    ("vault-example",          re.compile(r"contract\s+Vault\b")),
    ("counter-example",        re.compile(r"contract\s+Counter\b")),
]


def detect_template(source: Optional[str]) -> Optional[str]:
    """Return the canonical template name for a contract source, or None."""
    if not source:
        return None
    for name, pattern in TEMPLATE_PATTERNS:
        if pattern.search(source):
            return name
    return None


def compute_vertical_summary(template: Optional[str], storage: Any) -> Optional[dict]:
    """Derive a per-vertical compliance/health summary from a contract's storage.

    This is a HEURISTIC at the indexer layer: we inspect well-known fields
    in the storage dict and compute summary flags so the dashboards can
    display them without re-implementing the view functions. The real
    compliance is enforced by the Skald invariants at the chain layer;
    this is for surfacing, not validation.

    Each template's storage shape is documented in its .skald file. We
    read fields conservatively — missing fields just yield None values
    in the summary.
    """
    if not isinstance(storage, dict):
        return None

    if template in ("sto-startup-equity", "sto-institutional-fund"):
        # Prospectus Regulation Art. 3: white paper must be registered before any issuance
        whitepaper = storage.get("whitepaper_registered", False)
        issued = int(storage.get("total_supply_issued", 0) or 0)
        cap = int(storage.get("total_supply_cap", 0) or 0)
        paused = storage.get("trading_paused", False)
        summary = {
            "kind": template,
            "compliant": bool(whitepaper or issued == 0),
            "whitepaper_registered": bool(whitepaper),
            "total_supply_issued": issued,
            "total_supply_cap": cap,
            "supply_utilization_pct": round(issued * 100 / cap, 2) if cap else 0.0,
            "trading_paused": bool(paused),
        }
        # AIFMD specifics for institutional fund
        if template == "sto-institutional-fund":
            depositary = storage.get("depositary", "")
            aifm = storage.get("aifm", "")
            nav = int(storage.get("latest_nav_per_share_mukrn", 0) or 0)
            nav_level = int(storage.get("nav_published_at_level", 0) or 0)
            summary.update({
                "depositary": depositary,
                "aifm": aifm,
                "depositary_independent": bool(depositary and aifm and depositary != aifm),
                "latest_nav_per_share_mukrn": nav,
                "nav_published_at_level": nav_level,
            })
        return summary

    if template == "sto-real-estate":
        title_notary = storage.get("title_attestation_notary", "")
        rental_received = int(storage.get("rental_income_received_mukrn", 0) or 0)
        rental_distributed = int(storage.get("rental_income_distributed_mukrn", 0) or 0)
        secondary_paused = storage.get("secondary_market_paused", False)
        return {
            "kind": template,
            "anti_ponzi_invariant_ok": rental_distributed <= rental_received,
            "title_attested": bool(title_notary),
            "title_attestation_notary": title_notary,
            "rental_income_received_mukrn": rental_received,
            "rental_income_distributed_mukrn": rental_distributed,
            "rental_distribution_utilization_pct":
                round(rental_distributed * 100 / rental_received, 2) if rental_received else 0.0,
            "secondary_market_paused": bool(secondary_paused),
        }

    if template == "quadratic-funding":
        contributors = int(storage.get("contributors_count", 0) or 0)
        sum_sqrt = int(storage.get("sum_of_sqrt_contributions", 0) or 0)
        total_received = int(storage.get("total_received_mukrn", 0) or 0)
        round_end = int(storage.get("round_end_level", 0) or 0)
        approved = storage.get("admin_approved", False)
        return {
            "kind": template,
            "contributors_count": contributors,
            "sum_of_sqrt_contributions": sum_sqrt,
            "total_received_mukrn": total_received,
            # QF matching estimate = (sum_sqrt)^2 (the formula; subject to matching pool cap)
            "matching_estimate_mukrn": sum_sqrt * sum_sqrt,
            "round_end_level": round_end,
            "admin_approved": bool(approved),
        }

    if template == "retroactive-pgf":
        score_sum = int(storage.get("score_sum", 0) or 0)
        score_count = int(storage.get("score_count", 0) or 0)
        nominated = storage.get("nominated_by", "")
        executed = storage.get("payout_executed", False)
        return {
            "kind": template,
            "average_score": round(score_sum / score_count, 2) if score_count else 0.0,
            "score_count": score_count,
            "nominated_by": nominated,
            "payout_executed": bool(executed),
        }

    if template in ("generic-data-oracle", "defi-price-oracle"):
        feeders = storage.get("feeders", []) or []
        latest_value = int(storage.get("latest_aggregated_value", 0) or 0)
        latest_level = int(storage.get("latest_aggregation_level", 0) or 0)
        circuit_tripped = storage.get("circuit_breaker_tripped", False)
        anomaly_count = int(storage.get("anomaly_count", 0) or 0)
        heartbeat = int(storage.get("heartbeat_levels", 0) or 0)
        summary = {
            "kind": template,
            "feeder_count": len(feeders) if isinstance(feeders, list) else 0,
            "latest_value": latest_value,
            "latest_aggregation_level": latest_level,
            "circuit_breaker_tripped": bool(circuit_tripped),
            "anomaly_count": anomaly_count,
            "heartbeat_levels": heartbeat,
        }
        if template == "defi-price-oracle":
            base = storage.get("base_asset", "")
            quote = storage.get("quote_asset", "")
            decimals = int(storage.get("decimals", 0) or 0)
            summary.update({
                "base_asset": base,
                "quote_asset": quote,
                "decimals": decimals,
                "human_price": (latest_value / (10 ** decimals)) if decimals else latest_value,
            })
        return summary

    if template == "schema-marketplace":
        return {
            "kind": template,
            "schema_id": storage.get("schema_id", ""),
            "issuer": storage.get("recognized_issuer", ""),
            "minimum_bond_mukrn": int(storage.get("minimum_bond_mukrn", 0) or 0),
            "is_active": bool(storage.get("is_active", False)),
        }

    return None


class Indexer:
    """Polling-based chain follower."""

    def __init__(self, db_path: str, rpc_base_url: str,
                 poll_interval_s: float = 1.0) -> None:
        self.db_path = db_path
        self.rpc_base_url = rpc_base_url
        self.poll_interval_s = poll_interval_s
        self._stop = asyncio.Event()

    async def run(self) -> None:
        """Main loop. Returns when self.stop() is called."""
        conn = open_db(self.db_path)
        init_schema(conn)
        backoff = 1.0

        async with KernRpcClient(self.rpc_base_url) as rpc:
            while not self._stop.is_set():
                try:
                    head = await rpc.head()
                    head_level = head.get("level", 0)
                    cursor = latest_indexed_level(conn)
                    if cursor >= head_level:
                        # Caught up — sleep briefly and re-check
                        await asyncio.sleep(self.poll_interval_s)
                        backoff = 1.0
                        continue
                    # Index one block forward
                    next_level = cursor + 1
                    await self._index_block(conn, rpc, next_level)
                    backoff = 1.0
                except KernRpcError as e:
                    logger.warning("RPC error: %s (backoff %.1fs)", e, backoff)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30.0)
                except Exception:
                    logger.exception("indexer unexpected error")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30.0)
        conn.close()

    def stop(self) -> None:
        self._stop.set()

    # --- per-block work --------------------------------------------------

    async def _index_block(self, conn, rpc: KernRpcClient, level: int) -> None:
        """Fetch block at `level`, write its rows, advance the cursor."""
        block = await rpc.block(level)
        ts = block.get("timestamp", int(time.time()))
        block_hash = block.get("hash", "")
        parent_hash = block.get("parent_hash")
        baker = block.get("baker")
        txs = block.get("transactions") or block.get("operations") or []
        tx_count = len(txs)
        indexed_at = int(time.time())

        # Track which contracts were called this block — we refresh their
        # storage snapshot from the live RPC after writing the block.
        called_contracts: set[str] = set()

        with transaction(conn):
            # Block row
            conn.execute(
                "INSERT OR REPLACE INTO blocks(level, hash, parent_hash, timestamp, "
                "baker, tx_count, indexed_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (level, block_hash, parent_hash, ts, baker, tx_count, indexed_at),
            )
            if baker:
                upsert_account(
                    conn,
                    address=baker,
                    is_validator=1,
                    last_seen_level=level,
                )

            for tx in txs:
                self._index_tx(conn, tx, level, ts)
                # If it was a CALL to a known contract, schedule a refresh
                if tx.get("kind") == "call":
                    recipient = tx.get("recipient")
                    if recipient:
                        called_contracts.add(recipient)

            set_meta(conn, "indexer.cursor", str(level))

        # Refresh storage for called contracts (outside the SQLite tx so
        # the async RPC fetches don't hold the write lock).
        for addr in called_contracts:
            try:
                data = await rpc.contract(addr)
            except KernRpcError:
                continue
            if data is None:
                continue
            row = conn.execute(
                "SELECT skald_template FROM contracts WHERE address = ?", (addr,)
            ).fetchone()
            if not row:
                continue
            template = row["skald_template"]
            storage = data.get("storage")
            summary = compute_vertical_summary(template, storage)
            with transaction(conn):
                from .db import update_contract_storage
                update_contract_storage(conn, addr, storage, summary, level)

        logger.info("indexed block %d (hash=%s txs=%d refreshed=%d)",
                    level, block_hash[:12], tx_count, len(called_contracts))

    def _index_tx(self, conn, tx: dict, block_level: int, block_ts: int) -> None:
        """Materialize a single transaction into the txs and derived tables."""
        kind = tx.get("kind", "unknown")
        sender = tx.get("sender", "")
        recipient = tx.get("recipient")
        amount = int(tx.get("amount", 0) or 0)
        fee = int(tx.get("fee", 0) or 0)
        nonce = int(tx.get("nonce", 0) or 0)
        gas_used = int(tx.get("gas_used", 0) or 0)

        result = tx.get("result") or {}
        success = 1 if result.get("ok", True) else 0
        error = result.get("error")
        extra = result.get("extra") or {}

        params = tx.get("params")

        # Compute or fetch the tx hash; chain RPC should provide it but
        # fall back to a deterministic identifier if needed.
        h = tx.get("hash") or f"tx-{block_level}-{nonce}-{sender[:8]}"

        conn.execute(
            "INSERT OR REPLACE INTO txs(hash, block_level, block_ts, kind, sender, "
            "recipient, amount, fee, gas_used, nonce, success, error, params_json, extra_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                h, block_level, block_ts, kind, sender, recipient,
                amount, fee, gas_used, nonce, success, error,
                json.dumps(params) if params is not None else None,
                json.dumps(extra) if extra else None,
            ),
        )

        # Maintain account counters (light cache; chain RPC is source of truth)
        upsert_account(
            conn, address=sender,
            last_seen_level=block_level,
            tx_count_sent=(_get_count(conn, sender, "tx_count_sent") + 1),
        )
        if recipient and recipient != sender:
            upsert_account(
                conn, address=recipient,
                last_seen_level=block_level,
                tx_count_recv=(_get_count(conn, recipient, "tx_count_recv") + 1),
            )

        # Vertical-specific materialization
        if success:
            if kind == "originate":
                self._index_origination(conn, tx, h, block_level, sender, extra)
            elif kind == "attest":
                self._index_attestation(conn, tx, h, block_level, block_ts, sender,
                                        amount, params, extra)
            elif kind == "revoke_attestation":
                self._index_revoke(conn, params, block_level)
            elif kind == "slash_attestation_equivocation":
                self._index_slash(conn, h, block_level, block_ts, sender, extra, params)

    def _index_origination(self, conn, tx, h, block_level, sender, extra) -> None:
        contract_addr = extra.get("new_contract") or extra.get("contract_address")
        if not contract_addr:
            return
        code = tx.get("code")
        initial_storage = tx.get("initial_storage")
        template = detect_template(code)
        summary = compute_vertical_summary(template, initial_storage)
        conn.execute(
            "INSERT OR REPLACE INTO contracts(address, code, storage_json, skald_template, "
            "originated_at_level, originated_by, last_refreshed_at_level, vertical_summary_json) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                contract_addr, code,
                json.dumps(initial_storage) if initial_storage is not None else None,
                template, block_level, sender, block_level,
                json.dumps(summary) if summary is not None else None,
            ),
        )
        upsert_account(conn, address=contract_addr, is_contract=1,
                       first_seen_level=block_level, last_seen_level=block_level)

    def _refresh_contract_after_call(self, conn, rpc_client, contract_addr: str,
                                     block_level: int) -> None:
        """Re-fetch a contract's storage from the live RPC and update our snapshot.

        Called after each successful CALL transaction so the dashboards
        always show recent storage. The fetch is best-effort: on RPC error
        we leave the previous snapshot in place.

        This refresh happens INSIDE the indexer transaction, but the
        RPC call itself is async so we accept the coupling cost.
        """
        # We import here to avoid circular dependency at module load
        from .db import update_contract_storage
        # Look up template
        row = conn.execute(
            "SELECT skald_template FROM contracts WHERE address = ?", (contract_addr,)
        ).fetchone()
        if not row:
            return
        template = row["skald_template"]
        try:
            data = rpc_client(contract_addr)
        except Exception:
            return
        if data is None:
            return
        storage = data.get("storage")
        summary = compute_vertical_summary(template, storage)
        update_contract_storage(conn, contract_addr, storage, summary, block_level)

    def _index_attestation(self, conn, tx, h, block_level, block_ts, sender,
                           amount, params, extra) -> None:
        att_id = extra.get("attestation_id")
        if not att_id:
            return
        schema_id = (params or {}).get("schema_id", "")
        subject = (params or {}).get("subject", "")
        claim = (params or {}).get("claim", {})
        # Heuristic: ZK claim if it has proof_system / verifier_key_hash
        is_zk = 1 if (isinstance(claim, dict) and "proof_system" in claim) else 0
        conn.execute(
            "INSERT OR REPLACE INTO attestations(attestation_id, issuer, schema_id, "
            "subject, claim_json, bond, issued_at_level, issued_at_ts, is_zk) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (att_id, sender, schema_id, subject, json.dumps(claim),
             amount, block_level, block_ts, is_zk),
        )

    def _index_revoke(self, conn, params, block_level) -> None:
        att_id = (params or {}).get("attestation_id")
        if not att_id:
            return
        conn.execute(
            "UPDATE attestations SET revoked_at_level = ? WHERE attestation_id = ?",
            (block_level, att_id),
        )

    def _index_slash(self, conn, h, block_level, block_ts, sender, extra, params) -> None:
        att1 = (params or {}).get("attestation_id_1")
        att2 = (params or {}).get("attestation_id_2")
        conn.execute(
            "INSERT OR REPLACE INTO slashings(tx_hash, block_level, block_ts, issuer, "
            "schema_id, subject, whistleblower, slashed_amount, whistleblower_reward, "
            "burned_amount, refunded_to_issuer, attestation_id_1, attestation_id_2) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                h, block_level, block_ts,
                extra.get("issuer", ""),
                extra.get("schema_id", ""),
                extra.get("subject", ""),
                sender,
                int(extra.get("slashed", 0)),
                int(extra.get("whistleblower_reward", 0)),
                int(extra.get("burned", 0)),
                int(extra.get("refunded_to_issuer", 0)),
                att1, att2,
            ),
        )
        # Mark both attestations as consumed
        if att1:
            conn.execute(
                "UPDATE attestations SET consumed_for_slashing = 1 WHERE attestation_id = ?",
                (att1,))
        if att2:
            conn.execute(
                "UPDATE attestations SET consumed_for_slashing = 1 WHERE attestation_id = ?",
                (att2,))


def _get_count(conn, address: str, col: str) -> int:
    """Return existing count for an account column, or 0 if absent."""
    if col not in ("tx_count_sent", "tx_count_recv"):
        raise ValueError(f"unsafe column: {col}")
    r = conn.execute(f"SELECT {col} AS c FROM accounts WHERE address = ?",
                     (address,)).fetchone()
    return r["c"] if r else 0
