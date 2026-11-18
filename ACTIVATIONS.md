# Network activations

Every Monad revision this fork's code defines, with its status on the networks we serve and
what it changes in the Firehose block that `monad-firehose-tracer` builds from the execution
event ring. Review the new or changed entries on every upstream bump, and refresh the
statuses when an activation is announced between bumps.

Statuses come from `get_monad_revision()` in
`category/execution/monad/chain/monad_mainnet.cpp` and `monad_testnet.cpp`; feature gates
come from `MonadTraits` in `category/vm/evm/traits.hpp`. We serve Monad mainnet only;
testnet is listed for reference.

Last checked: 2026-11-18, at upstream `v0.16.6`.

| Revision | Gates | Mainnet | Testnet | Effect on the Firehose block |
|---|---|---|---|---|
| `MONAD_ZERO` | Monad rules on EVM Cancun, consensus header V0 | Never active (mainnet starts at `MONAD_TWO`) | 2025-02-14 or earlier | Baseline. |
| `MONAD_ONE` | `charges_gas_limit`: transactions are charged their full gas limit | Active at genesis | Active (2025-02-14) | Receipt and block `gas_used` carry the charged gas limit, not the gas the EVM consumed. Values only, no new field. |
| `MONAD_TWO` | Larger maximum contract code size | Active at genesis | Active (2025-03-14) | None: changes which deployments succeed, not the block shape. |
| `MONAD_THREE` | Consensus header V1 | Active (2025-08-13) | Active (2025-08-12) | None: the tracer reads the Ethereum header fields from `BLOCK_START`, which do not change. |
| `MONAD_FOUR` | EVM Prague (EIP-7702 set-code transactions, EIP-2537 BLS precompiles), EIP-7951 P-256 precompile, reserve balance checks, consensus header V2 | Active (2025-11-04, with `MONAD_SIX`) | Active (2025-10-14) | Type 4 transactions with authorization lists (`TXN_AUTH_LIST_ENTRY` events, mapped). Reserve balance reverts a transaction with no state change, which shows as a failed transaction. |
| `MONAD_FIVE` | Staking contract changes; `execute_block_prelude` clears the staking `proposer_val_id` slot at the start of every block | Active (2025-11-04, with `MONAD_SIX`) | Active (2025-10-28) | The prelude's storage write is not in the block: this fork emits block-prologue state changes only inside the EIP-2935 and EIP-4788 system calls, which run before the prelude. Not changed by `v0.16.6`, see the `v0.16.6-fh3.1` PR. |
| `MONAD_SIX` | EIP-2935 block hash history contract (`eip_2935_active`) | Active (2025-11-04) | Active (2025-10-31) | One `BLOCK_SYSTEM_CALL_START`/`END` pair per block for the history contract write, emitted by this fork and traced as a system call. |
| `MONAD_SEVEN` | Opcode pricing version 1 (Monad specification §4) | Active (2025-11-07) | Active (2025-11-05) | Gas values in calls and receipts. No new field. |
| `MONAD_EIGHT` | Reserve balance uses the account's current code hash; staking constant changes | Active (2025-11-20) | Active (2025-11-19) | None beyond which transactions revert. |
| `MONAD_NINE` | EVM Osaka (EIP-7823, EIP-7883 MODEXP limits and pricing, EIP-7939 `CLZ`), MIP-3, MIP-4 reserve balance precompile | Active (2026-03-19) | Active (2026-03-10) | Calls to the reserve balance precompile appear as precompile calls. Gas values change. No new field. |
| `MONAD_TEN` | MIP-8 page-encoded storage and page-based storage gas | Active (2026-09-02) | Active (2026-08-12) | Storage values are unchanged; warm/cold storage gas is per 128-slot page, which changes gas values. From `v0.16.6` on, live execution refuses a database that is not page-encoded. |
| `MONAD_NEXT` | EVM Amsterdam (EIP-7981 access list data cost), MIP-12 maximum block reward lowered from 25 to 18 MON | Not scheduled | Not scheduled | Intrinsic gas of transactions with access lists, and the staking reward amounts (balance changes). No new transaction type or field. |

Features defined in the traits but disabled on every Monad revision: EIP-4844 blobs
(`eip_4844_active`, the blob opcodes return stub data), EIP-7685 requests (`requests_hash`
stays zero), EIP-7691, EIP-7918, MIP-11 priority fee distribution.
