// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <category/core/assert.h>
#include <category/core/bytes.hpp>
#include <category/core/int.hpp>
#include <category/core/likely.h>
#include <category/execution/ethereum/block_hash_history.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_event_recorder.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/state3/state.hpp>

#include <evmc/evmc.h>

#include <cstdint>

MONAD_NAMESPACE_BEGIN

// TO REMOVE - Helper function to emit account and storage access events for system calls
[[maybe_unused]] static void emit_account_access_events(
    State const &state,
    monad_exec_account_access_context access_context)
{
    ExecutionEventRecorder *const exec_recorder = g_exec_event_recorder.get();
    if (!exec_recorder) {
        return;
    }

    auto const &current = state.current();
    auto const &original = state.original();

    // Count total accounts
    uint32_t const total_accounts = static_cast<uint32_t>(current.size());
    if (total_accounts == 0) {
        return;
    }

    // Emit ACCOUNT_ACCESS_LIST_HEADER
    ReservedExecEvent const header_event =
        exec_recorder->reserve_block_event<monad_exec_account_access_list_header>(
            MONAD_EXEC_ACCOUNT_ACCESS_LIST_HEADER);
    *header_event.payload = monad_exec_account_access_list_header{
        .entry_count = total_accounts,
        .access_context = access_context};
    exec_recorder->commit(header_event);

    uint32_t account_index = 0;
    for (auto const &[address, current_stack] : current) {
        auto const &current_account_state = current_stack.recent();

        auto const it = original.find(address);
        auto const &orig_account = (it != original.end()) ?
            it->second.account_ : std::optional<Account>{};

        ReservedExecEvent const account_event =
            exec_recorder->reserve_block_event<monad_exec_account_access>(
                MONAD_EXEC_ACCOUNT_ACCESS);
        *account_event.payload = monad_exec_account_access{
            .index = account_index,
            .address = address,
            .access_context = access_context,
            .is_balance_modified = false,
            .is_nonce_modified = false,
            .prestate = orig_account.has_value() ?
                monad_c_eth_account_state{
                    .nonce = orig_account->nonce,
                    .balance = orig_account->balance,
                    .code_hash = orig_account->code_hash} :
                monad_c_eth_account_state{},
            .modified_balance = {},
            .modified_nonce = 0,
            .storage_key_count =
                static_cast<uint32_t>(current_account_state.storage_.size()),
            .transient_count = 0};
        exec_recorder->commit(account_event);

        uint32_t storage_index = 0;
        for (auto const &[key, end_value] : current_account_state.storage_) {
            bytes32_t start_value{};
            if (it != original.end()) {
                auto const &original_account_state = it->second;
                auto const storage_it = original_account_state.storage_.find(key);
                if (storage_it != original_account_state.storage_.end()) {
                    start_value = storage_it->second;
                }
            }

            ReservedExecEvent const storage_event =
                exec_recorder->reserve_block_event<monad_exec_storage_access>(
                    MONAD_EXEC_STORAGE_ACCESS);
            *storage_event.payload = monad_exec_storage_access{
                .address = address,
                .index = storage_index,
                .access_context = access_context,
                .modified = (start_value != end_value),
                .transient = false,
                .key = key,
                .start_value = start_value,
                .end_value = end_value};
            exec_recorder->commit(storage_event);
            storage_index++;
        }

        account_index++;
    }
}

constexpr uint8_t BLOCK_HISTORY_CODE[] = {
    0x33, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x14, 0x60,
    0x46, 0x57, 0x60, 0x20, 0x36, 0x03, 0x60, 0x42, 0x57, 0x5f, 0x35, 0x60,
    0x01, 0x43, 0x03, 0x81, 0x11, 0x60, 0x42, 0x57, 0x61, 0x1f, 0xff, 0x81,
    0x43, 0x03, 0x11, 0x60, 0x42, 0x57, 0x61, 0x1f, 0xff, 0x90, 0x06, 0x54,
    0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3, 0x5b, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f,
    0x35, 0x61, 0x1f, 0xff, 0x60, 0x01, 0x43, 0x03, 0x06, 0x55, 0x00};

void deploy_block_hash_history_contract(State &state)
{
    if (MONAD_LIKELY(state.account_exists(BLOCK_HISTORY_ADDRESS))) {
        return;
    }

    bytes32_t const code_hash = to_bytes(keccak256(BLOCK_HISTORY_CODE));

    state.create_contract(BLOCK_HISTORY_ADDRESS);
    state.set_code_hash(BLOCK_HISTORY_ADDRESS, code_hash);
    state.set_code(BLOCK_HISTORY_ADDRESS, BLOCK_HISTORY_CODE);
    state.set_nonce(BLOCK_HISTORY_ADDRESS, 1);
}

void set_block_hash_history(BlockState &block_state, BlockHeader const &header)
{
    constexpr auto SYSTEM_ADDRESS{
        0xfffffffffffffffffffffffffffffffffffffffe_address};

    if (MONAD_UNLIKELY(!header.number)) {
        return;
    }

    State state{block_state, Incarnation{header.number, 0}};
    if (MONAD_LIKELY(state.account_exists(BLOCK_HISTORY_ADDRESS))) {
        // Emit call frame event for system call tracing
        if (ExecutionEventRecorder *const exec_recorder = g_exec_event_recorder.get()) {
            bytes32_t const &input_data = header.parent_hash;
            ReservedExecEvent const call_frame_event =
                exec_recorder->reserve_block_event<monad_exec_txn_call_frame>(
                    MONAD_EXEC_TXN_CALL_FRAME,
                    as_bytes(std::span{&input_data, 1}));
            *call_frame_event.payload = monad_exec_txn_call_frame{
                .index = 1,
                .caller = SYSTEM_ADDRESS,
                .call_target = BLOCK_HISTORY_ADDRESS,
                .opcode = 0xF1, // CALL opcode
                .value = 0,
                .gas = 0,
                .gas_used = 0,
                .evmc_status = EVMC_SUCCESS,
                .depth = 0,
                .input_length = 32,
                .return_length = 0};
            exec_recorder->commit(call_frame_event);
        }

        uint64_t const parent_number = header.number - 1;
        uint256_t const index{parent_number % BLOCK_HISTORY_LENGTH};
        bytes32_t const key{to_bytes(to_big_endian(index))};
        state.set_storage(BLOCK_HISTORY_ADDRESS, key, header.parent_hash);

        // TO REMOVE - Emit account and storage access events before merging
        emit_account_access_events(state, MONAD_ACCT_ACCESS_BLOCK_PROLOGUE);

        MONAD_ASSERT(block_state.can_merge(state));
        block_state.merge(state);
    }
}

// Note: EIP-2935 says the get on the block hash history contract should revert
// if the block number is outside of the block history. However, current usage
// of this function guarantees that it is always valid.
bytes32_t get_block_hash_history(State &state, uint64_t const block_number)
{
    if (MONAD_UNLIKELY(!state.account_exists(BLOCK_HISTORY_ADDRESS))) {
        return bytes32_t{};
    }

    uint256_t const index{block_number % BLOCK_HISTORY_LENGTH};
    return state.get_storage(
        BLOCK_HISTORY_ADDRESS, to_bytes(to_big_endian(index)));
}

MONAD_NAMESPACE_END
