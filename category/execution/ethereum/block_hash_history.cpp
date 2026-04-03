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
#include <category/core/hex.hpp>
#include <category/core/int.hpp>
#include <category/core/likely.h>
#include <category/execution/ethereum/block_hash_history.hpp>
#include <category/execution/ethereum/core/address.hpp>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_event_recorder.hpp>
#include <category/execution/ethereum/event/record_block_events.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/state3/state.hpp>

#include <evmc/evmc.h>

#include <cstdint>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

byte_string const BLOCK_HISTORY_CODE =
    from_hex(
        "0x3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f"
        "35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5f"
        "fd5b5f35611fff60014303065500")
        .value();

constexpr auto BLOCK_HISTORY_CODE_HASH{
    0x6e49e66782037c0555897870e29fa5e552daf4719552131a0abce779daec0a5d_bytes32};

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

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
        if (ExecutionEventRecorder *const exec_recorder = g_exec_event_recorder.get()) {
            bytes32_t const &input_data = header.parent_hash;
            ReservedExecEvent const start_event =
                exec_recorder->reserve_block_event<monad_exec_block_system_call_start>(
                    MONAD_EXEC_BLOCK_SYSTEM_CALL_START,
                    as_bytes(std::span{&input_data, 1}));
            *start_event.payload = monad_exec_block_system_call_start{
                .caller = SYSTEM_ADDRESS,
                .call_target = BLOCK_HISTORY_ADDRESS,
                .opcode = 0xF1, // CALL opcode
                .gas = 0,
                .input_length = 32};
            exec_recorder->commit(start_event);
        }

        uint64_t const parent_number = header.number - 1;
        uint256_t const index{parent_number % BLOCK_HISTORY_LENGTH};
        bytes32_t const key{to_bytes(to_big_endian(index))};
        state.set_storage(BLOCK_HISTORY_ADDRESS, key, header.parent_hash);

        uint32_t const num_account_accesses =
            record_system_call_account_accesses(state, MONAD_ACCT_ACCESS_BLOCK_PROLOGUE);

        MONAD_ASSERT(block_state.can_merge(state));
        block_state.merge(state);

        if (ExecutionEventRecorder *const exec_recorder = g_exec_event_recorder.get()) {
            ReservedExecEvent const end_event =
                exec_recorder->reserve_block_event<monad_exec_block_system_call_end>(
                    MONAD_EXEC_BLOCK_SYSTEM_CALL_END);
            *end_event.payload = monad_exec_block_system_call_end{
                .gas_used = 0,
                .evmc_status = EVMC_SUCCESS,
                .return_length = 0,
                .num_account_accesses = num_account_accesses};
            exec_recorder->commit(end_event);
        }
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
