// Copyright (C) 2025-26 Category Labs, Inc.
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

#include <category/core/address.hpp>
#include <category/core/assert.h>
#include <category/core/bytes.hpp>
#include <category/core/endian.hpp>
#include <category/core/int.hpp>
#include <category/execution/ethereum/block_hash_history.hpp>
#include <category/execution/ethereum/core/block.hpp>
#include <category/execution/ethereum/event/exec_event_ctypes.h>
#include <category/execution/ethereum/event/exec_event_recorder.hpp>
#include <category/execution/ethereum/event/record_block_events.hpp>
#include <category/execution/ethereum/event/record_txn_events.hpp>
#include <category/execution/ethereum/execute_block_header.hpp>
#include <category/execution/ethereum/state2/block_state.hpp>
#include <category/execution/ethereum/state3/state.hpp>
#include <category/execution/ethereum/types/incarnation.hpp>
#include <category/execution/monad/staking/execute_block_prelude.hpp>
#include <category/vm/evm/explicit_traits.hpp>
#include <category/vm/evm/traits.hpp>

#include <cstdint>
#include <span>

MONAD_ANONYMOUS_NAMESPACE_BEGIN

using namespace monad::literals;

// EIP-4788
void set_beacon_root(State &state, BlockHeader const &header)
{
    constexpr auto BEACON_ROOTS_ADDRESS{
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address};
    constexpr uint256_t HISTORY_BUFFER_LENGTH{8191};
    constexpr auto SYSTEM_ADDRESS{
        0xfffffffffffffffffffffffffffffffffffffffe_address};

    if (state.account_exists(BEACON_ROOTS_ADDRESS)) {
        if (ExecutionEventRecorder *const exec_recorder =
                g_exec_event_recorder.get()) {
            bytes32_t const &input_data =
                header.parent_beacon_block_root.value();
            ReservedExecEvent const start_event =
                exec_recorder
                    ->reserve_block_event<monad_exec_block_system_call_start>(
                        MONAD_EXEC_BLOCK_SYSTEM_CALL_START,
                        as_bytes(std::span{&input_data, 1}));
            *start_event.payload = monad_exec_block_system_call_start{
                .caller = SYSTEM_ADDRESS,
                .call_target = BEACON_ROOTS_ADDRESS,
                .opcode = 0xF1, // CALL opcode
                .gas = 0,
                .input_length = 32};
            exec_recorder->commit(start_event);
        }

        uint256_t timestamp{header.timestamp};
        bytes32_t k1{store_be_as<bytes32_t>(timestamp % HISTORY_BUFFER_LENGTH)};
        bytes32_t k2{store_be_as<bytes32_t>(
            timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH)};
        state.set_storage(
            BEACON_ROOTS_ADDRESS, k1, store_be_as<bytes32_t>(timestamp));
        state.set_storage(
            BEACON_ROOTS_ADDRESS, k2, header.parent_beacon_block_root.value());

        uint32_t const num_account_accesses = record_system_call_account_accesses(
            state, MONAD_ACCT_ACCESS_BLOCK_PROLOGUE);

        if (ExecutionEventRecorder *const exec_recorder =
                g_exec_event_recorder.get()) {
            ReservedExecEvent const end_event =
                exec_recorder
                    ->reserve_block_event<monad_exec_block_system_call_end>(
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

MONAD_ANONYMOUS_NAMESPACE_END

MONAD_NAMESPACE_BEGIN

template <Traits traits>
void execute_block_header(BlockState &block_state, BlockHeader const &header)
{
    static_assert(traits::evm_rev() >= MONAD_ETH_TANGERINE_WHISTLE);

    State state{block_state, Incarnation{header.number, 0}};

    deploy_block_hash_history_contract<traits>(state);
    set_block_hash_history<traits>(state, header);

    if constexpr (traits::evm_rev() >= MONAD_ETH_CANCUN) {
        set_beacon_root(state, header);
    }

    // TODO: move to execute_monad_block eventually
    if constexpr (is_monad_trait_v<traits>) {
        staking::execute_block_prelude<traits>(state);
    }

    MONAD_ASSERT(block_state.can_merge(state));
    block_state.merge(state);
    // NOTE(firehose): the block-prologue account access list is not emitted
    // here; each prologue system call (block hash history, EIP-4788 beacon
    // root) emits its own list between its SYSTEM_CALL_START/END pair.
}

EXPLICIT_TRAITS(execute_block_header);

MONAD_NAMESPACE_END
