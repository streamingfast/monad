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

#pragma once

#include <category/core/bytes.hpp>
#include <category/core/config.hpp>
#include <category/execution/ethereum/core/address.hpp>

#include <cstdint>

MONAD_NAMESPACE_BEGIN

struct BlockHeader;
class State;
class BlockState;

constexpr Address BLOCK_HISTORY_ADDRESS{
    {{0x00, 0x00, 0xF9, 0x08, 0x27, 0xF1, 0xC5, 0x3a, 0x10, 0xcb,
      0x7A, 0x02, 0x33, 0x5B, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35}}};

constexpr uint64_t BLOCK_HISTORY_LENGTH{8191};

void deploy_block_hash_history_contract(State &);

void set_block_hash_history(BlockState &, BlockHeader const &);

bytes32_t get_block_hash_history(State &, uint64_t block_number);

MONAD_NAMESPACE_END
