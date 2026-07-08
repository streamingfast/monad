# Copyright (C) 2025 Category Labs, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This toolchain is good for an AVX2 CPU with arbitrary precision arithmetic extensions
set(CMAKE_ASM_FLAGS_INIT "-march=haswell")
set(CMAKE_C_FLAGS_INIT "-march=haswell")
set(CMAKE_CXX_FLAGS_INIT "-march=haswell")

# Use mold linker for dramatically faster link times
find_program(MOLD_LINKER "mold")
if(MOLD_LINKER)
  set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=mold")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=mold")
  set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=mold")
endif()
