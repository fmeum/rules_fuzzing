#!/bin/bash
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# llvm-symbolizer is a sibling of the wrapper script that sources the current
# script.
declare -r this_dir=$(dirname "${BASH_SOURCE}")
COMMON_SANITIZER_OPTIONS=symbolize=1:external_symbolizer_path=$this_dir/llvm-symbolizer:detect_leaks=0:handle_segv=1

export ASAN_OPTIONS=${ASAN_OPTIONS:+${ASAN_OPTIONS}:}$COMMON_SANITIZER_OPTIONS:allow_user_segv_handler=1
export UBSAN_OPTIONS=${UBSAN_OPTIONS:+${UBSAN_OPTIONS}:}$COMMON_SANITIZER_OPTIONS
