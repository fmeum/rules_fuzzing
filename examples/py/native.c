// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <string.h>

__attribute__((optnone)) void parse(const char *input, size_t len) {
  if (len > 5 && input[0] == 'a' && input[1] == 'b' && input[5] == 'c') {
    if (strstr(input, "secret_in_native_library") != NULL) {
      // Read past null byte to trigger an OOB read.
      if (input[len + 1] != 0x12) {
        return;
      }
    }
  }
}
