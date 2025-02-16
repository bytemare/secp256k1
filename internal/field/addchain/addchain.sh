#!/bin/zsh
# Automate addition chain creation for big exponentiation in finite fields using https://github.com/mmcloughlin/addchain.
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree or at
# https://spdx.org/licenses/MIT.html



# Curve secpk256k1 finite field
# p = 2^256 - 2^32 - 977

# Finite field element inversion
# To find v = (1/u) mod p, we do v = u^(p-2) mod p.
# So we look for: 2^256 - 2^32 - 977 - 2.

addchain search "2^256 - 2^32 - 977 - 2" > fe_invert.acc
addchain gen -tmpl fe_invert.tmpl fe_invert.acc | gofmt > ../fe_invert.go
rm fe_invert.acc

# Finite field square root does y = a^((p - 3) / 4), and p = 3 mod 4.
# So we look for: (2^256 - 2^32 - 977 - 3) / 4. addchain doesn't like '/', so we have to calculate the result.
# > 28948022309329048855892746252171976963317496166410141009864396001977208667915

addchain search "28948022309329048855892746252171976963317496166410141009864396001977208667915" > fe_expPMin3Div4.acc
addchain gen -tmpl fe_expPMin3Div4.tmpl fe_expPMin3Div4.acc > ../fe_expPMin3Div4.go
rm fe_expPMin3Div4.acc