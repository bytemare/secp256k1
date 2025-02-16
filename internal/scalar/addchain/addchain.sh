#!/bin/zsh
# Automate addition chain creation for big exponentiation in finite fields using https://github.com/mmcloughlin/addchain.
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree or at
# https://spdx.org/licenses/MIT.html

# Prime-order group
# p = 2^256 - 432420386565659656852420866394968145599
# To find v = (1/u) mod p, we do v = u^(p-2) mod p.
# So we look for: 2^256 - 432420386565659656852420866394968145599 - 2.

addchain search "2^256 - 432420386565659656852420866394968145599 - 2" > scalar_invert.acc
addchain gen -tmpl scalar_invert.tmpl scalar_invert.acc > ../scalar_invert.go
rm scalar_invert.acc