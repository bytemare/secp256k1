// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import "github.com/bytemare/secp256k1/internal/field"

// SSWU applies the Simplified Shallue-van de Woestijne-Ulas (SWU) method to map e to a point on the secp256k1 3-ISO
// curve in affine coordinates. Note that calling IsogenySecp256k13iso() is necessary to then get a point on secpk256k1.
func SSWU(e *field.Element) *Element {
	// 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533.
	isoA := &field.Element{
		E: field.MontgomeryDomainFieldElement{
			15812504324673914017,
			4924912935180573090,
			11593825521208392688,
			5790129131709978969,
		},
	}
	// 1771.
	isoB := &field.Element{E: field.MontgomeryDomainFieldElement{7606388811483, 0, 0, 0}}
	// z = -11
	// - non-square in F, Z != -1 in F.
	// The polynomial g(x) - Z is irreducible over F, and g(B / (Z * A)) is square in F.
	z := &field.Element{
		E: field.MontgomeryDomainFieldElement{
			18446744022169932340,
			18446744073709551615,
			18446744073709551615,
			18446744073709551615,
		},
	}

	tv1 := field.New().Square(e)                   //    1.  tv1 = u^2
	tv1.Multiply(z, tv1)                           //    2.  tv1 = Z * tv1
	tv2 := field.New().Square(tv1)                 //    3.  tv2 = tv1^2
	tv2.Add(tv2, tv1)                              //    4.  tv2 = tv2 + tv1
	tv3 := field.New().Add(tv2, field.New().One()) //    5.  tv3 = tv2 + 1
	tv3.Multiply(isoB, tv3)                        //    6.  tv3 = B * tv3
	tv2Zero := tv2.IsZero()
	tv2.Negate(tv2)
	tv4 := field.New().CMove(tv2Zero, tv2, z)          // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0) or CMOV(-tv2, Z, tv2 == 0)
	tv4.Multiply(isoA, tv4)                            //    8.  tv4 = A * tv4
	tv2.Square(tv3)                                    //    9.  tv2 = tv3^2
	tv6 := field.New().Square(tv4)                     //    10. tv6 = tv4^2
	tv5 := field.New().Multiply(isoA, tv6)             //    11. tv5 = A * tv6
	tv2.Add(tv2, tv5)                                  //    12. tv2 = tv2 + tv5
	tv2.Multiply(tv2, tv3)                             //    13. tv2 = tv2 * tv3
	tv6.Multiply(tv6, tv4)                             //    14. tv6 = tv6 * tv4
	tv5.Multiply(isoB, tv6)                            //    15. tv5 = B * tv6
	tv2.Add(tv2, tv5)                                  //    16. tv2 = tv2 + tv5
	x := field.New().Multiply(tv1, tv3)                //    17.   x = tv1 * tv3
	y1, isGx1Square := field.New().SqrtRatio(tv2, tv6) //    18. isGx1Square, y1 = sqrt_ratio(tv2, tv6)
	y := field.New().Multiply(tv1, e)                  //    19.   y = tv1 * u
	y.Multiply(y, y1)                                  //    20.   y = y * y1
	x.CMove(isGx1Square, x, tv3)                       //    21.   x = CMOV(x, tv3, isGx1Square)
	y.CMove(isGx1Square, y, y1)                        //    22.   y = CMOV(y, y1, isGx1Square)
	e1 := field.IsEqual(e.Sgn0(), y.Sgn0())            //    23.  e1 = sgn0(u) == sgn0(y)
	y1.Negate(y)
	y.CMove(e1, y1, y) //    24.   y = CMOV(-y, y, e1),
	tv4.Invert(*tv4)   //    25.   1 / tv4
	x.Multiply(x, tv4) //	 26.   x = x / tv4

	return &Element{
		x: *x,
		y: *y,
		z: *field.New().One(), // No need to set Z here, it won't be used before being set in IsogenySecp256k13iso anyway.
	}
}

// IsogenySecp256k13iso is a 3-degree isogeny from secp256k1 3-ISO to the secp256k1 elliptic curve. It handles
// exceptional cases where inversions to denominators evaluate to 0.
func IsogenySecp256k13iso(e *Element) *Element {
	var (
		// _kx are the constants used in the 3-Isogeny Map for secp256k1, from RFC9380 Section E.1.
		_k10 = &field.Element{E: field.MontgomeryDomainFieldElement{253880346804, 0, 0, 0}}
		_k11 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				15401556054675218246,
				3224699913824136141,
				5815130584626317824,
				16947662544290920057,
			},
		}
		_k12 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				5242624389536649661,
				6503044766135799011,
				13715044361241875287,
				702316956669180165,
			},
		}
		_k13 = &field.Element{E: field.MontgomeryDomainFieldElement{477218697, 0, 0, 0}}
		_k20 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				10013643957699995642,
				13279921378413469365,
				9434573195234168324,
				14865030926825602763,
			},
		}
		_k21 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				10290131358410743717,
				3187170674093536253,
				12754934808919567890,
				6320852610022621491,
			},
		}
		_k30 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				18446743860074648259,
				18446744073709551615,
				18446744073709551615,
				18446744073709551615,
			},
		}
		_k31 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				13429969373273428526,
				5674984992785315314,
				2875401403253613739,
				12950111799174569234,
			},
		}
		_k32 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				11844684229475616502,
				12474894419922675313,
				16080894217475713451,
				9574530515189365890,
			},
		}
		_k33 = &field.Element{E: field.MontgomeryDomainFieldElement{159072899, 0, 0, 0}}
		_k40 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				18446740822418568955,
				18446744073709551615,
				18446744073709551615,
				18446744073709551615,
			},
		}
		_k41 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				11594187807980371856,
				2946275987821304864,
				9856975511992953358,
				7701604633057705058,
			},
		}
		_k42 = &field.Element{
			E: field.MontgomeryDomainFieldElement{
				6211825002908823904,
				4780756011140304380,
				9909030176524576027,
				257906878179156429,
			},
		}
	)

	x2 := field.New().Square(&e.x)
	x3 := field.New().Multiply(x2, &e.x)

	// x_num, x_den
	kx3 := field.New().Multiply(_k13, x3)
	kx2 := field.New().Multiply(_k12, x2)
	kx1 := field.New().Multiply(_k11, &e.x)
	xNum := field.New().Add(kx3, kx2) // k_(1,3) * x'^3 + k_(1,2) * x'^2
	xNum.Add(xNum, kx1)               // k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x'
	xNum.Add(xNum, _k10)              // k_(1,3) * x'^3 + k_(1,2) * x'^2 + k_(1,1) * x' + k_(1,0)

	k21 := field.New().Multiply(_k21, &e.x) // _k(2,1) * x'
	xDen := field.New().Add(x2, k21)        // x'^2 + k_(2,1) * x'
	xDen.Add(xDen, _k20)                    // x_den = x'^2 + k_(2,1) * x' + k_(2,0)
	xDen.Invert(*xDen)
	isIdentity := xDen.IsZero()

	// y_num, y_den
	kx3 = field.New().Multiply(_k33, x3)
	kx2 = field.New().Multiply(_k32, x2)
	kx1 = field.New().Multiply(_k31, &e.x)
	yNum := field.New().Add(kx3, kx2) // k_(3,3) * x'^3 + k_(3,2) * x'^2
	yNum.Add(yNum, kx1)               // k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x'
	yNum.Add(yNum, _k30)              // k_(3,3) * x'^3 + k_(3,2) * x'^2 + k_(3,1) * x' + k_(3,0)

	k42 := field.New().Multiply(_k42, x2)
	k41 := field.New().Multiply(_k41, &e.x)
	yDen := field.New().Add(x3, k42)
	yDen.Add(yDen, k41)
	yDen.Add(yDen, _k40)
	isIdentity |= yDen.IsZero()
	yDen.Invert(*yDen)
	// originally, we would do 'isIdentity |= yDen.IsZero()' here, but it doesn't work

	// compose final point
	e.x.Multiply(xNum, xDen)
	e.y.Multiply(&e.y, yNum)
	e.y.Multiply(&e.y, yDen)

	// If either denominator == 0, set to identity point.
	e.x.CMove(isIdentity, &e.x, field.New()) // field.New() is 0
	e.y.CMove(isIdentity, &e.y, field.New().One())
	e.z.CMove(isIdentity, field.New().One(), field.New()) // field.New() is 0

	return e
}
