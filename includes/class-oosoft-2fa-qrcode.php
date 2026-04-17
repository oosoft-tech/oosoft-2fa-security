<?php
/**
 * Minimal QR Code generator — pure PHP, zero dependencies.
 *
 * Outputs an inline SVG string. Supports byte-mode data, error
 * correction level M, versions 1–10 (up to 216 bytes).
 *
 * Algorithm references: ISO/IEC 18004:2015.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable

class OOSOFT_2FA_QRCode {

	/* EC level M: byte capacity per version (index = version). */
	private const CAP = [ 0, 16, 28, 44, 64, 86, 108, 124, 154, 182, 216 ];

	/* RS params for EC level M: [ec_per_block, g1_blocks, g1_data, g2_blocks, g2_data] */
	private const RSB = [
		null,
		[ 10, 1, 16, 0,  0 ],
		[ 16, 1, 28, 0,  0 ],
		[ 26, 1, 44, 0,  0 ],
		[ 18, 2, 32, 0,  0 ],
		[ 24, 2, 43, 0,  0 ],
		[ 16, 4, 27, 0,  0 ],
		[ 18, 4, 31, 0,  0 ],
		[ 22, 2, 38, 2, 39 ],
		[ 22, 3, 36, 2, 37 ],
		[ 26, 4, 43, 1, 44 ],
	];

	/* Alignment pattern center coordinate lists per version. */
	private const AP = [
		[], [], [ 6, 18 ], [ 6, 22 ], [ 6, 26 ], [ 6, 30 ], [ 6, 34 ],
		[ 6, 22, 38 ], [ 6, 24, 42 ], [ 6, 26, 46 ], [ 6, 28, 50 ],
	];

	/* Remainder bits to append after last codeword (v1-10). */
	private const REM = [ 0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0 ];

	/* GF(256) tables (populated once). */
	private static array $gf_exp = [];
	private static array $gf_log = [];

	/* Finder pattern (7×7). */
	private const FP = [
		[ 1,1,1,1,1,1,1 ],
		[ 1,0,0,0,0,0,1 ],
		[ 1,0,1,1,1,0,1 ],
		[ 1,0,1,1,1,0,1 ],
		[ 1,0,1,1,1,0,1 ],
		[ 1,0,0,0,0,0,1 ],
		[ 1,1,1,1,1,1,1 ],
	];

	// -----------------------------------------------------------------------
	// Public API
	// -----------------------------------------------------------------------

	/**
	 * Generate a QR code SVG string for $data.
	 *
	 * @param string $data     Plaintext to encode (byte mode).
	 * @param int    $module   Pixels per module (default 4).
	 * @param int    $quiet    Quiet zone modules (default 4).
	 * @return string Inline SVG markup, or empty comment on failure.
	 */
	public static function svg( string $data, int $module = 4, int $quiet = 4 ): string {
		$ver = self::pick_version( $data );
		if ( 0 === $ver ) {
			return '<!-- QR: data too long (max 216 bytes at EC-M v10) -->';
		}

		$sz = ( $ver - 1 ) * 4 + 21;
		$cw = self::build_codewords( $data, $ver );
		$m  = self::build_matrix( $cw, $ver, $sz );
		$m  = self::best_mask( $m, $ver, $sz );

		return self::render( $m, $sz, $module, $quiet );
	}

	// -----------------------------------------------------------------------
	// Version
	// -----------------------------------------------------------------------

	private static function pick_version( string $data ): int {
		$len = strlen( $data );
		for ( $v = 1; $v <= 10; $v++ ) {
			if ( $len <= self::CAP[ $v ] ) {
				return $v;
			}
		}
		return 0;
	}

	// -----------------------------------------------------------------------
	// Codeword construction
	// -----------------------------------------------------------------------

	private static function build_codewords( string $data, int $ver ): array {
		[ $ec_n, $g1b, $g1d, $g2b, $g2d ] = self::RSB[ $ver ];
		$total_data = $g1b * $g1d + $g2b * $g2d;

		/* --- Bit stream (byte mode) --- */
		$bits = '0100'; // mode indicator
		$bits .= str_pad( decbin( strlen( $data ) ), 8, '0', STR_PAD_LEFT );
		for ( $i = 0, $l = strlen( $data ); $i < $l; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$bits .= '0000'; // terminator
		// Pad to next byte boundary.
		if ( strlen( $bits ) % 8 ) {
			$bits = str_pad( $bits, (int) ceil( strlen( $bits ) / 8 ) * 8, '0' );
		}
		// Pad to total_data bytes.
		$pi = 0;
		$pad = [ '11101100', '00010001' ];
		while ( strlen( $bits ) < $total_data * 8 ) {
			$bits .= $pad[ $pi++ % 2 ];
		}

		/* --- Convert to byte array --- */
		$dc = [];
		for ( $i = 0; $i < $total_data; $i++ ) {
			$dc[] = (int) bindec( substr( $bits, $i * 8, 8 ) );
		}

		/* --- Split into blocks + compute EC --- */
		self::gf_init();
		$blocks = [];
		$off    = 0;
		for ( $b = 0; $b < $g1b; $b++ ) {
			$d = array_slice( $dc, $off, $g1d );
			$blocks[] = [ 'data' => $d, 'ec' => self::rs_encode( $d, $ec_n ) ];
			$off += $g1d;
		}
		for ( $b = 0; $b < $g2b; $b++ ) {
			$d = array_slice( $dc, $off, $g2d );
			$blocks[] = [ 'data' => $d, 'ec' => self::rs_encode( $d, $ec_n ) ];
			$off += $g2d;
		}

		/* --- Interleave data then EC --- */
		$all     = [];
		$max_d   = max( $g1d, $g2d ?: $g1d );
		for ( $i = 0; $i < $max_d; $i++ ) {
			foreach ( $blocks as $bl ) {
				if ( isset( $bl['data'][ $i ] ) ) {
					$all[] = $bl['data'][ $i ];
				}
			}
		}
		for ( $i = 0; $i < $ec_n; $i++ ) {
			foreach ( $blocks as $bl ) {
				$all[] = $bl['ec'][ $i ];
			}
		}
		return $all;
	}

	// -----------------------------------------------------------------------
	// Reed-Solomon
	// -----------------------------------------------------------------------

	private static function gf_init(): void {
		if ( ! empty( self::$gf_exp ) ) {
			return;
		}
		self::$gf_exp = array_fill( 0, 512, 0 );
		self::$gf_log = array_fill( 0, 256, 0 );
		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			self::$gf_exp[ $i ] = $x;
			self::$gf_log[ $x ] = $i;
			$x <<= 1;
			if ( $x > 255 ) {
				$x ^= 0x11d;
			}
		}
		for ( $i = 255; $i < 512; $i++ ) {
			self::$gf_exp[ $i ] = self::$gf_exp[ $i - 255 ];
		}
	}

	private static function gf_mul( int $a, int $b ): int {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		return self::$gf_exp[ self::$gf_log[ $a ] + self::$gf_log[ $b ] ];
	}

	private static function rs_encode( array $data, int $n_ec ): array {
		/* Generator polynomial g(x) = ∏(x + α^i) for i=0..n_ec-1 */
		$g = [ 1 ];
		for ( $i = 0; $i < $n_ec; $i++ ) {
			$ng = array_fill( 0, count( $g ) + 1, 0 );
			foreach ( $g as $j => $gv ) {
				$ng[ $j ]     ^= $gv;
				$ng[ $j + 1 ] ^= self::gf_mul( $gv, self::$gf_exp[ $i ] );
			}
			$g = $ng;
		}
		/* Polynomial long-division (data × x^n_ec) ÷ g(x) → remainder = EC */
		$msg = array_merge( $data, array_fill( 0, $n_ec, 0 ) );
		for ( $i = 0, $dl = count( $data ); $i < $dl; $i++ ) {
			$c = $msg[ $i ];
			if ( 0 !== $c ) {
				for ( $j = 1; $j <= $n_ec; $j++ ) {
					$msg[ $i + $j ] ^= self::gf_mul( $g[ $j ], $c );
				}
			}
		}
		return array_slice( $msg, count( $data ) );
	}

	// -----------------------------------------------------------------------
	// Matrix construction
	// -----------------------------------------------------------------------

	/**
	 * Build the QR matrix with all functional patterns and data placed.
	 * Cell values: -1=free(data), 0=white-fixed, 1=dark-fixed.
	 * After masking data cells become 0 or 1 too.
	 */
	private static function build_matrix( array $cw, int $ver, int $sz ): array {
		$m = array_fill( 0, $sz, array_fill( 0, $sz, -1 ) );

		/* Finder patterns + separators */
		foreach ( [ [ 0, 0 ], [ 0, $sz - 7 ], [ $sz - 7, 0 ] ] as [ $fr, $fc ] ) {
			self::place_finder( $m, $fr, $fc, $sz );
		}

		/* Timing patterns (row 6, col 6) */
		for ( $i = 8; $i < $sz - 8; $i++ ) {
			if ( $m[6][ $i ] === -1 ) {
				$m[6][ $i ] = ( $i % 2 === 0 ) ? 1 : 0;
			}
			if ( $m[ $i ][6] === -1 ) {
				$m[ $i ][6] = ( $i % 2 === 0 ) ? 1 : 0;
			}
		}

		/* Alignment patterns */
		$ap = self::AP[ $ver ];
		$apc = count( $ap );
		for ( $ai = 0; $ai < $apc; $ai++ ) {
			for ( $aj = 0; $aj < $apc; $aj++ ) {
				$r = $ap[ $ai ];
				$c = $ap[ $aj ];
				/* Skip positions that overlap finder+separator areas */
				if ( ( $r <= 8 && $c <= 8 ) || ( $r <= 8 && $c >= $sz - 8 ) || ( $r >= $sz - 8 && $c <= 8 ) ) {
					continue;
				}
				/* Skip alignment centers on the timing row or column (row 6 / col 6).
				 * Those cells are already occupied by timing patterns; placing an
				 * alignment there would corrupt them. */
				if ( $r === 6 || $c === 6 ) {
					continue;
				}
				self::place_alignment( $m, $r, $c );
			}
		}

		/* Dark module */
		$m[ 4 * $ver + 9 ][8] = 1;

		/* Version information — required for V7 and above (ISO 18004 §7.10).
		 * Two 6×3 / 3×6 blocks are placed near the top-right and bottom-left
		 * finder patterns.  Each encodes the 6-bit version number with a
		 * BCH(18,6) check so scanners can self-correct it. */
		if ( $ver >= 7 ) {
			$vinfo = self::version_bits( $ver );
			for ( $i = 0; $i < 18; $i++ ) {
				$bit = ( $vinfo >> $i ) & 1;
				// Top-right copy: rows 0-5, cols (sz-11)..(sz-9)
				$m[ $i % 6 ][ $sz - 11 + (int)( $i / 6 ) ] = $bit;
				// Bottom-left copy: rows (sz-11)..(sz-9), cols 0-5
				$m[ $sz - 11 + (int)( $i / 6 ) ][ $i % 6 ] = $bit;
			}
		}

		/* Reserve format info cells (will be overwritten by write_format) */
		/* Copy 1: row 8 (cols 0-8) + col 8 (rows 0-8) */
		for ( $i = 0; $i <= 8; $i++ ) {
			if ( $m[8][ $i ] === -1 ) {
				$m[8][ $i ] = 0;
			}
			if ( $m[ $i ][8] === -1 ) {
				$m[ $i ][8] = 0;
			}
		}
		/* Copy 2: row 8 (cols sz-8..sz-1) + col 8 (rows sz-7..sz-1) */
		for ( $i = $sz - 8; $i < $sz; $i++ ) {
			if ( $m[8][ $i ] === -1 ) {
				$m[8][ $i ] = 0;
			}
		}
		for ( $i = $sz - 7; $i < $sz; $i++ ) {
			if ( $m[ $i ][8] === -1 ) {
				$m[ $i ][8] = 0;
			}
		}

		/* Convert codewords to bit stream */
		$bits = [];
		foreach ( $cw as $byte ) {
			for ( $b = 7; $b >= 0; $b-- ) {
				$bits[] = ( $byte >> $b ) & 1;
			}
		}
		for ( $i = 0; $i < self::REM[ $ver ]; $i++ ) {
			$bits[] = 0;
		}

		/* Place data in zigzag order */
		$bit_idx   = 0;
		$total_bits = count( $bits );
		$go_up     = true;
		$right_col = $sz - 1;

		while ( $right_col >= 1 ) {
			if ( $right_col === 6 ) {
				$right_col--; // skip timing column
			}
			for ( $step = 0; $step < $sz; $step++ ) {
				$row = $go_up ? ( $sz - 1 - $step ) : $step;
				for ( $dc = 0; $dc <= 1; $dc++ ) {
					$col = $right_col - $dc;
					if ( $m[ $row ][ $col ] === -1 ) {
						$m[ $row ][ $col ] = ( $bit_idx < $total_bits ) ? $bits[ $bit_idx++ ] : 0;
					}
				}
			}
			$go_up     = ! $go_up;
			$right_col -= 2;
		}

		return $m;
	}

	private static function place_finder( array &$m, int $fr, int $fc, int $sz ): void {
		/* 7×7 pattern */
		for ( $r = 0; $r < 7; $r++ ) {
			for ( $c = 0; $c < 7; $c++ ) {
				$m[ $fr + $r ][ $fc + $c ] = self::FP[ $r ][ $c ];
			}
		}
		/* Separator: 1-module white border around finder */
		for ( $i = -1; $i <= 7; $i++ ) {
			/* Top/bottom horizontal separators */
			foreach ( [ $fr - 1, $fr + 7 ] as $sr ) {
				$sc = $fc + $i;
				if ( $sr >= 0 && $sr < $sz && $sc >= 0 && $sc < $sz && $m[ $sr ][ $sc ] === -1 ) {
					$m[ $sr ][ $sc ] = 0;
				}
			}
			/* Left/right vertical separators */
			$sr = $fr + $i;
			foreach ( [ $fc - 1, $fc + 7 ] as $sc ) {
				if ( $sr >= 0 && $sr < $sz && $sc >= 0 && $sc < $sz && $m[ $sr ][ $sc ] === -1 ) {
					$m[ $sr ][ $sc ] = 0;
				}
			}
		}
	}

	private static function place_alignment( array &$m, int $r, int $c ): void {
		/* 5×5 alignment: dark border + white ring + dark center */
		for ( $dr = -2; $dr <= 2; $dr++ ) {
			for ( $dc = -2; $dc <= 2; $dc++ ) {
				$v = ( abs( $dr ) === 2 || abs( $dc ) === 2 ) ? 1
					: ( ( $dr === 0 && $dc === 0 ) ? 1 : 0 );
				$m[ $r + $dr ][ $c + $dc ] = $v;
			}
		}
	}

	// -----------------------------------------------------------------------
	// Masking
	// -----------------------------------------------------------------------

	private static function best_mask( array $m, int $ver, int $sz ): array {
		$best_score = PHP_INT_MAX;
		$best_m     = $m;

		for ( $mask = 0; $mask < 8; $mask++ ) {
			$tm = self::apply_mask( $m, $mask, $sz );
			self::write_format( $tm, $mask, $sz );
			$score = self::penalty( $tm, $sz );
			if ( $score < $best_score ) {
				$best_score = $score;
				$best_m     = $tm;
			}
		}
		return $best_m;
	}

	private static function apply_mask( array $m, int $mask, int $sz ): array {
		$t = $m; // deep copy
		for ( $r = 0; $r < $sz; $r++ ) {
			for ( $c = 0; $c < $sz; $c++ ) {
				if ( $t[ $r ][ $c ] < 0 || $t[ $r ][ $c ] > 1 ) {
					/* Fixed function cell — never mask */
					continue;
				}
				/* Only mask data cells (originally placed from bit stream).
				 * We detect them as cells that were -1 at construction time.
				 * After build_matrix they are 0 or 1 but in the free area.
				 * We distinguish with a separate fixed-cell check. */
				if ( self::is_function( $m, $r, $c ) ) {
					continue;
				}
				if ( self::mask_condition( $mask, $r, $c ) ) {
					$t[ $r ][ $c ] ^= 1;
				}
			}
		}
		return $t;
	}

	private static function mask_condition( int $mask, int $r, int $c ): bool {
		switch ( $mask ) {
			case 0: return ( $r + $c ) % 2 === 0;
			case 1: return $r % 2 === 0;
			case 2: return $c % 3 === 0;
			case 3: return ( $r + $c ) % 3 === 0;
			case 4: return ( (int)( $r / 2 ) + (int)( $c / 3 ) ) % 2 === 0;
			case 5: return ( $r * $c ) % 2 + ( $r * $c ) % 3 === 0;
			case 6: return ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) % 2 === 0;
			case 7: return ( ( $r + $c ) % 2 + ( $r * $c ) % 3 ) % 2 === 0;
		}
		return false;
	}

	/**
	 * Determine whether a cell belongs to a fixed function pattern
	 * (finder, separator, timing, alignment, format info, dark module).
	 * We rebuild the fixed-cell map from the original pre-mask matrix:
	 * any cell that was NOT -1 after build_matrix (before data placement)
	 * is fixed. Since we can't go back, we re-derive from position rules.
	 */
	private static function is_function( array $m, int $r, int $c ): bool {
		/* The original matrix $m here is the post-build_matrix, pre-mask copy.
		 * Fixed cells were written as 0 or 1 during matrix construction;
		 * data cells are also 0 or 1 but only in areas never written by
		 * functional patterns. We check by position. */
		$sz = count( $m );
		$ver = ( $sz - 21 ) / 4 + 1;

		/* Finder + separator zones (9×9 corners) */
		if ( $r <= 8 && $c <= 8 )         return true; // TL
		if ( $r <= 8 && $c >= $sz - 8 )   return true; // TR
		if ( $r >= $sz - 8 && $c <= 8 )   return true; // BL

		/* Timing patterns */
		if ( $r === 6 || $c === 6 )        return true;

		/* Dark module */
		if ( $r === 4 * $ver + 9 && $c === 8 ) return true;

		/* Alignment patterns — must mirror the exact skip rules used in build_matrix */
		$ap = self::AP[ $ver ];
		foreach ( $ap as $arow ) {
			foreach ( $ap as $acol ) {
				if ( ( $arow <= 8 && $acol <= 8 ) || ( $arow <= 8 && $acol >= $sz - 8 ) || ( $arow >= $sz - 8 && $acol <= 8 ) ) {
					continue; // overlaps finder zone
				}
				if ( $arow === 6 || $acol === 6 ) {
					continue; // on timing row/col — not placed
				}
				if ( abs( $r - $arow ) <= 2 && abs( $c - $acol ) <= 2 ) {
					return true;
				}
			}
		}

		/* Format info strips */
		if ( $r === 8 && ( $c <= 8 || $c >= $sz - 8 ) ) return true;
		if ( $c === 8 && ( $r <= 8 || $r >= $sz - 7 ) ) return true;

		/* Version information blocks (V7+) */
		if ( $ver >= 7 ) {
			// Top-right copy: rows 0-5, cols sz-11 to sz-9
			if ( $r <= 5 && $c >= $sz - 11 && $c <= $sz - 9 ) return true;
			// Bottom-left copy: rows sz-11 to sz-9, cols 0-5
			if ( $r >= $sz - 11 && $r <= $sz - 9 && $c <= 5 ) return true;
		}

		return false;
	}

	// -----------------------------------------------------------------------
	// Format information
	// -----------------------------------------------------------------------

	private static function write_format( array &$m, int $mask, int $sz ): void {
		$fmt = self::format_bits( $mask );

		/* Copy 1: row 8 (cols 0-8, skip timing col 6) + col 8 (rows 0-8, skip timing row 6).
		 * Bit i (LSB=0) → positions1[i]. i0→[8,0], i6→[8,7], i7→[8,8], i8→[7,8], i14→[0,8]. */
		$positions1 = [
			[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],
			[7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8],
		];
		/* Copy 2: col 8 (rows sz-1 down to sz-7) + row 8 (cols sz-8..sz-1).
		 * Bit i (LSB=0) → positions2[i]. i0→[sz-1,8], i6→[sz-7,8], i7→[8,sz-8], i14→[8,sz-1]. */
		$positions2 = [
			[$sz-1,8],[$sz-2,8],[$sz-3,8],[$sz-4,8],[$sz-5,8],[$sz-6,8],[$sz-7,8],
			[8,$sz-8],[8,$sz-7],[8,$sz-6],[8,$sz-5],[8,$sz-4],[8,$sz-3],[8,$sz-2],[8,$sz-1],
		];

		for ( $i = 0; $i < 15; $i++ ) {
			$bit = ( $fmt >> $i ) & 1;   // LSB first: bit 0 → position 0.
			[ $r, $c ] = $positions1[ $i ];
			$m[ $r ][ $c ] = $bit;
			[ $r, $c ] = $positions2[ $i ];
			$m[ $r ][ $c ] = $bit;
		}
	}

	/**
	 * Compute the 18-bit version information word for versions 7–40.
	 * = (version << 12) | BCH(18,6) remainder, generator 0x1F25.
	 * No XOR mask is applied to version information.
	 */
	private static function version_bits( int $ver ): int {
		$rem = $ver << 12;
		for ( $i = 5; $i >= 0; $i-- ) {
			if ( ( $rem >> ( $i + 12 ) ) & 1 ) {
				$rem ^= 0x1F25 << $i;
			}
		}
		return ( $ver << 12 ) | ( $rem & 0xFFF );
	}

	/**
	 * Compute the 15-bit format information word for EC level M and given mask.
	 * = (EC bits | mask bits) with BCH(15,5) error correction, XOR'd with 101010000010010.
	 */
	private static function format_bits( int $mask ): int {
		/* EC level M = 0b00; data = EC(2)|mask(3) = 5 bits */
		$data = ( 0b00 << 3 ) | ( $mask & 0x07 );
		/* BCH error correction with generator 0x537 = x^10+x^8+x^5+x^4+x^2+x+1 */
		$rem = $data << 10;
		for ( $i = 4; $i >= 0; $i-- ) {
			if ( ( $rem >> ( $i + 10 ) ) & 1 ) {
				$rem ^= 0x537 << $i;
			}
		}
		return ( ( $data << 10 ) | ( $rem & 0x3FF ) ) ^ 0x5412;
	}

	// -----------------------------------------------------------------------
	// Mask penalty scoring (ISO 18004 §7.8.3)
	// -----------------------------------------------------------------------

	private static function penalty( array $m, int $sz ): int {
		$score = 0;

		/* Rule 1: 5+ consecutive same-colour modules in a row or column */
		foreach ( [ 'row', 'col' ] as $axis ) {
			for ( $i = 0; $i < $sz; $i++ ) {
				$run = 1;
				$prev = $axis === 'row' ? $m[ $i ][0] : $m[0][ $i ];
				for ( $j = 1; $j < $sz; $j++ ) {
					$cur = $axis === 'row' ? $m[ $i ][ $j ] : $m[ $j ][ $i ];
					if ( $cur === $prev ) {
						$run++;
					} else {
						if ( $run >= 5 ) {
							$score += 3 + ( $run - 5 );
						}
						$run = 1;
					}
					$prev = $cur;
				}
				if ( $run >= 5 ) {
					$score += 3 + ( $run - 5 );
				}
			}
		}

		/* Rule 2: 2×2 blocks of same colour */
		for ( $r = 0; $r < $sz - 1; $r++ ) {
			for ( $c = 0; $c < $sz - 1; $c++ ) {
				$v = $m[ $r ][ $c ];
				if ( $v === $m[ $r ][ $c + 1 ] && $v === $m[ $r + 1 ][ $c ] && $v === $m[ $r + 1 ][ $c + 1 ] ) {
					$score += 3;
				}
			}
		}

		/* Rule 3: specific patterns (1011101 bordered by 4 whites) */
		$p3a = [ 1,0,1,1,1,0,1,0,0,0,0 ];
		$p3b = [ 0,0,0,0,1,0,1,1,1,0,1 ];
		for ( $r = 0; $r < $sz; $r++ ) {
			for ( $c = 0; $c <= $sz - 11; $c++ ) {
				$match_a = true; $match_b = true;
				for ( $k = 0; $k < 11; $k++ ) {
					if ( $m[ $r ][ $c + $k ] !== $p3a[ $k ] ) { $match_a = false; }
					if ( $m[ $r ][ $c + $k ] !== $p3b[ $k ] ) { $match_b = false; }
				}
				if ( $match_a ) { $score += 40; }
				if ( $match_b ) { $score += 40; }
			}
		}
		for ( $c = 0; $c < $sz; $c++ ) {
			for ( $r = 0; $r <= $sz - 11; $r++ ) {
				$match_a = true; $match_b = true;
				for ( $k = 0; $k < 11; $k++ ) {
					if ( $m[ $r + $k ][ $c ] !== $p3a[ $k ] ) { $match_a = false; }
					if ( $m[ $r + $k ][ $c ] !== $p3b[ $k ] ) { $match_b = false; }
				}
				if ( $match_a ) { $score += 40; }
				if ( $match_b ) { $score += 40; }
			}
		}

		/* Rule 4: proportion of dark modules */
		$dark = 0;
		for ( $r = 0; $r < $sz; $r++ ) {
			for ( $c = 0; $c < $sz; $c++ ) {
				$dark += $m[ $r ][ $c ] & 1;
			}
		}
		$pct  = $dark * 100 / ( $sz * $sz );
		$prev5 = (int)( $pct / 5 ) * 5;
		$next5 = $prev5 + 5;
		$score += min( abs( $prev5 - 50 ), abs( $next5 - 50 ) ) / 5 * 10;

		return (int) $score;
	}

	// -----------------------------------------------------------------------
	// SVG renderer
	// -----------------------------------------------------------------------

	private static function render( array $m, int $sz, int $px, int $quiet ): string {
		$total = ( $sz + 2 * $quiet ) * $px;
		$qpx   = $quiet * $px;

		$rects = '';
		for ( $r = 0; $r < $sz; $r++ ) {
			for ( $c = 0; $c < $sz; $c++ ) {
				if ( ( $m[ $r ][ $c ] & 1 ) === 1 ) {
					$x      = $qpx + $c * $px;
					$y      = $qpx + $r * $px;
					$rects .= '<rect x="' . $x . '" y="' . $y . '" width="' . $px . '" height="' . $px . '"/>';
				}
			}
		}

		return '<svg xmlns="http://www.w3.org/2000/svg"'
			. ' viewBox="0 0 ' . $total . ' ' . $total . '"'
			. ' width="' . $total . '" height="' . $total . '">'
			. '<rect width="' . $total . '" height="' . $total . '" fill="#fff"/>'
			. '<g fill="#000">' . $rects . '</g>'
			. '</svg>';
	}
}

// phpcs:enable
