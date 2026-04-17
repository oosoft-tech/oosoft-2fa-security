/**
 * QR Code Generator — Byte mode, EC level M, versions 1–10.
 * Renders to an HTML5 <canvas> element.
 * ISO/IEC 18004:2015 compliant.
 *
 * Public API:
 *   OOSoftQR.draw(text, containerElement [, px [, quiet]])
 *   Clears containerElement and appends a <canvas> with the QR code.
 */
/* global window */
(function (win) {
  'use strict';

  // ── GF(256) tables ──────────────────────────────────────────────────────────
  var EXP = new Array(512);
  var LOG = new Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x = (x << 1) ^ (x > 127 ? 0x11d : 0);
    }
    for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
  }());

  function gfMul(a, b) {
    return (a && b) ? EXP[LOG[a] + LOG[b]] : 0;
  }

  // ── Reed-Solomon encoder ────────────────────────────────────────────────────
  function rsEncode(data, nec) {
    // Build generator polynomial g(x) = ∏(x + α^i) i=0..nec-1
    var g = [1];
    for (var i = 0; i < nec; i++) {
      var ng = [];
      for (var k = 0; k <= g.length; k++) ng.push(0);
      for (var j = 0; j < g.length; j++) {
        ng[j]     ^= g[j];
        ng[j + 1] ^= gfMul(g[j], EXP[i]);
      }
      g = ng;
    }
    // Polynomial long-division → remainder = EC codewords
    var msg = data.slice();
    for (var z = 0; z < nec; z++) msg.push(0);
    for (var i = 0; i < data.length; i++) {
      var c = msg[i];
      if (c) for (var j = 1; j <= nec; j++) msg[i + j] ^= gfMul(g[j], c);
    }
    return msg.slice(data.length);
  }

  // ── Spec tables ─────────────────────────────────────────────────────────────
  // CAP[v] = max bytes, EC level M
  var CAP = [0,16,28,44,64,86,108,124,154,182,216];
  // RSB[v] = [ec_cw_per_block, g1_blocks, g1_data_cw, g2_blocks, g2_data_cw]
  var RSB = [null,
    [10,1,16,0, 0],[16,1,28,0, 0],[26,1,44,0, 0],[18,2,32,0, 0],
    [24,2,43,0, 0],[16,4,27,0, 0],[18,4,31,0, 0],[22,2,38,2,39],
    [22,3,36,2,37],[26,4,43,1,44]
  ];
  // AP[v] = alignment-pattern centre coordinates
  var AP = [[],[],[6,18],[6,22],[6,26],[6,30],[6,34],
    [6,22,38],[6,24,42],[6,26,46],[6,28,50]];
  // Remainder bits appended after last codeword
  var REM = [0,0,7,7,7,7,7,0,0,0,0];

  // ── Helpers ─────────────────────────────────────────────────────────────────
  function pad8(n) { return ('00000000' + n.toString(2)).slice(-8); }

  function pickVersion(text) {
    for (var v = 1; v <= 10; v++) if (text.length <= CAP[v]) return v;
    return 0;
  }

  // ── Codeword builder ────────────────────────────────────────────────────────
  function buildCodewords(text, ver) {
    var rsb = RSB[ver];
    var ec_n = rsb[0], g1b = rsb[1], g1d = rsb[2], g2b = rsb[3], g2d = rsb[4];
    var totalData = g1b * g1d + g2b * g2d;

    // Bit stream — byte mode
    var bits = '0100';                         // mode indicator
    bits += pad8(text.length);                 // character count (8 bits for V1-9)
    for (var i = 0; i < text.length; i++) bits += pad8(text.charCodeAt(i));
    bits += '0000';                            // terminator
    while (bits.length % 8) bits += '0';       // byte-boundary padding
    var pi = 0;
    while (bits.length < totalData * 8) bits += (pi++ % 2 ? '00010001' : '11101100');

    // Convert to byte array
    var dc = [];
    for (var i = 0; i < totalData; i++) dc.push(parseInt(bits.substr(i * 8, 8), 2));

    // Split into blocks and compute RS error correction
    var blocks = [], off = 0;
    for (var b = 0; b < g1b; b++) { var d = dc.slice(off, off + g1d); off += g1d; blocks.push({ d: d, ec: rsEncode(d, ec_n) }); }
    for (var b = 0; b < g2b; b++) { var d = dc.slice(off, off + g2d); off += g2d; blocks.push({ d: d, ec: rsEncode(d, ec_n) }); }

    // Interleave data codewords
    var all = [];
    var maxD = Math.max(g1d, g2d || g1d);
    for (var i = 0; i < maxD; i++) for (var b = 0; b < blocks.length; b++) if (i < blocks[b].d.length) all.push(blocks[b].d[i]);
    // Interleave EC codewords
    for (var i = 0; i < ec_n; i++) for (var b = 0; b < blocks.length; b++) all.push(blocks[b].ec[i]);
    return all;
  }

  // ── Matrix construction ─────────────────────────────────────────────────────
  var FP = [[1,1,1,1,1,1,1],[1,0,0,0,0,0,1],[1,0,1,1,1,0,1],
            [1,0,1,1,1,0,1],[1,0,1,1,1,0,1],[1,0,0,0,0,0,1],[1,1,1,1,1,1,1]];

  function newMatrix(sz) {
    var m = [];
    for (var i = 0; i < sz; i++) { m.push([]); for (var j = 0; j < sz; j++) m[i].push(-1); }
    return m;
  }

  function placeFinder(m, fr, fc, sz) {
    for (var r = 0; r < 7; r++) for (var c = 0; c < 7; c++) m[fr + r][fc + c] = FP[r][c];
    for (var i = -1; i <= 7; i++) {
      var cells = [[fr - 1, fc + i], [fr + 7, fc + i], [fr + i, fc - 1], [fr + i, fc + 7]];
      for (var k = 0; k < cells.length; k++) {
        var r2 = cells[k][0], c2 = cells[k][1];
        if (r2 >= 0 && r2 < sz && c2 >= 0 && c2 < sz && m[r2][c2] < 0) m[r2][c2] = 0;
      }
    }
  }

  function placeAlign(m, r, c) {
    for (var dr = -2; dr <= 2; dr++) for (var dc = -2; dc <= 2; dc++)
      m[r + dr][c + dc] = (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) ? 1 : 0;
  }

  function buildMatrix(cw, ver, sz) {
    var m = newMatrix(sz);

    // Finder patterns + separators
    placeFinder(m, 0, 0, sz);
    placeFinder(m, 0, sz - 7, sz);
    placeFinder(m, sz - 7, 0, sz);

    // Timing patterns
    for (var i = 8; i < sz - 8; i++) {
      if (m[6][i] < 0) m[6][i] = (i % 2 === 0) ? 1 : 0;
      if (m[i][6] < 0) m[i][6] = (i % 2 === 0) ? 1 : 0;
    }

    // Alignment patterns (skip finder zones and timing row/col)
    var ap = AP[ver];
    for (var ai = 0; ai < ap.length; ai++) for (var aj = 0; aj < ap.length; aj++) {
      var r = ap[ai], c = ap[aj];
      if ((r <= 8 && c <= 8) || (r <= 8 && c >= sz - 8) || (r >= sz - 8 && c <= 8)) continue;
      if (r === 6 || c === 6) continue;
      placeAlign(m, r, c);
    }

    // Dark module
    m[4 * ver + 9][8] = 1;

    // Version information (V7+)
    if (ver >= 7) {
      var vb = versionBits(ver);
      for (var i = 0; i < 18; i++) {
        var bit = (vb >> i) & 1;
        m[i % 6][sz - 11 + Math.floor(i / 6)] = bit;   // top-right copy
        m[sz - 11 + Math.floor(i / 6)][i % 6] = bit;   // bottom-left copy
      }
    }

    // Reserve format information strips (placeholder 0s — overwritten by writeFormat)
    for (var i = 0; i <= 8; i++) {
      if (m[8][i] < 0) m[8][i] = 0;
      if (m[i][8] < 0) m[i][8] = 0;
    }
    for (var i = sz - 8; i < sz; i++) if (m[8][i] < 0) m[8][i] = 0;
    for (var i = sz - 7; i < sz; i++) if (m[i][8] < 0) m[i][8] = 0;

    // Convert codewords → bit stream
    var bits = [];
    for (var i = 0; i < cw.length; i++) for (var b = 7; b >= 0; b--) bits.push((cw[i] >> b) & 1);
    for (var i = 0; i < REM[ver]; i++) bits.push(0);

    // Place data in zigzag order
    var bi = 0, goUp = true, col = sz - 1;
    while (col >= 1) {
      if (col === 6) col--;
      for (var step = 0; step < sz; step++) {
        var row = goUp ? (sz - 1 - step) : step;
        for (var dc = 0; dc <= 1; dc++) {
          var c2 = col - dc;
          if (m[row][c2] < 0) m[row][c2] = bi < bits.length ? bits[bi++] : 0;
        }
      }
      goUp = !goUp;
      col -= 2;
    }
    return m;
  }

  // ── Format information ──────────────────────────────────────────────────────
  function formatBits(mask) {
    // EC level M = 0b00; 5-bit data = (0b00 << 3) | mask
    var data = mask & 7;
    var rem  = data << 10;
    // BCH(15,5) with generator 0x537
    for (var i = 4; i >= 0; i--) if ((rem >> (i + 10)) & 1) rem ^= (0x537 << i);
    // XOR with mask pattern 101010000010010
    return ((data << 10) | (rem & 0x3FF)) ^ 0x5412;
  }

  function versionBits(ver) {
    // BCH(18,6) with generator 0x1F25
    var rem = ver << 12;
    for (var i = 5; i >= 0; i--) if ((rem >> (i + 12)) & 1) rem ^= (0x1F25 << i);
    return (ver << 12) | (rem & 0xFFF);
  }

  // Format info bit positions (ISO 18004 §7.9):
  // Copy 1: bit i (LSB=0) → P1[i].  Copy 2: bit i → P2[i].
  var FMT_P1 = [[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],[7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]];

  function writeFormat(m, mask, sz) {
    var fmt = formatBits(mask);
    var p2r = [sz-1,sz-2,sz-3,sz-4,sz-5,sz-6,sz-7];   // col 8 rows (copy 2, column part)
    var p2c = [sz-8,sz-7,sz-6,sz-5,sz-4,sz-3,sz-2,sz-1]; // row 8 cols (copy 2, row part)
    for (var i = 0; i < 15; i++) {
      var bit = (fmt >> i) & 1;
      m[FMT_P1[i][0]][FMT_P1[i][1]] = bit;
      // Copy 2
      if (i < 7) { m[p2r[i]][8]    = bit; }   // i=0→[sz-1,8] … i=6→[sz-7,8]
      else        { m[8][p2c[i-7]] = bit; }    // i=7→[8,sz-8] … i=14→[8,sz-1]
    }
  }

  // ── Masking ─────────────────────────────────────────────────────────────────
  function isFunc(r, c, ver, sz) {
    // Finder + separator zones
    if (r <= 8 && c <= 8)       return true;
    if (r <= 8 && c >= sz - 8)  return true;
    if (r >= sz - 8 && c <= 8)  return true;
    // Timing
    if (r === 6 || c === 6)     return true;
    // Dark module
    if (r === 4 * ver + 9 && c === 8) return true;
    // Alignment patterns (same skip rules as buildMatrix)
    var ap = AP[ver];
    for (var ai = 0; ai < ap.length; ai++) for (var aj = 0; aj < ap.length; aj++) {
      var ar = ap[ai], ac = ap[aj];
      if ((ar <= 8 && ac <= 8) || (ar <= 8 && ac >= sz - 8) || (ar >= sz - 8 && ac <= 8)) continue;
      if (ar === 6 || ac === 6) continue;
      if (Math.abs(r - ar) <= 2 && Math.abs(c - ac) <= 2) return true;
    }
    // Format information strips
    if (r === 8 && (c <= 8 || c >= sz - 8)) return true;
    if (c === 8 && (r <= 8 || r >= sz - 7)) return true;
    // Version information (V7+)
    if (ver >= 7) {
      if (r <= 5 && c >= sz - 11 && c <= sz - 9) return true;
      if (r >= sz - 11 && r <= sz - 9 && c <= 5)  return true;
    }
    return false;
  }

  function maskCondition(mask, r, c) {
    switch (mask) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return (r * c) % 2 + (r * c) % 3 === 0;
      case 6: return ((r * c) % 2 + (r * c) % 3) % 2 === 0;
      case 7: return ((r + c) % 2 + (r * c) % 3) % 2 === 0;
    }
    return false;
  }

  function applyMask(m, mask, ver, sz) {
    var t = [];
    for (var r = 0; r < sz; r++) { t.push([]); for (var c = 0; c < sz; c++) t[r].push(m[r][c]); }
    for (var r = 0; r < sz; r++) for (var c = 0; c < sz; c++)
      if (!isFunc(r, c, ver, sz) && maskCondition(mask, r, c)) t[r][c] ^= 1;
    return t;
  }

  // ── Penalty scoring (ISO 18004 §7.8.3) ──────────────────────────────────────
  function penalty(m, sz) {
    var score = 0, r, c, k;

    // Rule 1: runs of 5+ same-colour modules
    for (r = 0; r < sz; r++) {
      var runR = 1, runC = 1;
      for (c = 1; c < sz; c++) {
        if (m[r][c] === m[r][c-1]) { runR++; } else { if (runR >= 5) score += runR - 2; runR = 1; }
        if (m[c][r] === m[c-1][r]) { runC++; } else { if (runC >= 5) score += runC - 2; runC = 1; }
      }
      if (runR >= 5) score += runR - 2;
      if (runC >= 5) score += runC - 2;
    }

    // Rule 2: 2×2 blocks
    for (r = 0; r < sz - 1; r++) for (c = 0; c < sz - 1; c++)
      if (m[r][c] === m[r][c+1] && m[r][c] === m[r+1][c] && m[r][c] === m[r+1][c+1]) score += 3;

    // Rule 3: finder-like patterns
    var p3a = [1,0,1,1,1,0,1,0,0,0,0], p3b = [0,0,0,0,1,0,1,1,1,0,1];
    for (r = 0; r < sz; r++) for (c = 0; c <= sz - 11; c++) {
      var ma = true, mb = true;
      for (k = 0; k < 11; k++) { if (m[r][c+k] !== p3a[k]) ma = false; if (m[r][c+k] !== p3b[k]) mb = false; }
      if (ma) score += 40; if (mb) score += 40;
    }
    for (c = 0; c < sz; c++) for (r = 0; r <= sz - 11; r++) {
      var ma = true, mb = true;
      for (k = 0; k < 11; k++) { if (m[r+k][c] !== p3a[k]) ma = false; if (m[r+k][c] !== p3b[k]) mb = false; }
      if (ma) score += 40; if (mb) score += 40;
    }

    // Rule 4: dark-module proportion
    var dark = 0;
    for (r = 0; r < sz; r++) for (c = 0; c < sz; c++) dark += m[r][c] & 1;
    var pct = dark * 100 / (sz * sz), p5 = Math.floor(pct / 5) * 5;
    score += Math.min(Math.abs(p5 - 50), Math.abs(p5 + 5 - 50)) / 5 * 10;
    return score;
  }

  // ── Best mask selection ──────────────────────────────────────────────────────
  function bestMask(m, ver, sz) {
    var best = null, bestScore = Infinity;
    for (var mask = 0; mask < 8; mask++) {
      var tm = applyMask(m, mask, ver, sz);
      writeFormat(tm, mask, sz);
      var s = penalty(tm, sz);
      if (s < bestScore) { bestScore = s; best = tm; }
    }
    return best;
  }

  // ── Canvas renderer ──────────────────────────────────────────────────────────
  function renderCanvas(m, sz, px, quiet) {
    var total = (sz + 2 * quiet) * px;
    var canvas = document.createElement('canvas');
    canvas.width  = total;
    canvas.height = total;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, total, total);
    ctx.fillStyle = '#000000';
    var qpx = quiet * px;
    for (var r = 0; r < sz; r++) for (var c = 0; c < sz; c++)
      if ((m[r][c] & 1) === 1) ctx.fillRect(qpx + c * px, qpx + r * px, px, px);
    return canvas;
  }

  // ── Public API ───────────────────────────────────────────────────────────────
  win.OOSoftQR = {
    draw: function (text, container, px, quiet) {
      px    = px    || 6;
      quiet = quiet || 4;
      var ver = pickVersion(text);
      if (!ver) { container.textContent = 'URI too long for QR'; return; }
      var sz = (ver - 1) * 4 + 21;
      var cw = buildCodewords(text, ver);
      var m  = buildMatrix(cw, ver, sz);
      m = bestMask(m, ver, sz);
      var canvas = renderCanvas(m, sz, px, quiet);
      while (container.firstChild) container.removeChild(container.firstChild);
      container.appendChild(canvas);
    }
  };

}(window));
