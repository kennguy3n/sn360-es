// tests/load/lib/seed.js
//
// Tiny deterministic PRNG so every k6 scenario can pick corpus rows
// and tenant indexes reproducibly. We don't import a library — k6
// runs JavaScript files in goja with no Node module resolution, so
// adding an npm dep means committing a vendored bundle. Mulberry32
// gives us 2^32 unique sequences and is fine for picking corpus
// indexes and tenant rotations; we are not generating cryptographic
// randomness here.

/**
 * mulberry32 returns a function that produces deterministic 32-bit
 * floats in [0, 1). Same seed -> identical sequence forever.
 *
 *   const rand = mulberry32(42);
 *   rand(); // 0.6011037519201636
 *
 * @param {number} seed   any 32-bit unsigned integer; 0 is fine.
 * @returns {() => number}
 */
export function mulberry32(seed) {
  // The bitwise ops force int32 arithmetic in V8/goja.
  let a = seed | 0;
  return function () {
    a = (a + 0x6d2b79f5) | 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * randInt returns an integer in [0, max). Throws on a non-positive
 * max so a bug in the caller doesn't silently always pick index 0.
 *
 * @param {() => number} rand   PRNG, e.g. mulberry32(seed)
 * @param {number} max          upper bound (exclusive)
 * @returns {number}
 */
export function randInt(rand, max) {
  if (!Number.isFinite(max) || max <= 0) {
    throw new Error(`randInt: max must be > 0, got ${max}`);
  }
  return Math.floor(rand() * max);
}
