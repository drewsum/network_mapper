import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { api } from "./api";

/* The home page's masthead: "NETMAP" decodes out of falling hex (MAC-address digits) above
 * a neon grid racing toward the horizon, with a scan bar that glitches it every few seconds.
 * Drawn as characters on a canvas, after Atelier ASCII's loops (decode, rain, scan, wave)
 * and post effects (glow, RGB split; scanlines and vignette are CSS). */

const ROWS = 14;
const LINE = 13; // px per row
const PAD = 6; // px above and below the grid
const FONT = '600 12px ui-monospace, "Cascadia Mono", Consolas, monospace';
const WORD_TOP = 1;
const TAGLINE = 8;
const HORIZON = 9;
const FPS = 30;

function rgba([r, g, b]: number[], a: number) {
  return `rgba(${r},${g},${b},${a})`;
}

const SCRAMBLE = "!<>-_\\/[]{}=+*^?#%01ABCDEF";
const HEX = "0123456789abcdef";
const WAVE = " .·:-=+";

// Atelier ASCII's Cyberpunk theme (#0B0420 on a #3D2BFF, #00E5FF, #FF2BD6, #FFF04D ramp),
// with an orange between its yellow and magenta.
const CYAN = [0, 229, 255];
const MAGENTA = [255, 43, 214];
const AMBER = [255, 166, 61];
const YELLOW = "#fff04d";
// The wordmark, top row to bottom.
const LETTER_COLORS = [[255, 240, 77], AMBER, MAGENTA, [128, 134, 234], CYAN].map((c, i) =>
  rgba(c, i === 0 ? 0.92 : 1),
);
const SHADOW = "#4a1d8a";

// 5x5 letters; the masthead shears them into italics.
const LETTERS: Record<string, string[]> = {
  N: ["X...X", "XX..X", "X.X.X", "X..XX", "X...X"],
  E: ["XXXXX", "X....", "XXXX.", "X....", "XXXXX"],
  T: ["XXXXX", "..X..", "..X..", "..X..", "..X.."],
  M: ["X...X", "XX.XX", "X.X.X", "X...X", "X...X"],
  A: [".XXX.", "X...X", "XXXXX", "X...X", "X...X"],
  P: ["XXXX.", "X...X", "XXXX.", "X....", "X...."],
};
const WORD = "NETMAP";

// Every 8 s from 3 s in, the scan bar crosses in 1.4 s.
const SCAN_FIRST = 3;
const SCAN_EVERY = 8;
const SCAN_TAKES = 1.4;

const pick = (chars: string) => chars[Math.floor(Math.random() * chars.length)];

interface Drop {
  col: number;
  y: number; // head row, fractional
  speed: number; // rows a second
  len: number;
  chars: string[];
  amber: boolean;
}

/** What depends on the canvas width: the grid, where the wordmark's cells are, the rain. */
interface Scene {
  width: number;
  cw: number; // px per column
  cols: number;
  word: Int8Array; // per cell: 0 empty, 1 letter, 2 its extruded shadow
  letterRow: Int8Array;
  lockAt: Float32Array; // when each letter cell stops scrambling
  drops: Drop[];
}

function newDrop(cols: number, top: boolean): Drop {
  const len = 3 + Math.floor(Math.random() * 6);
  return {
    col: Math.floor(Math.random() * cols),
    y: top ? -Math.random() * 10 : Math.random() * HORIZON,
    speed: 5 + Math.random() * 11,
    len,
    chars: Array.from({ length: len }, () => pick(HEX)),
    amber: Math.random() < 0.25,
  };
}

function buildScene(width: number, cw: number): Scene {
  const cols = Math.max(1, Math.floor(width / cw));
  const word = new Int8Array(cols * ROWS);
  const letterRow = new Int8Array(cols * ROWS);
  const lockAt = new Float32Array(cols * ROWS);
  const scale = cols >= 84 ? 2 : 1;
  const gap = cols >= 42 ? scale + 1 : 1;
  const shear = (r: number) => Math.floor(((4 - r) * scale) / 2);
  const wide = WORD.length * 5 * scale + (WORD.length - 1) * gap + shear(0);
  const x0 = Math.floor((cols - wide) / 2);
  [...WORD].forEach((ch, li) => {
    LETTERS[ch].forEach((line, r) => {
      [...line].forEach((px, k) => {
        if (px !== "X") return;
        for (let sx = 0; sx < scale; sx++) {
          const c = x0 + li * (5 * scale + gap) + k * scale + sx + shear(r);
          if (c < 0 || c >= cols) continue;
          const i = (WORD_TOP + r) * cols + c;
          word[i] = 1;
          letterRow[i] = r;
          lockAt[i] = 0.3 + Math.random() * 0.9 + ((c - x0) / wide) * 0.5;
        }
      });
    });
  });
  // Extrude down and to the right.
  for (let i = word.length - cols - 2; i >= 0; i--) {
    const j = i + cols + 1;
    if (word[i] === 1 && word[j] === 0 && j % cols !== 0) word[j] = 2;
  }
  const drops = Array.from({ length: Math.ceil(cols / 6) }, () => newDrop(cols, false));
  return { width, cw, cols, word, letterRow, lockAt, drops };
}

function tagline(total: number | undefined, online: number): string {
  if (total === undefined) return "> SCANNING THE LAN";
  const clock = new Date().toLocaleTimeString([], { hour12: false });
  return `> ${total} DEVICES ▸ ${online} ONLINE ▸ ${clock}`;
}

/** One frame at t seconds. Glyphs go on `glyphs` (transparent), which is then laid on the
 * background twice: sharp, and blurred for the glow. */
function draw(
  out: CanvasRenderingContext2D,
  glyphs: CanvasRenderingContext2D,
  s: Scene,
  t: number,
  text: string,
) {
  const { cw, cols, word } = s;
  const g = glyphs;
  const at = (ch: string, c: number, r: number, color: string, dx = 0) => {
    g.fillStyle = color;
    g.fillText(ch, c * cw + dx, PAD + r * LINE);
  };
  g.clearRect(0, 0, g.canvas.width, g.canvas.height);
  g.font = FONT;
  g.textBaseline = "top";

  const scanPhase = t >= SCAN_FIRST ? (t - SCAN_FIRST) % SCAN_EVERY : Infinity;
  const bar = scanPhase < SCAN_TAKES ? (scanPhase / SCAN_TAKES) * (cols + 12) - 6 : -99;

  const typed = Math.max(0, Math.floor((t - 1.6) * 30));
  const shown = text.slice(0, typed) + (Math.floor(t * 2) % 2 ? " " : "█");
  const tx = Math.floor((cols - text.length - 1) / 2);

  // Wave field and rain, above the horizon, behind the letters and the tagline.
  const free = (c: number, r: number) =>
    word[r * cols + c] === 0 && !(r === TAGLINE && c >= tx - 1 && c <= tx + text.length + 1);
  for (let r = 0; r < HORIZON; r++) {
    for (let c = 0; c < cols; c++) {
      const v = Math.sin(c * 0.11 + t * 0.6) + Math.sin(r * 0.55 - t * 0.9) + Math.sin((c + r * 2) * 0.05 + t * 0.4);
      const n = (v + 3) / 6;
      const k = Math.floor(Math.max(0, n - 0.45) * 1.9 * WAVE.length);
      if (k > 0 && free(c, r)) at(WAVE[Math.min(k, WAVE.length - 1)], c, r, `rgba(140,70,255,${0.08 + n * 0.22})`);
    }
  }
  for (const d of s.drops) {
    for (let i = 0; i < d.len; i++) {
      const r = Math.floor(d.y) - i;
      if (r < 0 || r >= HORIZON || !free(d.col, r)) continue;
      at(d.chars[(r + d.len) % d.len], d.col, r, i === 0 ? (d.amber ? "#fff6b0" : "#d8fbff") : rgba(d.amber ? AMBER : CYAN, (1 - i / d.len) * 0.55));
    }
  }

  // The floor: lines to the vanishing point, and crossbars rushing in.
  const cx = cols / 2;
  for (let j = 1; HORIZON + j < ROWS; j++) {
    const r = HORIZON + j;
    const alpha = 0.2 + j * 0.16;
    const spread = 0.6 + j * 1.7;
    for (let i = -Math.ceil(cx / spread); i <= Math.ceil(cx / spread); i++) {
      const c = Math.round(cx + i * spread * 3);
      if (c >= 0 && c < cols) at(i < 0 ? "/" : i > 0 ? "\\" : "|", c, r, rgba(MAGENTA, alpha));
    }
  }
  const depth = ROWS - HORIZON - 0.5;
  for (let k = 0; k < 6; k++) {
    const z = k + 1 - ((t * 1.1) % 1);
    const j = Math.round(depth / z);
    if (j < 1 || HORIZON + j >= ROWS) continue;
    for (let c = 0; c < cols; c++) at("─", c, HORIZON + j, rgba(MAGENTA, 0.15 + j * 0.12));
  }
  for (let c = 0; c < cols; c++) at("═", c, HORIZON, rgba(MAGENTA, 0.9));

  // The wordmark: shadow, then letters decoding, shimmering, and glitched by the scan bar.
  for (let i = 0; i < word.length; i++) {
    if (!word[i]) continue;
    const c = i % cols;
    const r = Math.floor(i / cols);
    if (word[i] === 2) {
      if (t >= s.lockAt[i - cols - 1]) at("▒", c, r, SHADOW);
      continue;
    }
    const lock = s.lockAt[i];
    if (t < lock - 0.7) continue;
    if (t < lock || Math.abs(c - bar) < 1.5) {
      at(pick(SCRAMBLE), c, r, t < lock ? rgba(CYAN, 0.8) : "#ffffff");
      continue;
    }
    const color = LETTER_COLORS[s.letterRow[i]];
    const ch = Math.sin(c * 0.25 - t * 2.5 + r * 0.6) > 0.92 ? "▓" : "█";
    if (Math.abs(c - bar) < 5) {
      g.globalCompositeOperation = "lighter";
      at(ch, c, r, rgba(CYAN, 0.7), -2);
      at(ch, c, r, rgba(MAGENTA, 0.7), 2);
      g.globalCompositeOperation = "source-over";
    }
    at(ch, c, r, color);
  }

  at(shown.slice(0, 1), tx, TAGLINE, YELLOW);
  for (let k = 1; k < shown.length; k++) {
    at(shown[k], tx + k, TAGLINE, k === shown.length - 1 && shown[k] === "█" ? YELLOW : "#9ff7ff");
  }

  // Composite: background, sharp glyphs, then a blurred copy added for the glow.
  const w = out.canvas.width;
  const h = out.canvas.height;
  const bg = out.createLinearGradient(0, 0, 0, h);
  bg.addColorStop(0, "#0b0420");
  bg.addColorStop(HORIZON / ROWS, "#160830");
  bg.addColorStop(1, "#05030b");
  out.setTransform(1, 0, 0, 1, 0, 0);
  out.fillStyle = bg;
  out.fillRect(0, 0, w, h);
  out.drawImage(g.canvas, 0, 0);
  out.globalCompositeOperation = "lighter";
  out.globalAlpha = 0.55;
  out.filter = `blur(${Math.round((w / s.width) * 4)}px)`;
  out.drawImage(g.canvas, 0, 0);
  out.filter = "none";
  out.globalAlpha = 1;
  out.globalCompositeOperation = "source-over";
}

function advance(s: Scene, dt: number) {
  for (const d of s.drops) {
    d.y += d.speed * dt;
    if (Math.random() < dt * 4) d.chars[Math.floor(Math.random() * d.len)] = pick(HEX);
    if (d.y - d.len > HORIZON) Object.assign(d, newDrop(s.cols, true));
  }
}

export function Masthead() {
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.devices });
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const counts = useRef<{ total?: number; online: number }>({ online: 0 });
  const redrawStill = useRef<() => void>(() => {});
  const total = devices.data?.length;
  const online = devices.data?.filter((d) => d.online).length ?? 0;

  useEffect(() => {
    const box = wrap.current;
    const out = canvas.current?.getContext("2d");
    const glyphs = document.createElement("canvas").getContext("2d");
    if (!box || !out || !glyphs) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)");
    let scene: Scene | null = null;
    let frame = 0;
    let visible = true;
    let last = 0;
    const start = performance.now();

    const render = (t: number) => {
      if (!scene) return;
      const c = counts.current;
      const dpr = window.devicePixelRatio || 1;
      glyphs.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw(out, glyphs, scene, t, tagline(c.total, c.online));
    };
    // Reduced motion: one settled frame (after the decode, between scans).
    const renderStill = () => render(6);
    redrawStill.current = () => still.matches && renderStill();

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const width = box.clientWidth;
      const height = ROWS * LINE + PAD * 2;
      for (const c of [out.canvas, glyphs.canvas]) {
        c.width = Math.round(width * dpr);
        c.height = Math.round(height * dpr);
      }
      glyphs.font = FONT;
      scene = buildScene(width, glyphs.measureText("M").width);
      if (still.matches) renderStill();
    };

    const tick = (now: number) => {
      frame = 0;
      if (!visible || still.matches) return;
      frame = requestAnimationFrame(tick);
      if (now - last < 1000 / FPS || !scene) return;
      advance(scene, Math.min(0.1, (now - last) / 1000));
      last = now;
      render((now - start) / 1000);
    };
    const play = () => {
      if (still.matches) renderStill();
      else if (visible && !frame) frame = requestAnimationFrame(tick);
    };

    const sized = new ResizeObserver(resize);
    sized.observe(box);
    const seen = new IntersectionObserver(([e]) => {
      visible = e.isIntersecting;
      play();
    });
    seen.observe(box);
    still.addEventListener("change", play);
    resize();
    play();
    return () => {
      cancelAnimationFrame(frame);
      sized.disconnect();
      seen.disconnect();
      still.removeEventListener("change", play);
    };
  }, []);

  // With reduced motion the still frame waits for the counts.
  useEffect(() => {
    counts.current = { total, online };
    redrawStill.current();
  }, [total, online]);

  const label =
    total === undefined ? "Network Mapper" : `Network Mapper: ${total} devices, ${online} online`;
  return (
    <div ref={wrap} className="masthead" role="img" aria-label={label}>
      <canvas ref={canvas} />
    </div>
  );
}
