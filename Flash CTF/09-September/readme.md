<h1 align="center">🚩 MetaCTF September 2026 Flash CTF</h1>
<p align="center">
  <b>Write-ups by TheDingo8MyBaby</b>
</p>
<p align="center">
  <a href="https://compete.metactf.com/652/"><img src="https://img.shields.io/badge/Platform-MetaCTF-red?style=for-the-badge" /></a>
  <img src="https://img.shields.io/badge/Solved-7%2F7-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Rank-50%20%2F%20307-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Score-1400-orange?style=for-the-badge" />
</p>

---

## 📋 About

This folder holds my write-ups for the **MetaCTF September 2026 Flash CTF**, a two-hour jeopardy-style event held on **Thursday, September 24th, 2026** (5:00 PM to 7:00 PM US Eastern). All seven challenges are solved, one in each category plus an extra Forensics.

I finished **50th out of 307** individuals/teams with at least one solve, clearing every challenge for a full **1400 points**.

> MetaCTF has since rebranded as **SkillBit**, so the flags are wrapped in `SkillBit{...}` even though the event ran under the MetaCTF name.

---

## 🗂️ Challenges

| # | Challenge | Category | Points | Solves | Write-up |
|---|-----------|----------|-------:|-------:|----------|
| 1 | Carry On | Forensics | 50 | 277 | [📄](./Carry-On-Writeup.md) |
| 2 | Careless Talk | Binary Exploitation | 100 | 273 | [📄](./Careless-Talk-Writeup.md) |
| 3 | Track Me | Web Exploitation | 150 | 152 | [📄](./Track-Me-Writeup.md) |
| 4 | CoilVM | Reverse Engineering | 200 | 117 | [📄](./CoilVM-Writeup.md) |
| 5 | Git Sleuth | Other | 250 | 101 | [📄](./Git-Sleuth-Writeup.md) |
| 6 | Ways To Lie | Cryptography | 300 | 96 | [📄](./Ways-To-Lie-Writeup.md) |
| 7 | Registry101 | Forensics | 350 | 68 | [📄](./Registry101-Writeup.md) |

Point values rose as solves fell, so the rarest solves are worth the most.

---

## 📝 Summaries

Short spoilers below. Each links to the full write-up.

### [Carry On](./Carry-On-Writeup.md) · Forensics · 50
A PNG floor plan carries a ZIP archive appended after its `IEND` marker. Image viewers stop at `IEND`, so the picture opens fine while 758 extra bytes ride along. Reading the ZIP reveals a note with the flag.

### [Careless Talk](./Careless-Talk-Writeup.md) · Binary Exploitation · 100
An unstripped ELF stores the flag in two `.rodata` halves and a hardcoded watchword between them. `strings` plus one `grep` for `FLAG_` recovers both halves; typing the watchword makes the binary print the flag.

### [Track Me](./Track-Me-Writeup.md) · Web Exploitation · 150
A PHP analytics page logs the `User-Agent` header unsanitized, and the log viewer `include()`s the log file. Poisoning the log with PHP in the header, then loading the viewer, gives code execution that reads the randomly named flag file with `glob()`.

### [CoilVM](./CoilVM-Writeup.md) · Reverse Engineering · 200
A nanomite crackme: the comparison function is a wall of `int3` traps, and the real per-byte check lives in the `SIGTRAP` handler, re-keyed by a running FNV-1a hash. The transform is invertible, so the 36-byte password is solved statically byte by byte, then fed back to unseal the flag.

### [Git Sleuth](./Git-Sleuth-Writeup.md) · Other · 250
A restricted `git`-only shell behind a keyword blacklist, with the flag hidden among 500 identical decoy files. `git -C /tmp init && add -A && ls-files --stage` prints every blob hash; the one file with a unique hash is the flag, read with `cat-file -p` (no banned words).

### [Ways To Lie](./Ways-To-Lie-Writeup.md) · Cryptography · 300
Two encoding layers: Base100 emoji wrapping a string of musical symbols. The symbols are a hex-nibble substitution, two per byte. The `SkillBit{`/`MetaCTF{` wrapper cribs most of the alphabet, and Unicode order plus the leetspeak fills the rest.

### [Registry101](./Registry101-Writeup.md) · Forensics · 350
A KAPE triage collection where the evidence is only in the `NTUSER.DAT` transaction log (`.LOG1`), not the committed hive. Carving the log finds two Base64 filenames that decode to the two halves of the flag.

---

## 🚩 Flags

<details>
<summary>Click to reveal all flags (spoilers)</summary>

| Challenge | Flag |
|-----------|------|
| Carry On | `SkillBit{0n3_f1l3_c4n_c4rry_4n0th3r}` |
| Careless Talk | `SkillBit{c4r3l355_t4lk_c05t5_l1v35}` |
| Track Me | `SkillBit{7r4ck1n9_u53r5_c4n_7r4ck_y0u_t00}` |
| CoilVM | `SkillBit{n4nom1tes_eat_y0ur_symb0lic_execut0r}` |
| Git Sleuth | `SkillBit{R3m3mb3r_t0_4lw4ys_3sc4p3_G1t_C0mm4nds}` |
| Ways To Lie | `SkillBit{4m0n9_100_W4y5_70_L13_Y0u_4ctu4lly_F0und_7h3_7ru7h}` |
| Registry101 | `MetaCTF{F1r5t_st3p_2_r3g1stry_4and6}` |

</details>

---

## 🛠️ Tools Used

`git` · `curl` · `ncat` · `objdump` · `strings` · `nm` · `file` · `grep` · `unzip` · Python 3 (`regipy`)

---

<p align="center"><i>Written up for learning and reference. Flags are public now that the event has ended.</i></p>

---

Written by **TheDingo8MyBaby**
MetaCTF September 2026 Flash CTF
