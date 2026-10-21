# Challenges

Build the target first:

```bash
./build.sh
./vault        # try a guess, see what happens
```

Work from the **binary**, not the source — the point is to practice reading
a program you didn't write. Check your answers (all three) with:

```bash
python3 tools/check_answers.py
```

The checker prompts for each answer, or reads `answers.txt` in this folder
(one answer per line, in challenge order) if it exists. Answers are
case-insensitive. The full walkthrough prints **only** when all three are
correct.

---

## Challenge 1 — strings (recon)

Run `strings ./vault` (or open the binary in `tools/hexview.html`).

Somewhere in the output is a hidden flag-formatted string the program
never prints. Find it.

**Answer:** the exact string, e.g. `FLAG{...}`.

## Challenge 2 — disassembly (find the gatekeeper)

Run `objdump -d ./vault` and read `main`.

- Which function does `main` call to decide whether your input opens the
  vault?
- Inside that function, what happens to each byte of your input before it
  is compared, and what is it compared against?

**Answer (for the checker):** the function's name. The rest is for your
own notes — the walkthrough confirms it once all three answers are in.

## Challenge 3 — recover the passphrase (break the obfuscation)

Using what Challenge 2 showed you — the transformation, the key value in
the disassembly, and the stored bytes it compares against (find them with
`objdump -s -j .rodata ./vault` or the hex viewer) — recover the correct
passphrase. Confirm it by running `./vault` and getting in.

**Answer (for the checker):** the passphrase itself. Be able to explain,
in one sentence, why the "hiding" in this program is obfuscation rather
than encryption. The walkthrough spells out the accepted explanation.

---

Stuck? Re-read `validate_input`'s loop in the disassembly and remember:
XOR is its own inverse.
