# reverse-engineering-lab

A hands-on self-study lab: build one small C binary, then take it apart with `strings`, `objdump`, and a hex viewer until it gives up its secrets.

## The target

`src/vault.c` compiles to `./vault`, a program that asks for a passphrase. The check is deliberately weak — a single-byte XOR obfuscation, **not real cryptography** — so every layer of it can be peeled back with beginner tools:

- a hidden string sits in plain sight for `strings` to find,
- the validating function is visible by name in the disassembly (the build keeps symbols: `-O0 -g`, no strip),
- the stored comparison bytes can be reversed by hand once you spot the XOR key in the instruction stream.

## Workflow

```bash
./build.sh                       # gcc -> ./vault
./vault                          # try a guess first

strings ./vault                  # Challenge 1: find the hidden string
objdump -d ./vault | less        # Challenge 2: find the gatekeeper function
objdump -s -j .rodata ./vault    # Challenge 3: dump the stored bytes,
                                 # reverse the transform, recover the passphrase

python3 tools/check_answers.py   # all 3 answers unlock the full walkthrough
```

No `xxd`/`objdump` handy? Open `tools/hexview.html` in any browser — it's a single self-contained file with a file picker, offset/hex/ASCII rendering, and a byte search box (hex like `6f 70 65 6e` or plain text). The file never leaves the page.

The three graduated challenges are written up in [challenges.md](challenges.md). The checker stores only SHA-256 hashes of the answers; the walkthrough is released when all three are right.

## Layout

```
src/vault.c             the target program (XOR-obfuscated passphrase check)
build.sh                gcc build, symbols kept on purpose
challenges.md           the 3 challenges and how answers are checked
tools/check_answers.py  hash-based answer checker + gated walkthrough
tools/hexview.html      single-file browser hex viewer with byte search
```

## Design notes

Custom choices that shape this lab:

- **Built to be read.** `-O0` keeps the disassembly close to the source, `-g` adds debug info, and nothing is stripped — fighting the tooling is not the exercise; reading code is.
- **One honest weakness, three angles.** The same XOR check is attacked via static strings (recon), control flow (which function validates?), and data recovery (undo the transform). That's the standard first pass on any unknown binary.
- **The gate is a study gate.** Answer hashes + a base64 walkthrough in `check_answers.py` keep the solution from spoiling itself while scrolling — anyone determined can decode it, and that's fine; the learning is in the hunt.
- **The takeaway is the point.** If a passphrase check ships inside a binary, the binary *is* the answer key. The walkthrough ends on where real verification belongs (server-side, or a real KDF/signature scheme).

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
