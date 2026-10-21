#!/usr/bin/env python3
"""Answer checker for the reverse-engineering lab.

Validates the three challenge answers against stored SHA-256 hashes
(answers are never stored in plaintext here). The walkthrough is printed
ONLY when all three are correct — it is a study gate for a self-paced
exercise, not a security boundary.

Usage:
    python3 tools/check_answers.py            # prompts for each answer
    ...or put one answer per line in answers.txt next to challenges.md.
Answers are case-insensitive.
"""

import base64
import hashlib
import sys
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent

QUESTIONS = [
    ("Challenge 1 - the hidden string (FLAG{...})",
     "fa7ce10c3fd559e89ca28931259a4499df5e747520c5dc830f6890a7a5ceb74f"),
    ("Challenge 2 - the function that validates input",
     "25d49ec5ab74f7760c5e4d4b8fdafbeeff2cdd477b50c2d579969cec05bbbc7b"),
    ("Challenge 3 - the correct passphrase",
     "d9fb92e3bbe65be1f1aad4a82eef4567f7a1ebe2cd110c8049b9698be7a70c88"),
]

WALKTHROUGH_B64 = (
    "SG93IHRoZSB2YXVsdCBhY3R1YWxseSB3b3Jrcwo9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
    "CgoxLiBUaGUgaGlkZGVuIHN0cmluZyAoQ2hhbGxlbmdlIDEpCiAgIGBoaWRkZW5fbm90ZWAgaXMg"
    "YSBwbGFpbiBDIHN0cmluZywgc28gaXQgc2l0cyB1bmVuY29kZWQgaW4gdGhlIGJpbmFyeSdzCiAg"
    "IC5yb2RhdGEgc2VjdGlvbi4gYHN0cmluZ3MgLi92YXVsdGAgcHJpbnRzIGl0IGRpcmVjdGx5Ogog"
    "ICBGTEFHe3N0cmluZ3Nfc2VlX2V2ZXJ5dGhpbmd9CiAgIExlc3NvbjogYW55dGhpbmcgcmVhZGFi"
    "bGUgaW4geW91ciBzb3VyY2UgaXMgcmVhZGFibGUgaW4geW91ciBiaW5hcnkuCgoyLiBUaGUgZ2F0"
    "ZWtlZXBlciAoQ2hhbGxlbmdlIDIpCiAgIEluIGBvYmpkdW1wIC1kIC4vdmF1bHRgLCBtYWluKCkg"
    "cmVhZHMgYSBsaW5lIHdpdGggZmdldHMoKSBhbmQgY2FsbHMKICAgdmFsaWRhdGVfaW5wdXQoKS4g"
    "SW5zaWRlIHZhbGlkYXRlX2lucHV0KCkgeW91IGNhbiBzZWUgdGhlIGxlbmd0aCBjaGVjawogICAo"
    "aW5wdXQgbXVzdCBiZSBleGFjdGx5IDEwIGJ5dGVzKSBhbmQgYSBsb29wIHRoYXQgWE9ScyBlYWNo"
    "IGlucHV0IGJ5dGUKICAgd2l0aCAweDJBIGFuZCBjb21wYXJlcyBpdCBhZ2FpbnN0IHRoZSB2YXVs"
    "dF9rZXlbXSBieXRlIGFycmF5LgogICBTYW1lIGxlbmd0aCArIGV2ZXJ5IHRyYW5zZm9ybWVkIGJ5"
    "dGUgZXF1YWwgPSBhY2Nlc3MgZ3JhbnRlZC4KCjMuIFRoZSBwYXNzcGhyYXNlIChDaGFsbGVuZ2Ug"
    "MykKICAgdmF1bHRfa2V5W10gc3RvcmVzIHRoZSBwYXNzcGhyYXNlIHdpdGggZWFjaCBieXRlIFhP"
    "UmVkIGJ5IDB4MkE6CiAgICAgICA0NSA1QSA0RiA0NCA1OSA0RiA1OSA0QiA0NyA0RiAgIChoZXgs"
    "IGFzIHN0b3JlZCkKICAgICBeIDJBIDJBIDJBIDJBIDJBIDJBIDJBIDJBIDJBIDJBICAgKHRoZSBr"
    "ZXkpCiAgICAgICA2RiA3MCA2NSA2RSA3MyA2NSA3MyA2MSA2RCA2NSAgID0gIm9wZW5zZXNhbWUi"
    "CiAgIFhPUiBpcyBpdHMgb3duIGludmVyc2UsIHNvIHRoZSBzYW1lIG9wZXJhdGlvbiB0aGF0ICJo"
    "aWRlcyIgdGhlIGJ5dGVzCiAgIHJldmVhbHMgdGhlbS4gVGhhdCBpcyB3aHkgc2luZ2xlLWJ5dGUg"
    "WE9SIGlzIG9iZnVzY2F0aW9uLCBub3QKICAgZW5jcnlwdGlvbjogbm8ga2V5IHNlY3JlY3ksIG5v"
    "IGRpZmZ1c2lvbiwgYW5kIHRoZSBrZXkgKDB4MkEpIGlzIHJpZ2h0CiAgIHRoZXJlIGluIHRoZSBk"
    "aXNhc3NlbWJseSBhcyBhbiBpbW1lZGlhdGUgb3BlcmFuZC4KClRha2Vhd2F5OiBjbGllbnQtc2lk"
    "ZSBwYXNzcGhyYXNlIGNoZWNrcyBpbiBzaGlwcGVkIGJpbmFyaWVzIGNhbiBhbHdheXMgYmUKcmVh"
    "ZCB0aGlzIHdheS4gUmVhbCBzeXN0ZW1zIHZlcmlmeSBzZWNyZXRzIHNlcnZlci1zaWRlLCBvciB3"
    "aXRoIGEgcHJvcGVyCktERi9zaWduYXR1cmUgc2NoZW1lIC0gbmV2ZXIgd2l0aCBhIGNvbXBhcmlz"
    "b24geW91IGNhbiBkaXNhc3NlbWJsZS4K"
)


def digest(answer: str) -> str:
    return hashlib.sha256(answer.strip().lower().encode("utf-8")).hexdigest()


def get_answers() -> list:
    answers_file = LAB_ROOT / "answers.txt"
    if answers_file.exists():
        lines = [ln for ln in answers_file.read_text(
            encoding="utf-8").splitlines() if ln.strip()]
        if len(lines) >= len(QUESTIONS):
            return lines[:len(QUESTIONS)]
    return [input(f"{label}: ") for label, _ in QUESTIONS]


def main() -> int:
    answers = get_answers()
    all_correct = True
    for (label, expected), given in zip(QUESTIONS, answers):
        correct = digest(given) == expected
        print(f"{label}: {'correct' if correct else 'not quite'}")
        all_correct = all_correct and correct
    if all_correct:
        print("\nAll three correct - here is the full walkthrough:\n")
        print(base64.b64decode(WALKTHROUGH_B64).decode("utf-8"))
        return 0
    print("\nKeep digging - the walkthrough unlocks when all three are right.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
