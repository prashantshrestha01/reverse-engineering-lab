/*
 * vault.c - a tiny passphrase checker built for reverse-engineering practice.
 *
 * This is a STUDY EXERCISE. The "protection" is a single-byte XOR
 * obfuscation, which is not cryptography and not security. It exists so
 * you can watch it fall apart under strings(1) and objdump(1).
 *
 * Build:  ./build.sh        (gcc -O0 -g, symbols kept on purpose)
 * Run:    ./vault
 */
#include <stdio.h>
#include <string.h>

/* Challenge 1 lives here: this string sits in plain sight in the binary. */
const char *hidden_note = "FLAG{strings_see_everything}";

/*
 * The passphrase, stored with each byte XORed by 0x2A.
 * These bytes are NOT the passphrase as-is: XOR them with 0x2A to read it.
 * (Working that out from the disassembly is Challenge 3.)
 */
static const unsigned char vault_key[] = {
    0x45, 0x5A, 0x4F, 0x44, 0x59, 0x4F, 0x59, 0x4B, 0x47, 0x4F
};
#define VAULT_KEY_LEN (sizeof(vault_key) / sizeof(vault_key[0]))
#define XOR_KEY 0x2A

int validate_input(const char *input)
{
    size_t len = strlen(input);
    size_t i;

    if (len != VAULT_KEY_LEN) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if ((unsigned char)(input[i] ^ XOR_KEY) != vault_key[i]) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    char buf[128];

    printf("Enter passphrase: ");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 1;
    }
    buf[strcspn(buf, "\r\n")] = '\0';

    if (validate_input(buf)) {
        printf("Access granted. The vault is open.\n");
        return 0;
    }
    printf("Access denied.\n");
    return 1;
}
