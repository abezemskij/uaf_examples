/*
 * 02_heap_reuse.c
 *
 * The simplest UAF exploit: heap reuse.
 *
 *   1. The program frees a chunk but keeps the pointer (the bug).
 *   2. The attacker gets the program to malloc() the same size again.
 *      malloc() is free to hand back the exact same memory.
 *   3. The attacker fills it with their own data.
 *   4. The program still reads through the old pointer
 *      -> it now sees the attacker's data.
 *
 * In a real program, step 4 is often where the damage is: the "old"
 * data might be a vtable pointer or a function pointer, so the attacker
 * controls what the program does next.
 *
 * Build:  gcc -g -O0 -no-pie -o reuse 02_heap_reuse.c
 * Run:    ./reuse
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *victim = malloc(64);

    /* The program thinks it owns this memory. */
    strcpy(victim, "secret: top-secret");
    printf("victim: %s\n", victim);

    /* The bug: the program frees victim but keeps the pointer. */
    free(victim);

    /* Attacker's move: allocate the same size.
     * malloc() hands back the very chunk that was just freed. */
    char *attacker = malloc(64);
    strcpy(attacker, "secret: PWNED");

    /* The program still reads through its old pointer... */
    printf("victim: %s\n", victim);

    return 0;
}
