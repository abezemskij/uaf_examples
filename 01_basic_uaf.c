/*
 * 01_basic_uaf.c
 *
 * The simplest form of Use-After-Free: reading memory after free().
 *
 * What happens:
 *   1. malloc() hands us a piece of the heap.
 *   2. free() gives it back to the heap. The memory is now "free".
 *   3. We keep the old pointer ('text') and still use it -> UAF.
 *
 * Compile:  gcc -g -O0 -o uaf1 01_basic_uaf.c
 * Run:      ./uaf1
 * Inspect:  gdb ./uaf1  ->  (gdb) b print_note  ->  (gdb) r  -> step
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *text = NULL; /* points to our note on the heap */

void add_note(const char *s)
{
    text = malloc(strlen(s) + 1);
    strcpy(text, s);
}

void free_note(void)
{
    free(text);
    /* BUG: 'text' still holds the old address.
     * It now points to memory we no longer own: a "dangling pointer". */
}

void print_note(void)
{
    /* BUG: if free_note() ran first, we read freed memory here. */
    printf("note: %s\n", text);
}

int main(void)
{
    add_note("hello students");
    print_note();

    free_note();
    printf("note was freed, printing again...\n");
    print_note(); /* <- Use-After-Free: reading freed memory */

    return 0;
}
