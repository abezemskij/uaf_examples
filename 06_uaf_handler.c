/*
 * 06_uaf_handler.c - the handler desk
 *
 * A UAF story about pointers, not payloads.
 *
 * The program keeps a cleanup PARAMETER (a global string) and, at
 * cleanup, runs:
 *
 *     char *target = myhandler->target;   // the handler target field
 *     system("echo " + target);
 *
 * i.e. it DEREFERENCES the handler target field and feeds what it
 * points to to a shell. The handler target field is at offset 0, the
 * SAME offset the allocator uses for a freed slot "next free" pointer.
 * That coincidence is the bug: after you free a handler you can still
 * write its target field (UAF), and that write is also a write into
 * the free-list bookkeeping.
 *
 * The world:
 *   - a pool of 8 slots of 16 bytes each.
 *   - two kinds of slot:
 *       DATA    - a plain 16-byte string slot.
 *       HANDLER - 16 bytes: [target:8][payload:8]. Only the target
 *                 field matters; cleanup dereferences it.
 *   - the desk free list lives inside the freed slots: each freed
 *     slot first 8 bytes hold the "next free" pointer (ASCII hex).
 *
 * The rules (what keeps the game honest):
 *   - every alloc hands you a POINTER (P0, P1, ...).
 *   - you may only read/write through a pointer you hold.
 *   - cleanup is the program OWN action: it dereferences
 *     myhandler->target. You do not type the parameter address as a
 *     target; you make the handler target field point where you want.
 *
 * The bug:
 *   - freeing a handler does not break the pointer. It stays dangling,
 *     and you can still write through it. Because target is at offset
 *     0, a UAF write to it is also a write to the free-list "next".
 *
 * The exploit (the point: you do NOT write the parameter directly):
 *
 *   1. alloc handler  -> P0 (the program myhandler). target=0 (static).
 *   2. alloc data     -> P1.
 *   3. free P1        -> slot first 8 bytes = free-list "next".
 *   4. put P1 0xSLOT2 [UAF write 1]
 *      -> P1 (dangling) now points at SLOT2 (a DATA slot).
 *   5. alloc data     -> the desk follows P1, hands out SLOT2 -> P2.
 *   6. put P2 ;id     -> SLOT2 (now yours, a DATA slot) holds ";id".
 *   7. free P0        -> myhandler freed; its target field = free-list next.
 *   8. put P0 0xSLOT2 [UAF write 2, the UAF]
 *      -> myhandler->target now points at SLOT2.
 *   9. cleanup        -> the program dereferences myhandler->target,
 *                        reads ";id", runs system("echo ;id").
 *                        the shell runs `id`. COMMAND INJECTION.
 *
 * Notice: the parameter itself is never written. The handler target
 * field is what you poison, and the program own dereference is what
 * hands you the write. That is the difference between "arbitrary write
 * to a global" (03/05) and "UAF -> wrong pointer -> code runs" (here).
 *
 * Build:  gcc -g -O0 -no-pie -o handler 06_uaf_handler.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define NSLOTS    8
#define SLOT_SIZE 16
#define NPOINTER  16

/* pinned to fixed addresses by the linker (see Makefile): parameter at
 * 0x4a0000, pool at 0x4b0000, so the map matches the README on any build. */
__attribute__((section(".uaf_param")))
static char param[16] = "all_ok";              /* the program parameter  */
__attribute__((section(".uaf_heap")))
static char slots[NSLOTS * SLOT_SIZE];         /* the pool               */
static char *free_head;                        /* free-list head         */

/* slot state */
static int slot_live[NSLOTS];                  /* allocated              */
static int slot_kind[NSLOTS];                  /* 0 free, 1 data, 2 handler */

/* the program own handler, the one cleanup dereferences */
static char *myhandler = 0;

/* pointers in your pocket */
static char *held[NPOINTER];
static int   held_kind[NPOINTER];              /* 1 data, 2 handler      */
static int   held_dangling[NPOINTER];
static int   npointer = 0;

static char *slot_addr(int i) { return slots + (size_t)i * SLOT_SIZE; }
static int   slot_no(char *p) { return (int)((p - slots) / SLOT_SIZE); }

static void show_slot(char *p)
{
    for (int i = 0; i < SLOT_SIZE; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c >= 32 && c < 127) putchar(c);
        else if (c == 0) putchar('.');
        else putchar('#');
    }
    putchar('\n');
}

/* ---------------- the desk ---------------- */

static void desk_alloc(int kind)
{
    if (!free_head) { puts("no free slots left."); return; }
    if (npointer >= NPOINTER) { puts("pocket full. free some first."); return; }
    char *p = free_head;
    free_head = (char *)strtoul(p, NULL, 16);
    int i = slot_no(p);
    if (i >= 0 && i < NSLOTS) {
        slot_live[i] = 1;
        slot_kind[i] = kind;
        memset(p, 0, SLOT_SIZE);
    }
    int mine = npointer;
    held[mine] = p;
    held_kind[mine] = kind;
    held_dangling[mine] = 0;
    npointer++;
    printf("the desk hands you %s -> 0x%lx\n",
           kind == 2 ? "HANDLER" : "DATA", (unsigned long)p);
    if (kind == 2)
        printf("  (handler layout: [target:8][payload:8])\n");
    if (p == myhandler)
        printf("  (that is the program handler, cleanup will dereference it.)\n");
}

static void desk_free(int mine)
{
    char *p = held[mine];
    if (held_dangling[mine])
        printf("  (%s is already dangling)\n",
               held_kind[mine] == 2 ? "handler" : "data");
    /* write the free-list "next" into the slot first 8 bytes (ASCII hex).
     * for a handler, those first 8 bytes are ALSO its target field. */
    snprintf(p, 8, "%lx", (unsigned long)free_head);
    free_head = p;
    held_dangling[mine] = 1;
    int i = slot_no(p);
    if (i >= 0 && i < NSLOTS) {
        slot_live[i] = 0;
    }
    printf("you handed %s back. its first 8 bytes now hold the free-list next:\n",
           held_kind[mine] == 2 ? "handler" : "data");
    show_slot(p);
    printf("  (it is now DANGLING. the desk still lets you use it. that is the bug.)\n");
}

static void desk_put(int mine, const char *text)
{
    char *p = held[mine];
    /* if the text is a hex address (0x...), write the numeric value
     * into the first 8 bytes (the pointer field), zero the rest.
     * otherwise, write the string into the slot. */
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        unsigned long val = strtoul(text, NULL, 16);
        memset(p, 0, SLOT_SIZE);
        memcpy(p, &val, 8);
        printf("wrote pointer 0x%lx through %s -> 0x%lx%s\n",
               val, held_kind[mine] == 2 ? "HANDLER" : "DATA",
               (unsigned long)p,
               held_dangling[mine] ? " (DANGLING, use-after-free)" : "");
    } else {
        size_t n = strlen(text);
        if (n > SLOT_SIZE - 1) n = SLOT_SIZE - 1;
        memset(p, 0, SLOT_SIZE);
        memcpy(p, text, n);
        printf("wrote %zu bytes through %s -> 0x%lx%s\n",
               n, held_kind[mine] == 2 ? "HANDLER" : "DATA",
               (unsigned long)p,
               held_dangling[mine] ? " (DANGLING, use-after-free)" : "");
    }
    show_slot(p);
}

static void desk_get(int mine)
{
    char *p = held[mine];
    printf("%s -> 0x%lx%s:\n",
           held_kind[mine] == 2 ? "HANDLER" : "DATA",
           (unsigned long)p,
           held_dangling[mine] ? " (dangling)" : "");
    show_slot(p);
}

/* the program OWN cleanup: dereference myhandler->target and feed
 * what it points to to the shell. */
static int do_cleanup(void)
{
    if (!myhandler) { puts("cleanup: no handler yet."); return 0; }
    unsigned long target = *(unsigned long *)myhandler; /* offset 0 */
    if (target == 0) {
        puts("cleanup: handler target is 0. nothing to echo.");
        return 0;
    }
    char *s = (char *)target;
    printf("cleanup: handler target = 0x%lx, contents: \"%s\"\n", target, s);
    char cmd[64];
    snprintf(cmd, sizeof cmd, "echo %s", s);
    system(cmd);
    /* the win: the program dereferenced a pointer that did NOT point at
     * the parameter. the shell ran whatever that pointer held. */
    if (target != (unsigned long)param) {
        puts("  (the handler pointed somewhere OTHER than the parameter.");
        puts("   the shell ran your bytes. command injection via UAF.)");
        return 1;
    }
    puts("  (the handler points at the parameter. normal echo.)");
    return 0;
}

/* ---------------- commands ---------------- */

static int is_digit(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

static int is_hex(const char *s)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return 0;
    for (; *s; s++) if (!isxdigit((unsigned char)*s)) return 0;
    return 1;
}

static int pointer_index(const char *s)
{
    if (!s) return -1;
    if ((s[0] == 'P' || s[0] == 'p') && isdigit((unsigned char)s[1])) {
        int i = atoi(s + 1);
        if (i >= 0 && i < npointer) return i;
        return -1;
    }
    if (is_hex(s)) {
        unsigned long h = strtoul(s, NULL, 16);
        for (int i = 0; i < npointer; i++)
            if (held[i] && (unsigned long)held[i] == h) return i;
    }
    return -1;
}

static void do_map(void)
{
    puts("pool:");
    for (int i = 0; i < NSLOTS; i++) {
        char *p = slot_addr(i);
        char who[32];
        if (slot_live[i])
            snprintf(who, sizeof who, "%s", slot_kind[i] == 2 ? "HANDLER" : "DATA");
        else
            snprintf(who, sizeof who, "free");
        printf("  slot %d   0x%lx   %s\n", i, (unsigned long)p, who);
    }
    printf("param:    0x%lx   \"%s\"   (the program parameter)\n",
           (unsigned long)param, param);
    if (myhandler)
        printf("handler:  0x%lx   target=0x%lx   (the program one, cleanup derefs it)\n",
               (unsigned long)myhandler, *(unsigned long *)myhandler);
    else
        printf("handler:  (not allocated yet)\n");
    if (free_head)
        printf("free list head: 0x%lx\n", (unsigned long)free_head);
    else
        printf("free list head: (empty)\n");
    puts("your pointers:");
    if (npointer == 0)
        puts("  (pocket empty)");
    for (int i = 0; i < npointer; i++)
        printf("  P%d   %s   0x%lx   %s\n", i,
               held_kind[i] == 2 ? "HANDLER" : "DATA",
               (unsigned long)held[i],
               held_dangling[i] ? "DANGLING" : "live");
}

static void do_hint(void)
{
    puts("think: a handler target field is at offset 0. the same place");
    puts("the allocator keeps the free-list 'next' for a freed slot.");
    puts("the program cleanup dereferences myhandler->target. so if you");
    puts("can make that field point at a slot holding ';id', cleanup");
    puts("will run `id`. steps:");
    puts("  1. alloc handler (the program myhandler). you hold it.");
    puts("  2. alloc a data slot, free it, UAF-write it to point at another");
    puts("     slot, alloc to get that slot, write ';id' into it.");
    puts("  3. free the handler, UAF-write its target field to point at the");
    puts("     ';id' slot.");
    puts("  4. cleanup. the program dereferences the target, reads ';id',");
    puts("     and the shell runs `id`. you did not write the parameter;");
    puts("     you redirected the pointer it dereferences.");
}

static void do_help(void)
{
    puts("alloc data           allocate a DATA slot (16-byte string)");
    puts("alloc handler        allocate a HANDLER slot ([target:8][payload:8])");
    puts("free  <Pn>           hand a pointer back (it becomes DANGLING)");
    puts("put   <Pn> text      write through a pointer you hold (bug: works even dangling!)");
    puts("get   <Pn>           read through a pointer you hold");
    puts("map                  show the pool, param, handler, free list, your pointers");
    puts("cleanup              the program OWN action: deref handler->target, system(\"echo \"+it)");
    puts("hint                 the desk thinks out loud");
    puts("quit");
    puts("(<Pn> may be P0, P1, ... or the address of a pointer you hold)");
}

int main(void)
{
    /* build the free list: slot0 -> slot1 -> ... -> slot7 -> (none) */
    for (int i = 0; i < NSLOTS; i++) {
        char *nx = (i + 1 < NSLOTS) ? slot_addr(i + 1) : (char *)0;
        snprintf(slot_addr(i), 8, "%lx", (unsigned long)nx);
    }
    free_head = slot_addr(0);

    puts("the handler desk. the program keeps a handler and, at cleanup,");
    puts("dereferences handler->target and feeds it to the shell.");
    puts("your job: make that target point at a slot holding ';id'");
    puts("WITHOUT writing the parameter directly.");
    do_help();

    char line[256];
    for (;;) {
        printf("desk> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) break;
        size_t pos = strcspn(line, "\r\n");
        if (pos >= sizeof line - 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { }
        }
        line[pos] = 0;
        if (!*line) continue;

        char *sp1 = strchr(line, ' ');
        char cmd[256] = {0};
        if (sp1) { *sp1 = 0; }
        char *arg = sp1 ? sp1 + 1 : "";
        snprintf(cmd, sizeof cmd, "%s", line);

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) break;
        else if (!strcmp(cmd, "alloc")) {
            if (!strcmp(arg, "data")) {
                desk_alloc(1);
            } else if (!strcmp(arg, "handler")) {
                if (myhandler) { puts("the program already has a handler."); continue; }
                desk_alloc(2);
                myhandler = held[npointer - 1];
            } else puts("alloc what? try: alloc data, alloc handler");
        }
        else if (!strcmp(cmd, "free")) {
            int mine = pointer_index(arg);
            if (mine >= 0) desk_free(mine);
            else puts("you do not hold a pointer like that.");
        }
        else if (!strcmp(cmd, "put")) {
            char *sp2 = strchr(arg, ' ');
            if (!sp2) { puts("what should I write?"); continue; }
            *sp2 = 0;
            char *text = sp2 + 1;
            while (*text == ' ') text++;
            int mine = pointer_index(arg);
            if (mine >= 0) desk_put(mine, text);
            else puts("you may only write through a pointer you hold.");
        }
        else if (!strcmp(cmd, "get")) {
            int mine = pointer_index(arg);
            if (mine >= 0) desk_get(mine);
            else puts("you may only read through a pointer you hold.");
        }
        else if (!strcmp(cmd, "map")) do_map();
        else if (!strcmp(cmd, "cleanup")) do_cleanup();
        else if (!strcmp(cmd, "hint")) do_hint();
        else if (!strcmp(cmd, "help")) do_help();
        else puts("try: alloc, free, put, get, map, cleanup, hint, quit");
    }

    printf("\n---\n");
    if (myhandler) {
        unsigned long t = *(unsigned long *)myhandler;
        printf("handler target at start: 0x0\n");
        printf("handler target at end:   0x%lx\n", t);
        if (t != 0 && t != (unsigned long)param)
            puts(">>> the handler points somewhere else. YOU REDIRECTED THE CLEANUP! <<<");
        else
            puts("(the handler still points at the parameter. not exploited yet)");
    }
    return 0;
}
