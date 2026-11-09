/*
 * 03_uaf_game.c — "the storage desk"
 *
 * An interactive heap game with an intentional use-after-free bug.
 *
 * The setup:
 *   - there is a heap: 8 boxes of 32 bytes each, in a row.
 *   - the desk (our allocator) keeps the free list inside the freed
 *     boxes: each freed box has a pointer in its CORNER (first 16
 *     bytes) to the next free box, stored as ASCII hex so you can
 *     read it and type it. Real allocators do exactly this — but
 *     with raw 8-byte pointers.
 *
 * The rules (this is what keeps the game honest):
 *   - every alloc hands you a POINTER (P0, P1, ...).
 *   - you may only read and write through a pointer you hold —
 *     i.e. only in the memory you allocated. There is no command
 *     that lets you touch "the cleanup parameter" directly.
 *
 * The bug:
 *   - when you free a pointer, the desk does not break it. It stays
 *     in your pocket, dangling — and the desk still lets you read
 *     and write through it. Writing through a freed box is a
 *     USE-AFTER-FREE, and it can rewrite the "next free" pointer
 *     sitting in that box's corner.
 *
 * The goal:
 *   there is a global in the program called cleanup — the parameter
 *   the program passes to system("echo " + parameter) in cleanup_run().
 *   The only way in is to make the DESK hand you a pointer that
 *   happens to point at cleanup, and write through it. Then make
 *   cleanup_run() run: if it prints more than "echo" wanted, your
 *   UAF write opened a command-injection path (try ";id").
 *
 * Commands:
 *   alloc [size]         ask the desk for memory; it hands you Pn
 *   free  <Pn>           hand a pointer back (it becomes dangling)
 *   put   <Pn> text      write through a pointer you hold (bug: still
 *                        works after free!)
 *   get   <Pn>           read through a pointer you hold
 *   map                  show the heap, the free list, the cleanup
 *                        parameter, and the pointers in your pocket
 *   run                  run the cleanup: prints "echo: <param>" and
 *                        runs system("echo " + parameter)
 *   hint                 the desk thinks out loud
 *   quit
 *
 * <Pn> may also be an address you hold a pointer to (e.g. 0x404100).
 *
 * A winning sequence (try it):
 *
 *   alloc            -> P0 -> box 0
 *   alloc            -> P1 -> box 1
 *   free P1          -> P1 dangling; box 1's corner now says "next free"
 *   map              -> note the cleanup parameter's address, e.g. 0x4040c0
 *   put P1 0x4040c0  -> UAF write: box 1's corner now points at cleanup
 *   alloc            -> the desk re-hands box 1 and reads its corner
 *   alloc            -> the desk hands you P2 -> 0x4040c0: the PARAMETER itself
 *   put P2 ;id       -> the parameter is now ";id"
 *   run              -> system("echo ;id") runs `id`: COMMAND INJECTION
 *
 * Build:  gcc -g -O0 -no-pie -o desk 03_uaf_game.c
 * (-no-pie gives the cleanup parameter a fixed address, stable every run)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define NBOXES   8
#define BOX_SIZE 32
#define CORNER   16                 /* first 16 bytes: the desk's bookkeeping */
#define USABLE   (BOX_SIZE - CORNER) /* last 16 bytes: your message */
#define NPOINTER 16                 /* pointers you may carry */

/* pinned to fixed addresses by the linker (see Makefile) so every build
 * puts the parameter at 0x4a0000 and the heap at 0x4b0000 — the map and
 * the README transcripts then match on any machine. */
__attribute__((section(".uaf_param")))
static char cleanup_param[32] = "all_ok";   /* the parameter of cleanup_run */
__attribute__((section(".uaf_heap")))
static char boxes[NBOXES * BOX_SIZE];       /* the "heap" */
static char *free_head;                     /* first free box (or NULL) */
static int  used[NBOXES];                   /* only for the map */
static char param_at_start[32];             /* to check the win */

/* the pointers in your pocket. A pointer is either LIVE (the memory is
 * still yours) or DANGLING (you freed it — the desk kept the address).
 * THE BUG: both are still usable. */
static char *held[NPOINTER];
static int   dangling[NPOINTER];
static int   npointer = 0;

static char *box_addr(int i) { return boxes + (size_t)i * BOX_SIZE; }
static int   box_no(char *p) { return (int)((p - boxes) / BOX_SIZE); }

static void show_corner(char *p)
{
    char c[CORNER + 1];
    memcpy(c, p, CORNER);
    c[CORNER] = 0;
    printf("%s", c);
}

/* ---------------- the desk (our tiny allocator) ---------------- */

static void desk_alloc(int want)
{
    if (!free_head) { printf("no free boxes left.\n"); return; }
    if (want > USABLE) {
        printf("the biggest box holds %d bytes.\n", USABLE);
        return;
    }
    if (npointer >= NPOINTER) {
        printf("your pocket is full (%d pointers). free some first.\n", NPOINTER);
        return;
    }
    char *p = free_head;
    /* the desk reads the NEXT address out of the corner of the box it
     * is about to hand out. that is the whole free list. */
    free_head = (char *)strtoul(p, NULL, 16);
    if (p >= boxes && p < boxes + NBOXES * BOX_SIZE) {
        used[box_no(p)] = 1;
        memset(p + CORNER, 0, USABLE); /* hand out a clean message part */
    }
    int mine = npointer;
    held[mine] = p;
    dangling[mine] = 0;
    npointer++;
    printf("the desk hands you P%d -> 0x%lx (you asked for %d bytes)\n",
           mine, (unsigned long)p, want);
    if (p < boxes || p >= boxes + NBOXES * BOX_SIZE)
        printf("  (hmm, that is not one of our boxes...)\n");
    if (p == cleanup_param)
        printf("  (you now hold a pointer to the cleanup parameter.)\n");
}

static void desk_free(int mine)
{
    char *p = held[mine];
    if (dangling[mine])
        printf("  (P%d is already dangling — freeing it again is a bug on its own)\n", mine);
    /* write "next free" into the corner, as ASCII hex */
    snprintf(p, CORNER, "%lx", (unsigned long)free_head);
    free_head = p;
    dangling[mine] = 1;
    int i = box_no(p);
    if (i >= 0 && i < NBOXES)
        used[i] = 0;
    printf("you handed P%d back. the desk writes the next free box into the corner of 0x%lx:\n",
           mine, (unsigned long)p);
    show_corner(p);
    printf("\n  P%d is now DANGLING — and the desk still lets you use it (that is the bug).\n",
           mine);
}

static void desk_put(int mine, const char *text)
{
    char *p = held[mine];
    size_t n = strlen(text);
    if (n > BOX_SIZE - 1) n = BOX_SIZE - 1;
    /* THE BUG: no check that the memory is still allocated to you.
     * a dangling pointer can be written — corner and all. */
    memset(p, 0, BOX_SIZE);
    memcpy(p, text, n);
    printf("wrote %zu bytes through P%d -> 0x%lx%s. corner now says: ",
           n, mine, (unsigned long)p, dangling[mine] ? " (DANGLING — use-after-free)" : "");
    show_corner(p);
    printf("\n");
}

static void desk_get(int mine)
{
    char *p = held[mine];
    printf("P%d -> 0x%lx%s contains: ", mine, (unsigned long)p,
           dangling[mine] ? " (dangling)" : "");
    for (size_t i = 0; i < BOX_SIZE; i++) {
        unsigned char c = (unsigned char)p[i];
        putchar((c >= 32 && c < 127) ? c : '.');
    }
    putchar('\n');
}

/* ---------------- commands ---------------- */

static int is_hex(const char *s)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return 0;
    for (; *s; s++) if (!isxdigit((unsigned char)*s)) return 0;
    return 1;
}

/* a target is a pointer in your pocket: P0..P15, or the address of one
 * of them. nothing else — you may only use what you hold. */
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
    printf("heap:\n");
    for (int i = 0; i < NBOXES; i++) {
        char *p = box_addr(i);
        char c[CORNER + 1];
        memcpy(c, p, CORNER);
        c[CORNER] = 0;
        printf("  box %d   0x%lx   %s   corner: %s\n", i,
               (unsigned long)p, used[i] ? "in use" : "FREE",
               c[0] ? c : "(blank)");
    }
    printf("param:\n");
    printf("  cleanup  0x%lx   \"%s\"   (parameter of cleanup_run())\n",
           (unsigned long)cleanup_param, cleanup_param);
    if (free_head)
        printf("free list head: 0x%lx\n", (unsigned long)free_head);
    else
        printf("free list head: (empty)\n");
    printf("your pointers:\n");
    if (npointer == 0)
        printf("  (pocket empty)\n");
    for (int i = 0; i < npointer; i++)
        printf("  P%d   0x%lx   %s\n", i, (unsigned long)held[i],
               dangling[i] ? "DANGLING" : "live");
}

/* the program's cleanup job: it takes the cleanup parameter and asks
 * the shell to echo it. if the parameter is not what we expect, the
 * shell may do more than echo. */
static int do_run(void)
{
    printf("echo: %s\n", cleanup_param);
    char cmd[64];
    snprintf(cmd, sizeof cmd, "echo %s", cleanup_param);
    system(cmd); /* system() hands the string to a shell: it is a
                   parameter, not a list of arguments. that is the hole. */
    if (strcmp(cleanup_param, param_at_start) != 0) {
        puts("  (the cleanup parameter is not what it started as —");
        puts("  you have command-injection power here.)");
    }
    else {
        puts("  (the parameter is exactly what the program set it to.)");
    }
    return 0;
}

static void do_hint(void)
{
    puts("think: the desk hands out memory from the free list, and the free");
    puts("list lives inside the freed boxes — each freed box has a \"next");
    puts("free\" pointer in its corner, and the desk reads exactly that");
    puts("corner when it hands the box out again.");
    puts("you may only write through pointers you hold. but freeing a");
    puts("pointer does not break it (the bug): you can still write through");
    puts("it. so: alloc, alloc, free one pointer, look at map for the");
    puts("cleanup parameter's address, write it into the freed box's");
    puts("corner (put Pn <addr>), alloc (consumes that box, the desk");
    puts("now points at the parameter), alloc again (you hold a pointer");
    puts("TO the parameter), and write through it. then: run.");
}

static void do_help(void)
{
    puts("alloc [size]         ask the desk for memory; it hands you Pn");
    puts("free  <Pn>           hand a pointer back (it becomes DANGLING)");
    puts("put   <Pn> text      write through a pointer you hold (bug: works even dangling!)");
    puts("get   <Pn>           read through a pointer you hold");
    puts("map                  show the heap, free list, cleanup param and your pointers");
    puts("run                  run the cleanup: system(\"echo \" + parameter)");
    puts("hint                 the desk thinks out loud");
    puts("quit");
    puts("(<Pn> may be P0, P1, ... or the address of a pointer you hold)");
}

int main(void)
{
    strcpy(param_at_start, cleanup_param);
    /* build the free list: box0 -> box1 -> ... -> box7 -> (none) */
    for (int i = 0; i < NBOXES; i++) {
        char *nx = (i + 1 < NBOXES) ? box_addr(i + 1) : (char *)0;
        snprintf(box_addr(i), CORNER, "%lx", (unsigned long)nx);
    }
    free_head = box_addr(0);

    puts("the storage desk. goal: gain write access to the cleanup parameter,");
    puts("then run the cleanup and watch it do more than echo.");
    puts("you may only use memory the desk has handed you — through the");
    puts("pointers it gives you. there is no shortcut to the parameter.");
    do_help();

    char line[256];
    for (;;) {
        printf("desk> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) break;
        size_t pos = strcspn(line, "\r\n"); /* strip Enter's newline (and \r) */
        if (pos >= sizeof line - 1) {       /* line longer than the buffer? */
            int c;                          /* swallow the rest, so the */
            while ((c = getchar()) != '\n' && c != EOF) { }
        }
        line[pos] = 0;
        if (!*line) continue;               /* just pressed Enter: re-prompt */

        char *sp1 = strchr(line, ' ');
        char cmd[256] = {0};
        if (sp1) { *sp1 = 0; }
        char *arg = sp1 ? sp1 + 1 : "";
        snprintf(cmd, sizeof cmd, "%s", line);

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) break;
        else if (!strcmp(cmd, "alloc")) {
            int want = atoi(arg);
            if (want <= 0) want = 8;
            desk_alloc(want);
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
        else if (!strcmp(cmd, "run")) do_run();
        else if (!strcmp(cmd, "hint")) do_hint();
        else if (!strcmp(cmd, "help")) do_help();
        else puts("try: alloc, free, put, get, map, run, hint, quit");
    }

    printf("\n---\n");
    printf("cleanup parameter at start: %s\n", param_at_start);
    printf("cleanup parameter at end:   %s\n", cleanup_param);
    if (strcmp(cleanup_param, param_at_start) != 0)
        puts(">>> the parameter changed. YOU EXPLOITED THE USE-AFTER-FREE! <<<");
    else
        puts("(the parameter is still the same — there is a hint if you want it)");
    return 0;
}
