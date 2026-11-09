/*
 * 05_heap_grooming.c — "the sorting desk" (bonus: order matters)
 *
 * Heap grooming = arranging the free list so the chunk you need is in
 * the right place when the exploit fires.
 *
 * Why order matters here (and in glibc):
 *   the desk's free list is LIFO, exactly like glibc's tcache:
 *     every free() puts the box at the FRONT of the list,
 *     every alloc() takes the box from the front.
 *   So "which box is at the front" is decided by the ORDER of your
 *   frees. That order is the grooming.
 *
 * The bug (same family as the storage desk, but smaller):
 *   after you free a box, you can still write into it — but only the
 *   MOST RECENTLY freed box (the UAF is in the desk's `last_freed`
 *   bookkeeping). Boxes deeper in the free list are not writable.
 *
 * So before you can poison a box's corner, it has to BE the most
 * recently freed box. Plan your frees first: that is the whole game.
 *
 * The world:
 *   - 6 boxes of 32 bytes; boxes 4 and 5 are held by the program.
 *   - each box: a corner (first 16 bytes) and a message (16 bytes).
 *   - a freed box's corner holds the NEXT box in the list (ASCII hex).
 *   - `map` shows the whole list, left = handed out first.
 *
 * Commands:
 *   alloc                 take the front box off the free list
 *   free  <box>           return a box (it lands at the FRONT of the list)
 *   put   <box|addr> text write — into a box you hold, or into the most
 *                           recently freed one (the UAF!)
 *   get   <box|addr>      read
 *   map                   the heap, the whole free list, the cleanup param
 *   run                   run the cleanup: system("echo " + parameter)
 *   hint                  the desk thinks out loud
 *   quit
 *
 * Build:  gcc -g -O0 -no-pie -o groom 05_heap_grooming.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define NBOXES   6
#define BOX_SIZE 32
#define CORNER   16
#define USABLE   (BOX_SIZE - CORNER)

/* pinned to fixed addresses by the linker (see Makefile): parameter at
 * 0x4a0000, heap at 0x4b0000, so the map matches the README on any build. */
__attribute__((section(".uaf_param")))
static char cleanup_param[32] = "all_ok";
__attribute__((section(".uaf_heap")))
static char boxes[NBOXES * BOX_SIZE];
static char *free_head;      /* front of the LIFO list */
static char *last_freed;     /* the desk's bookkeeping — this is the UAF */
static int  yours[NBOXES];   /* boxes the desk handed to you */
static int  held[NBOXES];    /* boxes held by the program */
static int  param_out;       /* the desk has handed out the parameter */
static char param_start[32];

static char *box_addr(int i) { return boxes + (size_t)i * BOX_SIZE; }
static int   box_no(char *p) { return (int)((p - boxes) / BOX_SIZE); }
static int   in_heap(char *p) {
    return p >= boxes && p < boxes + NBOXES * BOX_SIZE;
}

static void corner(char *p, char *out, size_t n)
{
    memcpy(out, p, CORNER);
    out[CORNER] = 0;
}

static void show_list(void)
{
    printf("free list (leftmost is handed out first): ");
    char *p = free_head;
    if (!p) { puts("(empty)"); return; }
    int n = 0;
    while (p && n++ < NBOXES + 2) {
        if (p == cleanup_param) printf("THE PARAMETER");
        else if (in_heap(p)) printf("box %d", box_no(p));
        else printf("0x%lx", (unsigned long)p);
        char *nx = (char *)strtoul(p, NULL, 16);
        if (!nx || nx == p || (!in_heap(nx) && nx != cleanup_param)) break;
        printf(" -> ");
        p = nx;
    }
    puts("");
}

/* ---------------- the desk ---------------- */

static void desk_alloc(void)
{
    if (!free_head) { puts("no free boxes left."); return; }
    char *p = free_head;
    free_head = (char *)strtoul(p, NULL, 16); /* reads the corner */
    if (in_heap(p)) {
        yours[box_no(p)] = 1;
        memset(p + CORNER, 0, USABLE);
    }
    if (p == cleanup_param) param_out = 1;
    printf("the desk hands out 0x%lx\n", (unsigned long)p);
    if (p == cleanup_param) puts("  (that is not a box. that is the cleanup parameter.)");
}

static void desk_free(char *p)
{
    if (!in_heap(p)) { puts("the desk only takes boxes back."); return; }
    int i = box_no(p);
    if (held[i]) { puts("the program is holding that one. not yours to free."); return; }
    if (!yours[i]) { puts("the desk says that box is not yours."); return; }
    snprintf(p, CORNER, "%lx", (unsigned long)free_head);
    free_head = p;          /* LIFO: the box lands at the FRONT */
    last_freed = p;         /* the desk remembers it — this is the bug */
    yours[i] = 0;
    char c[CORNER + 1];
    corner(p, c, sizeof c);
    printf("released 0x%lx. its corner now says: %s\n", (unsigned long)p, c);
}

static void desk_put(char *p, const char *text)
{
    int uaf = 0;
    if (p == cleanup_param) {
        if (!param_out) { puts("the desk says: hold it, you do not have that one."); return; }
    }
    else if (in_heap(p)) {
        int i = box_no(p);
        if (yours[i]) { /* normal write into a box you hold */ }
        else if (p == last_freed) uaf = 1; /* the UAF write */
        else {
            puts("the desk says: you may only write into a box you hold —");
            puts("or the most recently freed one, if you are feeling lucky.");
            return;
        }
    }
    else { puts("the desk does not know that one."); return; }

    size_t n = strlen(text);
    if (n > BOX_SIZE - 1) n = BOX_SIZE - 1;
    memset(p, 0, BOX_SIZE);
    memcpy(p, text, n);
    printf("wrote %zu bytes to 0x%lx.%s", n, (unsigned long)p,
           uaf ? " (through the UAF: that box was already free)" : "");
    if (in_heap(p)) {
        char c[CORNER + 1];
        corner(p, c, sizeof c);
        printf(" corner now says: %s", c);
    }
    puts("");
}

static void desk_get(char *p)
{
    if (p == cleanup_param) { printf("the parameter at 0x%lx: %s\n", (unsigned long)p, p); return; }
    if (!in_heap(p)) { puts("the desk does not know that one."); return; }
    printf("0x%lx contains: ", (unsigned long)p);
    for (size_t i = 0; i < BOX_SIZE; i++) {
        unsigned char c = (unsigned char)p[i];
        putchar((c >= 32 && c < 127) ? c : '.');
    }
    putchar('\n');
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

static char *target_from(const char *s)
{
    if (is_digit(s)) {
        unsigned long v = strtoul(s, NULL, 10);
        if (v < NBOXES) return box_addr((int)v);
    }
    if (is_hex(s)) {
        unsigned long h = strtoul(s, NULL, 16);
        if (h == (unsigned long)cleanup_param) return cleanup_param;
        for (int i = 0; i < NBOXES; i++)
            if (h == (unsigned long)box_addr(i)) return box_addr(i);
    }
    return NULL;
}

static void do_map(void)
{
    puts("heap:");
    for (int i = 0; i < NBOXES; i++) {
        const char *who = held[i] ? "program" : (yours[i] ? "yours" : "free");
        printf("  box %d   0x%lx   %s\n", i, (unsigned long)box_addr(i), who);
    }
    printf("  cleanup  0x%lx   \"%s\"   (parameter of cleanup_run())\n",
           (unsigned long)cleanup_param, cleanup_param);
    show_list();
}

static void do_hint(void)
{
    puts("the list is LIFO: every free lands a box at the FRONT,");
    puts("every alloc takes from the FRONT. read `map`, left to right.");
    puts("you may only write into the most recently freed box (the UAF).");
    puts("so: work out the order first. hold a box, free it LAST among your");
    puts("frees, write the parameter's address into its corner, then alloc until");
    puts("the desk hands out the parameter — and then write into it,");
    puts("then: run. the cleanup will do more than echo.");
}

static void do_help(void)
{
    puts("alloc                 take the front box off the free list");
    puts("free  <box>           return a box (lands at the FRONT of the list)");
    puts("put   <box|addr> text write (you hold it, or most recently freed)");
    puts("get   <box|addr>      read");
    puts("map                   the heap, the whole free list, the cleanup param");
    puts("run                   run the cleanup: system(\"echo \" + parameter)");
    puts("hint                  the desk thinks out loud");
    puts("quit");
}

int main(void)
{
    strcpy(param_start, cleanup_param);
    /* free list: box0 -> box1 -> box2 -> box3 -> (none) */
    for (int i = 0; i < NBOXES - 2; i++) {
        char *nx = (i + 1 < NBOXES - 2) ? box_addr(i + 1) : (char *)0;
        snprintf(box_addr(i), CORNER, "%lx", (unsigned long)nx);
    }
    free_head = box_addr(0);
    held[NBOXES - 2] = held[NBOXES - 1] = 1; /* program holds 4 and 5 */
    strcpy(boxes + (NBOXES - 2) * BOX_SIZE, "program data");
    strcpy(boxes + (NBOXES - 1) * BOX_SIZE, "program data");

    puts("the sorting desk. goal: change the cleanup parameter, then run it.");
    puts("twist: you may only write into the MOST RECENTLY freed box.");
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
        if (sp1) *sp1 = 0;
        char *arg = sp1 ? sp1 + 1 : "";
        snprintf(cmd, sizeof cmd, "%s", line);

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) break;
        else if (!strcmp(cmd, "alloc")) desk_alloc();
        else if (!strcmp(cmd, "free")) {
            char *p = target_from(arg);
            if (p) desk_free(p);
        }
        else if (!strcmp(cmd, "put")) {
            char *sp2 = strchr(arg, ' ');
            if (!sp2) { puts("what should I write?"); continue; }
            *sp2 = 0;
            char *text = sp2 + 1;
            while (*text == ' ') text++;
            char *p = target_from(arg);
            if (p) desk_put(p, text);
        }
        else if (!strcmp(cmd, "get")) {
            char *p = target_from(arg);
            if (p) desk_get(p);
        }
        else if (!strcmp(cmd, "map")) do_map();
        else if (!strcmp(cmd, "run")) {
            printf("echo: %s\n", cleanup_param);
            char c[64];
            snprintf(c, sizeof c, "echo %s", cleanup_param);
            system(c);
            if (strcmp(cleanup_param, param_start) != 0)
                puts("  (the parameter is not what it started as — command-injection power.)");
        }
        else if (!strcmp(cmd, "hint")) do_hint();
        else if (!strcmp(cmd, "help")) do_help();
        else puts("try: alloc, free, put, get, map, run, hint, quit");
    }

    printf("\n---\n");
    printf("cleanup parameter at start: %s\n", param_start);
    printf("cleanup parameter at end:   %s\n", cleanup_param);
    if (strcmp(cleanup_param, param_start) != 0)
        puts(">>> the parameter changed. YOU GROOMED THE HEAP AND WON! <<<");
    else
        puts("(the parameter is still the same — there is a hint if you want it)");
    return 0;
}
