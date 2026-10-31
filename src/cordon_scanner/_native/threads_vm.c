/* threads_run: rule_engine.threads.Threads.run written in C, results only (the modelling team's
 * program format, spec v2). Included by anchors.c.
 *
 * A thread is (pc, counts..., skipped): its counted loops' counts, innermost last. A run keeps
 * Threads' priority order, its live-thread count (the bound that raises "too many threads" at
 * the same point), its settle (an epsilon closure, a fork's new thread right after the current
 * one, a fork reached twice in one settle ending the later thread), its step (a read consumes,
 * a test re-enters the step, the first DONE ends every thread after it unless every match is
 * wanted) and its dedupe between steps (the later of two identical threads dropped). The memo,
 * the masks shortcut and the per-mode caches of the Python are speed only and are not here.
 *
 * Program buffer (int64): a header of 7 (magic, version, op count, class count, forward entry,
 * backward entry, max counts), then op records of 6 (code, a, b, c, d, e), then the classes,
 * 4 int64 (256 bits) each. */

enum {
    T_BYTE = 1, T_NOT_BYTE = 2, T_MASK = 3, T_NOT_MASK = 4, T_ANY = 5, T_CLASS = 6, T_WORD = 7,
    T_NON_WORD = 8, T_SPACE = 9, T_NON_SPACE = 10, T_DIGIT = 11, T_NON_DIGIT = 12, T_SKIP = 13,
    T_START = 14, T_END = 15, T_EDGE = 16, T_NON_EDGE = 17, T_DONE = 18, T_FORK = 19, T_GOTO = 20,
    T_ENTER = 21, T_AGAIN = 22
};
#define T_HEADER 7
#define T_RECORD 6
#define T_MAX_COUNTS 64
#define T_VERSION 2

enum { TF_BACKWARDS = 1, TF_WIDE = 2, TF_NOCASE = 4, TF_DOTALL = 8, TF_EVERY = 16, TF_SCAN = 32 };

static uint8_t T_WORDS[256], T_SPACES[256], T_SWAP[256];

/* A thread list: `n` threads of `stride` int32 each: pc, depth, skipped, counts[max]. */
typedef struct { int32_t *t; Py_ssize_t n, cap; int stride; } TList;

typedef struct {
    const int64_t *ops, *classes; Py_ssize_t nops, nclasses;
    int maxc, stride;
    long flags;
    Py_ssize_t live, max_threads;
    int error; /* 1 too many threads, 2 out of memory, 3 a malformed program, 4 out of time */
    double began, left; int64_t steps;
} VM;

static int tl_room(TList *l, Py_ssize_t need, VM *vm) {
    if (need <= l->cap) return 1;
    Py_ssize_t c = l->cap ? 2 * l->cap : 16;
    while (c < need) c *= 2;
    int32_t *p = PyMem_RawRealloc(l->t, sizeof(int32_t) * (size_t)(c * l->stride));
    if (!p) { vm->error = 2; return 0; }
    l->t = p; l->cap = c;
    return 1;
}

static int32_t *tl_at(TList *l, Py_ssize_t i) { return l->t + i * l->stride; }

static int tl_push(TList *l, const int32_t *th, VM *vm) {
    if (!tl_room(l, l->n + 1, vm)) return 0;
    memcpy(tl_at(l, l->n), th, sizeof(int32_t) * (size_t)l->stride);
    l->n++;
    return 1;
}

static int tl_insert(TList *l, Py_ssize_t at, const int32_t *th, VM *vm) {
    if (!tl_room(l, l->n + 1, vm)) return 0;
    memmove(tl_at(l, at + 1), tl_at(l, at), sizeof(int32_t) * (size_t)((l->n - at) * l->stride));
    memcpy(tl_at(l, at), th, sizeof(int32_t) * (size_t)l->stride);
    l->n++;
    return 1;
}

static void tl_remove(TList *l, Py_ssize_t at) {
    memmove(tl_at(l, at), tl_at(l, at + 1), sizeof(int32_t) * (size_t)((l->n - at - 1) * l->stride));
    l->n--;
}

/* Threads._new: the bound is checked before the thread is counted. */
static int vm_new(VM *vm) {
    if (vm->live >= vm->max_threads) { vm->error = 1; return 0; }
    vm->live++;
    return 1;
}

static int same_thread(const int32_t *a, const int32_t *b) {
    if (a[0] != b[0] || a[1] != b[1] || a[2] != b[2]) return 0;
    for (int32_t k = 0; k < a[1]; k++) if (a[3 + k] != b[3 + k]) return 0;
    return 1;
}

static const int64_t *vm_op(VM *vm, int32_t pc) { return vm->ops + (Py_ssize_t)pc * T_RECORD; }

/* Threads._settle: `first` and the threads it forks, moved on to their next read or test, in
 * priority order, appended to `out`. */
static int vm_settle(VM *vm, const int32_t *first, TList *out) {
    TList queue = {NULL, 0, 0, vm->stride};
    int64_t *forked = NULL; Py_ssize_t nforked = 0, fcap = 0;
    int ok = 1;
    int32_t th[3 + T_MAX_COUNTS];
    if (!tl_push(&queue, first, vm)) { ok = 0; goto end; }
    while (queue.n > 0) {
        int32_t *t = tl_at(&queue, 0);
        const int64_t *op = vm_op(vm, t[0]);
        int64_t code = op[0];
        if (code == T_FORK) {
            int seen = 0;
            for (Py_ssize_t k = 0; k < nforked; k++) if (forked[k] == op[1]) { seen = 1; break; }
            if (seen) { vm->live--; tl_remove(&queue, 0); continue; }
            if (nforked == fcap) {
                fcap = fcap ? 2 * fcap : 8;
                int64_t *f = PyMem_RawRealloc(forked, sizeof(int64_t) * (size_t)fcap);
                if (!f) { vm->error = 2; ok = 0; goto end; }
                forked = f;
            }
            forked[nforked++] = op[1];
            if (!vm_new(vm)) { ok = 0; goto end; }
            memcpy(th, t, sizeof(int32_t) * (size_t)vm->stride);
            int32_t was = t[0]; /* both from the fork's own pc, as the Python assigns them */
            if (op[3]) { t[0] = (int32_t)op[2]; th[0] = was + 1; }
            else { t[0] = was + 1; th[0] = (int32_t)op[2]; }
            if (!tl_insert(&queue, 1, th, vm)) { ok = 0; goto end; }
        } else if (code == T_GOTO) {
            t[0] = (int32_t)op[1];
        } else if (code == T_ENTER) {
            int64_t lo = op[1], out_to = op[3], eager = op[4];
            if (t[1] >= vm->maxc) { vm->error = 3; ok = 0; goto end; }
            if (lo == 0) {
                if (!vm_new(vm)) { ok = 0; goto end; }
                memcpy(th, t, sizeof(int32_t) * (size_t)vm->stride);
                int32_t *inside = eager ? t : th, *outside = eager ? th : t;
                outside[0] = (int32_t)out_to;
                inside[0] += 1;
                inside[3 + inside[1]] = 0; inside[1] += 1;
                if (!tl_insert(&queue, 1, th, vm)) { ok = 0; goto end; }
            } else {
                t[0] += 1;
                t[3 + t[1]] = 0; t[1] += 1;
            }
        } else if (code == T_AGAIN) {
            int64_t lo = op[1], hi = op[2], body = op[3], eager = op[4];
            if (t[1] < 1) { vm->error = 3; ok = 0; goto end; }
            int32_t n = t[3 + t[1] - 1] + 1;
            t[3 + t[1] - 1] = n;
            if (n < lo) { t[0] = (int32_t)body; continue; }
            if (n < hi) {
                if (!vm_new(vm)) { ok = 0; goto end; }
                memcpy(th, t, sizeof(int32_t) * (size_t)vm->stride);
                int32_t *again = eager ? t : th, *leave = eager ? th : t;
                again[0] = (int32_t)body;
                leave[0] += 1;
                leave[1] -= 1;
                if (!tl_insert(&queue, 1, th, vm)) { ok = 0; goto end; }
            } else {
                t[0] += 1;
                t[1] -= 1;
            }
        } else if (code == T_SKIP) {
            int64_t lo = op[1], hi = op[2], eager = op[3];
            if (t[2] == -1) t[2] = 0;
            if (t[2] < lo) {
                t[2] += 1;
                if (!tl_push(out, t, vm)) { ok = 0; goto end; }
                tl_remove(&queue, 0);
            } else if (t[2] < hi) {
                if (!vm_new(vm)) { ok = 0; goto end; }
                memcpy(th, t, sizeof(int32_t) * (size_t)vm->stride);
                int32_t *spin = eager ? t : th, *go = eager ? th : t;
                spin[2] += 1;
                go[0] += 1;
                go[2] = -1;
                /* the settle of `go`, recursively, as its own call (its own forks) */
                TList went = {NULL, 0, 0, vm->stride};
                int32_t copy[3 + T_MAX_COUNTS], keep[3 + T_MAX_COUNTS];
                memcpy(copy, go, sizeof(int32_t) * (size_t)vm->stride);
                memcpy(keep, spin, sizeof(int32_t) * (size_t)vm->stride);
                if (!vm_settle(vm, copy, &went)) { PyMem_RawFree(went.t); ok = 0; goto end; }
                if (eager && !tl_push(out, keep, vm)) { PyMem_RawFree(went.t); ok = 0; goto end; }
                for (Py_ssize_t k = 0; k < went.n; k++)
                    if (!tl_push(out, tl_at(&went, k), vm)) { PyMem_RawFree(went.t); ok = 0; goto end; }
                if (!eager && !tl_push(out, keep, vm)) { PyMem_RawFree(went.t); ok = 0; goto end; }
                PyMem_RawFree(went.t);
                tl_remove(&queue, 0);
            } else {
                t[0] += 1;
                t[2] = -1;
            }
        } else {
            if (!tl_push(out, t, vm)) { ok = 0; goto end; }
            tl_remove(&queue, 0);
        }
    }
end:
    PyMem_RawFree(queue.t); PyMem_RawFree(forked);
    return ok;
}

/* The later of two identical threads dropped (Threads._keys), in place. */
static void vm_dedupe(TList *l) {
    Py_ssize_t w = 0;
    for (Py_ssize_t i = 0; i < l->n; i++) {
        int32_t *t = tl_at(l, i);
        int dup = 0;
        for (Py_ssize_t j = 0; j < w && !dup; j++) dup = same_thread(tl_at(l, j), t);
        if (!dup) { if (w != i) memcpy(tl_at(l, w), t, sizeof(int32_t) * (size_t)l->stride); w++; }
    }
    l->n = w;
}

static int vm_read(VM *vm, const int64_t *op, int c) {
    int nocase = (vm->flags & TF_NOCASE) != 0, dotall = (vm->flags & TF_DOTALL) != 0;
    switch (op[0]) {
    case T_BYTE: return nocase ? LOWER[c] == LOWER[op[1] & 255] : c == op[1];
    case T_ANY: case T_SKIP: return dotall || c != 10;
    case T_CLASS: {
        const int64_t *bits = vm->classes + op[1] * 4;
        int in = (int)((bits[c >> 6] >> (c & 63)) & 1);
        if (!in && nocase) { int s = T_SWAP[c]; in = (int)((bits[s >> 6] >> (s & 63)) & 1); }
        return in != (op[2] != 0);
    }
    case T_NOT_BYTE: return c != op[1];
    case T_MASK: return (c & op[1]) == op[2];
    case T_NOT_MASK: return (c & op[1]) != op[2];
    case T_WORD: return T_WORDS[c]; case T_NON_WORD: return !T_WORDS[c];
    case T_SPACE: return T_SPACES[c]; case T_NON_SPACE: return !T_SPACES[c];
    case T_DIGIT: return c >= 48 && c <= 57;
    default: return !(c >= 48 && c <= 57); /* T_NON_DIGIT */
    }
}

/* Threads._pass: one step over `in` (consumed), the next step's threads into `out`. */
static int vm_pass(VM *vm, TList *in, int c, int low, const int around[4], TList *out, int64_t *hits) {
    TList tested = {NULL, 0, 0, vm->stride};
    Py_ssize_t i = 0;
    int ok = 1;
    *hits = 0;
    while (i < in->n) {
        if (++vm->steps % 4096 == 0 && vm->left >= 0.0 && now_seconds() - vm->began >= vm->left) {
            vm->error = 4; ok = 0; break;
        }
        int32_t *t = tl_at(in, i);
        const int64_t *op = vm_op(vm, t[0]);
        int64_t code = op[0];
        if (code >= T_BYTE && code <= T_SKIP) {
            if (c < 0 || !low || !vm_read(vm, op, c)) { vm->live--; i++; continue; }
            if (code != T_SKIP) t[0] += 1;
            if (!vm_settle(vm, t, out)) { ok = 0; break; }
            i++;
            continue;
        }
        if (code >= T_START && code <= T_NON_EDGE) {
            int dup = 0;
            for (Py_ssize_t k = 0; k < tested.n && !dup; k++) dup = same_thread(tl_at(&tested, k), t);
            if (dup) { vm->live--; i++; continue; }
            if (!tl_push(&tested, t, vm)) { ok = 0; break; }
            int pass = code == T_START ? around[0] : code == T_END ? around[1]
                     : ((around[2] != around[3]) == (code == T_EDGE));
            if (!pass) { vm->live--; i++; continue; }
            t[0] += 1;
            /* what it settles to re-enters this step where it stood */
            TList moved = {NULL, 0, 0, vm->stride};
            int32_t copy[3 + T_MAX_COUNTS];
            memcpy(copy, t, sizeof(int32_t) * (size_t)vm->stride);
            if (!vm_settle(vm, copy, &moved)) { PyMem_RawFree(moved.t); ok = 0; break; }
            tl_remove(in, i);
            for (Py_ssize_t k = moved.n - 1; k >= 0; k--)
                if (!tl_insert(in, i, tl_at(&moved, k), vm)) { ok = 0; break; }
            PyMem_RawFree(moved.t);
            if (!ok) break;
            continue;
        }
        /* DONE */
        *hits += 1;
        if (vm->flags & TF_EVERY) { vm->live--; i++; continue; }
        vm->live -= in->n - i;
        break;
    }
    PyMem_RawFree(tested.t);
    return ok;
}

static int t_word(const uint8_t *d, int64_t n, int64_t p, int width) {
    if (p < 0 || p + width > n) return 0;
    return T_WORDS[d[p]] && (width == 1 || d[p + 1] == 0);
}

typedef struct { int64_t *s, *l; Py_ssize_t n, cap; } Pairs;

static int pairs_push(Pairs *p, int64_t s, int64_t l, VM *vm) {
    if (p->n == p->cap) {
        Py_ssize_t c = p->cap ? 2 * p->cap : 16;
        int64_t *a = PyMem_RawRealloc(p->s, sizeof(int64_t) * (size_t)c);
        if (!a) { vm->error = 2; return 0; }
        p->s = a;
        int64_t *b = PyMem_RawRealloc(p->l, sizeof(int64_t) * (size_t)c);
        if (!b) { vm->error = 2; return 0; }
        p->l = b; p->cap = c;
    }
    p->s[p->n] = s; p->l[p->n] = l; p->n++;
    return 1;
}

/* Threads.run: the found length (-1 for none), every match into `found` in every mode. */
static int64_t vm_run(VM *vm, int32_t entry, const uint8_t *d, int64_t n, int64_t at, int64_t reach_most, Pairs *found) {
    int backwards = (vm->flags & TF_BACKWARDS) != 0, wide = (vm->flags & TF_WIDE) != 0;
    int width = wide ? 2 : 1;
    int64_t step = backwards ? -width : width;
    int64_t reach = backwards ? at : n - at;
    if (reach > reach_most) reach = reach_most;
    reach -= reach % width;
    int64_t pos = backwards ? at - width : at, done = 0, result = -1;
    TList cur = {NULL, 0, 0, vm->stride}, nxt = {NULL, 0, 0, vm->stride};
    int32_t start[3 + T_MAX_COUNTS];
    memset(start, 0, sizeof start);
    start[0] = entry; start[1] = 0; start[2] = -1;
    vm->live = 0;
    if (!vm_new(vm) || !vm_settle(vm, start, &cur)) goto end;
    vm_dedupe(&cur);
    while (cur.n > 0) {
        int c = -1, low = 0;
        if (done < reach) { c = d[pos]; low = !wide || d[pos + 1] == 0; }
        int around[4] = {
            backwards ? at <= done : (at == 0 && done == 0),
            !backwards && n - at <= done,
            t_word(d, n, pos - step, width),
            t_word(d, n, pos, width),
        };
        vm->live = cur.n;
        int64_t hits = 0;
        nxt.n = 0;
        if (!vm_pass(vm, &cur, c, low, around, &nxt, &hits)) goto end;
        vm_dedupe(&nxt);
        if (hits) {
            result = done;
            if (vm->flags & TF_EVERY)
                for (int64_t k = 0; k < hits; k++)
                    if (!pairs_push(found, backwards ? pos + width : at, done, vm)) goto end;
        }
        pos += step;
        done += width;
        if ((vm->flags & TF_SCAN) && done < reach) {
            vm->live = nxt.n;
            if (!vm_new(vm) || !vm_settle(vm, start, &nxt)) goto end;
            vm_dedupe(&nxt);
        }
        TList swap = cur; cur = nxt; nxt = swap;
    }
end:
    PyMem_RawFree(cur.t); PyMem_RawFree(nxt.t);
    return result;
}

static PyObject *TooManyThreads;

/* threads_run(program, entry, data, at, flags, max_threads, reach[, left]) -> length, or with
 * flag 16 (every) the (starts, lengths) int64 pair. Raises TooManyThreads where Threads raises
 * RunError, TimeoutError past the time allowed, ValueError for a program it cannot run. */
static PyObject *threads_run(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer prog, data; int entry; Py_ssize_t at, max_threads, reach; long flags; double left = -1.0;
    if (!PyArg_ParseTuple(args, "y*iy*nlnn|d", &prog, &entry, &data, &at, &flags, &max_threads, &reach, &left)) return NULL;
    PyObject *result = NULL;
    VM vm; memset(&vm, 0, sizeof vm);
    Pairs found = {NULL, NULL, 0, 0};
    const int64_t *p = prog.buf;
    Py_ssize_t words = prog.len / 8;
    if (prog.len % 8 || words < T_HEADER || p[1] != T_VERSION) { PyErr_SetString(PyExc_ValueError, "not a version 2 program"); goto done; }
    vm.nops = (Py_ssize_t)p[2]; vm.nclasses = (Py_ssize_t)p[3]; vm.maxc = (int)p[6];
    if (vm.nops < 1 || vm.nclasses < 0 || p[6] < 0 || p[6] > T_MAX_COUNTS ||
        words != T_HEADER + vm.nops * T_RECORD + vm.nclasses * 4) {
        PyErr_SetString(PyExc_ValueError, "a program's sizes do not add up, or it nests too deep"); goto done;
    }
    vm.ops = p + T_HEADER; vm.classes = vm.ops + vm.nops * T_RECORD;
    vm.stride = 3 + (vm.maxc ? vm.maxc : 1);
    for (Py_ssize_t i = 0; i < vm.nops; i++) { /* every target and table index in range */
        const int64_t *op = vm.ops + i * T_RECORD;
        int64_t c = op[0];
        int bad = c < T_BYTE || c > T_AGAIN;
        if (c == T_FORK) bad = bad || op[2] < 0 || op[2] >= vm.nops || i + 1 >= vm.nops;
        if (c == T_GOTO) bad = bad || op[1] < 0 || op[1] >= vm.nops;
        if (c == T_ENTER) bad = bad || op[3] < 0 || op[3] >= vm.nops || i + 1 >= vm.nops || op[1] < 0 || op[2] < op[1];
        if (c == T_AGAIN) bad = bad || op[3] < 0 || op[3] >= vm.nops || i + 1 >= vm.nops || op[1] < 0 || op[2] < op[1];
        if (c == T_CLASS) bad = bad || op[1] < 0 || op[1] >= vm.nclasses;
        if (c == T_SKIP) bad = bad || op[1] < 0 || op[2] < op[1] || op[2] > 65535;
        if (c == T_BYTE || c == T_NOT_BYTE) bad = bad || op[1] < 0 || op[1] > 255;
        if (c == T_MASK || c == T_NOT_MASK) bad = bad || op[1] < 0 || op[1] > 255 || op[2] < 0 || op[2] > 255;
        if ((c >= T_BYTE && c <= T_SKIP) || (c >= T_START && c <= T_NON_EDGE)) bad = bad || i + 1 >= vm.nops;
        if (bad) { PyErr_SetString(PyExc_ValueError, "a program holds an instruction out of range"); goto done; }
    }
    if (entry < 0 || entry >= vm.nops || at < 0 || at > data.len || max_threads < 1 || max_threads > (1 << 20) ||
        reach < 0 || reach > (1 << 20)) {
        PyErr_SetString(PyExc_ValueError, "an entry, offset, thread bound or reach out of range"); goto done;
    }
    vm.flags = flags; vm.max_threads = max_threads; vm.left = left;
    int64_t length;
    Py_BEGIN_ALLOW_THREADS
    vm.began = now_seconds();
    length = vm_run(&vm, entry, data.buf, data.len, at, reach, &found);
    Py_END_ALLOW_THREADS
    if (vm.error == 1) { PyErr_SetString(TooManyThreads, "a pattern needed too many threads"); goto done; }
    if (vm.error == 2) { PyErr_NoMemory(); goto done; }
    if (vm.error == 3) { PyErr_SetString(PyExc_ValueError, "a program's counts do not nest as declared"); goto done; }
    if (vm.error == 4) { PyErr_SetString(PyExc_TimeoutError, "matching took longer than the time allowed"); goto done; }
    if (flags & TF_EVERY) {
        static const char none[1] = {0};
        result = Py_BuildValue("(y#y#)", found.n ? (const char *)found.s : none, found.n * 8,
                               found.n ? (const char *)found.l : none, found.n * 8);
    } else {
        result = PyLong_FromLongLong(length);
    }
done:
    PyMem_RawFree(found.s); PyMem_RawFree(found.l);
    PyBuffer_Release(&prog); PyBuffer_Release(&data);
    return result;
}

/* A program read and checked once (threads_run's entry checks), for a whole-string call. */
static int vm_program(VM *vm, Py_buffer *prog) {
    const int64_t *p = prog->buf;
    Py_ssize_t words = prog->len / 8;
    if (prog->len % 8 || words < T_HEADER || p[1] != T_VERSION) { PyErr_SetString(PyExc_ValueError, "not a version 2 program"); return 0; }
    vm->nops = (Py_ssize_t)p[2]; vm->nclasses = (Py_ssize_t)p[3]; vm->maxc = (int)p[6];
    if (vm->nops < 1 || vm->nclasses < 0 || p[6] < 0 || p[6] > T_MAX_COUNTS ||
        words != T_HEADER + vm->nops * T_RECORD + vm->nclasses * 4) {
        PyErr_SetString(PyExc_ValueError, "a program's sizes do not add up, or it nests too deep"); return 0;
    }
    vm->ops = p + T_HEADER; vm->classes = vm->ops + vm->nops * T_RECORD;
    vm->stride = 3 + (vm->maxc ? vm->maxc : 1);
    for (Py_ssize_t i = 0; i < vm->nops; i++) {
        const int64_t *op = vm->ops + i * T_RECORD;
        int64_t c = op[0];
        int bad = c < T_BYTE || c > T_AGAIN;
        if (c == T_FORK) bad = bad || op[2] < 0 || op[2] >= vm->nops || i + 1 >= vm->nops;
        if (c == T_GOTO) bad = bad || op[1] < 0 || op[1] >= vm->nops;
        if (c == T_ENTER || c == T_AGAIN) bad = bad || op[3] < 0 || op[3] >= vm->nops || i + 1 >= vm->nops || op[1] < 0 || op[2] < op[1];
        if (c == T_CLASS) bad = bad || op[1] < 0 || op[1] >= vm->nclasses;
        if (c == T_SKIP) bad = bad || op[1] < 0 || op[2] < op[1] || op[2] > 65535;
        if (c == T_BYTE || c == T_NOT_BYTE) bad = bad || op[1] < 0 || op[1] > 255;
        if (c == T_MASK || c == T_NOT_MASK) bad = bad || op[1] < 0 || op[1] > 255 || op[2] < 0 || op[2] > 255;
        if ((c >= T_BYTE && c <= T_SKIP) || (c >= T_START && c <= T_NON_EDGE)) bad = bad || i + 1 >= vm->nops;
        if (bad) { PyErr_SetString(PyExc_ValueError, "a program holds an instruction out of range"); return 0; }
    }
    return 1;
}

/* The starts recorded for one string: first length kept, or the last with greedy (scan._Hunt._record). */
typedef struct { int64_t *keys, *slot, *hs, *hl; Py_ssize_t kcap, hcap, held, max_hits; int full, greedy; } Record;

static int rec_put(Record *r, int64_t start, int64_t length) {
    if (r->kcap) {
        uint64_t x = (uint64_t)start * 0x9E3779B97F4A7C15ULL;
        Py_ssize_t j = (Py_ssize_t)(x & (uint64_t)(r->kcap - 1));
        while (r->keys[j] != -1 && r->keys[j] != start) j = (j + 1) & (r->kcap - 1);
        if (r->keys[j] == start) { if (r->greedy) r->hl[r->slot[j]] = length; return 1; }
    }
    if (r->held >= r->max_hits) { r->full = 1; return 1; }
    if (r->held + 1 > r->hcap) {
        Py_ssize_t c = r->hcap ? 2 * r->hcap : 64;
        int64_t *a = PyMem_RawRealloc(r->hs, sizeof(int64_t) * (size_t)c); if (!a) return 0; r->hs = a;
        int64_t *b = PyMem_RawRealloc(r->hl, sizeof(int64_t) * (size_t)c); if (!b) return 0; r->hl = b;
        r->hcap = c;
    }
    if (2 * (r->held + 1) > r->kcap) {
        Py_ssize_t kc = r->kcap ? 2 * r->kcap : 128;
        int64_t *k = PyMem_RawMalloc(sizeof(int64_t) * (size_t)kc), *sl = PyMem_RawMalloc(sizeof(int64_t) * (size_t)kc);
        if (!k || !sl) { PyMem_RawFree(k); PyMem_RawFree(sl); return 0; }
        for (Py_ssize_t i = 0; i < kc; i++) k[i] = -1;
        for (Py_ssize_t i = 0; i < r->held; i++) {
            uint64_t x = (uint64_t)r->hs[i] * 0x9E3779B97F4A7C15ULL;
            Py_ssize_t j = (Py_ssize_t)(x & (uint64_t)(kc - 1));
            while (k[j] != -1) j = (j + 1) & (kc - 1);
            k[j] = r->hs[i]; sl[j] = i;
        }
        PyMem_RawFree(r->keys); PyMem_RawFree(r->slot); r->keys = k; r->slot = sl; r->kcap = kc;
    }
    uint64_t x = (uint64_t)start * 0x9E3779B97F4A7C15ULL;
    Py_ssize_t j = (Py_ssize_t)(x & (uint64_t)(r->kcap - 1));
    while (r->keys[j] != -1) j = (j + 1) & (r->kcap - 1);
    r->keys[j] = start; r->slot[j] = r->held; r->hs[r->held] = start; r->hl[r->held] = length; r->held++;
    return 1;
}

enum { PH_ASCII = 1, PH_WIDE = 2, PH_NOCASE = 4, PH_DOTALL = 8, PH_FULLWORD = 16, PH_GREEDY = 32 };

/* pattern_hits(data, owners, forward, backward, flags, max_hits, fixed, max_threads, reach[,
 * left]) -> (starts, lengths): one pattern string of one part (a regex, or hex with
 * alternatives) found as scan._Hunt finds it: the events in the hunt's order (owners as
 * hex_hits takes them), at each, for each width (ascii, then wide), the forward program run
 * from the anchor's forward entry, then the backward one from its backward entry with every
 * start it reaches a match of the two lengths together (nothing to run backwards: the match as
 * it stands, its whole-word test one byte wide), fullword applied, the first length at a start
 * kept (greedy: the last), and the stop at max_hits. TooManyThreads where the hunt's Threads
 * raises RunError; the time allowed read every 4,096 events and inside each run. */
static PyObject *pattern_hits(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer data, fb, bb; PyObject *owners; long flags; Py_ssize_t max_hits, fixed, max_threads, reach; double left = -1.0;
    if (!PyArg_ParseTuple(args, "y*Oy*y*lnnnn|d", &data, &owners, &fb, &bb, &flags, &max_hits, &fixed, &max_threads, &reach, &left)) return NULL;
    PyObject *result = NULL, *seq = NULL;
    Event *ev = NULL; int64_t *ent = NULL;
    VM fv, bv; memset(&fv, 0, sizeof fv); memset(&bv, 0, sizeof bv);
    Record rec; memset(&rec, 0, sizeof rec);
    Pairs back = {NULL, NULL, 0, 0};
    if (!vm_program(&fv, &fb) || !vm_program(&bv, &bb)) goto done;
    if (max_hits < 0 || max_hits > ((Py_ssize_t)1 << 30) || max_threads < 1 || max_threads > (1 << 20) || reach < 1 || reach > (1 << 20)) {
        PyErr_SetString(PyExc_ValueError, "max_hits, the thread bound or reach out of range"); goto done;
    }
    rec.max_hits = max_hits; rec.greedy = (flags & PH_GREEDY) != 0;
    seq = PySequence_Tuple(owners);
    if (!seq) goto done;
    Py_ssize_t no = PyTuple_GET_SIZE(seq), total = 0, count = 0;
    for (Py_ssize_t k = 0; k < no; k++) {
        PyObject *o = PyTuple_GET_ITEM(seq, k);
        if (!PyTuple_Check(o) || PyTuple_GET_SIZE(o) != 6 || !PyList_Check(PyTuple_GET_ITEM(o, 0))) {
            PyErr_SetString(PyExc_TypeError, "an owner is (list of starts, length, back, order, forward entry, backward entry)"); goto done;
        }
        for (Py_ssize_t q = 1; q < 6; q++)
            if (!PyLong_CheckExact(PyTuple_GET_ITEM(o, q))) { PyErr_SetString(PyExc_TypeError, "an owner's field is not an int"); goto done; }
        Py_ssize_t m = PyList_GET_SIZE(PyTuple_GET_ITEM(o, 0));
        if (m > ((Py_ssize_t)1 << 28) - total) { PyErr_SetString(PyExc_MemoryError, "too many occurrences"); goto done; }
        total += m;
    }
    ev = PyMem_RawMalloc(sizeof(Event) * (size_t)(total ? total : 1));
    ent = PyMem_RawMalloc(sizeof(int64_t) * 2 * (size_t)(no ? no : 1));
    if (!ev || !ent) { PyErr_NoMemory(); goto done; }
    for (Py_ssize_t k = 0; k < no; k++) {
        PyObject *o = PyTuple_GET_ITEM(seq, k), *starts = PyTuple_GET_ITEM(o, 0);
        long long length = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 1)), bk = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 2));
        long long order = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 3));
        long long fe = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 4)), be = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 5));
        if (PyErr_Occurred()) goto done;
        if (length < 0 || length > TEXT_MOST || bk < 0 || bk > TEXT_MOST || fe < -1 || fe >= fv.nops || be < -1 || be >= bv.nops) {
            PyErr_SetString(PyExc_ValueError, "an owner's length, back or entries are out of range"); goto done;
        }
        ent[2 * k] = fe; ent[2 * k + 1] = be;
        Py_ssize_t m = PyList_GET_SIZE(starts);
        if (m > total - count) { PyErr_SetString(PyExc_RuntimeError, "an owner's starts changed while read"); goto done; }
        for (Py_ssize_t i = 0; i < m; i++) {
            PyObject *x = PyList_GET_ITEM(starts, i);
            if (!PyLong_CheckExact(x)) { PyErr_SetString(PyExc_TypeError, "a start is not an int"); goto done; }
            long long sv = PyLong_AsLongLong(x);
            if (sv == -1 && PyErr_Occurred()) goto done;
            if (sv < 0 || sv > TEXT_MOST) { PyErr_SetString(PyExc_ValueError, "a start is out of range"); goto done; }
            if (bk <= sv + length) {
                ev[count].e0 = sv + length; ev[count].nl = -length; ev[count].no = -order;
                ev[count].seq = count; ev[count].at = sv + length - bk; ev[count].owner = (int32_t)k;
                count++;
            }
        }
    }
    const uint8_t *d = data.buf; int64_t n = data.len;
    int err = 0, nomem = 0;
    double began = now_seconds();
    fv.max_threads = bv.max_threads = max_threads; fv.left = bv.left = left; fv.began = bv.began = began;
    long base = (flags & PH_NOCASE ? TF_NOCASE : 0) | (flags & PH_DOTALL ? TF_DOTALL : 0);
    Py_BEGIN_ALLOW_THREADS
    qsort(ev, (size_t)count, sizeof(Event), cmp_event);
    for (Py_ssize_t i = 0; i < count && !err && !nomem; i++) {
        if (i % 4096 == 0 && left >= 0.0 && now_seconds() - began >= left) { err = 4; break; }
        if (rec.full) break;
        int64_t at = ev[i].at;
        if (at >= n || (fixed >= 0 && at != fixed)) continue;
        int64_t fe = ent[2 * ev[i].owner], be = ent[2 * ev[i].owner + 1];
        if (fe < 0) continue;
        for (int w = 0; w < 2 && !err && !nomem; w++) {
            if (!(flags & (w ? PH_WIDE : PH_ASCII))) continue;
            fv.flags = base | (w ? TF_WIDE : 0);
            fv.error = 0;
            int64_t length = vm_run(&fv, (int32_t)fe, d, n, at, reach, NULL);
            if (fv.error) { err = fv.error; break; }
            if (length != -1 && be >= 0) {
                bv.flags = base | (w ? TF_WIDE : 0) | TF_BACKWARDS | TF_EVERY;
                bv.error = 0; back.n = 0;
                vm_run(&bv, (int32_t)be, d, n, at, reach, &back);
                if (bv.error) { err = bv.error; break; }
                for (Py_ssize_t k = 0; k < back.n; k++) {
                    int64_t st = back.s[k], len = back.l[k] + length;
                    if ((flags & PH_FULLWORD) && !whole(d, n, st, len, w)) continue;
                    if (!rec_put(&rec, st, len)) { nomem = 1; break; }
                }
            } else if (length >= 0) {
                if ((flags & PH_FULLWORD) && !whole(d, n, at, length, 0)) continue;
                if (!rec_put(&rec, at, length)) { nomem = 1; break; }
            }
        }
    }
    Py_END_ALLOW_THREADS
    if (nomem || err == 2) { PyErr_NoMemory(); goto done; }
    if (err == 1) { PyErr_SetString(TooManyThreads, "a pattern needed too many threads"); goto done; }
    if (err == 3) { PyErr_SetString(PyExc_ValueError, "a program's counts do not nest as declared"); goto done; }
    if (err == 4) { PyErr_SetString(PyExc_TimeoutError, "matching took longer than the time allowed"); goto done; }
    {
        Py_ssize_t held = rec.held;
        int64_t *pairs = PyMem_RawMalloc(sizeof(int64_t) * 2 * (size_t)(held ? held : 1));
        if (!pairs) { PyErr_NoMemory(); goto done; }
        for (Py_ssize_t i = 0; i < held; i++) { pairs[2 * i] = rec.hs[i]; pairs[2 * i + 1] = rec.hl[i]; }
        qsort(pairs, (size_t)held, 2 * sizeof(int64_t), cmp_i64);
        for (Py_ssize_t i = 0; i < held; i++) { rec.hs[i] = pairs[2 * i]; rec.hl[i] = pairs[2 * i + 1]; }
        PyMem_RawFree(pairs);
        static const char none[1] = {0};
        result = Py_BuildValue("(y#y#)", held ? (const char *)rec.hs : none, held * 8, held ? (const char *)rec.hl : none, held * 8);
    }
done:
    PyMem_RawFree(ev); PyMem_RawFree(ent); PyMem_RawFree(back.s); PyMem_RawFree(back.l);
    PyMem_RawFree(rec.keys); PyMem_RawFree(rec.slot); PyMem_RawFree(rec.hs); PyMem_RawFree(rec.hl);
    Py_XDECREF(seq);
    PyBuffer_Release(&fb); PyBuffer_Release(&bb); PyBuffer_Release(&data);
    return result;
}

static int threads_vm_init(PyObject *m) {
    for (int i = 0; i < 256; i++) {
        T_WORDS[i] = (uint8_t)((i >= '0' && i <= '9') || (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z') || i == '_');
        T_SPACES[i] = (uint8_t)(i == '\t' || i == '\n' || i == 0x0b || i == 0x0c || i == '\r' || i == ' ');
        T_SWAP[i] = (uint8_t)(i >= 'A' && i <= 'Z' ? i + 32 : i >= 'a' && i <= 'z' ? i - 32 : i);
    }
    TooManyThreads = PyErr_NewException("_anchors.TooManyThreads", PyExc_RuntimeError, NULL);
    if (!TooManyThreads) return -1;
    Py_INCREF(TooManyThreads);
    if (PyModule_AddObject(m, "TooManyThreads", TooManyThreads) < 0) { Py_DECREF(TooManyThreads); return -1; }
    return 0;
}
