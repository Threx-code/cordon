/* cordon_scanner._native._anchors: one Aho-Corasick automaton over a rule set's anchors.
 *
 * Cordon's own code (C11, the Python C API only). It reads hostile files, so: no recursion, every
 * array index checked against the array's length, the data read only within [0, len), memory
 * bounded by the automaton (capped at build) plus the output (capped per anchor at scan), and the
 * GIL released for the walk over the data.
 *
 *   Automaton(needles, fold=False)       needles: a sequence of distinct, non-empty bytes
 *   .present(data) -> list[int]          the ids (positions in `needles`) occurring, ascending
 *   .positions(data, ids, cap) -> dict   id -> bytes of int64 start offsets (ascending, overlapping
 *                                        ones included), or None where more than `cap` occur
 *   .nbytes, .nodes
 *
 * With fold, each data byte is read through ASCII lowering (A-Z only, bytes.lower's rule); the
 * needles are matched as given, so the caller passes lowered needles.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

#define MAX_BYTES ((size_t)256 << 20) /* an automaton larger than this is refused at build */
#define NONE (-1)
#define DENSE_ROWS 16384 /* nodes with a full row of 256 next states (16 MB at most) */

typedef struct {
    PyObject_HEAD
    int32_t nodes, edges, needles;
    int32_t *first;   /* per node: index of its first edge */
    int32_t *count;   /* per node: how many edges */
    uint8_t *ebyte;   /* per edge: its byte, ascending within a node */
    int32_t *target;  /* per edge: the child node */
    int32_t *fail;    /* per node: the failure link (the root's is NONE) */
    int32_t *out;     /* per node: the nearest node on the failure chain that ends a needle */
    int32_t *term;    /* per node: the needle ending here, or NONE */
    int32_t *length;  /* per needle: its length */
    int32_t root[256];/* the root's child for each byte, or 0 (stay at the root) */
    int32_t *dense;   /* per node: its row in `table`, or NONE (the busiest nodes have one) */
    int32_t *table;   /* rows of 256: the state after each byte, failure links already followed */
    int32_t rows;
    int fold;
    size_t nbytes;
} Automaton;

static uint8_t LOWER[256];

static void free_arrays(Automaton *a) {
    PyMem_RawFree(a->first); PyMem_RawFree(a->count); PyMem_RawFree(a->ebyte);
    PyMem_RawFree(a->target); PyMem_RawFree(a->fail); PyMem_RawFree(a->out);
    PyMem_RawFree(a->term); PyMem_RawFree(a->length); PyMem_RawFree(a->dense); PyMem_RawFree(a->table);
    a->first = a->count = a->target = a->fail = a->out = a->term = a->length = a->dense = a->table = NULL;
    a->ebyte = NULL;
}

/* The child of `node` on byte `c`, or NONE: the root by table, any other node by binary search
 * over its sorted edges. */
static inline int32_t child(const Automaton *a, int32_t node, uint8_t c) {
    if (node == 0) {
        int32_t t = a->root[c];
        return t ? t : NONE;
    }
    int32_t lo = a->first[node], hi = lo + a->count[node] - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        uint8_t b = a->ebyte[mid];
        if (b == c) return a->target[mid];
        if (b < c) lo = mid + 1; else hi = mid - 1;
    }
    return NONE;
}

/* The state after reading `c` in `state`: one load at a node with a table row, else its edges
 * and failure links (which lead to shallower nodes, the shallowest of which have rows). */
static inline int32_t step(const Automaton *a, int32_t state, uint8_t c) {
    for (;;) {
        if (a->dense && a->dense[state] != NONE) return a->table[(size_t)a->dense[state] * 256 + c];
        int32_t t = child(a, state, c);
        if (t != NONE) return t;
        if (state == 0) return 0;
        state = a->fail[state];
    }
}

/* build() runs no Python code: it reads the list only through PyBytes_Check and the size and data
 * macros, so the list cannot change while it is read. Keep it so.
 *
 * Build: needles sorted (so each new branch is the last child at its node), a trie in
 * first-child/next-sibling form, laid out breadth-first into the edge arrays, failure and
 * output links by the breadth-first queue. Returns 0, or -1 with an exception set. */
static int build(Automaton *a, PyObject *seq) {
    Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
    PyObject **items = PySequence_Fast_ITEMS(seq);
    if (n > INT32_MAX - 1) { PyErr_SetString(PyExc_ValueError, "too many needles"); return -1; }
    size_t total = 1;
    for (Py_ssize_t i = 0; i < n; i++) {
        if (!PyBytes_Check(items[i])) { PyErr_SetString(PyExc_TypeError, "a needle is not bytes"); return -1; }
        Py_ssize_t m = PyBytes_GET_SIZE(items[i]);
        if (m == 0) { PyErr_SetString(PyExc_ValueError, "an empty needle"); return -1; }
        if ((size_t)m > MAX_BYTES || total > MAX_BYTES) { PyErr_SetString(PyExc_MemoryError, "the needles are past the automaton's limit"); return -1; }
        total += (size_t)m;
    }
    if (total * 30 > MAX_BYTES) { PyErr_SetString(PyExc_MemoryError, "the needles are past the automaton's limit"); return -1; }
    size_t cap = total; /* nodes at most: one per needle byte, plus the root */
    /* the sort order of the needles, by an index array and insertion-free merge sort */
    Py_ssize_t *order = PyMem_RawMalloc(sizeof(Py_ssize_t) * (size_t)(n ? n : 1));
    Py_ssize_t *tmp = PyMem_RawMalloc(sizeof(Py_ssize_t) * (size_t)(n ? n : 1));
    int32_t *fc = PyMem_RawMalloc(sizeof(int32_t) * cap);   /* first child */
    int32_t *lc = PyMem_RawMalloc(sizeof(int32_t) * cap);   /* last child */
    int32_t *ns = PyMem_RawMalloc(sizeof(int32_t) * cap);   /* next sibling */
    uint8_t *by = PyMem_RawMalloc(cap);                      /* the byte into the node */
    int32_t *tm = PyMem_RawMalloc(sizeof(int32_t) * cap);   /* needle ending at the node */
    int32_t *queue = PyMem_RawMalloc(sizeof(int32_t) * cap);
    int32_t *newid = PyMem_RawMalloc(sizeof(int32_t) * cap);
    a->length = PyMem_RawMalloc(sizeof(int32_t) * (size_t)(n ? n : 1));
    if (!order || !tmp || !fc || !lc || !ns || !by || !tm || !queue || !newid || !a->length) {
        PyErr_NoMemory(); goto fail;
    }
    for (Py_ssize_t i = 0; i < n; i++) { order[i] = i; a->length[i] = (int32_t)PyBytes_GET_SIZE(items[i]); }
    /* bottom-up merge sort of `order` by the needles' bytes */
    for (Py_ssize_t width = 1; width < n; width *= 2) {
        for (Py_ssize_t lo = 0; lo < n; lo += 2 * width) {
            Py_ssize_t mid = lo + width < n ? lo + width : n, hi = lo + 2 * width < n ? lo + 2 * width : n;
            Py_ssize_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi) {
                PyObject *x = items[order[i]], *y = items[order[j]];
                Py_ssize_t lx = PyBytes_GET_SIZE(x), ly = PyBytes_GET_SIZE(y);
                int c = memcmp(PyBytes_AS_STRING(x), PyBytes_AS_STRING(y), (size_t)(lx < ly ? lx : ly));
                if (c < 0 || (c == 0 && lx <= ly)) tmp[k++] = order[i++]; else tmp[k++] = order[j++];
            }
            while (i < mid) tmp[k++] = order[i++];
            while (j < hi) tmp[k++] = order[j++];
        }
        Py_ssize_t *sw = order; order = tmp; tmp = sw;
    }
    int32_t made = 1;
    fc[0] = lc[0] = ns[0] = NONE; tm[0] = NONE; by[0] = 0;
    for (Py_ssize_t r = 0; r < n; r++) {
        Py_ssize_t id = order[r];
        const uint8_t *s = (const uint8_t *)PyBytes_AS_STRING(items[id]);
        Py_ssize_t m = PyBytes_GET_SIZE(items[id]);
        int32_t node = 0;
        for (Py_ssize_t k = 0; k < m; k++) {
            int32_t last = lc[node];
            if (last != NONE && by[last] == s[k]) { node = last; continue; }
            if ((size_t)made >= cap) { PyErr_SetString(PyExc_RuntimeError, "trie past its bound"); goto fail; }
            int32_t fresh = made++;
            fc[fresh] = lc[fresh] = ns[fresh] = NONE; tm[fresh] = NONE; by[fresh] = s[k];
            if (last == NONE) fc[node] = fresh; else ns[last] = fresh;
            lc[node] = fresh;
            node = fresh;
        }
        if (tm[node] != NONE) { PyErr_SetString(PyExc_ValueError, "a needle is given twice"); goto fail; }
        tm[node] = (int32_t)id;
    }
    /* breadth-first numbering: the queue order is the new node order */
    int32_t head = 0, tail = 0;
    queue[tail++] = 0;
    while (head < tail) {
        int32_t u = queue[head++];
        for (int32_t v = fc[u]; v != NONE; v = ns[v]) {
            if (tail >= made) { PyErr_SetString(PyExc_RuntimeError, "queue past its bound"); goto fail; }
            queue[tail++] = v;
        }
    }
    for (int32_t i = 0; i < made; i++) newid[queue[i]] = i;
    a->nodes = made; a->edges = made - 1; a->needles = (int32_t)n;
    size_t nn = (size_t)made, ne = (size_t)(made > 1 ? made - 1 : 1);
    a->first = PyMem_RawMalloc(sizeof(int32_t) * nn); a->count = PyMem_RawMalloc(sizeof(int32_t) * nn);
    a->fail = PyMem_RawMalloc(sizeof(int32_t) * nn); a->out = PyMem_RawMalloc(sizeof(int32_t) * nn);
    a->term = PyMem_RawMalloc(sizeof(int32_t) * nn);
    a->ebyte = PyMem_RawMalloc(ne); a->target = PyMem_RawMalloc(sizeof(int32_t) * ne);
    if (!a->first || !a->count || !a->fail || !a->out || !a->term || !a->ebyte || !a->target) { PyErr_NoMemory(); goto fail; }
    int32_t e = 0;
    for (int32_t i = 0; i < made; i++) {
        int32_t u = queue[i];
        a->first[i] = e; a->count[i] = 0; a->term[i] = tm[u];
        for (int32_t v = fc[u]; v != NONE; v = ns[v]) {
            if (e >= a->edges) { PyErr_SetString(PyExc_RuntimeError, "edges past their bound"); goto fail; }
            a->ebyte[e] = by[v]; a->target[e] = newid[v]; e++; a->count[i]++;
        }
    }
    memset(a->root, 0, sizeof(a->root));
    for (int32_t k = 0; k < a->count[0]; k++) a->root[a->ebyte[a->first[0] + k]] = a->target[a->first[0] + k];
    /* failure and output links, in node order (which is breadth-first) */
    a->fail[0] = NONE; a->out[0] = NONE;
    for (int32_t u = 0; u < made; u++) {
        for (int32_t k = 0; k < a->count[u]; k++) {
            int32_t v = a->target[a->first[u] + k];
            uint8_t c = a->ebyte[a->first[u] + k];
            int32_t f;
            if (u == 0) f = 0;
            else f = step(a, a->fail[u], c);
            a->fail[v] = f;
            a->out[v] = a->term[f] != NONE ? f : a->out[f];
        }
    }
    /* table rows for the root and the shallowest nodes (node order is breadth-first, so they come
     * first), DENSE_ROWS at most: the walk spends most of its steps there */
    {
        int32_t rows = made < DENSE_ROWS ? made : DENSE_ROWS;
        a->dense = PyMem_RawMalloc(sizeof(int32_t) * nn);
        a->table = PyMem_RawMalloc(sizeof(int32_t) * 256 * (size_t)rows);
        if (!a->dense || !a->table) { PyErr_NoMemory(); goto fail; }
        for (size_t i = 0; i < nn; i++) a->dense[i] = NONE;
        for (int32_t u = 0; u < rows; u++) {
            int32_t *row = a->table + (size_t)u * 256;
            for (int c = 0; c < 256; c++) {
                int32_t t = child(a, u, (uint8_t)c);
                if (t != NONE) row[c] = t;
                else if (u == 0) row[c] = 0;
                else row[c] = step(a, a->fail[u], (uint8_t)c); /* a shallower node, already done */
            }
            a->dense[u] = u;
        }
        a->rows = rows;
    }
    a->nbytes = nn * (sizeof(int32_t) * 6) + ne * (1 + sizeof(int32_t)) + (size_t)n * sizeof(int32_t) + sizeof(a->root)
              + (size_t)a->rows * 256 * sizeof(int32_t);
    PyMem_RawFree(order); PyMem_RawFree(tmp); PyMem_RawFree(fc); PyMem_RawFree(lc); PyMem_RawFree(ns);
    PyMem_RawFree(by); PyMem_RawFree(tm); PyMem_RawFree(queue); PyMem_RawFree(newid);
    return 0;
fail:
    PyMem_RawFree(order); PyMem_RawFree(tmp); PyMem_RawFree(fc); PyMem_RawFree(lc); PyMem_RawFree(ns);
    PyMem_RawFree(by); PyMem_RawFree(tm); PyMem_RawFree(queue); PyMem_RawFree(newid);
    free_arrays(a);
    return -1;
}

static int Automaton_init(Automaton *self, PyObject *args, PyObject *kwds) {
    static char *kw[] = {"needles", "fold", NULL};
    PyObject *needles; int fold = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|p", kw, &needles, &fold)) return -1;
    if (self->first) { PyErr_SetString(PyExc_RuntimeError, "already built"); return -1; }
    PyObject *seq = PySequence_Fast(needles, "needles must be a sequence");
    if (!seq) return -1;
    self->fold = fold;
    int rc = build(self, seq);
    Py_DECREF(seq);
    return rc;
}

static void Automaton_dealloc(Automaton *self) {
    free_arrays(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/* present: one walk; a node's output chain is followed only the first time the node is reached
 * (its chain was reported then), so the walk costs O(len + nodes). */
static PyObject *Automaton_present(Automaton *self, PyObject *arg) {
    if (!self->first) { PyErr_SetString(PyExc_RuntimeError, "not built"); return NULL; }
    Py_buffer view;
    if (PyObject_GetBuffer(arg, &view, PyBUF_SIMPLE) < 0) return NULL;
    uint8_t *reached = PyMem_RawCalloc((size_t)self->nodes, 1);
    uint8_t *found = PyMem_RawCalloc((size_t)self->needles ? (size_t)self->needles : 1, 1);
    if (!reached || !found) { PyMem_RawFree(reached); PyMem_RawFree(found); PyBuffer_Release(&view); return PyErr_NoMemory(); }
    const uint8_t *d = view.buf; Py_ssize_t len = view.len; const Automaton *a = self; int fold = self->fold;
    Py_BEGIN_ALLOW_THREADS
    int32_t s = 0;
    for (Py_ssize_t i = 0; i < len; i++) {
        uint8_t c = fold ? LOWER[d[i]] : d[i];
        s = step(a, s, c);
        int32_t v = a->term[s] != NONE ? s : a->out[s];
        while (v != NONE && !reached[v]) {
            reached[v] = 1;
            int32_t id = a->term[v];
            if (id >= 0 && id < a->needles) found[id] = 1;
            v = a->out[v];
        }
    }
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&view);
    PyObject *list = PyList_New(0);
    for (int32_t i = 0; list && i < self->needles; i++) {
        if (!found[i]) continue;
        PyObject *x = PyLong_FromLong(i);
        if (!x || PyList_Append(list, x) < 0) { Py_XDECREF(x); Py_CLEAR(list); break; }
        Py_DECREF(x);
    }
    PyMem_RawFree(reached); PyMem_RawFree(found);
    return list;
}

/* positions: one walk; each wanted needle's start offsets, at most `cap` of them, then marked
 * as too many and no longer collected. The ids are copied into a tuple and must be exact ints, so
 * no Python code runs between reading them and using them (an __index__ could change a list under
 * the loop). Each needle's offsets grow as they are found, doubling up to cap + 1, so memory is
 * bounded by what the data holds, not by what the caller asks for. */
static PyObject *Automaton_positions(Automaton *self, PyObject *args) {
    PyObject *data, *ids; Py_ssize_t cap;
    if (!PyArg_ParseTuple(args, "OOn", &data, &ids, &cap)) return NULL;
    if (!self->first) { PyErr_SetString(PyExc_RuntimeError, "not built"); return NULL; }
    if (cap < 0 || cap > (Py_ssize_t)1 << 24) { PyErr_SetString(PyExc_ValueError, "cap out of range"); return NULL; }
    PyObject *seq = PySequence_Tuple(ids);
    if (!seq) return NULL;
    Py_ssize_t rows = PyTuple_GET_SIZE(seq);
    if (rows > (Py_ssize_t)self->needles) {
        PyErr_SetString(PyExc_ValueError, "more ids than needles"); Py_DECREF(seq); return NULL;
    }
    size_t nn = (size_t)(self->needles ? self->needles : 1), nr = (size_t)(rows ? rows : 1);
    int32_t *slot = PyMem_RawMalloc(sizeof(int32_t) * nn); /* needle -> its row, or NONE */
    int64_t **off = PyMem_RawCalloc(nr, sizeof(int64_t *));
    Py_ssize_t *got = PyMem_RawCalloc(nr, sizeof(Py_ssize_t));
    Py_ssize_t *room = PyMem_RawCalloc(nr, sizeof(Py_ssize_t));
    int32_t *who = PyMem_RawMalloc(sizeof(int32_t) * nr);
    PyObject *out = NULL;
    int short_of_memory = 0;
    if (!slot || !off || !got || !room || !who) { PyErr_NoMemory(); goto done; }
    for (size_t i = 0; i < nn; i++) slot[i] = NONE;
    for (Py_ssize_t r = 0; r < rows; r++) {
        PyObject *item = PyTuple_GET_ITEM(seq, r);
        if (!PyLong_CheckExact(item)) { PyErr_SetString(PyExc_TypeError, "a needle id is not an int"); goto done; }
        long id = PyLong_AsLong(item);
        if (id == -1 && PyErr_Occurred()) goto done;
        if (id < 0 || id >= self->needles) { PyErr_SetString(PyExc_IndexError, "a needle id out of range"); goto done; }
        if (slot[id] != NONE) { PyErr_SetString(PyExc_ValueError, "a needle id asked twice"); goto done; }
        slot[id] = (int32_t)r; who[r] = (int32_t)id;
    }
    Py_buffer view;
    if (PyObject_GetBuffer(data, &view, PyBUF_SIMPLE) < 0) goto done;
    const uint8_t *d = view.buf; Py_ssize_t len = view.len; const Automaton *a = self; int fold = self->fold;
    Py_BEGIN_ALLOW_THREADS
    int32_t s = 0;
    for (Py_ssize_t i = 0; i < len && !short_of_memory; i++) {
        uint8_t c = fold ? LOWER[d[i]] : d[i];
        s = step(a, s, c);
        for (int32_t v = a->term[s] != NONE ? s : a->out[s]; v != NONE; v = a->out[v]) {
            int32_t id = a->term[v];
            if (id < 0 || id >= a->needles) continue;
            int32_t r = slot[id];
            if (r == NONE || got[r] > cap) continue;
            if (got[r] < cap) {
                if (got[r] == room[r]) { /* grow: double, up to cap */
                    Py_ssize_t want = room[r] ? room[r] * 2 : 16;
                    if (want > cap) want = cap;
                    int64_t *grown = PyMem_RawRealloc(off[r], sizeof(int64_t) * (size_t)want);
                    if (!grown) { short_of_memory = 1; break; }
                    off[r] = grown; room[r] = want;
                }
                off[r][got[r]] = (int64_t)(i - a->length[id] + 1);
            }
            got[r]++;
        }
    }
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&view);
    if (short_of_memory) { PyErr_NoMemory(); goto done; }
    out = PyDict_New();
    for (Py_ssize_t r = 0; out && r < rows; r++) {
        PyObject *key = PyLong_FromLong(who[r]), *val;
        if (got[r] > cap) { val = Py_None; Py_INCREF(val); }
        else val = PyBytes_FromStringAndSize(got[r] ? (const char *)off[r] : "", (Py_ssize_t)(got[r] * (Py_ssize_t)sizeof(int64_t)));
        if (!key || !val || PyDict_SetItem(out, key, val) < 0) Py_CLEAR(out);
        Py_XDECREF(key); Py_XDECREF(val);
    }
done:
    if (off) for (Py_ssize_t r = 0; r < rows; r++) PyMem_RawFree(off[r]);
    PyMem_RawFree(off); PyMem_RawFree(got); PyMem_RawFree(room); PyMem_RawFree(who); PyMem_RawFree(slot);
    Py_DECREF(seq);
    return out;
}

static PyObject *Automaton_reduce(Automaton *self, PyObject *unused) {
    (void)self; (void)unused;
    PyErr_SetString(PyExc_TypeError, "an Automaton is built from its needles, never pickled");
    return NULL;
}

static PyObject *get_nbytes(Automaton *self, void *c) { (void)c; return PyLong_FromSize_t(self->nbytes); }
static PyObject *get_nodes(Automaton *self, void *c) { (void)c; return PyLong_FromLong(self->nodes); }

static PyMethodDef Automaton_methods[] = {
    {"present", (PyCFunction)Automaton_present, METH_O, "The ids of the needles occurring in data, ascending."},
    {"positions", (PyCFunction)Automaton_positions, METH_VARARGS, "positions(data, ids, cap) -> {id: int64 offsets as bytes, or None past cap}."},
    {"__reduce__", (PyCFunction)Automaton_reduce, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}};

static PyGetSetDef Automaton_getset[] = {
    {"nbytes", (getter)get_nbytes, NULL, "The automaton's size in bytes.", NULL},
    {"nodes", (getter)get_nodes, NULL, "How many trie nodes.", NULL},
    {NULL, NULL, NULL, NULL, NULL}};

static PyTypeObject AutomatonType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "cordon_scanner._native._anchors.Automaton",
    .tp_basicsize = sizeof(Automaton),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "An Aho-Corasick automaton over distinct, non-empty byte needles.",
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)Automaton_init,
    .tp_dealloc = (destructor)Automaton_dealloc,
    .tp_methods = Automaton_methods,
    .tp_getset = Automaton_getset,
};


/* check_text(data, offsets, text, mode) -> bytes of int64: for each candidate offset (int64 bytes),
 * the length a text string matches there, or 0, as rule_engine.scan._Hunt._check_text reads it.
 * mode: 1 ascii, 2 wide, 4 nocase (ASCII folding on both sides), 8 xor. The order of the tries is
 * the Python one: nocase: ascii, then wide; else ascii, then wide, then (xor) xor-wide, then xor. */
#define M_ASCII 1
#define M_WIDE 2
#define M_NOCASE 4
#define M_XOR 8

static int64_t same(const uint8_t *d, Py_ssize_t n, Py_ssize_t at, const uint8_t *t, Py_ssize_t m, int fold) {
    if (n - at < m) return 0;
    for (Py_ssize_t i = 0; i < m; i++) {
        uint8_t a = d[at + i], b = t[i];
        if (fold) { a = LOWER[a]; b = LOWER[b]; }
        if (a != b) return 0;
    }
    return (int64_t)m;
}

static int64_t same_wide(const uint8_t *d, Py_ssize_t n, Py_ssize_t at, const uint8_t *t, Py_ssize_t m, int fold) {
    if (n - at < 2 * m) return 0;
    for (Py_ssize_t i = 0; i < m; i++) if (d[at + 2 * i + 1] != 0) return 0;
    for (Py_ssize_t i = 0; i < m; i++) {
        uint8_t a = d[at + 2 * i], b = t[i];
        if (fold) { a = LOWER[a]; b = LOWER[b]; }
        if (a != b) return 0;
    }
    return (int64_t)(2 * m);
}

static int64_t xored(const uint8_t *d, Py_ssize_t n, Py_ssize_t at, const uint8_t *t, Py_ssize_t m) {
    if (n - at < m || m == 0) return 0;
    uint8_t key = (uint8_t)(d[at] ^ t[0]);
    for (Py_ssize_t i = 0; i < m; i++) if (d[at + i] != (uint8_t)(t[i] ^ key)) return 0;
    return (int64_t)m;
}

static int64_t xored_wide(const uint8_t *d, Py_ssize_t n, Py_ssize_t at, const uint8_t *t, Py_ssize_t m) {
    if (n - at < 2 * m || m == 0) return 0;
    uint8_t key = (uint8_t)(d[at] ^ t[0]);
    for (Py_ssize_t i = 0; i < m; i++) {
        if (d[at + 2 * i] != (uint8_t)(t[i] ^ key) || (uint8_t)(d[at + 2 * i + 1] ^ key) != 0) return 0;
    }
    return (int64_t)(2 * m);
}

static int64_t text_at(const uint8_t *d, Py_ssize_t n, Py_ssize_t at, const uint8_t *t, Py_ssize_t m, long mode) {
    if (at < 0 || at >= n) return 0;
    int64_t length = 0;
    if (mode & M_NOCASE) {
        if (mode & M_ASCII) length = same(d, n, at, t, m, 1);
        if ((mode & M_WIDE) && length == 0) length = same_wide(d, n, at, t, m, 1);
        return length;
    }
    if (mode & M_ASCII) length = same(d, n, at, t, m, 0);
    if ((mode & M_WIDE) && length == 0) length = same_wide(d, n, at, t, m, 0);
    if ((mode & M_XOR) && length == 0) {
        if (mode & M_WIDE) length = xored_wide(d, n, at, t, m);
        if (length == 0) length = xored(d, n, at, t, m);
    }
    return length;
}

static PyObject *check_text(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer data, offsets, text; long mode;
    if (!PyArg_ParseTuple(args, "y*y*y*l", &data, &offsets, &text, &mode)) return NULL;
    PyObject *out = NULL;
    if (offsets.len % (Py_ssize_t)sizeof(int64_t) != 0) {
        PyErr_SetString(PyExc_ValueError, "offsets must be int64s"); goto done;
    }
    Py_ssize_t count = offsets.len / (Py_ssize_t)sizeof(int64_t);
    out = PyBytes_FromStringAndSize(NULL, offsets.len);
    if (!out) goto done;
    int64_t *lengths = (int64_t *)PyBytes_AS_STRING(out);
    const int64_t *at = (const int64_t *)offsets.buf;
    const uint8_t *d = data.buf, *t = text.buf; Py_ssize_t n = data.len, m = text.len;
    Py_BEGIN_ALLOW_THREADS
    for (Py_ssize_t i = 0; i < count; i++) {
        int64_t q = at[i];
        lengths[i] = (q < 0 || q >= (int64_t)n) ? 0 : text_at(d, n, (Py_ssize_t)q, t, m, mode);
    }
    Py_END_ALLOW_THREADS
done:
    PyBuffer_Release(&data); PyBuffer_Release(&offsets); PyBuffer_Release(&text);
    return out;
}


/* text_hits(data, owners, text, mode, flags, max_hits, fixed) -> (starts, lengths), int64 bytes by
 * start: one text string's matches from its anchors' occurrences, as rule_engine.scan's hunt finds
 * them. owners: a sequence of (starts, anchor length, back, order, fit length), starts a sequence
 * of ints (each owner's anchor occurrences). Each occurrence s with back <= s + length is an
 * event at end e = s + length starting at e - back; the events are taken in order of
 * (end, longer anchor first, higher order first, as listed), the text checked at each start
 * (or, flag 1 "fits", the owner's fit length taken), flag 2 "fullword" applied, and each start
 * recorded once (flag 4 "greedy": a later event replaces its length), stopping at the first new
 * start past max_hits. fixed >= 0: only that start counts. */
typedef struct { int64_t e0, nl, no, seq, at; int32_t owner; } Event;

/* seconds on a monotonic clock, for the match's time allowed */
#ifdef _WIN32
#include <windows.h>
static double now_seconds(void) {
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#else
#include <time.h>
static double now_seconds(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
#endif

static int cmp_event(const void *x, const void *y) {
    const Event *a = x, *b = y;
    if (a->e0 != b->e0) return a->e0 < b->e0 ? -1 : 1;
    if (a->nl != b->nl) return a->nl < b->nl ? -1 : 1;
    if (a->no != b->no) return a->no < b->no ? -1 : 1;
    return a->seq < b->seq ? -1 : (a->seq > b->seq);
}

static int cmp_i64(const void *x, const void *y) {
    int64_t a = *(const int64_t *)x, b = *(const int64_t *)y;
    return a < b ? -1 : (a > b);
}

static uint8_t ALNUM[256];

static int whole(const uint8_t *d, int64_t n, int64_t start, int64_t length, int wide) {
    if (wide) {
        if (start >= 2 && d[start - 1] == 0 && ALNUM[d[start - 2]]) return 0;
        int64_t end = start + length;
        return !(end + 1 < n && d[end + 1] == 0 && ALNUM[d[end]]);
    }
    if (start >= 1 && ALNUM[d[start - 1]]) return 0;
    return !(start + length < n && ALNUM[d[start + length]]);
}

static PyObject *text_hits(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer data, text; PyObject *owners; long mode, flags; Py_ssize_t max_hits, fixed; double left = -1.0;
    if (!PyArg_ParseTuple(args, "y*Oy*llnn|d", &data, &owners, &text, &mode, &flags, &max_hits, &fixed, &left)) return NULL;
    PyObject *result = NULL, *seq = NULL;
    Event *ev = NULL; int64_t *fit = NULL, *keys = NULL, *hs = NULL, *hl = NULL, *slot = NULL;
    seq = PySequence_Tuple(owners);
    if (!seq) goto done;
    Py_ssize_t no = PyTuple_GET_SIZE(seq), total = 0;
    if (max_hits < 0 || max_hits > ((Py_ssize_t)1 << 30)) { PyErr_SetString(PyExc_ValueError, "max_hits out of range"); goto done; }
    for (Py_ssize_t k = 0; k < no; k++) {
        PyObject *o = PyTuple_GET_ITEM(seq, k);
        if (!PyTuple_Check(o) || PyTuple_GET_SIZE(o) != 5 || !PyList_Check(PyTuple_GET_ITEM(o, 0))) {
            PyErr_SetString(PyExc_TypeError, "an owner is (list of starts, length, back, order, fit length)"); goto done;
        }
        Py_ssize_t m = PyList_GET_SIZE(PyTuple_GET_ITEM(o, 0));
        if (m > ((Py_ssize_t)1 << 28) - total) { PyErr_SetString(PyExc_MemoryError, "too many occurrences"); goto done; }
        total += m;
    }
    ev = PyMem_RawMalloc(sizeof(Event) * (size_t)(total ? total : 1));
    fit = PyMem_RawMalloc(sizeof(int64_t) * (size_t)(no ? no : 1));
    if (!ev || !fit) { PyErr_NoMemory(); goto done; }
    Py_ssize_t count = 0;
    for (Py_ssize_t k = 0; k < no; k++) {
        PyObject *o = PyTuple_GET_ITEM(seq, k), *starts = PyTuple_GET_ITEM(o, 0);
        long long length = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 1)), back = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 2));
        long long order = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 3)), f = PyLong_AsLongLong(PyTuple_GET_ITEM(o, 4));
        if (PyErr_Occurred()) goto done;
        fit[k] = f;
        Py_ssize_t m = PyList_GET_SIZE(starts);
        for (Py_ssize_t i = 0; i < m; i++) {
            PyObject *x = PyList_GET_ITEM(starts, i);
            if (!PyLong_CheckExact(x)) { PyErr_SetString(PyExc_TypeError, "a start is not an int"); goto done; }
            long long sv = PyLong_AsLongLong(x);
            if (sv == -1 && PyErr_Occurred()) goto done;
            if (back <= sv + length) {
                ev[count].e0 = sv + length; ev[count].nl = -length; ev[count].no = -order;
                ev[count].seq = count; ev[count].at = sv + length - back; ev[count].owner = (int32_t)k;
                count++;
            }
        }
    }
    Py_ssize_t cap = 1; /* the recorded starts: an open-addressed table of at least twice their bound */
    Py_ssize_t bound = count < max_hits + 1 ? count : max_hits + 1;
    while (cap < 2 * (bound ? bound : 1)) cap <<= 1;
    keys = PyMem_RawMalloc(sizeof(int64_t) * (size_t)cap);
    slot = PyMem_RawMalloc(sizeof(int64_t) * (size_t)cap);
    hs = PyMem_RawMalloc(sizeof(int64_t) * (size_t)(bound ? bound : 1));
    hl = PyMem_RawMalloc(sizeof(int64_t) * (size_t)(bound ? bound : 1));
    if (!keys || !slot || !hs || !hl) { PyErr_NoMemory(); goto done; }
    for (Py_ssize_t i = 0; i < cap; i++) keys[i] = -1;
    const uint8_t *d = data.buf, *t = text.buf; int64_t n = data.len, mt = text.len;
    Py_ssize_t held = 0;
    int late = 0;
    double began = now_seconds();
    Py_BEGIN_ALLOW_THREADS
    qsort(ev, (size_t)count, sizeof(Event), cmp_event);
    for (Py_ssize_t i = 0; i < count; i++) {
        /* the time allowed, read where the hunt reads it: the first event and every 4096th */
        if (i % 4096 == 0 && left >= 0.0 && now_seconds() - began >= left) { late = 1; break; }
        int64_t at = ev[i].at;
        if (at >= n) continue;
        if (fixed >= 0 && at != fixed) continue;
        int64_t length = (flags & 1) ? fit[ev[i].owner] : text_at(d, n, (Py_ssize_t)at, t, mt, mode);
        if (length == 0) continue;
        if ((flags & 2) && !whole(d, n, at, length, length == 2 * mt)) continue;
        uint64_t h = (uint64_t)at * 0x9E3779B97F4A7C15ULL;
        Py_ssize_t j = (Py_ssize_t)(h & (uint64_t)(cap - 1));
        while (keys[j] != -1 && keys[j] != at) j = (j + 1) & (cap - 1);
        if (keys[j] == at) { if (flags & 4) hl[slot[j]] = length; continue; }
        if (held >= max_hits) break; /* full: no event after this one is read */
        keys[j] = at; slot[j] = held; hs[held] = at; hl[held] = length; held++;
    }
    Py_END_ALLOW_THREADS
    if (late) { PyErr_SetString(PyExc_TimeoutError, "matching took longer than the time allowed"); goto done; }
    { /* by start */
        int64_t *pairs = PyMem_RawMalloc(sizeof(int64_t) * 2 * (size_t)(held ? held : 1));
        if (!pairs) { PyErr_NoMemory(); goto done; }
        for (Py_ssize_t i = 0; i < held; i++) { pairs[2 * i] = hs[i]; pairs[2 * i + 1] = hl[i]; }
        qsort(pairs, (size_t)held, 2 * sizeof(int64_t), cmp_i64);
        for (Py_ssize_t i = 0; i < held; i++) { hs[i] = pairs[2 * i]; hl[i] = pairs[2 * i + 1]; }
        PyMem_RawFree(pairs);
    }
    result = Py_BuildValue("(y#y#)", (const char *)hs, (Py_ssize_t)(held * 8), (const char *)hl, (Py_ssize_t)(held * 8));
done:
    PyMem_RawFree(ev); PyMem_RawFree(fit); PyMem_RawFree(keys); PyMem_RawFree(slot); PyMem_RawFree(hs); PyMem_RawFree(hl);
    Py_XDECREF(seq);
    PyBuffer_Release(&data); PyBuffer_Release(&text);
    return result;
}

static PyMethodDef module_methods[] = {
    {"check_text", check_text, METH_VARARGS, "check_text(data, offsets, text, mode) -> int64 lengths."},
    {"text_hits", text_hits, METH_VARARGS, "text_hits(data, owners, text, mode, flags, max_hits, fixed) -> (starts, lengths)."},
    {NULL, NULL, 0, NULL}};

/* The GIL: this module keeps it (single-phase init, so a free-threaded build turns the GIL on
 * when it is imported). The automaton is immutable once built and a walk only reads it, but the
 * check-then-build in __init__ is not atomic without the GIL, so the module does not declare
 * itself free-threading safe. */
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_anchors", "Cordon's native anchor automaton and text check.", -1, module_methods, NULL, NULL, NULL, NULL};

PyMODINIT_FUNC PyInit__anchors(void) {
    for (int i = 0; i < 256; i++) {
        LOWER[i] = (uint8_t)(i >= 'A' && i <= 'Z' ? i + 32 : i);
        ALNUM[i] = (uint8_t)((i >= '0' && i <= '9') || (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z'));
    }
    if (PyType_Ready(&AutomatonType) < 0) return NULL;
    PyObject *m = PyModule_Create(&module);
    if (!m) return NULL;
    Py_INCREF(&AutomatonType);
    if (PyModule_AddObject(m, "Automaton", (PyObject *)&AutomatonType) < 0) { Py_DECREF(&AutomatonType); Py_DECREF(m); return NULL; }
    return m;
}
