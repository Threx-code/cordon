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
    int fold;
    size_t nbytes;
} Automaton;

static uint8_t LOWER[256];

static void free_arrays(Automaton *a) {
    PyMem_RawFree(a->first); PyMem_RawFree(a->count); PyMem_RawFree(a->ebyte);
    PyMem_RawFree(a->target); PyMem_RawFree(a->fail); PyMem_RawFree(a->out);
    PyMem_RawFree(a->term); PyMem_RawFree(a->length);
    a->first = a->count = a->target = a->fail = a->out = a->term = a->length = NULL;
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

/* The state after reading `c` in `state`. */
static inline int32_t step(const Automaton *a, int32_t state, uint8_t c) {
    for (;;) {
        int32_t t = child(a, state, c);
        if (t != NONE) return t;
        if (state == 0) return 0;
        state = a->fail[state];
    }
}

/* Build: needles sorted (so each new branch is the last child at its node), a trie in
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
    a->nbytes = nn * (sizeof(int32_t) * 5) + ne * (1 + sizeof(int32_t)) + (size_t)n * sizeof(int32_t) + sizeof(a->root);
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
 * as too many and no longer collected. */
static PyObject *Automaton_positions(Automaton *self, PyObject *args) {
    PyObject *data, *ids; Py_ssize_t cap;
    if (!PyArg_ParseTuple(args, "OOn", &data, &ids, &cap)) return NULL;
    if (!self->first) { PyErr_SetString(PyExc_RuntimeError, "not built"); return NULL; }
    if (cap < 0 || cap > (Py_ssize_t)1 << 24) { PyErr_SetString(PyExc_ValueError, "cap out of range"); return NULL; }
    size_t nn = (size_t)(self->needles ? self->needles : 1);
    int32_t *slot = PyMem_RawMalloc(sizeof(int32_t) * nn); /* needle -> its row, or NONE */
    if (!slot) return PyErr_NoMemory();
    for (size_t i = 0; i < nn; i++) slot[i] = NONE;
    PyObject *seq = PySequence_Fast(ids, "ids must be a sequence");
    if (!seq) { PyMem_RawFree(slot); return NULL; }
    Py_ssize_t rows = PySequence_Fast_GET_SIZE(seq);
    if (rows > (Py_ssize_t)self->needles) { /* distinct ids in range: never more rows than needles */
        PyErr_SetString(PyExc_ValueError, "more ids than needles"); PyMem_RawFree(slot); Py_DECREF(seq); return NULL;
    }
    int64_t **off = PyMem_RawCalloc((size_t)(rows ? rows : 1), sizeof(int64_t *));
    Py_ssize_t *got = PyMem_RawCalloc((size_t)(rows ? rows : 1), sizeof(Py_ssize_t));
    int32_t *who = PyMem_RawMalloc(sizeof(int32_t) * (size_t)(rows ? rows : 1));
    if (!off || !got || !who) { PyErr_NoMemory(); goto done_early; }
    for (Py_ssize_t r = 0; r < rows; r++) {
        long id = PyLong_AsLong(PySequence_Fast_GET_ITEM(seq, r));
        if (id == -1 && PyErr_Occurred()) goto done_early;
        if (id < 0 || id >= self->needles) { PyErr_SetString(PyExc_IndexError, "a needle id out of range"); goto done_early; }
        if (slot[id] != NONE) { PyErr_SetString(PyExc_ValueError, "a needle id asked twice"); goto done_early; }
        slot[id] = (int32_t)r; who[r] = (int32_t)id;
        off[r] = PyMem_RawMalloc(sizeof(int64_t) * (size_t)(cap + 1));
        if (!off[r]) { PyErr_NoMemory(); goto done_early; }
    }
    Py_buffer view;
    if (PyObject_GetBuffer(data, &view, PyBUF_SIMPLE) < 0) goto done_early;
    const uint8_t *d = view.buf; Py_ssize_t len = view.len; const Automaton *a = self; int fold = self->fold;
    Py_BEGIN_ALLOW_THREADS
    int32_t s = 0;
    for (Py_ssize_t i = 0; i < len; i++) {
        uint8_t c = fold ? LOWER[d[i]] : d[i];
        s = step(a, s, c);
        for (int32_t v = a->term[s] != NONE ? s : a->out[s]; v != NONE; v = a->out[v]) {
            int32_t id = a->term[v];
            if (id < 0 || id >= a->needles) continue;
            int32_t r = slot[id];
            if (r == NONE || got[r] > cap) continue;
            if (got[r] < cap + 1) off[r][got[r]] = (int64_t)(i - a->length[id] + 1);
            got[r]++;
        }
    }
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&view);
    PyObject *out = PyDict_New();
    for (Py_ssize_t r = 0; out && r < rows; r++) {
        PyObject *key = PyLong_FromLong(who[r]), *val;
        if (got[r] > cap) { val = Py_None; Py_INCREF(val); }
        else val = PyBytes_FromStringAndSize((const char *)off[r], (Py_ssize_t)(got[r] * (Py_ssize_t)sizeof(int64_t)));
        if (!key || !val || PyDict_SetItem(out, key, val) < 0) Py_CLEAR(out);
        Py_XDECREF(key); Py_XDECREF(val);
    }
    for (Py_ssize_t r = 0; r < rows; r++) PyMem_RawFree(off[r]);
    PyMem_RawFree(off); PyMem_RawFree(got); PyMem_RawFree(who); PyMem_RawFree(slot); Py_DECREF(seq);
    return out;
done_early:
    if (off) for (Py_ssize_t r = 0; r < rows; r++) PyMem_RawFree(off[r]);
    PyMem_RawFree(off); PyMem_RawFree(got); PyMem_RawFree(who); PyMem_RawFree(slot); Py_DECREF(seq);
    return NULL;
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

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_anchors", "Cordon's native anchor automaton.", -1, NULL, NULL, NULL, NULL, NULL};

PyMODINIT_FUNC PyInit__anchors(void) {
    for (int i = 0; i < 256; i++) LOWER[i] = (uint8_t)(i >= 'A' && i <= 'Z' ? i + 32 : i);
    if (PyType_Ready(&AutomatonType) < 0) return NULL;
    PyObject *m = PyModule_Create(&module);
    if (!m) return NULL;
    Py_INCREF(&AutomatonType);
    if (PyModule_AddObject(m, "Automaton", (PyObject *)&AutomatonType) < 0) { Py_DECREF(&AutomatonType); Py_DECREF(m); return NULL; }
    return m;
}
