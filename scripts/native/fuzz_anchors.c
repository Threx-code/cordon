/* libFuzzer harness for cordon_scanner._native._anchors, run under ASan and UBSan:
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
 *       -I$(python -c 'import sysconfig;print(sysconfig.get_paths()["include"])') \
 *       scripts/native/fuzz_anchors.c -L/usr/local/lib -lpython3.12 -o fuzz_anchors
 *   ASAN_OPTIONS=detect_leaks=0 ./fuzz_anchors -max_total_time=1800 corpus/
 *
 * The extension's source is compiled into the harness, and an embedded interpreter hosts it. Each
 * input is split: its first byte is the needle count (at most 64), each needle is a length byte and
 * that many bytes, a flag byte picks fold and the cap, and the rest is the data. Every call is
 * made: the build (which may refuse the needles), present, and positions over every id; the
 * results are checked against a naive search of the same data, so a wrong answer is a crash too.
 * check_text is held to naive_text at every offset and mode, and text_hits, over the needles'
 * occurrences as owners with flags, max_hits and fixed drawn from the data, to naive_hits.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../../src/cordon_scanner/_native/anchors.c"

static PyObject *Type;
static PyObject *Check;
static PyObject *Hits;

/* the text check written again, plainly, for the harness to hold check_text to */
static int64_t naive_text(const uint8_t *d, int64_t n, int64_t at, const uint8_t *t, int64_t m, long mode) {
    if (at < 0 || at >= n) return 0;
    int fold = (mode & 4) != 0;
    int64_t len = 0;
    for (int pass = 0; pass < 4 && len == 0; pass++) {
        int wide = pass == 1 || pass == 2, x = pass >= 2;
        if (pass == 0 && !(mode & 1)) continue;
        if (pass == 1 && !(mode & 2)) continue;
        if (pass == 2 && (!(mode & 8) || !(mode & 2) || fold)) continue;
        if (pass == 3 && (!(mode & 8) || fold)) continue;
        int64_t need = wide ? 2 * m : m;
        if (n - at < need || m == 0) continue;
        uint8_t key = x ? (uint8_t)(d[at] ^ t[0]) : 0;
        int ok = 1;
        for (int64_t i = 0; i < m && ok; i++) {
            uint8_t a = d[at + (wide ? 2 * i : i)], b = (uint8_t)(t[i] ^ key);
            if (fold) { a = LOWER[a]; b = LOWER[b]; }
            if (a != b) ok = 0;
            if (wide && (uint8_t)(d[at + 2 * i + 1] ^ key) != 0) ok = 0;
        }
        if (ok) len = need;
    }
    return len;
}

static int naive_count(const uint8_t *d, size_t n, const uint8_t *s, size_t m, int fold, int64_t *first, size_t keep) {
    int count = 0;
    for (size_t i = 0; m && i + m <= n; i++) {
        size_t k = 0;
        while (k < m && (fold ? LOWER[d[i + k]] : d[i + k]) == s[k]) k++;
        if (k == m) { if ((size_t)count < keep) first[count] = (int64_t)i; count++; }
    }
    return count;
}

/* text_hits written again, plainly: events in listed order, an insertion sort on (end, longer
 * anchor first, higher order first), a linear search for recorded starts, its own fullword */
typedef struct { int64_t occ[64]; int64_t m, length, back, order, fit; } Owner;

static int alnum(uint8_t c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

static int naive_whole(const uint8_t *d, int64_t n, int64_t at, int64_t len, int wide) {
    if (!wide) return !(at > 0 && alnum(d[at - 1])) && !(at + len < n && alnum(d[at + len]));
    int before = at >= 2 && d[at - 1] == 0 && alnum(d[at - 2]);
    int after = at + len + 1 < n && d[at + len + 1] == 0 && alnum(d[at + len]);
    return !before && !after;
}

static int64_t naive_hits(const uint8_t *d, int64_t n, const Owner *ow, int no, const uint8_t *t, int64_t mt,
                          long mode, long flags, int64_t max_hits, int64_t fixed, int64_t *hs, int64_t *hl) {
    int64_t ev[64 * 8][4]; /* end, -length, -order, owner */
    int64_t count = 0, held = 0;
    for (int k = 0; k < no; k++)
        for (int64_t i = 0; i < ow[k].m; i++) {
            int64_t s = ow[k].occ[i];
            if (ow[k].back > s + ow[k].length) continue;
            int64_t e[4] = {s + ow[k].length, -ow[k].length, -ow[k].order, k}, j = count++;
            while (j > 0 && (ev[j - 1][0] > e[0] || (ev[j - 1][0] == e[0] && (ev[j - 1][1] > e[1] ||
                   (ev[j - 1][1] == e[1] && ev[j - 1][2] > e[2]))))) { memcpy(ev[j], ev[j - 1], sizeof ev[j]); j--; }
            memcpy(ev[j], e, sizeof e);
        }
    for (int64_t i = 0; i < count; i++) {
        const Owner *o = &ow[ev[i][3]];
        int64_t at = ev[i][0] - o->back;
        if (at >= n || (fixed >= 0 && at != fixed)) continue;
        int64_t len = (flags & 1) ? o->fit : naive_text(d, n, at, t, mt, mode);
        if (len == 0 || ((flags & 2) && !naive_whole(d, n, at, len, len == 2 * mt))) continue;
        int64_t j = 0;
        while (j < held && hs[j] != at) j++;
        if (j < held) { if (flags & 4) hl[j] = len; continue; }
        if (held >= max_hits) break;
        hs[held] = at; hl[held] = len; held++;
    }
    for (int64_t i = 1; i < held; i++) /* by start */
        for (int64_t j = i; j > 0 && hs[j - 1] > hs[j]; j--) {
            int64_t a = hs[j]; hs[j] = hs[j - 1]; hs[j - 1] = a; a = hl[j]; hl[j] = hl[j - 1]; hl[j - 1] = a;
        }
    return held;
}

static void check_hits(const uint8_t *d, size_t dn, PyObject *needles, PyObject *data, int fold) {
    Py_ssize_t n = PyList_GET_SIZE(needles);
    if (n == 0) return;
    uint8_t c0 = dn ? d[0] : 0, c1 = dn > 1 ? d[1] : 0, c2 = dn > 2 ? d[dn - 1] : 0;
    Owner ow[8]; int no = 0;
    PyObject *owners = PyList_New(0);
    for (Py_ssize_t i = 0; i < n && no < 8; i++, no++) {
        PyObject *s = PyList_GET_ITEM(needles, i);
        Owner *o = &ow[no];
        o->length = PyBytes_GET_SIZE(s);
        o->m = naive_count(d, dn, (const uint8_t *)PyBytes_AS_STRING(s), (size_t)o->length, fold, o->occ, 64);
        if (o->m > 64) o->m = 64;
        o->back = (int64_t)((c0 >> (i % 4)) % (o->length + 3)); /* at, before or past the anchor */
        o->order = (int64_t)((c1 + i * 7) % 5);
        o->fit = o->length + (int64_t)(c2 % 3);
        PyObject *starts = PyList_New(0);
        for (int64_t k = 0; k < o->m; k++) { PyObject *x = PyLong_FromLongLong(o->occ[k]); PyList_Append(starts, x); Py_DECREF(x); }
        PyObject *row = Py_BuildValue("(OLLLL)", starts, o->length, o->back, o->order, o->fit);
        PyList_Append(owners, row); Py_DECREF(row); Py_DECREF(starts);
    }
    PyObject *text = PyList_GET_ITEM(needles, 0);
    const uint8_t *t = (const uint8_t *)PyBytes_AS_STRING(text); int64_t mt = PyBytes_GET_SIZE(text);
    long mode = (long)(c1 & 15), flags = (long)((c0 >> 4) & 7);
    int64_t max_hits = (int64_t)(c2 % 9), fixed = (c2 & 16) ? (int64_t)(c1 % (dn + 1)) : -1;
    PyObject *got = PyObject_CallFunction(Hits, "OOOllnn", data, owners, text, mode, flags, (Py_ssize_t)max_hits, (Py_ssize_t)fixed);
    if (!got || !PyTuple_Check(got) || PyTuple_GET_SIZE(got) != 2) abort();
    static int64_t hs[64 * 8], hl[64 * 8];
    int64_t held = naive_hits(d, (int64_t)dn, ow, no, t, mt, mode, flags, max_hits, fixed, hs, hl);
    PyObject *gs = PyTuple_GET_ITEM(got, 0), *gl = PyTuple_GET_ITEM(got, 1);
    if (PyBytes_GET_SIZE(gs) != held * 8 || PyBytes_GET_SIZE(gl) != held * 8) abort();
    if (memcmp(PyBytes_AS_STRING(gs), hs, (size_t)held * 8) || memcmp(PyBytes_AS_STRING(gl), hl, (size_t)held * 8)) abort();
    Py_DECREF(got); Py_DECREF(owners);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    PyImport_AppendInittab("_anchors", PyInit__anchors);
    Py_InitializeEx(0);
    PyObject *m = PyImport_ImportModule("_anchors");
    if (!m) { PyErr_Print(); abort(); }
    Type = PyObject_GetAttrString(m, "Automaton");
    Check = PyObject_GetAttrString(m, "check_text");
    Hits = PyObject_GetAttrString(m, "text_hits");
    if (!Type || !Check || !Hits) abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t size) {
    if (size < 2) return 0;
    size_t at = 0, want = buf[at++] % 65;
    PyObject *needles = PyList_New(0);
    for (size_t i = 0; i < want && at < size; i++) {
        size_t m = buf[at++] % 33;
        if (at + m > size) m = size - at;
        PyObject *b = PyBytes_FromStringAndSize((const char *)buf + at, (Py_ssize_t)m);
        at += m;
        int dup = PySequence_Contains(needles, b);
        if (dup == 0 && m > 0) PyList_Append(needles, b);
        Py_DECREF(b);
    }
    int fold = 0; Py_ssize_t cap = 8;
    if (at < size) { fold = buf[at] & 1; cap = (buf[at] >> 1) & 63; at++; }
    PyObject *data = PyBytes_FromStringAndSize((const char *)buf + at, (Py_ssize_t)(size - at));
    PyObject *kw = Py_BuildValue("{s:O}", "fold", fold ? Py_True : Py_False);
    PyObject *args = PyTuple_Pack(1, needles);
    PyObject *a = PyObject_Call(Type, args, kw);
    if (!a) { PyErr_Clear(); goto out; }
    PyObject *present = PyObject_CallMethod(a, "present", "O", data);
    if (!present) abort();
    Py_ssize_t n = PyList_GET_SIZE(needles);
    PyObject *ids = PyList_New(0);
    for (Py_ssize_t i = 0; i < n; i++) { PyObject *x = PyLong_FromSsize_t(i); PyList_Append(ids, x); Py_DECREF(x); }
    PyObject *pos = PyObject_CallMethod(a, "positions", "OOn", data, ids, cap);
    if (!pos) abort();
    const uint8_t *d = (const uint8_t *)PyBytes_AS_STRING(data); size_t dn = (size_t)PyBytes_GET_SIZE(data);
    int64_t first[64];
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *s = PyList_GET_ITEM(needles, i);
        int count = naive_count(d, dn, (const uint8_t *)PyBytes_AS_STRING(s), (size_t)PyBytes_GET_SIZE(s), fold, first, 64);
        PyObject *key = PyLong_FromSsize_t(i);
        int in_present = PySequence_Contains(present, key);
        if ((count > 0) != (in_present == 1)) abort();
        PyObject *got = PyDict_GetItem(pos, key);
        Py_DECREF(key);
        if (!got) abort();
        if (count > cap) { if (got != Py_None) abort(); continue; }
        if (got == Py_None || PyBytes_GET_SIZE(got) != (Py_ssize_t)(count * 8)) abort();
        const int64_t *o = (const int64_t *)PyBytes_AS_STRING(got);
        for (int k = 0; k < count && k < 64; k++) if (o[k] != first[k]) abort();
    }
    Py_DECREF(pos); Py_DECREF(ids); Py_DECREF(present); Py_DECREF(a);
    {   /* the text check: the first needle as text, every offset from -2 to past the end */
        if (n > 0) {
            PyObject *text = PyList_GET_ITEM(needles, 0);
            int64_t count = (int64_t)dn + 4, *offs = malloc(sizeof(int64_t) * (size_t)count);
            if (!offs) abort();
            for (int64_t i = 0; i < count; i++) offs[i] = i - 2;
            for (long mode = 0; mode < 16; mode++) {
                PyObject *ob = PyBytes_FromStringAndSize((const char *)offs, (Py_ssize_t)(count * 8));
                PyObject *got = PyObject_CallFunction(Check, "OOOl", data, ob, text, mode);
                if (!got || PyBytes_GET_SIZE(got) != count * 8) abort();
                const int64_t *g = (const int64_t *)PyBytes_AS_STRING(got);
                for (int64_t i = 0; i < count; i++) {
                    int64_t want = naive_text(d, (int64_t)dn, offs[i], (const uint8_t *)PyBytes_AS_STRING(text), PyBytes_GET_SIZE(text), mode);
                    if (g[i] != want) abort();
                }
                Py_DECREF(got); Py_DECREF(ob);
            }
            free(offs);
        }
    }
    check_hits((const uint8_t *)PyBytes_AS_STRING(data), (size_t)PyBytes_GET_SIZE(data), needles, data, fold);
out:
    Py_DECREF(args); Py_DECREF(kw); Py_DECREF(data); Py_DECREF(needles);
    return 0;
}
