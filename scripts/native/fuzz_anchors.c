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
 * occurrences as owners with flags, max_hits and fixed drawn from the data, to naive_hits; and
 * hex_hits, with forward and backward layouts drawn from the input, to naive_hex (a search over
 * each layout from its entry: the shortest match forwards, every start reached backwards).
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../../src/cordon_scanner/_native/anchors.c"

static PyObject *Type;
static PyObject *Check;
static PyObject *Hits;
static PyObject *HexHits;

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

/* hex_hits checked: a layout of at most 8 instructions drawn from the input, both ways */
#define HX_REACH 64
typedef struct { int64_t op[9][3]; int n; } Layout;

static void draw_layout(Layout *l, const uint8_t *b, size_t nb) {
    l->n = 0;
    for (size_t i = 0; i + 1 < nb && l->n < 8; i += 2) {
        uint8_t k = b[i] % 6, v = b[i + 1];
        int64_t *o = l->op[l->n++];
        o[1] = o[2] = 0;
        if (k == 0) { o[0] = L_BYTE; o[1] = v % 4 + 'a'; }
        else if (k == 1) { o[0] = L_NOT_BYTE; o[1] = v % 4 + 'a'; }
        else if (k == 2) { o[0] = L_MASK; o[1] = 0xF0; o[2] = 0x60; }
        else if (k == 3) { o[0] = L_NOT_MASK; o[1] = 0x0F; o[2] = v & 0x0F; }
        else if (k == 4) { o[0] = L_ANY; }
        else if (l->n < 8) { o[0] = L_SKIP; o[1] = v % 3; o[2] = o[1] + v / 64; }
        else { o[0] = L_ANY; }
        if (o[0] == L_SKIP && l->n == 8) o[0] = L_ANY;
    }
    if (l->n > 0 && l->op[l->n - 1][0] == L_SKIP) l->op[l->n - 1][0] = L_ANY;
    l->op[l->n][0] = L_DONE; l->op[l->n][1] = l->op[l->n][2] = 0; l->n++;
}

/* forwards: the shortest length from (pc, done), -1 if none; as Lanes reads (reach limits) */
static int64_t hx_fwd(const Layout *l, int pc, int64_t done, const uint8_t *d, int64_t at, int64_t reach) {
    const int64_t *o = l->op[pc];
    if (o[0] == L_DONE) return done;
    if (o[0] == L_SKIP) {
        if (done + o[1] >= reach) return -1;
        int64_t best = -1;
        for (int64_t j = o[1]; j <= o[2]; j++) {
            if (j > o[1] && done + j >= reach) break;
            int64_t r = hx_fwd(l, pc + 1, done + j, d, at, reach);
            if (r >= 0 && (best < 0 || r < best)) best = r;
        }
        return best;
    }
    if (done >= reach) return -1;
    uint8_t c = d[at + done]; int ok;
    if (o[0] == L_ANY) ok = 1; else if (o[0] == L_BYTE) ok = c == o[1]; else if (o[0] == L_NOT_BYTE) ok = c != o[1];
    else if (o[0] == L_MASK) ok = (c & o[1]) == o[2]; else ok = (c & o[1]) != o[2];
    return ok ? hx_fwd(l, pc + 1, done + 1, d, at, reach) : -1;
}

/* backwards: marks each done reached at DONE (a start at - done) */
static void hx_back(const Layout *l, int pc, int64_t done, const uint8_t *d, int64_t at, int64_t reach, uint8_t *got) {
    const int64_t *o = l->op[pc];
    if (o[0] == L_DONE) { got[done < reach ? done : reach] = 1; return; }
    if (o[0] == L_SKIP) {
        if (done + o[1] >= reach) return;
        for (int64_t j = o[1]; j <= o[2]; j++) {
            if (j > o[1] && done + j >= reach) break;
            hx_back(l, pc + 1, done + j, d, at, reach, got);
        }
        return;
    }
    if (done >= reach) return;
    uint8_t c = d[at - 1 - done]; int ok;
    if (o[0] == L_ANY) ok = 1; else if (o[0] == L_BYTE) ok = c == o[1]; else if (o[0] == L_NOT_BYTE) ok = c != o[1];
    else if (o[0] == L_MASK) ok = (c & o[1]) == o[2]; else ok = (c & o[1]) != o[2];
    if (ok) hx_back(l, pc + 1, done + 1, d, at, reach, got);
}

static PyObject *layout_bytes(const Layout *l) {
    return PyBytes_FromStringAndSize((const char *)l->op, (Py_ssize_t)(l->n * 3 * 8));
}

static void check_hex(const uint8_t *buf, size_t size, const uint8_t *d, size_t dn, PyObject *needles, PyObject *data) {
    Py_ssize_t n = PyList_GET_SIZE(needles);
    if (n == 0 || size < 4) return;
    Layout fw, bw;
    size_t half = size / 2 < 16 ? size / 2 : 16;
    draw_layout(&fw, buf, half); draw_layout(&bw, buf + half, half);
    int64_t occ[64], backs[8], ends[64 * 8], start_len[4096]; int no = 0;
    PyObject *owners = PyList_New(0);
    int64_t evn = 0, ev[64 * 8][4];
    for (Py_ssize_t i = 0; i < n && no < 8; i++, no++) {
        PyObject *s = PyList_GET_ITEM(needles, i);
        int64_t len = PyBytes_GET_SIZE(s);
        int m = naive_count(d, dn, (const uint8_t *)PyBytes_AS_STRING(s), (size_t)len, 0, occ, 64);
        if (m > 64) m = 64;
        backs[no] = len + (int64_t)(buf[i % size] % 3);
        int fe = buf[(i + 1) % size] & 1 ? 0 : -1, be = buf[(i + 2) % size] & 2 ? 0 : -1;
        if (i == 0) fe = 0;
        PyObject *starts = PyList_New(0);
        for (int k = 0; k < m; k++) {
            PyObject *x = PyLong_FromLongLong(occ[k]); PyList_Append(starts, x); Py_DECREF(x);
            if (backs[no] > occ[k] + len) continue;
            int64_t e[4] = {occ[k] + len, -len, -(int64_t)i, (int64_t)no * 4 + (fe == 0) * 2 + (be == 0)}, j = evn++;
            while (j > 0 && (ev[j - 1][0] > e[0] || (ev[j - 1][0] == e[0] && (ev[j - 1][1] > e[1] ||
                   (ev[j - 1][1] == e[1] && ev[j - 1][2] > e[2]))))) { memcpy(ev[j], ev[j - 1], sizeof ev[j]); j--; }
            memcpy(ev[j], e, sizeof e);
            ends[j] = 0;
        }
        PyObject *row = Py_BuildValue("(OLLLii)", starts, len, backs[no], (long long)i, fe, be);
        PyList_Append(owners, row); Py_DECREF(row); Py_DECREF(starts);
    }
    (void)ends;
    PyObject *fo = layout_bytes(&fw), *bo = layout_bytes(&bw);
    PyObject *got = PyObject_CallFunction(HexHits, "OOOOnlnn", data, owners, fo, bo, (Py_ssize_t)HX_REACH, 0L, (Py_ssize_t)4096, (Py_ssize_t)-1);
    if (!got) { PyErr_Print(); abort(); }
    for (size_t i = 0; i < 4096; i++) start_len[i] = -1;
    for (int64_t i = 0; i < evn; i++) {
        int k = (int)(ev[i][3] / 4), fe = (ev[i][3] & 2) != 0, be = (ev[i][3] & 1) != 0;
        if (!fe) continue;
        int64_t len = -ev[i][1], at = ev[i][0] - backs[k];
        (void)len;
        if (at >= (int64_t)dn) continue;
        int64_t reach = (int64_t)dn - at < HX_REACH ? (int64_t)dn - at : HX_REACH;
        int64_t length = hx_fwd(&fw, 0, 0, d, at, reach);
        if (length < 0) continue;
        if (be) {
            uint8_t reached[HX_REACH + 1]; memset(reached, 0, sizeof reached);
            int64_t rb = at < HX_REACH ? at : HX_REACH;
            hx_back(&bw, 0, 0, d, at, rb, reached);
            for (int64_t dd = 0; dd <= rb; dd++)
                if (reached[dd] && at - dd >= 0 && at - dd < 4096 && start_len[at - dd] < 0) start_len[at - dd] = dd + length;
        } else if (at < 4096 && start_len[at] < 0) start_len[at] = length;
    }
    PyObject *gs = PyTuple_GET_ITEM(got, 0), *gl = PyTuple_GET_ITEM(got, 1);
    const int64_t *s0 = (const int64_t *)PyBytes_AS_STRING(gs), *l0 = (const int64_t *)PyBytes_AS_STRING(gl);
    Py_ssize_t held = PyBytes_GET_SIZE(gs) / 8, w = 0;
    for (int64_t st = 0; st < 4096; st++) {
        if (start_len[st] < 0) continue;
        if (w >= held || s0[w] != st || l0[w] != start_len[st]) abort();
        w++;
    }
    if (w != held) abort();
    Py_DECREF(got); Py_DECREF(fo); Py_DECREF(bo); Py_DECREF(owners);
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
    HexHits = PyObject_GetAttrString(m, "hex_hits");
    if (!Type || !Check || !Hits || !HexHits) abort();
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
    if (PyBytes_GET_SIZE(data) < 4000)
        check_hex(buf, size, (const uint8_t *)PyBytes_AS_STRING(data), (size_t)PyBytes_GET_SIZE(data), needles, data);
out:
    Py_DECREF(args); Py_DECREF(kw); Py_DECREF(data); Py_DECREF(needles);
    return 0;
}
