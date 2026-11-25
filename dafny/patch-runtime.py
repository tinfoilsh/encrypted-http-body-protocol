#!/usr/bin/env python3
"""Patches the Dafny runtimes in the generated bundles so the SDKs can import
them as-is (run by generate.sh for Go and generate-events.sh for the rest;
the Go runtime lives in gen/go so importers of this module get the patched
copy, which a vendor/ directory or a replace directive would not give them).
Each patch replaces one verbatim
anchor of the runtime; an anchor that is neither in its original nor in its
patched form fails the run, so a Dafny upgrade cannot drop a patch silently.
Running it twice is a no-op.

  js: Seq.Concat and Seq.UnicodeFromString spread whole sequences into
      argument lists (RangeError above ~64K elements: a response frame or a
      request chunk reaches it) and Array#slice on the subclass takes the
      generic species path (~27x slower than a loop for 64 KiB).
  py: Seq holds every sequence as a list, so bytes cross the boundary as boxed
      ints and every slice or concat is a list<->bytes conversion (~300x per
      frame). For byte input the backing store stays `bytes`; indexing and
      iteration yield the same ints and equality with a list-backed byte
      sequence compares element-wise.
  go: every sequence element is an interface{} (16 bytes per byte, scanned by
      the GC), so a 128 KiB chunk costs 2 MiB of pointerful heap and the
      collector throttles the server. SeqOfBytes builds a []byte-backed
      ImmutableArray (GoByteArray) instead; slices share it, a concatenation
      of byte arrays flattens to bytes, and the places that assumed the boxed
      array accept any ImmutableArray.
  all: the generated printer (Go String, JS toString, Python __dafnystr__ and
      __repr__, Rust DafnyPrint and Debug, Java toString) of every constructor
      in SECRET_TYPES is replaced by "<Module>.<Datatype>.<Ctor>(<redacted>)",
      so a logged value cannot expose key material. Containers (State,
      Response.Body, SessionStore, HpkeOut...) print those fields through the
      constructor's own printer, so they are safe without a patch. Equality
      and hashing are untouched."""
import re
import sys
from pathlib import Path

# Constructors whose fields hold key material: the X25519 private scalar or
# shared secret, HKDF inputs and outputs, AEAD keys, the exporter secret and the
# Token. Declared in dafny/ehbp.dfy (EHBP), dafny/ehbp_events.dfy (EHBPEvents)
# and dafny/ehbp_server.dfy (EHBPServer, in the Go bundle only); a new
# secret-bearing constructor must be added here.
SECRET_TYPES = {
    "EHBP.Token.Token",  # exportedSecret
    "EHBPEvents.Event.RandomResult",  # the client's ephemeral scalar skE
    "EHBPEvents.Event.X25519Result",  # the DH shared secret
    "EHBPEvents.Event.HmacResult",  # HKDF prk and key blocks
    "EHBPEvents.Action.PublishToken",  # exportedSecret
    "EHBPEvents.Action.X25519",  # scalar
    "EHBPEvents.Action.HmacSha256",  # key (salt or prk), data (ikm, previous block)
    "EHBPEvents.Action.AeadSeal",  # key
    "EHBPEvents.Action.AeadOpen",  # key
    "EHBPEvents.Job.JExtract",  # salt and ikm (shared secret)
    "EHBPEvents.Job.JExpand",  # prk, acc, prev
    "EHBPEvents.JobOut.Output",  # the HKDF output (secret, key, nonce, exporter secret)
    "EHBPEvents.Ctx.Ctx",  # key, baseNonce, exporterSecret
    "EHBPEvents.Hpke.HEnc",  # skE
    "EHBPEvents.Hpke.HSchedule",  # shared, secret, key, baseNonce, job
    "EHBPEvents.Response.AwaitKeys",  # prk, key, job
    "EHBPServer.SEvent.X25519Result",  # the DH shared secret
    "EHBPServer.SEvent.HmacResult",  # HKDF prk and key blocks
    "EHBPServer.SAction.X25519",  # the server's private key
    "EHBPServer.SAction.HmacSha256",  # key, data
    "EHBPServer.SAction.AeadSeal",  # key
    "EHBPServer.SAction.AeadOpen",  # key
    "EHBPServer.Phase.Deriving",  # secret, prk, key, job
    "EHBPServer.SState.SState",  # sk, ctx
}

# One rule per backend: (printer regex, redacted form), with {q} the escaped
# constructor name and {n} the plain one; the regex spans from the opening
# "<name>(" to the closing ")" of the generated printer.
REDACT = {
    # `data` is the type switch's binding; Go rejects it unused once every case is redacted.
    "go": (r'return "{q}" \+ "\(" \+ .*\)"', '_ = data\n\t\t\treturn "{n}(<redacted>)"'),
    "js": (r'"{q}" \+ "\(" \+ .*\)"', '"{n}(<redacted>)"'),
    "py": (r"return f'{q}\(.*\)'", "return '{n}(<redacted>)'\n    __repr__ = __dafnystr__"),
    "rs": (r'write!\(_formatter, "{q}\("\)\?;\n(?:.*\n)*?\s*write!\(_formatter, "\)"\)\?;\n',
           'write!(_formatter, "{n}(<redacted>)")?;\n'),
    "java": (r's\.append\("{q}"\);\n    s\.append\("\("\);\n(?:.*\n)*?    s\.append\("\)"\);\n',
             's.append("{n}(<redacted>)");\n'),
}

JS = [
    (
        """    static UnicodeFromString(s) {
      return new Seq(...([...s].map(c => new _dafny.CodePoint(c.codePointAt(0)))))
    }""",
        """    static UnicodeFromString(s) {
      const r = new Seq();
      for (const c of s) r.push(new _dafny.CodePoint(c.codePointAt(0)));
      return r;
    }""",
    ),
    (
        """        // ordinary concatenation
        let r = Seq.of(...a);
        r.push(...b);
        return r;""",
        """        // ordinary concatenation
        const r = new Seq(a.length + b.length);
        for (let i = 0; i < a.length; i++) r[i] = a[i];
        for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
        return r;""",
    ),
    (
        """    get UniqueElements() {
      return _dafny.Set.fromElements(...this);
    }""",
        """    get UniqueElements() {
      return _dafny.Set.fromElements(...this);
    }
    slice(start = 0, end = this.length) {
      const s = Number(start), r = new Seq(Number(end) - s);
      for (let i = 0; i < r.length; i++) r[i] = this[s + i];
      return r;
    }""",
    ),
]

PY = [
    (
        """    def flatten(self):
        l = []
        q = deque([self])
        while q:
            e = q.pop()
            if isinstance(e, list) or isinstance(e, Slice):
                l += e
            elif isinstance(e, Concat):
                q.append(e.r)
                q.append(e.l)
        return l""",
        """    def flatten(self):
        parts = []
        q = deque([self])
        while q:
            e = q.pop()
            if isinstance(e, Concat):
                q.append(e.r)
                q.append(e.l)
            else:
                parts.append(e)
        if any(isinstance(p, bytes) for p in parts):
            return b"".join(p if isinstance(p, bytes) else bytes(p) for p in parts)
        l = []
        for p in parts:
            l += p
        return l""",
    ),
    (
        """            self.elems = iterable if isinstance(iterable, Concat) else (list(iterable) if iterable is not None else [])""",
        """            self.elems = iterable if isinstance(iterable, Concat) else bytes(iterable) if isinstance(iterable, (bytes, bytearray)) else (list(iterable) if iterable is not None else [])""",
    ),
    (
        """        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            elements = self.elems if isinstance(self.elems, Slice) else self.Elements""",
        """        if isinstance(key, slice):
            if isinstance(self.elems, bytes):
                return Seq(self.elems[key], isStr=self.isStr)
            start, stop, step = key.indices(len(self))
            elements = self.elems if isinstance(self.elems, Slice) else self.Elements""",
    ),
    (
        """    def __eq__(self, other: object) -> bool:
        return self.Elements == other.Elements""",
        """    def __eq__(self, other: object) -> bool:
        a, b = self.Elements, other.Elements
        return a == b if type(a) is type(b) else list(a) == list(b)""",
    ),
]

GO = [
    (
        """	l := left.ToArray().(GoNativeArray).contents
	r := right.ToArray().(GoNativeArray).contents
	if IsEqualityComparable(l[0]) {""",
        """	lb, lok := left.ToArray().(GoByteArray)
	rb, rok := right.ToArray().(GoByteArray)
	if lok && rok {
		return slices.Equal(lb.contents[:index], rb.contents[:index])
	}
	if lok || rok {
		for i := uint32(0); i < index; i++ {
			if !AreEqual(left.Select(i), right.Select(i)) {
				return false
			}
		}
		return true
	}
	l := left.ToArray().(GoNativeArray).contents
	r := right.ToArray().(GoNativeArray).contents
	if IsEqualityComparable(l[0]) {""",
    ),
    (
        """func SeqOfBytes(values []byte) Sequence {
	arr := make([]interface{}, len(values))
	for i, v := range values {
		arr[i] = v
	}
	return SeqFromArray(arr, false)
}""",
        """func SeqOfBytes(values []byte) Sequence {
	result := New_ArraySequence_()
	result.Ctor__(GoByteArray{contents: slices.Clone(values)}, false)
	return result
}

// A GoByteArray is an ImmutableArray over a Go byte slice: a byte sequence
// built from native bytes stays unboxed (one byte per element, nothing for
// the GC to scan) and its slices share the storage.
type GoByteArray struct {
	contents []byte
}

func (array GoByteArray) Length() uint32 {
	return uint32(len(array.contents))
}

func (array GoByteArray) Select(i uint32) interface{} {
	return array.contents[i]
}

func (array GoByteArray) Subarray(lo uint32, hi uint32) ImmutableArray {
	return GoByteArray{contents: array.contents[lo:hi]}
}

// Bytes is the backing slice; the sequence is immutable, so do not write to it.
func (array GoByteArray) Bytes() []byte {
	return array.contents
}

func (array GoByteArray) String() string {
	return "dafny.GoByteArray"
}

// ConcatBytes flattens a sequence whose leaves are all byte arrays into one
// byte slice; false when some leaf is boxed.
func ConcatBytes(seq Sequence) ([]byte, bool) {
	return appendByteLeaves(make([]byte, 0, seq.Cardinality()), seq)
}

func appendByteLeaves(out []byte, seq Sequence) ([]byte, bool) {
	switch v := seq.(type) {
	case *LazySequence:
		return appendByteLeaves(out, v.Box().Get().(Sequence))
	case *ConcatSequence:
		if out, ok := appendByteLeaves(out, v.Left()); ok {
			return appendByteLeaves(out, v.Right())
		}
	case *ArraySequence:
		if arr, ok := v.Values().(GoByteArray); ok {
			return append(out, arr.contents...), true
		}
	}
	return nil, false
}""",
    ),
    (
        """func ToByteArray(x Sequence) []byte {
	nativeArray := x.ToArray().(GoNativeArray)
	arr := make([]byte, len(nativeArray.contents))
	for i, v := range nativeArray.contents {
		arr[i] = v.(byte)
	}
	return arr
}""",
        """func ToByteArray(x Sequence) []byte {
	array := x.ToArray()
	if byteArray, ok := array.(GoByteArray); ok {
		return slices.Clone(byteArray.contents)
	}
	nativeArray := array.(GoNativeArray)
	arr := make([]byte, len(nativeArray.contents))
	for i, v := range nativeArray.contents {
		arr[i] = v.(byte)
	}
	return arr
}""",
    ),
    (
        """func (array GoNativeArray) UpdateSubarray(i uint32, other ImmutableArray) {
	otherArray := other.(GoNativeArray)
	copy(array.contents[i:(i+otherArray.Length())], otherArray.contents)
}""",
        """func (array GoNativeArray) UpdateSubarray(i uint32, other ImmutableArray) {
	otherArray, ok := other.(GoNativeArray)
	if !ok {
		for j, n := uint32(0), other.Length(); j < n; j++ {
			array.contents[i+j] = other.Select(j)
		}
		return
	}
	copy(array.contents[i:(i+otherArray.Length())], otherArray.contents)
}""",
    ),
    (
        """func (CompanionStruct_NativeArray_) Copy(other ImmutableArray) NativeArray {
	otherArray := other.(GoNativeArray)
	contents := make([]interface{}, otherArray.Length())
	copy(contents, otherArray.contents)
	return GoNativeArray{
		contents: contents,
	}
}""",
        """func (CompanionStruct_NativeArray_) Copy(other ImmutableArray) NativeArray {
	array := GoNativeArray{contents: make([]interface{}, other.Length())}
	array.UpdateSubarray(0, other)
	return array
}""",
    ),
]

GO_FROM_DAFNY = [
    (
        """func (_this *ConcatSequence) ToArray() ImmutableArray {
	{
		var ret ImmutableArray = (ImmutableArray)(nil)
		_ = ret
		var _0_builder *Vector""",
        """func (_this *ConcatSequence) ToArray() ImmutableArray {
	{
		var ret ImmutableArray = (ImmutableArray)(nil)
		_ = ret
		if bytes, ok := ConcatBytes(_this); ok {
			ret = GoByteArray{contents: bytes}
			return ret
		}
		var _0_builder *Vector""",
    ),
]


def patch(path: Path, patches) -> None:
    text = path.read_text()
    for i, (old, new) in enumerate(patches):
        if text.count(new) == 1:
            continue
        if text.count(old) != 1:
            sys.exit(f"{path}: patch {i} anchor not found exactly once; the Dafny runtime changed, update patch-runtime.py")
        text = text.replace(old, new)
    path.write_text(text)


def redact(path: Path, backend: str, names) -> None:
    text = path.read_text()
    pattern, redacted = REDACT[backend]
    for n in names:
        new = redacted.format(n=n)
        if text.count(new) == 1:
            continue
        text, count = re.subn(pattern.format(q=re.escape(n)), lambda _: new, text)
        if count != 1 or text.count(new) != 1:
            sys.exit(f"{path}: printer of {n} not found exactly once; the Dafny backend changed, update patch-runtime.py")
    path.write_text(text)


def redact_all(here: Path) -> None:
    by_module = {}
    for n in SECRET_TYPES:
        by_module.setdefault(n.split(".")[0], []).append(n)
    client = {n for n in SECRET_TYPES if not n.startswith("EHBPServer.")}
    redact(here / "gen-events/js/ehbp.js", "js", client)
    redact(here / "gen-events/rs/src/ehbp_events.rs", "rs", client)
    for module, names in by_module.items():
        go = "gen/go" if module == "EHBP" else "gen-events/go"
        redact(here / f"{go}/{module}/{module}.go", "go", names)
        if module == "EHBPServer":
            continue  # Go only; the client bundles have no server module
        redact(here / f"gen-events/py/{module}.py", "py", names)
        for n in names:
            _, datatype, ctor = n.split(".")
            java = here / f"gen-events/java/{module}/{datatype}_{ctor}.java"
            redact(java if java.exists() else java.with_name(f"{datatype}.java"), "java", [n])


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    patch(here / "gen-events/js/ehbp.js", JS)
    patch(here / "gen-events/py/_dafny/__init__.py", PY)
    patch(here / "gen/go/dafny/dafny.go", GO)
    patch(here / "gen/go/dafny/dafnyFromDafny.go", GO_FROM_DAFNY)
    redact_all(here)
