// Dafny program ehbp_events.dfy compiled into JavaScript
// Copyright by the contributors to the Dafny Project
// SPDX-License-Identifier: MIT

const BigNumber = require('bignumber.js');
BigNumber.config({ MODULO_MODE: BigNumber.EUCLID })
let _dafny = (function() {
  let $module = {};
  $module.areEqual = function(a, b) {
    if (typeof a === 'string' && b instanceof _dafny.Seq) {
      // Seq.equals(string) works as expected,
      // and the catch-all else block handles that direction.
      // But the opposite direction doesn't work; handle it here.
      return b.equals(a);
    } else if (typeof a === 'number' && BigNumber.isBigNumber(b)) {
      // This conditional would be correct even without the `typeof a` part,
      // but in most cases it's probably faster to short-circuit on a `typeof`
      // than to call `isBigNumber`. (But it remains to properly test this.)
      return b.isEqualTo(a);
    } else if (typeof a !== 'object' || a === null || b === null) {
      return a === b;
    } else if (BigNumber.isBigNumber(a)) {
      return a.isEqualTo(b);
    } else if (a._tname !== undefined || (Array.isArray(a) && a.constructor.name == "Array")) {
      return a === b;  // pointer equality
    } else {
      return a.equals(b);  // value-type equality
    }
  }
  $module.toString = function(a) {
    if (a === null) {
      return "null";
    } else if (typeof a === "number") {
      return a.toFixed();
    } else if (BigNumber.isBigNumber(a)) {
      return a.toFixed();
    } else if (a._tname !== undefined) {
      return a._tname;
    } else {
      return a.toString();
    }
  }
  $module.escapeCharacter = function(cp) {
    let s = String.fromCodePoint(cp.value)
    switch (s) {
      case '\n': return "\\n";
      case '\r': return "\\r";
      case '\t': return "\\t";
      case '\0': return "\\0";
      case '\'': return "\\'";
      case '\"': return "\\\"";
      case '\\': return "\\\\";
      default: return s;
    };
  }
  $module.NewObject = function() {
    return { _tname: "object" };
  }
  $module.InstanceOfTrait = function(obj, trait) {
    return obj._parentTraits !== undefined && obj._parentTraits().includes(trait);
  }
  $module.Rtd_bool = class {
    static get Default() { return false; }
  }
  $module.Rtd_char = class {
    static get Default() { return 'D'; }  // See CharType.DefaultValue in Dafny source code
  }
  $module.Rtd_codepoint = class {
    static get Default() { return new _dafny.CodePoint('D'.codePointAt(0)); }
  }
  $module.Rtd_int = class {
    static get Default() { return BigNumber(0); }
  }
  $module.Rtd_number = class {
    static get Default() { return 0; }
  }
  $module.Rtd_ref = class {
    static get Default() { return null; }
  }
  $module.Rtd_array = class {
    static get Default() { return []; }
  }
  $module.ZERO = new BigNumber(0);
  $module.ONE = new BigNumber(1);
  $module.NUMBER_LIMIT = new BigNumber(0x20).multipliedBy(0x1000000000000);  // 2^53
  $module.Tuple = class Tuple extends Array {
    constructor(...elems) {
      super(...elems);
    }
    toString() {
      return "(" + arrayElementsToString(this) + ")";
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      for (let i = 0; i < this.length; i++) {
        if (!_dafny.areEqual(this[i], other[i])) {
          return false;
        }
      }
      return true;
    }
    static Default(...values) {
      return Tuple.of(...values);
    }
    static Rtd(...rtdArgs) {
      return {
        Default: Tuple.from(rtdArgs, rtd => rtd.Default)
      };
    }
  }
  $module.Set = class Set extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return Set.Empty;
    }
    toString() {
      return "{" + arrayElementsToString(this) + "}";
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new Set();
      }
      return this._empty;
    }
    static fromElements(...elmts) {
      let s = new Set();
      for (let k of elmts) {
        s.add(k);
      }
      return s;
    }
    contains(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i], k)) {
          return true;
        }
      }
      return false;
    }
    add(k) {  // mutates the Set; use only during construction
      if (!this.contains(k)) {
        this.push(k);
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let e of this) {
        if (!other.contains(e)) {
          return false;
        }
      }
      return true;
    }
    get Elements() {
      return this;
    }
    Union(that) {
      if (this.length === 0) {
        return that;
      } else if (that.length === 0) {
        return this;
      } else {
        let s = Set.of(...this);
        for (let k of that) {
          s.add(k);
        }
        return s;
      }
    }
    Intersect(that) {
      if (this.length === 0) {
        return this;
      } else if (that.length === 0) {
        return that;
      } else {
        let s = new Set();
        for (let k of this) {
          if (that.contains(k)) {
            s.push(k);
          }
        }
        return s;
      }
    }
    Difference(that) {
      if (this.length == 0 || that.length == 0) {
        return this;
      } else {
        let s = new Set();
        for (let k of this) {
          if (!that.contains(k)) {
            s.push(k);
          }
        }
        return s;
      }
    }
    IsDisjointFrom(that) {
      for (let k of this) {
        if (that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    IsSubsetOf(that) {
      if (that.length < this.length) {
        return false;
      }
      for (let k of this) {
        if (!that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    IsProperSubsetOf(that) {
      if (that.length <= this.length) {
        return false;
      }
      for (let k of this) {
        if (!that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    get AllSubsets() {
      return this.AllSubsets_();
    }
    *AllSubsets_() {
      // Start by putting all set elements into a list, but don't include null
      let elmts = Array.of(...this);
      let n = elmts.length;
      let which = new Array(n);
      which.fill(false);
      let a = [];
      while (true) {
        yield Set.of(...a);
        // "add 1" to "which", as if doing a carry chain.  For every digit changed, change the membership of the corresponding element in "a".
        let i = 0;
        for (; i < n && which[i]; i++) {
          which[i] = false;
          // remove elmts[i] from a
          for (let j = 0; j < a.length; j++) {
            if (_dafny.areEqual(a[j], elmts[i])) {
              // move the last element of a into slot j
              a[j] = a[-1];
              a.pop();
              break;
            }
          }
        }
        if (i === n) {
          // we have cycled through all the subsets
          break;
        }
        which[i] = true;
        a.push(elmts[i]);
      }
    }
  }
  $module.MultiSet = class MultiSet extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return MultiSet.Empty;
    }
    toString() {
      let s = "multiset{";
      let sep = "";
      for (let e of this) {
        let [k, n] = e;
        let ks = _dafny.toString(k);
        while (!n.isZero()) {
          n = n.minus(1);
          s += sep + ks;
          sep = ", ";
        }
      }
      s += "}";
      return s;
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new MultiSet();
      }
      return this._empty;
    }
    static fromElements(...elmts) {
      let s = new MultiSet();
      for (let e of elmts) {
        s.add(e, _dafny.ONE);
      }
      return s;
    }
    static FromArray(arr) {
      let s = new MultiSet();
      for (let e of arr) {
        s.add(e, _dafny.ONE);
      }
      return s;
    }
    cardinality() {
      let c = _dafny.ZERO;
      for (let e of this) {
        let [k, n] = e;
        c = c.plus(n);
      }
      return c;
    }
    clone() {
      let s = new MultiSet();
      for (let e of this) {
        let [k, n] = e;
        s.push([k, n]);  // make sure to create a new array [k, n] here
      }
      return s;
    }
    findIndex(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i][0], k)) {
          return i;
        }
      }
      return this.length;
    }
    get(k) {
      let i = this.findIndex(k);
      if (i === this.length) {
        return _dafny.ZERO;
      } else {
        return this[i][1];
      }
    }
    contains(k) {
      return !this.get(k).isZero();
    }
    add(k, n) {
      let i = this.findIndex(k);
      if (i === this.length) {
        this.push([k, n]);
      } else {
        let m = this[i][1];
        this[i] = [k, m.plus(n)];
      }
    }
    update(k, n) {
      let i = this.findIndex(k);
      if (i < this.length && this[i][1].isEqualTo(n)) {
        return this;
      } else if (i === this.length && n.isZero()) {
        return this;
      } else if (i === this.length) {
        let m = this.slice();
        m.push([k, n]);
        return m;
      } else {
        let m = this.slice();
        m[i] = [k, n];
        return m;
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      for (let e of this) {
        let [k, n] = e;
        let m = other.get(k);
        if (!n.isEqualTo(m)) {
          return false;
        }
      }
      return this.cardinality().isEqualTo(other.cardinality());
    }
    get Elements() {
      return this.Elements_();
    }
    *Elements_() {
      for (let i = 0; i < this.length; i++) {
        let [k, n] = this[i];
        while (!n.isZero()) {
          yield k;
          n = n.minus(1);
        }
      }
    }
    get UniqueElements() {
      return this.UniqueElements_();
    }
    *UniqueElements_() {
      for (let e of this) {
        let [k, n] = e;
        if (!n.isZero()) {
          yield k;
        }
      }
    }
    Union(that) {
      if (this.length === 0) {
        return that;
      } else if (that.length === 0) {
        return this;
      } else {
        let s = this.clone();
        for (let e of that) {
          let [k, n] = e;
          s.add(k, n);
        }
        return s;
      }
    }
    Intersect(that) {
      if (this.length === 0) {
        return this;
      } else if (that.length === 0) {
        return that;
      } else {
        let s = new MultiSet();
        for (let e of this) {
          let [k, n] = e;
          let m = that.get(k);
          if (!m.isZero()) {
            s.push([k, m.isLessThan(n) ? m : n]);
          }
        }
        return s;
      }
    }
    Difference(that) {
      if (this.length === 0 || that.length === 0) {
        return this;
      } else {
        let s = new MultiSet();
        for (let e of this) {
          let [k, n] = e;
          let d = n.minus(that.get(k));
          if (d.isGreaterThan(0)) {
            s.push([k, d]);
          }
        }
        return s;
      }
    }
    IsDisjointFrom(that) {
      let intersection = this.Intersect(that);
      return intersection.cardinality().isZero();
    }
    IsSubsetOf(that) {
      for (let e of this) {
        let [k, n] = e;
        let m = that.get(k);
        if (!n.isLessThanOrEqualTo(m)) {
          return false;
        }
      }
      return true;
    }
    IsProperSubsetOf(that) {
      return this.IsSubsetOf(that) && this.cardinality().isLessThan(that.cardinality());
    }
  }
  $module.CodePoint = class CodePoint {
    constructor(value) {
      this.value = value
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      return this.value === other.value
    }
    isLessThan(other) {
      return this.value < other.value
    }
    isLessThanOrEqual(other) {
      return this.value <= other.value
    }
    toString() {
      return "'" + $module.escapeCharacter(this) + "'";
    }
    static isCodePoint(i) {
      return (
        (_dafny.ZERO.isLessThanOrEqualTo(i) && i.isLessThan(new BigNumber(0xD800))) ||
        (new BigNumber(0xE000).isLessThanOrEqualTo(i) && i.isLessThan(new BigNumber(0x11_0000))))
    }
  }
  $module.Seq = class Seq extends Array {
    constructor(...elems) {
      super(...elems);
    }
    static get Default() {
      return Seq.of();
    }
    static Create(n, init) {
      return Seq.from({length: n}, (_, i) => init(new BigNumber(i)));
    }
    static UnicodeFromString(s) {
      const r = new Seq();
      for (const c of s) r.push(new _dafny.CodePoint(c.codePointAt(0)));
      return r;
    }
    toString() {
      return "[" + arrayElementsToString(this) + "]";
    }
    toVerbatimString(asLiteral) {
      if (asLiteral) {
        return '"' + this.map(c => _dafny.escapeCharacter(c)).join("") + '"';
      } else {
        return this.map(c => String.fromCodePoint(c.value)).join("");
      }
    }
    static update(s, i, v) {
      if (typeof s === "string") {
        let p = s.slice(0, i);
        let q = s.slice(i.toNumber() + 1);
        return p.concat(v, q);
      } else {
        let t = s.slice();
        t[i] = v;
        return t;
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let i = 0; i < this.length; i++) {
        if (!_dafny.areEqual(this[i], other[i])) {
          return false;
        }
      }
      return true;
    }
    static contains(s, k) {
      if (typeof s === "string") {
        return s.includes(k);
      } else {
        for (let x of s) {
          if (_dafny.areEqual(x, k)) {
            return true;
          }
        }
        return false;
      }
    }
    get Elements() {
      return this;
    }
    get UniqueElements() {
      return _dafny.Set.fromElements(...this);
    }
    slice(start = 0, end = this.length) {
      const s = Number(start), r = new Seq(Number(end) - s);
      for (let i = 0; i < r.length; i++) r[i] = this[s + i];
      return r;
    }
    static Concat(a, b) {
      if (typeof a === "string" || typeof b === "string") {
        // string concatenation, so make sure both operands are strings before concatenating
        if (typeof a !== "string") {
          // a must be a Seq
          a = a.join("");
        }
        if (typeof b !== "string") {
          // b must be a Seq
          b = b.join("");
        }
        return a + b;
      } else {
        // ordinary concatenation
        const r = new Seq(a.length + b.length);
        for (let i = 0; i < a.length; i++) r[i] = a[i];
        for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
        return r;
      }
    }
    static JoinIfPossible(x) {
      try { return x.join(""); } catch(_error) { return x; }
    }
    static IsPrefixOf(a, b) {
      if (b.length < a.length) {
        return false;
      }
      for (let i = 0; i < a.length; i++) {
        if (!_dafny.areEqual(a[i], b[i])) {
          return false;
        }
      }
      return true;
    }
    static IsProperPrefixOf(a, b) {
      if (b.length <= a.length) {
        return false;
      }
      for (let i = 0; i < a.length; i++) {
        if (!_dafny.areEqual(a[i], b[i])) {
          return false;
        }
      }
      return true;
    }
  }
  $module.Map = class Map extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return Map.of();
    }
    toString() {
      return "map[" + this.map(maplet => _dafny.toString(maplet[0]) + " := " + _dafny.toString(maplet[1])).join(", ") + "]";
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new Map();
      }
      return this._empty;
    }
    findIndex(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i][0], k)) {
          return i;
        }
      }
      return this.length;
    }
    get(k) {
      let i = this.findIndex(k);
      if (i === this.length) {
        return undefined;
      } else {
        return this[i][1];
      }
    }
    contains(k) {
      return this.findIndex(k) < this.length;
    }
    update(k, v) {
      let m = this.slice();
      m.updateUnsafe(k, v);
      return m;
    }
    // Similar to update, but make the modification in-place.
    // Meant to be used in the map constructor.
    updateUnsafe(k, v) {
      let m = this;
      let i = m.findIndex(k);
      m[i] = [k, v];
      return m;
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let e of this) {
        let [k, v] = e;
        let w = other.get(k);
        if (w === undefined || !_dafny.areEqual(v, w)) {
          return false;
        }
      }
      return true;
    }
    get Keys() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.push(k);
      }
      return s;
    }
    get Values() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.add(v);
      }
      return s;
    }
    get Items() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.push(_dafny.Tuple.of(k, v));
      }
      return s;
    }
    Merge(that) {
      let m = that.slice();
      for (let e of this) {
        let [k, v] = e;
        let i = m.findIndex(k);
        if (i == m.length) {
          m[i] = [k, v];
        }
      }
      return m;
    }
    Subtract(keys) {
      if (this.length === 0 || keys.length === 0) {
        return this;
      }
      let m = new Map();
      for (let e of this) {
        let [k, v] = e;
        if (!keys.contains(k)) {
          m[m.length] = e;
        }
      }
      return m;
    }
  }
  $module.newArray = function(initValue, ...dims) {
    return { dims: dims, elmts: buildArray(initValue, ...dims) };
  }
  $module.BigOrdinal = class BigOrdinal {
    static get Default() {
      return _dafny.ZERO;
    }
    static IsLimit(ord) {
      return ord.isZero();
    }
    static IsSucc(ord) {
      return ord.isGreaterThan(0);
    }
    static Offset(ord) {
      return ord;
    }
    static IsNat(ord) {
      return true;  // at run time, every ORDINAL is a natural number
    }
  }
  $module.BigRational = class BigRational {
    static get ZERO() {
      if (this._zero === undefined) {
        this._zero = new BigRational(_dafny.ZERO);
      }
      return this._zero;
    }
    constructor (n, d) {
      // requires d === undefined || 1 <= d
      this.num = n;
      this.den = d === undefined ? _dafny.ONE : d;
      // invariant 1 <= den || (num == 0 && den == 0)
    }
    static get Default() {
      return _dafny.BigRational.ZERO;
    }
    // We need to deal with the special case `num == 0 && den == 0`, because
    // that's what C#'s default struct constructor will produce for BigRational. :(
    // To deal with it, we ignore `den` when `num` is 0.
    toString() {
      if (this.num.isZero() || this.den.isEqualTo(1)) {
        return this.num.toFixed() + ".0";
      }
      let answer = this.dividesAPowerOf10(this.den);
      if (answer !== undefined) {
        let n = this.num.multipliedBy(answer[0]);
        let log10 = answer[1];
        let sign, digits;
        if (this.num.isLessThan(0)) {
          sign = "-"; digits = n.negated().toFixed();
        } else {
          sign = ""; digits = n.toFixed();
        }
        if (log10 < digits.length) {
          let digitCount = digits.length - log10;
          return sign + digits.slice(0, digitCount) + "." + digits.slice(digitCount);
        } else {
          return sign + "0." + "0".repeat(log10 - digits.length) + digits;
        }
      } else {
        return "(" + this.num.toFixed() + ".0 / " + this.den.toFixed() + ".0)";
      }
    }
    isPowerOf10(x) {
      if (x.isZero()) {
        return undefined;
      }
      let log10 = 0;
      while (true) {  // invariant: x != 0 && x * 10^log10 == old(x)
        if (x.isEqualTo(1)) {
          return log10;
        } else if (x.mod(10).isZero()) {
          log10++;
          x = x.dividedToIntegerBy(10);
        } else {
          return undefined;
        }
      }
    }
    dividesAPowerOf10(i) {
      let factor = _dafny.ONE;
      let log10 = 0;
      if (i.isLessThanOrEqualTo(_dafny.ZERO)) {
        return undefined;
      }

      // invariant: 1 <= i && i * 10^log10 == factor * old(i)
      while (i.mod(10).isZero()) {
        i = i.dividedToIntegerBy(10);
       log10++;
      }

      while (i.mod(5).isZero()) {
        i = i.dividedToIntegerBy(5);
        factor = factor.multipliedBy(2);
        log10++;
      }
      while (i.mod(2).isZero()) {
        i = i.dividedToIntegerBy(2);
        factor = factor.multipliedBy(5);
        log10++;
      }

      if (i.isEqualTo(_dafny.ONE)) {
        return [factor, log10];
      } else {
        return undefined;
      }
    }
    toBigNumber() {
      if (this.num.isZero() || this.den.isEqualTo(1)) {
        return this.num;
      } else if (this.num.isGreaterThan(0)) {
        return this.num.dividedToIntegerBy(this.den);
      } else {
        return this.num.minus(this.den).plus(1).dividedToIntegerBy(this.den);
      }
    }
    isInteger() {
      return this.equals(new _dafny.BigRational(this.toBigNumber(), _dafny.ONE));
    }
    // Returns values such that aa/dd == a and bb/dd == b.
    normalize(b) {
      let a = this;
      let aa, bb, dd;
      if (a.num.isZero()) {
        aa = a.num;
        bb = b.num;
        dd = b.den;
      } else if (b.num.isZero()) {
        aa = a.num;
        dd = a.den;
        bb = b.num;
      } else {
        let gcd = BigNumberGcd(a.den, b.den);
        let xx = a.den.dividedToIntegerBy(gcd);
        let yy = b.den.dividedToIntegerBy(gcd);
        // We now have a == a.num / (xx * gcd) and b == b.num / (yy * gcd).
        aa = a.num.multipliedBy(yy);
        bb = b.num.multipliedBy(xx);
        dd = a.den.multipliedBy(yy);
      }
      return [aa, bb, dd];
    }
    compareTo(that) {
      // simple things first
      let asign = this.num.isZero() ? 0 : this.num.isLessThan(0) ? -1 : 1;
      let bsign = that.num.isZero() ? 0 : that.num.isLessThan(0) ? -1 : 1;
      if (asign < 0 && 0 <= bsign) {
        return -1;
      } else if (asign <= 0 && 0 < bsign) {
        return -1;
      } else if (bsign < 0 && 0 <= asign) {
        return 1;
      } else if (bsign <= 0 && 0 < asign) {
        return 1;
      }
      let [aa, bb, dd] = this.normalize(that);
      if (aa.isLessThan(bb)) {
        return -1;
      } else if (aa.isEqualTo(bb)){
        return 0;
      } else {
        return 1;
      }
    }
    equals(that) {
      return this.compareTo(that) === 0;
    }
    isLessThan(that) {
      return this.compareTo(that) < 0;
    }
    isAtMost(that) {
      return this.compareTo(that) <= 0;
    }
    plus(b) {
      let [aa, bb, dd] = this.normalize(b);
      return new BigRational(aa.plus(bb), dd);
    }
    minus(b) {
      let [aa, bb, dd] = this.normalize(b);
      return new BigRational(aa.minus(bb), dd);
    }
    negated() {
      return new BigRational(this.num.negated(), this.den);
    }
    multipliedBy(b) {
      return new BigRational(this.num.multipliedBy(b.num), this.den.multipliedBy(b.den));
    }
    dividedBy(b) {
      let a = this;
      // Compute the reciprocal of b
      let bReciprocal;
      if (b.num.isGreaterThan(0)) {
        bReciprocal = new BigRational(b.den, b.num);
      } else {
        // this is the case b.num < 0
        bReciprocal = new BigRational(b.den.negated(), b.num.negated());
      }
      return a.multipliedBy(bReciprocal);
    }
  }
  $module.EuclideanDivisionNumber = function(a, b) {
    if (0 <= a) {
      if (0 <= b) {
        // +a +b: a/b
        return Math.floor(a / b);
      } else {
        // +a -b: -(a/(-b))
        return -Math.floor(a / -b);
      }
    } else {
      if (0 <= b) {
        // -a +b: -((-a-1)/b) - 1
        return -Math.floor((-a-1) / b) - 1;
      } else {
        // -a -b: ((-a-1)/(-b)) + 1
        return Math.floor((-a-1) / -b) + 1;
      }
    }
  }
  $module.EuclideanDivision = function(a, b) {
    if (a.isGreaterThanOrEqualTo(0)) {
      if (b.isGreaterThanOrEqualTo(0)) {
        // +a +b: a/b
        return a.dividedToIntegerBy(b);
      } else {
        // +a -b: -(a/(-b))
        return a.dividedToIntegerBy(b.negated()).negated();
      }
    } else {
      if (b.isGreaterThanOrEqualTo(0)) {
        // -a +b: -((-a-1)/b) - 1
        return a.negated().minus(1).dividedToIntegerBy(b).negated().minus(1);
      } else {
        // -a -b: ((-a-1)/(-b)) + 1
        return a.negated().minus(1).dividedToIntegerBy(b.negated()).plus(1);
      }
    }
  }
  $module.EuclideanModuloNumber = function(a, b) {
    let bp = Math.abs(b);
    if (0 <= a) {
      // +a: a % bp
      return a % bp;
    } else {
      // c = ((-a) % bp)
      // -a: bp - c if c > 0
      // -a: 0 if c == 0
      let c = (-a) % bp;
      return c === 0 ? c : bp - c;
    }
  }
  $module.ShiftLeft = function(b, n) {
    return b.multipliedBy(new BigNumber(2).exponentiatedBy(n));
  }
  $module.ShiftRight = function(b, n) {
    return b.dividedToIntegerBy(new BigNumber(2).exponentiatedBy(n));
  }
  $module.RotateLeft = function(b, n, w) {  // truncate(b << n) | (b >> (w - n))
    let x = _dafny.ShiftLeft(b, n).mod(new BigNumber(2).exponentiatedBy(w));
    let y = _dafny.ShiftRight(b, w - n);
    return x.plus(y);
  }
  $module.RotateRight = function(b, n, w) {  // (b >> n) | truncate(b << (w - n))
    let x = _dafny.ShiftRight(b, n);
    let y = _dafny.ShiftLeft(b, w - n).mod(new BigNumber(2).exponentiatedBy(w));;
    return x.plus(y);
  }
  $module.BitwiseAnd = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 & b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    return r;
  }
  $module.BitwiseOr = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 | b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    r = r.plus(h.multipliedBy(a | b));
    return r;
  }
  $module.BitwiseXor = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 ^ b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    r = r.plus(h.multipliedBy(a | b));
    return r;
  }
  $module.BitwiseNot = function(a, bits) {
    let r = _dafny.ZERO;
    let h = _dafny.ONE;
    for (let i = 0; i < bits; i++) {
      let bit = a.mod(2);
      if (bit.isZero()) {
        r = r.plus(h);
      }
      a = a.dividedToIntegerBy(2);
      h = h.multipliedBy(2);
    }
    return r;
  }
  $module.Quantifier = function(vals, frall, pred) {
    for (let u of vals) {
      if (pred(u) !== frall) { return !frall; }
    }
    return frall;
  }
  $module.PlusChar = function(a, b) {
    return String.fromCharCode(a.charCodeAt(0) + b.charCodeAt(0));
  }
  $module.UnicodePlusChar = function(a, b) {
    return new _dafny.CodePoint(a.value + b.value);
  }
  $module.MinusChar = function(a, b) {
    return String.fromCharCode(a.charCodeAt(0) - b.charCodeAt(0));
  }
  $module.UnicodeMinusChar = function(a, b) {
    return new _dafny.CodePoint(a.value - b.value);
  }
  $module.AllBooleans = function*() {
    yield false;
    yield true;
  }
  $module.AllChars = function*() {
    for (let i = 0; i < 0x10000; i++) {
      yield String.fromCharCode(i);
    }
  }
  $module.AllUnicodeChars = function*() {
    for (let i = 0; i < 0xD800; i++) {
      yield new _dafny.CodePoint(i);
    }
    for (let i = 0xE0000; i < 0x110000; i++) {
      yield new _dafny.CodePoint(i);
    }
  }
  $module.AllIntegers = function*() {
    yield _dafny.ZERO;
    for (let j = _dafny.ONE;; j = j.plus(1)) {
      yield j;
      yield j.negated();
    }
  }
  $module.IntegerRange = function*(lo, hi) {
    if (lo === null) {
      while (true) {
        hi = hi.minus(1);
        yield hi;
      }
    } else if (hi === null) {
      while (true) {
        yield lo;
        lo = lo.plus(1);
      }
    } else {
      while (lo.isLessThan(hi)) {
        yield lo;
        lo = lo.plus(1);
      }
    }
  }
  $module.SingleValue = function*(v) {
    yield v;
  }
  $module.HaltException = class HaltException extends Error {
    constructor(message) {
      super(message)
    }
  }
  $module.HandleHaltExceptions = function(f) {
    try {
      f()
    } catch (e) {
      if (e instanceof _dafny.HaltException) {
        process.stdout.write("[Program halted] " + e.message + "\n")
        process.exitCode = 1
      } else {
        throw e
      }
    }
  }
  $module.FromMainArguments = function(args) {
    var a = [...args];
    a.splice(0, 2, args[0] + " " + args[1]);
    return a;
  }
  $module.UnicodeFromMainArguments = function(args) {
    return $module.FromMainArguments(args).map(_dafny.Seq.UnicodeFromString);
  }
  return $module;

  // What follows are routines private to the Dafny runtime
  function buildArray(initValue, ...dims) {
    if (dims.length === 0) {
      return initValue;
    } else {
      let a = Array(dims[0].toNumber());
      let b = Array.from(a, (x) => buildArray(initValue, ...dims.slice(1)));
      return b;
    }
  }
  function arrayElementsToString(a) {
    // like `a.join(", ")`, but calling _dafny.toString(x) on every element x instead of x.toString()
    let s = "";
    let sep = "";
    for (let x of a) {
      s += sep + _dafny.toString(x);
      sep = ", ";
    }
    return s;
  }
  function BigNumberGcd(a, b){  // gcd of two non-negative BigNumber's
    while (true) {
      if (a.isZero()) {
        return b;
      } else if (b.isZero()) {
        return a;
      }
      if (a.isLessThan(b)) {
        b = b.modulo(a);
      } else {
        a = a.modulo(b);
      }
    }
  }
})();
// Dafny program systemModulePopulator.dfy compiled into JavaScript
let _System = (function() {
  let $module = {};

  $module.nat = class nat {
    constructor () {
    }
    static get Default() {
      return _dafny.ZERO;
    }
    static _Is(__source) {
      let _0_x = (__source);
      return (_dafny.ZERO).isLessThanOrEqualTo(_0_x);
    }
  };

  return $module;
})(); // end of module _System
let EHBP = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "EHBP._default";
    }
    _parentTraits() {
      return [];
    }
    static CheckPublicKey(b) {
      if ((new BigNumber((b).length)).isEqualTo(new BigNumber(32))) {
        let _0_key = b;
        return EHBP.Result.create_Ok(_0_key);
      } else {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("public key must be 32 bytes"));
      }
    };
    static CodeString(c) {
      let _source0 = c;
      {
        if (_source0.is_InvalidKeyConfig) {
          return _dafny.Seq.UnicodeFromString("INVALID_KEY_CONFIG");
        }
      }
      {
        if (_source0.is_UnsupportedSuite) {
          return _dafny.Seq.UnicodeFromString("UNSUPPORTED_SUITE");
        }
      }
      {
        if (_source0.is_InvalidEncapsulatedKey) {
          return _dafny.Seq.UnicodeFromString("INVALID_ENCAPSULATED_KEY");
        }
      }
      {
        if (_source0.is_HpkeSetupFailed) {
          return _dafny.Seq.UnicodeFromString("HPKE_SETUP_FAILED");
        }
      }
      {
        if (_source0.is_MissingResponseNonce) {
          return _dafny.Seq.UnicodeFromString("MISSING_RESPONSE_NONCE");
        }
      }
      {
        if (_source0.is_UnexpectedRedirect) {
          return _dafny.Seq.UnicodeFromString("UNEXPECTED_REDIRECT");
        }
      }
      {
        if (_source0.is_InvalidResponseNonce) {
          return _dafny.Seq.UnicodeFromString("INVALID_RESPONSE_NONCE");
        }
      }
      {
        if (_source0.is_DuplicateResponseNonce) {
          return _dafny.Seq.UnicodeFromString("DUPLICATE_RESPONSE_NONCE");
        }
      }
      {
        if (_source0.is_KeyConfigMismatch) {
          return _dafny.Seq.UnicodeFromString("KEY_CONFIG_MISMATCH");
        }
      }
      {
        if (_source0.is_FramingTruncated) {
          return _dafny.Seq.UnicodeFromString("FRAMING_TRUNCATED");
        }
      }
      {
        if (_source0.is_ChunkTooLarge) {
          return _dafny.Seq.UnicodeFromString("CHUNK_TOO_LARGE");
        }
      }
      {
        if (_source0.is_AeadDecryptFailed) {
          return _dafny.Seq.UnicodeFromString("AEAD_DECRYPT_FAILED");
        }
      }
      {
        if (_source0.is_SequenceOverflow) {
          return _dafny.Seq.UnicodeFromString("SEQUENCE_OVERFLOW");
        }
      }
      {
        if (_source0.is_InvalidToken) {
          return _dafny.Seq.UnicodeFromString("INVALID_TOKEN");
        }
      }
      {
        if (_source0.is_InvalidInput) {
          return _dafny.Seq.UnicodeFromString("INVALID_INPUT");
        }
      }
      {
        return _dafny.Seq.UnicodeFromString("");
      }
    };
    static U16(b, i) {
      return (((b)[i]) * (256)) + ((b)[(i).plus(_dafny.ONE)]);
    };
    static U32(b, i) {
      return ((EHBP.__default.U16(b, i)) * (65536)) + (EHBP.__default.U16(b, (i).plus(new BigNumber(2))));
    };
    static BE16(v) {
      return _dafny.Seq.of(_dafny.EuclideanDivisionNumber(v, 256), _dafny.EuclideanModuloNumber(v, 256));
    };
    static BE32(v) {
      return _dafny.Seq.Concat(EHBP.__default.BE16(_dafny.EuclideanDivisionNumber(v, 65536)), EHBP.__default.BE16(_dafny.EuclideanModuloNumber(v, 65536)));
    };
    static IsAscii(s) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) || ((new BigNumber(((s)[_0_i]).value)).isLessThan(new BigNumber(128)));
      });
    };
    static Ascii(s) {
      return _dafny.Seq.Create(new BigNumber((s).length), ((_0_s) => function (_1_i) {
        return (new BigNumber(((_0_s)[_1_i]).value)).toNumber();
      })(s));
    };
    static LowerChar(c) {
      if (((new _dafny.CodePoint('A'.codePointAt(0))).isLessThanOrEqual(c)) && ((c).isLessThanOrEqual(new _dafny.CodePoint('Z'.codePointAt(0))))) {
        return new _dafny.CodePoint(((new BigNumber((c).value)).plus(new BigNumber(32))).toNumber());
      } else {
        return c;
      }
    };
    static Lower(s) {
      return _dafny.Seq.Create(new BigNumber((s).length), ((_0_s) => function (_1_i) {
        return EHBP.__default.LowerChar((_0_s)[_1_i]);
      })(s));
    };
    static EqualFold(a, b) {
      return _dafny.areEqual(EHBP.__default.Lower(a), EHBP.__default.Lower(b));
    };
    static IsSpace(c) {
      return (_dafny.areEqual(c, new _dafny.CodePoint(' '.codePointAt(0)))) || (_dafny.areEqual(c, new _dafny.CodePoint('\t'.codePointAt(0))));
    };
    static TrimLeft(s) {
      TAIL_CALL_START: while (true) {
        if (((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (EHBP.__default.IsSpace((s)[_dafny.ZERO]))) {
          let _in0 = (s).slice(_dafny.ONE);
          s = _in0;
          continue TAIL_CALL_START;
        } else {
          return s;
        }
      }
    };
    static TrimRight(s) {
      TAIL_CALL_START: while (true) {
        if (((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (EHBP.__default.IsSpace((s)[(new BigNumber((s).length)).minus(_dafny.ONE)]))) {
          let _in0 = (s).slice(0, (new BigNumber((s).length)).minus(_dafny.ONE));
          s = _in0;
          continue TAIL_CALL_START;
        } else {
          return s;
        }
      }
    };
    static Trim(s) {
      return EHBP.__default.TrimRight(EHBP.__default.TrimLeft(s));
    };
    static Before(s, sep) {
      return EHBP.__default.BeforeFrom(s, sep, _dafny.ZERO);
    };
    static BeforeFrom(s, sep, i) {
      TAIL_CALL_START: while (true) {
        if (((i).isEqualTo(new BigNumber((s).length))) || (_dafny.areEqual((s)[i], sep))) {
          return (s).slice(0, i);
        } else {
          let _in0 = s;
          let _in1 = sep;
          let _in2 = (i).plus(_dafny.ONE);
          s = _in0;
          sep = _in1;
          i = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static MediaType(contentType) {
      return EHBP.__default.Lower(EHBP.__default.Trim(EHBP.__default.Before(contentType, new _dafny.CodePoint(';'.codePointAt(0)))));
    };
    static HasMediaType(contentType, want) {
      return ((contentType).is_Some) && (_dafny.areEqual(EHBP.__default.MediaType((contentType).dtor_value), EHBP.__default.Lower(want)));
    };
    static HexDigitValue(c) {
      if (((new _dafny.CodePoint('0'.codePointAt(0))).isLessThanOrEqual(c)) && ((c).isLessThanOrEqual(new _dafny.CodePoint('9'.codePointAt(0))))) {
        return EHBP.Option.create_Some(((new BigNumber((c).value)).minus(new BigNumber((new _dafny.CodePoint('0'.codePointAt(0))).value))).toNumber());
      } else if (((new _dafny.CodePoint('a'.codePointAt(0))).isLessThanOrEqual(c)) && ((c).isLessThanOrEqual(new _dafny.CodePoint('f'.codePointAt(0))))) {
        return EHBP.Option.create_Some((((new BigNumber((c).value)).minus(new BigNumber((new _dafny.CodePoint('a'.codePointAt(0))).value))).plus(new BigNumber(10))).toNumber());
      } else if (((new _dafny.CodePoint('A'.codePointAt(0))).isLessThanOrEqual(c)) && ((c).isLessThanOrEqual(new _dafny.CodePoint('F'.codePointAt(0))))) {
        return EHBP.Option.create_Some((((new BigNumber((c).value)).minus(new BigNumber((new _dafny.CodePoint('A'.codePointAt(0))).value))).plus(new BigNumber(10))).toNumber());
      } else {
        return EHBP.Option.create_None();
      }
    };
    static IsHex(s) {
      return (((new BigNumber((s).length)).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) || ((EHBP.__default.HexDigitValue((s)[_0_i])).is_Some);
      }));
    };
    static DecodeHex(s) {
      if (!(EHBP.__default.IsHex(s))) {
        return EHBP.Option.create_None();
      } else {
        return EHBP.Option.create_Some(_dafny.Seq.Create(_dafny.EuclideanDivision(new BigNumber((s).length), new BigNumber(2)), ((_0_s) => function (_1_i) {
  return (((EHBP.__default.HexDigitValue((_0_s)[(new BigNumber(2)).multipliedBy(_1_i)])).dtor_value) * (16)) + ((EHBP.__default.HexDigitValue((_0_s)[((new BigNumber(2)).multipliedBy(_1_i)).plus(_dafny.ONE)])).dtor_value);
})(s)));
      }
    };
    static EncodeHex(b) {
      return _dafny.Seq.Create((new BigNumber(2)).multipliedBy(new BigNumber((b).length)), ((_0_b) => function (_1_i) {
        return ((((_1_i).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) ? ((EHBP.__default.HexDigits)[_dafny.EuclideanDivision(new BigNumber((_0_b)[_dafny.EuclideanDivision(_1_i, new BigNumber(2))]), new BigNumber(16))]) : ((EHBP.__default.HexDigits)[(new BigNumber((_0_b)[_dafny.EuclideanDivision(_1_i, new BigNumber(2))])).mod(new BigNumber(16))]));
      })(b));
    };
    static ComputeNonce(nonceBase, seqNo) {
      return _dafny.Seq.Create(EHBP.__default.NonceLength, ((_0_nonceBase, _1_seqNo) => function (_2_i) {
        return function (_pat_let0_0) {
          return function (_3_j) {
            return (((_3_j) < (4)) ? ((_0_nonceBase)[_3_j]) : ((_dafny.BitwiseXor(new BigNumber((_0_nonceBase)[_3_j]), new BigNumber(EHBP.__default.ByteAt(_1_seqNo, (11) - (_3_j))))).toNumber()));
          }(_pat_let0_0);
        }((_2_i).toNumber());
      })(nonceBase, seqNo));
    };
    static NonceFor(nonceBase, seqNo) {
      if (!(new BigNumber((nonceBase).length)).isEqualTo(EHBP.__default.NonceLength)) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("nonce base must be 12 bytes"));
      } else {
        return EHBP.Result.create_Ok(EHBP.__default.ComputeNonce(nonceBase, seqNo));
      }
    };
    static ByteAt(x, k) {
      TAIL_CALL_START: while (true) {
        if ((k) === (0)) {
          return ((x).mod(new BigNumber(256))).toNumber();
        } else {
          let _in0 = _dafny.EuclideanDivision(x, new BigNumber(256));
          let _in1 = (k) - (1);
          x = _in0;
          k = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static KnownKdf(id) {
      return (((id) === (1)) || ((id) === (2))) || ((id) === (3));
    };
    static KnownAead(id) {
      return (((id) === (1)) || ((id) === (2))) || ((id) === (3));
    };
    static ParseConfig(data) {
      if ((new BigNumber((data).length)).isLessThan(new BigNumber(3))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("invalid config"));
      } else if ((EHBP.__default.U16(data, _dafny.ONE)) !== (EHBP.__default.KemX25519)) {
        return EHBP.Result.create_Err(EHBP.Code.create_UnsupportedSuite(), _dafny.Seq.UnicodeFromString("unsupported KEM"));
      } else if ((new BigNumber((data).length)).isLessThan(((new BigNumber(3)).plus(EHBP.__default.PublicKeyLength)).plus(new BigNumber(2)))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("invalid config"));
      } else {
        let _0_pk = (data).slice(new BigNumber(3), (new BigNumber(3)).plus(EHBP.__default.PublicKeyLength));
        let _1_suitesLen = new BigNumber(EHBP.__default.U16(data, (new BigNumber(3)).plus(EHBP.__default.PublicKeyLength)));
        let _2_start = ((new BigNumber(3)).plus(EHBP.__default.PublicKeyLength)).plus(new BigNumber(2));
        if ((new BigNumber((data).length)).isLessThan((_2_start).plus(_1_suitesLen))) {
          return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("invalid config"));
        } else {
          let _source0 = EHBP.__default.ParseSuites((data).slice(_2_start, (_2_start).plus(_1_suitesLen)));
          {
            if (_source0.is_Err) {
              let _3_code = (_source0).code;
              let _4_message = (_source0).message;
              return EHBP.Result.create_Err(_3_code, _4_message);
            }
          }
          {
            let _5_suites = (_source0).value;
            if ((new BigNumber((_5_suites).length)).isEqualTo(_dafny.ZERO)) {
              return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("no cipher suites found in config"));
            } else if (!(new BigNumber((_5_suites).length)).isEqualTo(_dafny.ONE)) {
              return EHBP.Result.create_Err(EHBP.Code.create_UnsupportedSuite(), _dafny.Seq.UnicodeFromString("expected exactly one cipher suite"));
            } else if (!_dafny.areEqual((_5_suites)[_dafny.ZERO], _dafny.Tuple.of(EHBP.__default.KdfHkdfSha256, EHBP.__default.AeadAes256Gcm))) {
              return EHBP.Result.create_Err(EHBP.Code.create_UnsupportedSuite(), _dafny.Seq.UnicodeFromString("unsupported cipher suite"));
            } else {
              return EHBP.Result.create_Ok(_0_pk);
            }
          }
        }
      }
    };
    static ParseSuites(s) {
      return EHBP.__default.ParseSuitesFrom(s, _dafny.ZERO, _dafny.Seq.of());
    };
    static ParseSuitesFrom(s, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((s).length))) {
          return EHBP.Result.create_Ok(acc);
        } else if (((new BigNumber((s).length)).minus(i)).isLessThan(new BigNumber(4))) {
          return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("invalid config"));
        } else {
          let _0_kdf = EHBP.__default.U16(s, i);
          let _1_aead = EHBP.__default.U16(s, (i).plus(new BigNumber(2)));
          if (!(EHBP.__default.KnownKdf(_0_kdf))) {
            return EHBP.Result.create_Err(EHBP.Code.create_UnsupportedSuite(), _dafny.Seq.UnicodeFromString("invalid KDF"));
          } else if (!(EHBP.__default.KnownAead(_1_aead))) {
            return EHBP.Result.create_Err(EHBP.Code.create_UnsupportedSuite(), _dafny.Seq.UnicodeFromString("invalid AEAD"));
          } else {
            let _in0 = s;
            let _in1 = (i).plus(new BigNumber(4));
            let _in2 = _dafny.Seq.Concat(acc, _dafny.Seq.of(_dafny.Tuple.of(_0_kdf, _1_aead)));
            s = _in0;
            i = _in1;
            acc = _in2;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static MarshalConfig(publicKey) {
      if (!(new BigNumber((publicKey).length)).isEqualTo(EHBP.__default.PublicKeyLength)) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("invalid public key"));
      } else {
        return EHBP.Result.create_Ok(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(0), EHBP.__default.BE16(EHBP.__default.KemX25519)), publicKey), EHBP.__default.BE16(4)), EHBP.__default.BE16(EHBP.__default.KdfHkdfSha256)), EHBP.__default.BE16(EHBP.__default.AeadAes256Gcm)));
      }
    };
    static ValidToken(t) {
      return ((new BigNumber(((t).dtor_exportedSecret).length)).isEqualTo(EHBP.__default.ExportLength)) && ((new BigNumber(((t).dtor_requestEnc).length)).isEqualTo(EHBP.__default.RequestEncLength));
    };
    static ValidateTokenFields(exportedSecretHex, requestEncHex) {
      if (((exportedSecretHex).is_None) || ((requestEncHex).is_None)) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidToken(), _dafny.Seq.UnicodeFromString("token field missing"));
      } else {
        let _source0 = _dafny.Tuple.of(EHBP.__default.DecodeHex((exportedSecretHex).dtor_value), EHBP.__default.DecodeHex((requestEncHex).dtor_value));
        {
          let _00 = (_source0)[0];
          if (_00.is_Some) {
            let _0_secret = (_00).value;
            let _10 = (_source0)[1];
            if (_10.is_Some) {
              let _1_enc = (_10).value;
              if ((!(new BigNumber((_0_secret).length)).isEqualTo(EHBP.__default.ExportLength)) || (!(new BigNumber((_1_enc).length)).isEqualTo(EHBP.__default.RequestEncLength))) {
                return EHBP.Result.create_Err(EHBP.Code.create_InvalidToken(), _dafny.Seq.UnicodeFromString("token field has wrong length"));
              } else {
                return EHBP.Result.create_Ok(EHBP.Token.create_Token(_0_secret, _1_enc));
              }
            }
          }
        }
        {
          return EHBP.Result.create_Err(EHBP.Code.create_InvalidToken(), _dafny.Seq.UnicodeFromString("token field is not hex"));
        }
      }
    };
    static Frame(ciphertext) {
      return _dafny.Seq.Concat(EHBP.__default.BE32((ciphertext).length), ciphertext);
    };
    static HeaderValues(headers, name) {
      return EHBP.__default.HeaderValuesFrom(headers, name, _dafny.ZERO, _dafny.Seq.of());
    };
    static HeaderValuesFrom(headers, name, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((headers).length))) {
          return acc;
        } else {
          let _in0 = headers;
          let _in1 = name;
          let _in2 = (i).plus(_dafny.ONE);
          let _in3 = ((EHBP.__default.EqualFold(((headers)[i])[0], name)) ? (_dafny.Seq.Concat(acc, _dafny.Seq.of(((headers)[i])[1]))) : (acc));
          headers = _in0;
          name = _in1;
          i = _in2;
          acc = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static FirstHeader(headers, name) {
      let _0_values = EHBP.__default.HeaderValues(headers, name);
      if ((new BigNumber((_0_values).length)).isEqualTo(_dafny.ZERO)) {
        return EHBP.Option.create_None();
      } else {
        return EHBP.Option.create_Some((_0_values)[_dafny.ZERO]);
      }
    };
    static BodylessSuccess(status) {
      return ((status).isEqualTo(new BigNumber(204))) || ((status).isEqualTo(new BigNumber(205)));
    };
    static Classify(encrypted, head) {
      let _0_nonces = EHBP.__default.HeaderValues((head).dtor_headers, EHBP.__default.ResponseNonceHeader);
      if (!(encrypted)) {
        return EHBP.Disposition.create_PassThrough();
      } else if (((head).dtor_redirected) || (((new BigNumber(300)).isLessThanOrEqualTo((head).dtor_status)) && (((head).dtor_status).isLessThan(new BigNumber(400))))) {
        return EHBP.Disposition.create_Refuse(EHBP.Code.create_UnexpectedRedirect(), _dafny.Seq.UnicodeFromString("redirect in response to an encrypted request"));
      } else if ((new BigNumber((_0_nonces).length)).isEqualTo(_dafny.ZERO)) {
        if (((head).dtor_status).isLessThan(new BigNumber(400))) {
          return EHBP.Disposition.create_Refuse(EHBP.Code.create_MissingResponseNonce(), _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.UnicodeFromString("missing "), EHBP.__default.ResponseNonceHeader), _dafny.Seq.UnicodeFromString(" header")));
        } else if ((((head).dtor_status).isEqualTo(new BigNumber(422))) && (EHBP.__default.HasMediaType(EHBP.__default.FirstHeader((head).dtor_headers, _dafny.Seq.UnicodeFromString("Content-Type")), EHBP.__default.ProblemJsonMediaType))) {
          return EHBP.Disposition.create_NeedProblemBody();
        } else {
          return EHBP.Disposition.create_PassThrough();
        }
      } else if ((_dafny.ONE).isLessThan(new BigNumber((_0_nonces).length))) {
        return EHBP.Disposition.create_Refuse(EHBP.Code.create_DuplicateResponseNonce(), _dafny.Seq.UnicodeFromString("duplicate response nonce"));
      } else if (_dafny.areEqual((_0_nonces)[_dafny.ZERO], _dafny.Seq.UnicodeFromString(""))) {
        return EHBP.Disposition.create_Refuse(EHBP.Code.create_InvalidResponseNonce(), _dafny.Seq.UnicodeFromString("empty response nonce"));
      } else {
        let _source0 = EHBP.__default.DecodeHex((_0_nonces)[_dafny.ZERO]);
        {
          if (_source0.is_None) {
            return EHBP.Disposition.create_Refuse(EHBP.Code.create_InvalidResponseNonce(), _dafny.Seq.UnicodeFromString("response nonce is not hex"));
          }
        }
        {
          let _1_nonce = (_source0).value;
          if (!(new BigNumber((_1_nonce).length)).isEqualTo(EHBP.__default.ResponseNonceLength)) {
            return EHBP.Disposition.create_Refuse(EHBP.Code.create_InvalidResponseNonce(), _dafny.Seq.UnicodeFromString("response nonce has wrong length"));
          } else if (EHBP.__default.BodylessSuccess((head).dtor_status)) {
            return EHBP.Disposition.create_Refuse(EHBP.Code.create_FramingTruncated(), _dafny.Seq.UnicodeFromString("status cannot carry an authenticated frame"));
          } else {
            return EHBP.Disposition.create_Decrypt(_1_nonce, ((head).dtor_status).isLessThan(new BigNumber(400)));
          }
        }
      }
    };
    static ClassifyProblem(oversized, isObject, typeValue, title) {
      if (((oversized) || (!(isObject))) || (!_dafny.areEqual(typeValue, EHBP.Option.create_Some(EHBP.__default.KeyConfigProblemType)))) {
        return EHBP.Disposition.create_PassThrough();
      } else {
        return EHBP.Disposition.create_Refuse(EHBP.Code.create_KeyConfigMismatch(), ((((title).is_Some) && (!_dafny.areEqual((title).dtor_value, _dafny.Seq.UnicodeFromString("")))) ? ((title).dtor_value) : (EHBP.__default.DefaultKeyConfigTitle)));
      }
    };
    static ClassifyDiscovery(head) {
      if (((head).dtor_redirected) || (!((head).dtor_status).isEqualTo(new BigNumber(200)))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("discovery returned a non-200 status"));
      } else if (!(EHBP.__default.HasMediaType(EHBP.__default.FirstHeader((head).dtor_headers, _dafny.Seq.UnicodeFromString("Content-Type")), EHBP.__default.KeysMediaType))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidKeyConfig(), _dafny.Seq.UnicodeFromString("discovery returned the wrong media type"));
      } else {
        return EHBP.Result.create_Ok(_dafny.Tuple.of());
      }
    };
    static DefaultPort(scheme) {
      if (_dafny.areEqual(EHBP.__default.Lower(scheme), _dafny.Seq.UnicodeFromString("https"))) {
        return new BigNumber(443);
      } else {
        return new BigNumber(80);
      }
    };
    static MakeOrigin(scheme, host, port, hasUserinfo) {
      let _0_s = EHBP.__default.Lower(scheme);
      if ((!_dafny.areEqual(_0_s, _dafny.Seq.UnicodeFromString("http"))) && (!_dafny.areEqual(_0_s, _dafny.Seq.UnicodeFromString("https")))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("base URL must include an HTTP origin"));
      } else if (_dafny.areEqual(host, _dafny.Seq.UnicodeFromString(""))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("base URL must include an HTTP origin"));
      } else if (hasUserinfo) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("base URL must not include credentials"));
      } else {
        return EHBP.Result.create_Ok(EHBP.Origin.create_Origin(_0_s, EHBP.__default.Lower(host), (((port).is_Some) ? ((port).dtor_value) : (EHBP.__default.DefaultPort(_0_s)))));
      }
    };
    static SameOrigin(a, b) {
      return ((_dafny.areEqual((a).dtor_scheme, (b).dtor_scheme)) && (_dafny.areEqual((a).dtor_host, (b).dtor_host))) && (((a).dtor_port).isEqualTo((b).dtor_port));
    };
    static ReservedHeader(name) {
      return ((EHBP.__default.EqualFold(name, EHBP.__default.EncapsulatedKeyHeader)) || (EHBP.__default.EqualFold(name, EHBP.__default.ResponseNonceHeader))) || (EHBP.__default.EqualFold(name, _dafny.Seq.UnicodeFromString("Host")));
    };
    static FramingHeader(name) {
      return (EHBP.__default.EqualFold(name, _dafny.Seq.UnicodeFromString("Content-Length"))) || (EHBP.__default.EqualFold(name, _dafny.Seq.UnicodeFromString("Transfer-Encoding")));
    };
    static ValidateRequest(origin, target, headers) {
      if ((target).is_Err) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), (target).dtor_message);
      } else if (!(EHBP.__default.SameOrigin(origin, (target).dtor_value))) {
        return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("request URL must use the configured origin"));
      } else {
        return EHBP.__default.ValidateHeadersFrom(headers, _dafny.ZERO);
      }
    };
    static ValidateHeadersFrom(headers, i) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((headers).length))) {
          return EHBP.Result.create_Ok(_dafny.Tuple.of());
        } else if (EHBP.__default.ReservedHeader(((headers)[i])[0])) {
          return EHBP.Result.create_Err(EHBP.Code.create_InvalidInput(), _dafny.Seq.Concat(_dafny.Seq.UnicodeFromString("reserved request header cannot be set by callers: "), ((headers)[i])[0]));
        } else {
          let _in0 = headers;
          let _in1 = (i).plus(_dafny.ONE);
          headers = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static DropFraming(headers) {
      return EHBP.__default.DropFramingFrom(headers, _dafny.ZERO, _dafny.Seq.of());
    };
    static DropFramingFrom(headers, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((headers).length))) {
          return acc;
        } else {
          let _in0 = headers;
          let _in1 = (i).plus(_dafny.ONE);
          let _in2 = ((EHBP.__default.FramingHeader(((headers)[i])[0])) ? (acc) : (_dafny.Seq.Concat(acc, _dafny.Seq.of((headers)[i]))));
          headers = _in0;
          i = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static OriginUrl(origin) {
      let _0_portPart = ((((origin).dtor_port).isEqualTo(EHBP.__default.DefaultPort((origin).dtor_scheme))) ? (_dafny.Seq.UnicodeFromString("")) : (_dafny.Seq.Concat(_dafny.Seq.UnicodeFromString(":"), EHBP.__default.IntToString((origin).dtor_port))));
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat((origin).dtor_scheme, _dafny.Seq.UnicodeFromString("://")), (origin).dtor_host), _0_portPart);
    };
    static IntToString(n) {
      if ((n).isLessThan(_dafny.ZERO)) {
        return _dafny.Seq.Concat(_dafny.Seq.UnicodeFromString("-"), EHBP.__default.IntToString((_dafny.ZERO).minus(n)));
      } else if ((n).isLessThan(new BigNumber(10))) {
        return _dafny.Seq.of(new _dafny.CodePoint(((new BigNumber((new _dafny.CodePoint('0'.codePointAt(0))).value)).plus(n)).toNumber()));
      } else {
        return _dafny.Seq.Concat(EHBP.__default.IntToString(_dafny.EuclideanDivision(n, new BigNumber(10))), _dafny.Seq.of(new _dafny.CodePoint(((new BigNumber((new _dafny.CodePoint('0'.codePointAt(0))).value)).plus((n).mod(new BigNumber(10)))).toNumber())));
      }
    };
    static get Codes() {
      return _dafny.Seq.of(EHBP.Code.create_InvalidKeyConfig(), EHBP.Code.create_UnsupportedSuite(), EHBP.Code.create_InvalidEncapsulatedKey(), EHBP.Code.create_HpkeSetupFailed(), EHBP.Code.create_MissingResponseNonce(), EHBP.Code.create_UnexpectedRedirect(), EHBP.Code.create_InvalidResponseNonce(), EHBP.Code.create_DuplicateResponseNonce(), EHBP.Code.create_KeyConfigMismatch(), EHBP.Code.create_FramingTruncated(), EHBP.Code.create_ChunkTooLarge(), EHBP.Code.create_AeadDecryptFailed(), EHBP.Code.create_SequenceOverflow(), EHBP.Code.create_InvalidToken(), EHBP.Code.create_InvalidInput());
    };
    static get KemX25519() {
      return 32;
    };
    static get KdfHkdfSha256() {
      return 1;
    };
    static get AeadAes256Gcm() {
      return 2;
    };
    static get MaxChunkBytes() {
      return ((64) * (1024)) * (1024);
    };
    static get RequestFrameBytes() {
      return 65536;
    };
    static get HexDigits() {
      return _dafny.Seq.UnicodeFromString("0123456789abcdef");
    };
    static get NonceLength() {
      return new BigNumber(12);
    };
    static get PublicKeyLength() {
      return new BigNumber(32);
    };
    static get ExportLength() {
      return new BigNumber(32);
    };
    static get RequestEncLength() {
      return new BigNumber(32);
    };
    static get ResponseNonceHeader() {
      return _dafny.Seq.UnicodeFromString("Ehbp-Response-Nonce");
    };
    static get ProblemJsonMediaType() {
      return _dafny.Seq.UnicodeFromString("application/problem+json");
    };
    static get ResponseNonceLength() {
      return new BigNumber(32);
    };
    static get KeyConfigProblemType() {
      return _dafny.Seq.UnicodeFromString("urn:ietf:params:ehbp:error:key-config");
    };
    static get DefaultKeyConfigTitle() {
      return _dafny.Seq.UnicodeFromString("key configuration mismatch");
    };
    static get KeysMediaType() {
      return _dafny.Seq.UnicodeFromString("application/ohttp-keys");
    };
    static get EncapsulatedKeyHeader() {
      return _dafny.Seq.UnicodeFromString("Ehbp-Encapsulated-Key");
    };
    static get KeyLength() {
      return new BigNumber(32);
    };
    static get HpkeRequestInfo() {
      return _dafny.Seq.UnicodeFromString("ehbp request");
    };
    static get ExportLabel() {
      return _dafny.Seq.UnicodeFromString("ehbp response");
    };
    static get ResponseKeyLabel() {
      return _dafny.Seq.UnicodeFromString("key");
    };
    static get ResponseNonceLabel() {
      return _dafny.Seq.UnicodeFromString("nonce");
    };
    static get KeysPath() {
      return _dafny.Seq.UnicodeFromString("/.well-known/hpke-keys");
    };
    static get MaxProblemBytes() {
      return (new BigNumber(64)).multipliedBy(new BigNumber(1024));
    };
    static get MaxKeyConfigBytes() {
      return (new BigNumber(37)).plus(new BigNumber(65535));
    };
    static get MaxEmptyReads() {
      return new BigNumber(100);
    };
    static get AeadTagLength() {
      return new BigNumber(16);
    };
    static get HashLength() {
      return new BigNumber(32);
    };
  };

  $module.uint8 = class uint8 {
    constructor () {
    }
    _parentTraits() {
      return [];
    }
    static *IntegerRange(lo, hi) {
      while (lo.isLessThan(hi)) {
        yield lo.toNumber();
        lo = lo.plus(1);
      }
    }
    static get Default() {
      return 0;
    }
    static _Is(__source) {
      let _0_x = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_0_x)) && ((_0_x).isLessThan(new BigNumber(256)));
    }
  };

  $module.uint16 = class uint16 {
    constructor () {
    }
    _parentTraits() {
      return [];
    }
    static *IntegerRange(lo, hi) {
      while (lo.isLessThan(hi)) {
        yield lo.toNumber();
        lo = lo.plus(1);
      }
    }
    static get Default() {
      return 0;
    }
    static _Is(__source) {
      let _1_x = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_1_x)) && ((_1_x).isLessThan(new BigNumber(65536)));
    }
  };

  $module.uint32 = class uint32 {
    constructor () {
    }
    _parentTraits() {
      return [];
    }
    static *IntegerRange(lo, hi) {
      while (lo.isLessThan(hi)) {
        yield lo.toNumber();
        lo = lo.plus(1);
      }
    }
    static get Default() {
      return 0;
    }
    static _Is(__source) {
      let _2_x = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_2_x)) && ((_2_x).isLessThan(new BigNumber(4294967296)));
    }
  };

  $module.uint64 = class uint64 {
    constructor () {
    }
    _parentTraits() {
      return [];
    }
    static get Default() {
      return _dafny.ZERO;
    }
    static _Is(__source) {
      let _3_x = __source;
      return ((_dafny.ZERO).isLessThanOrEqualTo(_3_x)) && ((_3_x).isLessThan(new BigNumber("18446744073709551616")));
    }
  };

  $module.PublicKey = class PublicKey {
    constructor () {
    }
    static get Witness() {
      return _dafny.Seq.Create(new BigNumber(32), function (_4_i) {
    return 0;
  });
    }
    static get Default() {
      return EHBP.PublicKey.Witness;
    }
    static _Is(__source) {
      let _5_b = __source;
      return (new BigNumber((_5_b).length)).isEqualTo(new BigNumber(32));
    }
  };

  $module.Code = class Code {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_InvalidKeyConfig() {
      let $dt = new Code(0);
      return $dt;
    }
    static create_UnsupportedSuite() {
      let $dt = new Code(1);
      return $dt;
    }
    static create_InvalidEncapsulatedKey() {
      let $dt = new Code(2);
      return $dt;
    }
    static create_HpkeSetupFailed() {
      let $dt = new Code(3);
      return $dt;
    }
    static create_MissingResponseNonce() {
      let $dt = new Code(4);
      return $dt;
    }
    static create_UnexpectedRedirect() {
      let $dt = new Code(5);
      return $dt;
    }
    static create_InvalidResponseNonce() {
      let $dt = new Code(6);
      return $dt;
    }
    static create_DuplicateResponseNonce() {
      let $dt = new Code(7);
      return $dt;
    }
    static create_KeyConfigMismatch() {
      let $dt = new Code(8);
      return $dt;
    }
    static create_FramingTruncated() {
      let $dt = new Code(9);
      return $dt;
    }
    static create_ChunkTooLarge() {
      let $dt = new Code(10);
      return $dt;
    }
    static create_AeadDecryptFailed() {
      let $dt = new Code(11);
      return $dt;
    }
    static create_SequenceOverflow() {
      let $dt = new Code(12);
      return $dt;
    }
    static create_InvalidToken() {
      let $dt = new Code(13);
      return $dt;
    }
    static create_InvalidInput() {
      let $dt = new Code(14);
      return $dt;
    }
    static create_Transport() {
      let $dt = new Code(15);
      return $dt;
    }
    get is_InvalidKeyConfig() { return this.$tag === 0; }
    get is_UnsupportedSuite() { return this.$tag === 1; }
    get is_InvalidEncapsulatedKey() { return this.$tag === 2; }
    get is_HpkeSetupFailed() { return this.$tag === 3; }
    get is_MissingResponseNonce() { return this.$tag === 4; }
    get is_UnexpectedRedirect() { return this.$tag === 5; }
    get is_InvalidResponseNonce() { return this.$tag === 6; }
    get is_DuplicateResponseNonce() { return this.$tag === 7; }
    get is_KeyConfigMismatch() { return this.$tag === 8; }
    get is_FramingTruncated() { return this.$tag === 9; }
    get is_ChunkTooLarge() { return this.$tag === 10; }
    get is_AeadDecryptFailed() { return this.$tag === 11; }
    get is_SequenceOverflow() { return this.$tag === 12; }
    get is_InvalidToken() { return this.$tag === 13; }
    get is_InvalidInput() { return this.$tag === 14; }
    get is_Transport() { return this.$tag === 15; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Code.create_InvalidKeyConfig();
      yield Code.create_UnsupportedSuite();
      yield Code.create_InvalidEncapsulatedKey();
      yield Code.create_HpkeSetupFailed();
      yield Code.create_MissingResponseNonce();
      yield Code.create_UnexpectedRedirect();
      yield Code.create_InvalidResponseNonce();
      yield Code.create_DuplicateResponseNonce();
      yield Code.create_KeyConfigMismatch();
      yield Code.create_FramingTruncated();
      yield Code.create_ChunkTooLarge();
      yield Code.create_AeadDecryptFailed();
      yield Code.create_SequenceOverflow();
      yield Code.create_InvalidToken();
      yield Code.create_InvalidInput();
      yield Code.create_Transport();
    }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Code.InvalidKeyConfig";
      } else if (this.$tag === 1) {
        return "EHBP.Code.UnsupportedSuite";
      } else if (this.$tag === 2) {
        return "EHBP.Code.InvalidEncapsulatedKey";
      } else if (this.$tag === 3) {
        return "EHBP.Code.HpkeSetupFailed";
      } else if (this.$tag === 4) {
        return "EHBP.Code.MissingResponseNonce";
      } else if (this.$tag === 5) {
        return "EHBP.Code.UnexpectedRedirect";
      } else if (this.$tag === 6) {
        return "EHBP.Code.InvalidResponseNonce";
      } else if (this.$tag === 7) {
        return "EHBP.Code.DuplicateResponseNonce";
      } else if (this.$tag === 8) {
        return "EHBP.Code.KeyConfigMismatch";
      } else if (this.$tag === 9) {
        return "EHBP.Code.FramingTruncated";
      } else if (this.$tag === 10) {
        return "EHBP.Code.ChunkTooLarge";
      } else if (this.$tag === 11) {
        return "EHBP.Code.AeadDecryptFailed";
      } else if (this.$tag === 12) {
        return "EHBP.Code.SequenceOverflow";
      } else if (this.$tag === 13) {
        return "EHBP.Code.InvalidToken";
      } else if (this.$tag === 14) {
        return "EHBP.Code.InvalidInput";
      } else if (this.$tag === 15) {
        return "EHBP.Code.Transport";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else if (this.$tag === 7) {
        return other.$tag === 7;
      } else if (this.$tag === 8) {
        return other.$tag === 8;
      } else if (this.$tag === 9) {
        return other.$tag === 9;
      } else if (this.$tag === 10) {
        return other.$tag === 10;
      } else if (this.$tag === 11) {
        return other.$tag === 11;
      } else if (this.$tag === 12) {
        return other.$tag === 12;
      } else if (this.$tag === 13) {
        return other.$tag === 13;
      } else if (this.$tag === 14) {
        return other.$tag === 14;
      } else if (this.$tag === 15) {
        return other.$tag === 15;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Code.create_InvalidKeyConfig();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Code.Default();
        }
      };
    }
  }

  $module.Result = class Result {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ok(value) {
      let $dt = new Result(0);
      $dt.value = value;
      return $dt;
    }
    static create_Err(code, message) {
      let $dt = new Result(1);
      $dt.code = code;
      $dt.message = message;
      return $dt;
    }
    get is_Ok() { return this.$tag === 0; }
    get is_Err() { return this.$tag === 1; }
    get dtor_value() { return this.value; }
    get dtor_code() { return this.code; }
    get dtor_message() { return this.message; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Result.Ok" + "(" + _dafny.toString(this.value) + ")";
      } else if (this.$tag === 1) {
        return "EHBP.Result.Err" + "(" + _dafny.toString(this.code) + ", " + this.message.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.value, other.value);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.code, other.code) && _dafny.areEqual(this.message, other.message);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Result.create_Err(EHBP.Code.Default(), _dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return Result.Default();
        }
      };
    }
  }

  $module.Option = class Option {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_None() {
      let $dt = new Option(0);
      return $dt;
    }
    static create_Some(value) {
      let $dt = new Option(1);
      $dt.value = value;
      return $dt;
    }
    get is_None() { return this.$tag === 0; }
    get is_Some() { return this.$tag === 1; }
    get dtor_value() { return this.value; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Option.None";
      } else if (this.$tag === 1) {
        return "EHBP.Option.Some" + "(" + _dafny.toString(this.value) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.value, other.value);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Token = class Token {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Token(exportedSecret, requestEnc) {
      let $dt = new Token(0);
      $dt.exportedSecret = exportedSecret;
      $dt.requestEnc = requestEnc;
      return $dt;
    }
    get is_Token() { return this.$tag === 0; }
    get dtor_exportedSecret() { return this.exportedSecret; }
    get dtor_requestEnc() { return this.requestEnc; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Token.Token(<redacted>)";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.exportedSecret, other.exportedSecret) && _dafny.areEqual(this.requestEnc, other.requestEnc);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Token.create_Token(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Token.Default();
        }
      };
    }
  }

  $module.Framed = class Framed {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Framed(seqNo, ciphertext) {
      let $dt = new Framed(0);
      $dt.seqNo = seqNo;
      $dt.ciphertext = ciphertext;
      return $dt;
    }
    get is_Framed() { return this.$tag === 0; }
    get dtor_seqNo() { return this.seqNo; }
    get dtor_ciphertext() { return this.ciphertext; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Framed.Framed" + "(" + _dafny.toString(this.seqNo) + ", " + _dafny.toString(this.ciphertext) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.seqNo, other.seqNo) && _dafny.areEqual(this.ciphertext, other.ciphertext);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Framed.create_Framed(_dafny.ZERO, _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Framed.Default();
        }
      };
    }
  }

  $module.Head = class Head {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Head(status, headers, redirected) {
      let $dt = new Head(0);
      $dt.status = status;
      $dt.headers = headers;
      $dt.redirected = redirected;
      return $dt;
    }
    get is_Head() { return this.$tag === 0; }
    get dtor_status() { return this.status; }
    get dtor_headers() { return this.headers; }
    get dtor_redirected() { return this.redirected; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Head.Head" + "(" + _dafny.toString(this.status) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.redirected) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers) && this.redirected === other.redirected;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Head.create_Head(_dafny.ZERO, _dafny.Seq.of(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Head.Default();
        }
      };
    }
  }

  $module.Disposition = class Disposition {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PassThrough() {
      let $dt = new Disposition(0);
      return $dt;
    }
    static create_Decrypt(nonce, requireFrame) {
      let $dt = new Disposition(1);
      $dt.nonce = nonce;
      $dt.requireFrame = requireFrame;
      return $dt;
    }
    static create_NeedProblemBody() {
      let $dt = new Disposition(2);
      return $dt;
    }
    static create_Refuse(code, message) {
      let $dt = new Disposition(3);
      $dt.code = code;
      $dt.message = message;
      return $dt;
    }
    get is_PassThrough() { return this.$tag === 0; }
    get is_Decrypt() { return this.$tag === 1; }
    get is_NeedProblemBody() { return this.$tag === 2; }
    get is_Refuse() { return this.$tag === 3; }
    get dtor_nonce() { return this.nonce; }
    get dtor_requireFrame() { return this.requireFrame; }
    get dtor_code() { return this.code; }
    get dtor_message() { return this.message; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Disposition.PassThrough";
      } else if (this.$tag === 1) {
        return "EHBP.Disposition.Decrypt" + "(" + _dafny.toString(this.nonce) + ", " + _dafny.toString(this.requireFrame) + ")";
      } else if (this.$tag === 2) {
        return "EHBP.Disposition.NeedProblemBody";
      } else if (this.$tag === 3) {
        return "EHBP.Disposition.Refuse" + "(" + _dafny.toString(this.code) + ", " + this.message.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.nonce, other.nonce) && this.requireFrame === other.requireFrame;
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.code, other.code) && _dafny.areEqual(this.message, other.message);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Disposition.create_PassThrough();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Disposition.Default();
        }
      };
    }
  }

  $module.Origin = class Origin {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Origin(scheme, host, port) {
      let $dt = new Origin(0);
      $dt.scheme = scheme;
      $dt.host = host;
      $dt.port = port;
      return $dt;
    }
    get is_Origin() { return this.$tag === 0; }
    get dtor_scheme() { return this.scheme; }
    get dtor_host() { return this.host; }
    get dtor_port() { return this.port; }
    toString() {
      if (this.$tag === 0) {
        return "EHBP.Origin.Origin" + "(" + this.scheme.toVerbatimString(true) + ", " + this.host.toVerbatimString(true) + ", " + _dafny.toString(this.port) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.scheme, other.scheme) && _dafny.areEqual(this.host, other.host) && _dafny.areEqual(this.port, other.port);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBP.Origin.create_Origin(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Origin.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module EHBP
let EHBPEvents = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "EHBPEvents._default";
    }
    _parentTraits() {
      return [];
    }
    static Terminal(a) {
      return (((((a).is_Fail) || ((a).is_Finished)) || ((a).is_Passthrough)) || ((a).is_Discovered)) || ((a).is_Close);
    };
    static Ends(acts) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acts).length)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((acts).length)))) && (EHBPEvents.__default.Terminal((acts)[_0_i]));
      });
    };
    static NoClear(acts) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acts).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((acts).length)))) || (!(((acts)[_0_i]).is_ClearToken));
      });
    };
    static ClearsOnce(acts, g) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acts).length)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return ((((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((acts).length)))) && (_dafny.areEqual((acts)[_0_i], EHBPEvents.Action.create_ClearToken(g)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acts).length)), true, function (_forall_var_0) {
          let _1_j = _forall_var_0;
          return !((((_dafny.ZERO).isLessThanOrEqualTo(_1_j)) && ((_1_j).isLessThan(new BigNumber((acts).length)))) && (!(_1_j).isEqualTo(_0_i))) || (!(((acts)[_1_j]).is_ClearToken));
        }));
      });
    };
    static NoEmit(acts) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acts).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((acts).length)))) || (!(((acts)[_0_i]).is_EmitPlaintext));
      });
    };
    static Perform(p, a) {
      let r = EHBPEvents.Performed.Default();
      let _source0 = a;
      Lmatch0: {
        {
          if (_source0.is_BeginSession) {
            let _0_generation;
            let _out0;
            _out0 = (p).BeginSession();
            _0_generation = _out0;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_SessionBegun(_0_generation));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_PublishToken) {
            let _1_generation = (_source0).generation;
            let _2_exportedSecret = (_source0).exportedSecret;
            let _3_requestEnc = (_source0).requestEnc;
            (p).PublishToken(_1_generation, _2_exportedSecret, _3_requestEnc);
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_ClearToken) {
            let _4_generation = (_source0).generation;
            (p).ClearToken(_4_generation);
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_RandomBytes) {
            let _5_length = (_source0).length;
            let _6_data;
            let _out1;
            _out1 = (p).RandomBytes(_5_length);
            _6_data = _out1;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_RandomResult(_6_data));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_X25519) {
            let _7_scalar = (_source0).scalar;
            let _8_point = (_source0).point;
            let _9_shared;
            let _out2;
            _out2 = (p).X25519(_7_scalar, _8_point);
            _9_shared = _out2;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_X25519Result(_9_shared));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_HmacSha256) {
            let _10_key = (_source0).key;
            let _11_data = (_source0).data;
            let _12_mac;
            let _out3;
            _out3 = (p).HmacSha256(_10_key, _11_data);
            _12_mac = _out3;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_HmacResult(_12_mac));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_AeadSeal) {
            let _13_key = (_source0).key;
            let _14_nonce = (_source0).nonce;
            let _15_plaintext = (_source0).plaintext;
            let _16_ciphertext;
            let _out4;
            _out4 = (p).AeadSeal(_13_key, _14_nonce, _15_plaintext);
            _16_ciphertext = _out4;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_AeadSealResult(_16_ciphertext));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_AeadOpen) {
            let _17_key = (_source0).key;
            let _18_nonce = (_source0).nonce;
            let _19_ciphertext = (_source0).ciphertext;
            let _20_ok;
            let _21_plaintext;
            let _out5;
            let _out6;
            let _outcollector0 = (p).AeadOpen(_17_key, _18_nonce, _19_ciphertext);
            _out5 = _outcollector0[0];
            _out6 = _outcollector0[1];
            _20_ok = _out5;
            _21_plaintext = _out6;
            r = EHBPEvents.Performed.create_Got(EHBPEvents.Event.create_AeadOpenResult(_20_ok, _21_plaintext));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Send) {
            let _22_verb = (_source0).verb;
            let _23_url = (_source0).url;
            let _24_headers = (_source0).headers;
            let _25_hasBody = (_source0).hasBody;
            let _26_ok;
            let _27_status;
            let _28_head;
            let _29_redirected;
            let _out7;
            let _out8;
            let _out9;
            let _out10;
            let _outcollector1 = (p).Send(_22_verb, _23_url, _24_headers, _25_hasBody);
            _out7 = _outcollector1[0];
            _out8 = _outcollector1[1];
            _out9 = _outcollector1[2];
            _out10 = _outcollector1[3];
            _26_ok = _out7;
            _27_status = _out8;
            _28_head = _out9;
            _29_redirected = _out10;
            r = EHBPEvents.Performed.create_Got(((_26_ok) ? (EHBPEvents.Event.create_ResponseHead(_27_status, _28_head, _29_redirected)) : (EHBPEvents.Event.create_StreamFailed(EHBPEvents.Stream.create_ResponseBody()))));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Write) {
            let _30_data = (_source0).data;
            let _31_end = (_source0).end;
            let _32_ok;
            let _out11;
            _out11 = (p).Write(_30_data, _31_end);
            _32_ok = _out11;
            if (_32_ok) {
              r = EHBPEvents.Performed.create_Quiet();
            } else {
              r = EHBPEvents.Performed.create_Stop();
            }
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Read) {
            let _33_stream = (_source0).stream;
            let _34_ok;
            let _35_data;
            let _36_eof;
            let _out12;
            let _out13;
            let _out14;
            let _outcollector2 = (p).Read(_33_stream);
            _out12 = _outcollector2[0];
            _out13 = _outcollector2[1];
            _out14 = _outcollector2[2];
            _34_ok = _out12;
            _35_data = _out13;
            _36_eof = _out14;
            r = EHBPEvents.Performed.create_Got(((_34_ok) ? (EHBPEvents.Event.create_Chunk(_33_stream, _35_data, _36_eof)) : (EHBPEvents.Event.create_StreamFailed(_33_stream))));
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Close) {
            let _37_stream = (_source0).stream;
            (p).Close(_37_stream);
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_EmitPlaintext) {
            let _38_data = (_source0).data;
            (p).EmitPlaintext(_38_data);
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Passthrough) {
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Done) {
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Finished) {
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_Discovered) {
            r = EHBPEvents.Performed.create_Quiet();
            return r;
            break Lmatch0;
          }
        }
        {
          r = EHBPEvents.Performed.create_Quiet();
          return r;
        }
      }
      return r;
    }
    static Extract(salt, ikm) {
      return EHBPEvents.Job.create_JExtract(salt, ikm);
    };
    static Expand(prk, info, length) {
      return EHBPEvents.Job.create_JExpand(prk, info, length, _dafny.Seq.of(), _dafny.Seq.of(), 1);
    };
    static JobAction(j) {
      let _source0 = j;
      {
        if (_source0.is_JExtract) {
          let _0_salt = (_source0).salt;
          let _1_ikm = (_source0).ikm;
          return EHBPEvents.Action.create_HmacSha256(_0_salt, _1_ikm);
        }
      }
      {
        let _2_prk = (_source0).prk;
        let _3_info = (_source0).info;
        let _4_prev = (_source0).prev;
        let _5_i = (_source0).i;
        return EHBPEvents.Action.create_HmacSha256(_2_prk, _dafny.Seq.Concat(_dafny.Seq.Concat(_4_prev, _3_info), _dafny.Seq.of(_5_i)));
      }
    };
    static JobStep(j, e) {
      if (!((e).is_HmacResult)) {
        return EHBPEvents.JobOut.create_JobFailed(EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unexpected event"));
      } else if (!(new BigNumber(((e).dtor_mac).length)).isEqualTo(EHBP.__default.HashLength)) {
        return EHBPEvents.JobOut.create_JobFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("HMAC returned the wrong length"));
      } else {
        let _source0 = j;
        {
          if (_source0.is_JExtract) {
            return EHBPEvents.JobOut.create_Output((e).dtor_mac);
          }
        }
        {
          let _0_prk = (_source0).prk;
          let _1_info = (_source0).info;
          let _2_length = (_source0).length;
          let _3_acc = (_source0).acc;
          let _4_i = (_source0).i;
          let _5_grown = _dafny.Seq.Concat(_3_acc, (e).dtor_mac);
          if ((_2_length).isLessThanOrEqualTo(new BigNumber((_5_grown).length))) {
            return EHBPEvents.JobOut.create_Output((_5_grown).slice(0, _2_length));
          } else if ((_4_i) === (255)) {
            return EHBPEvents.JobOut.create_JobFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("HKDF expand length too large"));
          } else {
            let _6_next = EHBPEvents.Job.create_JExpand(_0_prk, _1_info, _2_length, _5_grown, (e).dtor_mac, (_4_i) + (1));
            return EHBPEvents.JobOut.create_Pending(_6_next, EHBPEvents.__default.JobAction(_6_next));
          }
        }
      }
    };
    static Repeat(n, v) {
      return _dafny.Seq.Create(n, ((_0_v) => function (_1_i) {
        return _0_v;
      })(v));
    };
    static Iota(n) {
      return _dafny.Seq.Create(n, ((_0_n) => function (_1_i) {
        return (_1_i).toNumber();
      })(n));
    };
    static LabeledExtract(suite, salt, tag, ikm) {
      return EHBPEvents.__default.Extract(salt, _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(EHBPEvents.__default.HpkeVersion, suite), EHBP.__default.Ascii(tag)), ikm));
    };
    static LabeledExpand(suite, prk, tag, info, length) {
      return EHBPEvents.__default.Expand(prk, _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(EHBP.__default.BE16((length).toNumber()), EHBPEvents.__default.HpkeVersion), suite), EHBP.__default.Ascii(tag)), info), length);
    };
    static SenderStart(pkR, info) {
      return EHBPEvents.HpkeOut.create_HContinue(EHBPEvents.Hpke.create_HRandom(pkR, info), EHBPEvents.Action.create_RandomBytes(new BigNumber(32)));
    };
    static RecipientStart(skR, pkR, enc, info) {
      return EHBPEvents.HpkeOut.create_HContinue(EHBPEvents.Hpke.create_HDh(enc, pkR, info), EHBPEvents.Action.create_X25519(skR, enc));
    };
    static Schedule(h, job) {
      let _pat_let_tv0 = job;
      return EHBPEvents.HpkeOut.create_HContinue(function (_pat_let1_0) {
  return function (_0_dt__update__tmp_h0) {
    return function (_pat_let2_0) {
      return function (_1_dt__update_hjob_h0) {
        return EHBPEvents.Hpke.create_HSchedule((_0_dt__update__tmp_h0).dtor_stage, _1_dt__update_hjob_h0, (_0_dt__update__tmp_h0).dtor_enc, (_0_dt__update__tmp_h0).dtor_pkR, (_0_dt__update__tmp_h0).dtor_info, (_0_dt__update__tmp_h0).dtor_shared, (_0_dt__update__tmp_h0).dtor_pskIdHash, (_0_dt__update__tmp_h0).dtor_infoHash, (_0_dt__update__tmp_h0).dtor_secret, (_0_dt__update__tmp_h0).dtor_key, (_0_dt__update__tmp_h0).dtor_baseNonce);
      }(_pat_let2_0);
    }(_pat_let_tv0);
  }(_pat_let1_0);
}(h), EHBPEvents.__default.JobAction(job));
    };
    static HpkeStep(h, e) {
      let _source0 = h;
      {
        if (_source0.is_HRandom) {
          let _0_pkR = (_source0).pkR;
          let _1_info = (_source0).info;
          if (!((e).is_RandomResult)) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unexpected event"));
          } else if (!(new BigNumber(((e).dtor_data).length)).isEqualTo(new BigNumber(32))) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("random bytes have the wrong length"));
          } else {
            return EHBPEvents.HpkeOut.create_HContinue(EHBPEvents.Hpke.create_HEnc((e).dtor_data, _0_pkR, _1_info), EHBPEvents.Action.create_X25519((e).dtor_data, EHBPEvents.__default.BasePoint));
          }
        }
      }
      {
        if (_source0.is_HEnc) {
          let _2_skE = (_source0).skE;
          let _3_pkR = (_source0).pkR;
          let _4_info = (_source0).info;
          if (!((e).is_X25519Result)) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unexpected event"));
          } else if (!(new BigNumber(((e).dtor_point).length)).isEqualTo(new BigNumber(32))) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("X25519 failed"));
          } else {
            return EHBPEvents.HpkeOut.create_HContinue(EHBPEvents.Hpke.create_HDh((e).dtor_point, _3_pkR, _4_info), EHBPEvents.Action.create_X25519(_2_skE, _3_pkR));
          }
        }
      }
      {
        if (_source0.is_HDh) {
          let _5_enc = (_source0).enc;
          let _6_pkR = (_source0).pkR;
          let _7_info = (_source0).info;
          if (!((e).is_X25519Result)) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unexpected event"));
          } else if (!(new BigNumber(((e).dtor_point).length)).isEqualTo(new BigNumber(32))) {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("X25519 failed"));
          } else {
            return EHBPEvents.__default.Schedule(EHBPEvents.Hpke.create_HSchedule(_dafny.ZERO, EHBPEvents.__default.Extract(_dafny.Seq.of(), _dafny.Seq.of()), _5_enc, _6_pkR, _7_info, _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of()), EHBPEvents.__default.LabeledExtract(EHBPEvents.__default.KemSuiteId, _dafny.Seq.of(), _dafny.Seq.UnicodeFromString("eae_prk"), (e).dtor_point));
          }
        }
      }
      {
        let _8_stage = (_source0).stage;
        let _9_job = (_source0).job;
        let _10_enc = (_source0).enc;
        let _11_pkR = (_source0).pkR;
        let _12_info = (_source0).info;
        let _13_shared = (_source0).shared;
        let _14_pskIdHash = (_source0).pskIdHash;
        let _15_infoHash = (_source0).infoHash;
        let _16_secret = (_source0).secret;
        let _17_key = (_source0).key;
        let _18_baseNonce = (_source0).baseNonce;
        let _source1 = EHBPEvents.__default.JobStep(_9_job, e);
        {
          if (_source1.is_JobFailed) {
            let _19_code = (_source1).code;
            let _20_message = (_source1).message;
            return EHBPEvents.HpkeOut.create_HFailed(_19_code, _20_message);
          }
        }
        {
          if (_source1.is_Pending) {
            let _21_next = (_source1).job;
            let _22_action = (_source1).action;
            return EHBPEvents.HpkeOut.create_HContinue(function (_pat_let3_0) {
  return function (_23_dt__update__tmp_h0) {
    return function (_pat_let4_0) {
      return function (_24_dt__update_hjob_h0) {
        return EHBPEvents.Hpke.create_HSchedule((_23_dt__update__tmp_h0).dtor_stage, _24_dt__update_hjob_h0, (_23_dt__update__tmp_h0).dtor_enc, (_23_dt__update__tmp_h0).dtor_pkR, (_23_dt__update__tmp_h0).dtor_info, (_23_dt__update__tmp_h0).dtor_shared, (_23_dt__update__tmp_h0).dtor_pskIdHash, (_23_dt__update__tmp_h0).dtor_infoHash, (_23_dt__update__tmp_h0).dtor_secret, (_23_dt__update__tmp_h0).dtor_key, (_23_dt__update__tmp_h0).dtor_baseNonce);
      }(_pat_let4_0);
    }(_21_next);
  }(_pat_let3_0);
}(h), _22_action);
          }
        }
        {
          let _25_out = (_source1).data;
          let _26_ksc = _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(0), _14_pskIdHash), _15_infoHash);
          if ((_8_stage).isEqualTo(_dafny.ZERO)) {
            return EHBPEvents.__default.Schedule(function (_pat_let5_0) {
              return function (_27_dt__update__tmp_h1) {
                return function (_pat_let6_0) {
                  return function (_28_dt__update_hstage_h0) {
                    return EHBPEvents.Hpke.create_HSchedule(_28_dt__update_hstage_h0, (_27_dt__update__tmp_h1).dtor_job, (_27_dt__update__tmp_h1).dtor_enc, (_27_dt__update__tmp_h1).dtor_pkR, (_27_dt__update__tmp_h1).dtor_info, (_27_dt__update__tmp_h1).dtor_shared, (_27_dt__update__tmp_h1).dtor_pskIdHash, (_27_dt__update__tmp_h1).dtor_infoHash, (_27_dt__update__tmp_h1).dtor_secret, (_27_dt__update__tmp_h1).dtor_key, (_27_dt__update__tmp_h1).dtor_baseNonce);
                  }(_pat_let6_0);
                }(_dafny.ONE);
              }(_pat_let5_0);
            }(h), EHBPEvents.__default.LabeledExpand(EHBPEvents.__default.KemSuiteId, _25_out, _dafny.Seq.UnicodeFromString("shared_secret"), _dafny.Seq.Concat(_10_enc, _11_pkR), EHBP.__default.HashLength));
          } else if ((_8_stage).isEqualTo(_dafny.ONE)) {
            return EHBPEvents.__default.Schedule(function (_pat_let7_0) {
              return function (_29_dt__update__tmp_h2) {
                return function (_pat_let8_0) {
                  return function (_30_dt__update_hshared_h0) {
                    return function (_pat_let9_0) {
                      return function (_31_dt__update_hstage_h1) {
                        return EHBPEvents.Hpke.create_HSchedule(_31_dt__update_hstage_h1, (_29_dt__update__tmp_h2).dtor_job, (_29_dt__update__tmp_h2).dtor_enc, (_29_dt__update__tmp_h2).dtor_pkR, (_29_dt__update__tmp_h2).dtor_info, _30_dt__update_hshared_h0, (_29_dt__update__tmp_h2).dtor_pskIdHash, (_29_dt__update__tmp_h2).dtor_infoHash, (_29_dt__update__tmp_h2).dtor_secret, (_29_dt__update__tmp_h2).dtor_key, (_29_dt__update__tmp_h2).dtor_baseNonce);
                      }(_pat_let9_0);
                    }(new BigNumber(2));
                  }(_pat_let8_0);
                }(_25_out);
              }(_pat_let7_0);
            }(h), EHBPEvents.__default.LabeledExtract(EHBPEvents.__default.HpkeSuiteId, _dafny.Seq.of(), _dafny.Seq.UnicodeFromString("psk_id_hash"), _dafny.Seq.of()));
          } else if ((_8_stage).isEqualTo(new BigNumber(2))) {
            return EHBPEvents.__default.Schedule(function (_pat_let10_0) {
              return function (_32_dt__update__tmp_h3) {
                return function (_pat_let11_0) {
                  return function (_33_dt__update_hpskIdHash_h0) {
                    return function (_pat_let12_0) {
                      return function (_34_dt__update_hstage_h2) {
                        return EHBPEvents.Hpke.create_HSchedule(_34_dt__update_hstage_h2, (_32_dt__update__tmp_h3).dtor_job, (_32_dt__update__tmp_h3).dtor_enc, (_32_dt__update__tmp_h3).dtor_pkR, (_32_dt__update__tmp_h3).dtor_info, (_32_dt__update__tmp_h3).dtor_shared, _33_dt__update_hpskIdHash_h0, (_32_dt__update__tmp_h3).dtor_infoHash, (_32_dt__update__tmp_h3).dtor_secret, (_32_dt__update__tmp_h3).dtor_key, (_32_dt__update__tmp_h3).dtor_baseNonce);
                      }(_pat_let12_0);
                    }(new BigNumber(3));
                  }(_pat_let11_0);
                }(_25_out);
              }(_pat_let10_0);
            }(h), EHBPEvents.__default.LabeledExtract(EHBPEvents.__default.HpkeSuiteId, _dafny.Seq.of(), _dafny.Seq.UnicodeFromString("info_hash"), _12_info));
          } else if ((_8_stage).isEqualTo(new BigNumber(3))) {
            return EHBPEvents.__default.Schedule(function (_pat_let13_0) {
              return function (_35_dt__update__tmp_h4) {
                return function (_pat_let14_0) {
                  return function (_36_dt__update_hinfoHash_h0) {
                    return function (_pat_let15_0) {
                      return function (_37_dt__update_hstage_h3) {
                        return EHBPEvents.Hpke.create_HSchedule(_37_dt__update_hstage_h3, (_35_dt__update__tmp_h4).dtor_job, (_35_dt__update__tmp_h4).dtor_enc, (_35_dt__update__tmp_h4).dtor_pkR, (_35_dt__update__tmp_h4).dtor_info, (_35_dt__update__tmp_h4).dtor_shared, (_35_dt__update__tmp_h4).dtor_pskIdHash, _36_dt__update_hinfoHash_h0, (_35_dt__update__tmp_h4).dtor_secret, (_35_dt__update__tmp_h4).dtor_key, (_35_dt__update__tmp_h4).dtor_baseNonce);
                      }(_pat_let15_0);
                    }(new BigNumber(4));
                  }(_pat_let14_0);
                }(_25_out);
              }(_pat_let13_0);
            }(h), EHBPEvents.__default.LabeledExtract(EHBPEvents.__default.HpkeSuiteId, _13_shared, _dafny.Seq.UnicodeFromString("secret"), _dafny.Seq.of()));
          } else if ((_8_stage).isEqualTo(new BigNumber(4))) {
            return EHBPEvents.__default.Schedule(function (_pat_let16_0) {
              return function (_38_dt__update__tmp_h5) {
                return function (_pat_let17_0) {
                  return function (_39_dt__update_hsecret_h0) {
                    return function (_pat_let18_0) {
                      return function (_40_dt__update_hstage_h4) {
                        return EHBPEvents.Hpke.create_HSchedule(_40_dt__update_hstage_h4, (_38_dt__update__tmp_h5).dtor_job, (_38_dt__update__tmp_h5).dtor_enc, (_38_dt__update__tmp_h5).dtor_pkR, (_38_dt__update__tmp_h5).dtor_info, (_38_dt__update__tmp_h5).dtor_shared, (_38_dt__update__tmp_h5).dtor_pskIdHash, (_38_dt__update__tmp_h5).dtor_infoHash, _39_dt__update_hsecret_h0, (_38_dt__update__tmp_h5).dtor_key, (_38_dt__update__tmp_h5).dtor_baseNonce);
                      }(_pat_let18_0);
                    }(new BigNumber(5));
                  }(_pat_let17_0);
                }(_25_out);
              }(_pat_let16_0);
            }(h), EHBPEvents.__default.LabeledExpand(EHBPEvents.__default.HpkeSuiteId, _25_out, _dafny.Seq.UnicodeFromString("key"), _26_ksc, EHBP.__default.KeyLength));
          } else if ((_8_stage).isEqualTo(new BigNumber(5))) {
            return EHBPEvents.__default.Schedule(function (_pat_let19_0) {
              return function (_41_dt__update__tmp_h6) {
                return function (_pat_let20_0) {
                  return function (_42_dt__update_hkey_h0) {
                    return function (_pat_let21_0) {
                      return function (_43_dt__update_hstage_h5) {
                        return EHBPEvents.Hpke.create_HSchedule(_43_dt__update_hstage_h5, (_41_dt__update__tmp_h6).dtor_job, (_41_dt__update__tmp_h6).dtor_enc, (_41_dt__update__tmp_h6).dtor_pkR, (_41_dt__update__tmp_h6).dtor_info, (_41_dt__update__tmp_h6).dtor_shared, (_41_dt__update__tmp_h6).dtor_pskIdHash, (_41_dt__update__tmp_h6).dtor_infoHash, (_41_dt__update__tmp_h6).dtor_secret, _42_dt__update_hkey_h0, (_41_dt__update__tmp_h6).dtor_baseNonce);
                      }(_pat_let21_0);
                    }(new BigNumber(6));
                  }(_pat_let20_0);
                }(_25_out);
              }(_pat_let19_0);
            }(h), EHBPEvents.__default.LabeledExpand(EHBPEvents.__default.HpkeSuiteId, _16_secret, _dafny.Seq.UnicodeFromString("base_nonce"), _26_ksc, EHBP.__default.NonceLength));
          } else if ((_8_stage).isEqualTo(new BigNumber(6))) {
            return EHBPEvents.__default.Schedule(function (_pat_let22_0) {
              return function (_44_dt__update__tmp_h7) {
                return function (_pat_let23_0) {
                  return function (_45_dt__update_hbaseNonce_h0) {
                    return function (_pat_let24_0) {
                      return function (_46_dt__update_hstage_h6) {
                        return EHBPEvents.Hpke.create_HSchedule(_46_dt__update_hstage_h6, (_44_dt__update__tmp_h7).dtor_job, (_44_dt__update__tmp_h7).dtor_enc, (_44_dt__update__tmp_h7).dtor_pkR, (_44_dt__update__tmp_h7).dtor_info, (_44_dt__update__tmp_h7).dtor_shared, (_44_dt__update__tmp_h7).dtor_pskIdHash, (_44_dt__update__tmp_h7).dtor_infoHash, (_44_dt__update__tmp_h7).dtor_secret, (_44_dt__update__tmp_h7).dtor_key, _45_dt__update_hbaseNonce_h0);
                      }(_pat_let24_0);
                    }(new BigNumber(7));
                  }(_pat_let23_0);
                }(_25_out);
              }(_pat_let22_0);
            }(h), EHBPEvents.__default.LabeledExpand(EHBPEvents.__default.HpkeSuiteId, _16_secret, _dafny.Seq.UnicodeFromString("exp"), _26_ksc, EHBP.__default.HashLength));
          } else if ((((_8_stage).isEqualTo(new BigNumber(7))) && ((new BigNumber((_17_key).length)).isEqualTo(EHBP.__default.KeyLength))) && ((new BigNumber((_18_baseNonce).length)).isEqualTo(EHBP.__default.NonceLength))) {
            let _47_k = _17_key;
            let _48_n = _18_baseNonce;
            return EHBPEvents.HpkeOut.create_HReady(EHBPEvents.Ctx.create_Ctx(_47_k, _48_n, _25_out, _dafny.ZERO), _10_enc);
          } else {
            return EHBPEvents.HpkeOut.create_HFailed(EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("key schedule produced the wrong lengths"));
          }
        }
      }
    };
    static SealAction(ctx, plaintext) {
      return EHBPEvents.Action.create_AeadSeal((ctx).dtor_key, EHBP.__default.ComputeNonce((ctx).dtor_baseNonce, (ctx).dtor_seqNo), plaintext);
    };
    static OpenAction(ctx, ciphertext) {
      return EHBPEvents.Action.create_AeadOpen((ctx).dtor_key, EHBP.__default.ComputeNonce((ctx).dtor_baseNonce, (ctx).dtor_seqNo), ciphertext);
    };
    static Bump(ctx) {
      let _0_dt__update__tmp_h0 = ctx;
      let _1_dt__update_hseqNo_h0 = ((ctx).dtor_seqNo).plus(_dafny.ONE);
      return EHBPEvents.Ctx.create_Ctx((_0_dt__update__tmp_h0).dtor_key, (_0_dt__update__tmp_h0).dtor_baseNonce, (_0_dt__update__tmp_h0).dtor_exporterSecret, _1_dt__update_hseqNo_h0);
    };
    static ExportJob(ctx, context, length) {
      return EHBPEvents.__default.LabeledExpand(EHBPEvents.__default.HpkeSuiteId, (ctx).dtor_exporterSecret, _dafny.Seq.UnicodeFromString("sec"), context, length);
    };
    static JsonWs(c) {
      return (((_dafny.areEqual(c, new _dafny.CodePoint(' '.codePointAt(0)))) || (_dafny.areEqual(c, new _dafny.CodePoint('\t'.codePointAt(0))))) || (_dafny.areEqual(c, new _dafny.CodePoint('\n'.codePointAt(0))))) || (_dafny.areEqual(c, new _dafny.CodePoint('\r'.codePointAt(0))));
    };
    static IsDigit(c) {
      return ((new _dafny.CodePoint('0'.codePointAt(0))).isLessThanOrEqual(c)) && ((c).isLessThanOrEqual(new _dafny.CodePoint('9'.codePointAt(0))));
    };
    static SkipWs(s, i) {
      TAIL_CALL_START: while (true) {
        if (((i).isLessThan(new BigNumber((s).length))) && (EHBPEvents.__default.JsonWs((s)[i]))) {
          let _in0 = s;
          let _in1 = (i).plus(_dafny.ONE);
          s = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        } else {
          return i;
        }
      }
    };
    static Digits(s, i) {
      TAIL_CALL_START: while (true) {
        if (((i).isLessThan(new BigNumber((s).length))) && (EHBPEvents.__default.IsDigit((s)[i]))) {
          let _in0 = s;
          let _in1 = (i).plus(_dafny.ONE);
          s = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        } else {
          return i;
        }
      }
    };
    static Hex4(s, i) {
      if ((new BigNumber((s).length)).isLessThan((i).plus(new BigNumber(4)))) {
        return EHBP.Option.create_None();
      } else {
        let _source0 = _dafny.Tuple.of(EHBP.__default.HexDigitValue((s)[i]), EHBP.__default.HexDigitValue((s)[(i).plus(_dafny.ONE)]), EHBP.__default.HexDigitValue((s)[(i).plus(new BigNumber(2))]), EHBP.__default.HexDigitValue((s)[(i).plus(new BigNumber(3))]));
        {
          let _00 = (_source0)[0];
          if (_00.is_Some) {
            let _0_a = (_00).value;
            let _10 = (_source0)[1];
            if (_10.is_Some) {
              let _1_b = (_10).value;
              let _20 = (_source0)[2];
              if (_20.is_Some) {
                let _2_c = (_20).value;
                let _30 = (_source0)[3];
                if (_30.is_Some) {
                  let _3_d = (_30).value;
                  return EHBP.Option.create_Some(((((new BigNumber(_0_a)).multipliedBy(new BigNumber(4096))).plus((new BigNumber(_1_b)).multipliedBy(new BigNumber(256)))).plus((new BigNumber(_2_c)).multipliedBy(new BigNumber(16)))).plus(new BigNumber(_3_d)));
                }
              }
            }
          }
        }
        {
          return EHBP.Option.create_None();
        }
      }
    };
    static Keep(acc, add) {
      if ((EHBPEvents.__default.MaxJsonStringChars).isLessThanOrEqualTo(new BigNumber((acc).length))) {
        return acc;
      } else if (((new BigNumber((acc).length)).plus(new BigNumber((add).length))).isLessThanOrEqualTo(EHBPEvents.__default.MaxJsonStringChars)) {
        return _dafny.Seq.Concat(acc, add);
      } else {
        return _dafny.Seq.Concat(acc, (add).slice(0, (EHBPEvents.__default.MaxJsonStringChars).minus(new BigNumber((acc).length))));
      }
    };
    static Max(a, b) {
      if ((b).isLessThanOrEqualTo(a)) {
        return a;
      } else {
        return b;
      }
    };
    static LiteralEnd(s, i) {
      TAIL_CALL_START: while (true) {
        if (((((i).isEqualTo(new BigNumber((s).length))) || (_dafny.areEqual((s)[i], new _dafny.CodePoint('"'.codePointAt(0))))) || (_dafny.areEqual((s)[i], new _dafny.CodePoint('\\'.codePointAt(0))))) || ((new BigNumber(((s)[i]).value)).isLessThan(new BigNumber(32)))) {
          return i;
        } else {
          let _in0 = s;
          let _in1 = (i).plus(_dafny.ONE);
          s = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static ParseString(s, i, acc) {
      TAIL_CALL_START: while (true) {
        let _0_j = EHBPEvents.__default.LiteralEnd(s, i);
        let _1_run = EHBPEvents.__default.Keep(acc, (s).slice(i, _0_j));
        if ((_0_j).isEqualTo(new BigNumber((s).length))) {
          return EHBP.Option.create_None();
        } else if (_dafny.areEqual((s)[_0_j], new _dafny.CodePoint('"'.codePointAt(0)))) {
          return EHBP.Option.create_Some(_dafny.Tuple.of(_1_run, (_0_j).plus(_dafny.ONE)));
        } else if ((new BigNumber(((s)[_0_j]).value)).isLessThan(new BigNumber(32))) {
          return EHBP.Option.create_None();
        } else if (((_0_j).plus(_dafny.ONE)).isEqualTo(new BigNumber((s).length))) {
          return EHBP.Option.create_None();
        } else {
          let _2_c = (s)[(_0_j).plus(_dafny.ONE)];
          if (((_dafny.areEqual(_2_c, new _dafny.CodePoint('"'.codePointAt(0)))) || (_dafny.areEqual(_2_c, new _dafny.CodePoint('\\'.codePointAt(0))))) || (_dafny.areEqual(_2_c, new _dafny.CodePoint('/'.codePointAt(0))))) {
            let _in0 = s;
            let _in1 = (_0_j).plus(new BigNumber(2));
            let _in2 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(_2_c));
            s = _in0;
            i = _in1;
            acc = _in2;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_2_c, new _dafny.CodePoint('b'.codePointAt(0)))) {
            let _in3 = s;
            let _in4 = (_0_j).plus(new BigNumber(2));
            let _in5 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(8)).toNumber())));
            s = _in3;
            i = _in4;
            acc = _in5;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_2_c, new _dafny.CodePoint('f'.codePointAt(0)))) {
            let _in6 = s;
            let _in7 = (_0_j).plus(new BigNumber(2));
            let _in8 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(12)).toNumber())));
            s = _in6;
            i = _in7;
            acc = _in8;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_2_c, new _dafny.CodePoint('n'.codePointAt(0)))) {
            let _in9 = s;
            let _in10 = (_0_j).plus(new BigNumber(2));
            let _in11 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint('\n'.codePointAt(0))));
            s = _in9;
            i = _in10;
            acc = _in11;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_2_c, new _dafny.CodePoint('r'.codePointAt(0)))) {
            let _in12 = s;
            let _in13 = (_0_j).plus(new BigNumber(2));
            let _in14 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint('\r'.codePointAt(0))));
            s = _in12;
            i = _in13;
            acc = _in14;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_2_c, new _dafny.CodePoint('t'.codePointAt(0)))) {
            let _in15 = s;
            let _in16 = (_0_j).plus(new BigNumber(2));
            let _in17 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint('\t'.codePointAt(0))));
            s = _in15;
            i = _in16;
            acc = _in17;
            continue TAIL_CALL_START;
          } else if (!_dafny.areEqual(_2_c, new _dafny.CodePoint('u'.codePointAt(0)))) {
            return EHBP.Option.create_None();
          } else {
            let _source0 = EHBPEvents.__default.Hex4(s, (_0_j).plus(new BigNumber(2)));
            {
              if (_source0.is_None) {
                return EHBP.Option.create_None();
              }
            }
            {
              let _3_cp = (_source0).value;
              if (((new BigNumber(55296)).isLessThanOrEqualTo(_3_cp)) && ((_3_cp).isLessThanOrEqualTo(new BigNumber(56319)))) {
                let _4_lo = ((((((_0_j).plus(new BigNumber(8))).isLessThanOrEqualTo(new BigNumber((s).length))) && (_dafny.areEqual((s)[(_0_j).plus(new BigNumber(6))], new _dafny.CodePoint('\\'.codePointAt(0))))) && (_dafny.areEqual((s)[(_0_j).plus(new BigNumber(7))], new _dafny.CodePoint('u'.codePointAt(0))))) ? (EHBPEvents.__default.Hex4(s, (_0_j).plus(new BigNumber(8)))) : (EHBP.Option.create_None()));
                if (((_4_lo).is_Some) && (((new BigNumber(56320)).isLessThanOrEqualTo((_4_lo).dtor_value)) && (((_4_lo).dtor_value).isLessThanOrEqualTo(new BigNumber(57343))))) {
                  let _in18 = s;
                  let _in19 = (_0_j).plus(new BigNumber(12));
                  let _in20 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((((new BigNumber(65536)).plus(((_3_cp).minus(new BigNumber(55296))).multipliedBy(new BigNumber(1024)))).plus(((_4_lo).dtor_value).minus(new BigNumber(56320)))).toNumber())));
                  s = _in18;
                  i = _in19;
                  acc = _in20;
                  continue TAIL_CALL_START;
                } else {
                  let _in21 = s;
                  let _in22 = (_0_j).plus(new BigNumber(6));
                  let _in23 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(65533)).toNumber())));
                  s = _in21;
                  i = _in22;
                  acc = _in23;
                  continue TAIL_CALL_START;
                }
              } else if (((new BigNumber(56320)).isLessThanOrEqualTo(_3_cp)) && ((_3_cp).isLessThanOrEqualTo(new BigNumber(57343)))) {
                let _in24 = s;
                let _in25 = (_0_j).plus(new BigNumber(6));
                let _in26 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(65533)).toNumber())));
                s = _in24;
                i = _in25;
                acc = _in26;
                continue TAIL_CALL_START;
              } else {
                let _in27 = s;
                let _in28 = (_0_j).plus(new BigNumber(6));
                let _in29 = EHBPEvents.__default.Keep(_1_run, _dafny.Seq.of(new _dafny.CodePoint((_3_cp).toNumber())));
                s = _in27;
                i = _in28;
                acc = _in29;
                continue TAIL_CALL_START;
              }
            }
          }
        }
      }
    };
    static Frac(s, i) {
      if (((i).isLessThan(new BigNumber((s).length))) && (_dafny.areEqual((s)[i], new _dafny.CodePoint('.'.codePointAt(0))))) {
        if ((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (EHBPEvents.__default.IsDigit((s)[(i).plus(_dafny.ONE)]))) {
          return EHBP.Option.create_Some(EHBPEvents.__default.Digits(s, (i).plus(_dafny.ONE)));
        } else {
          return EHBP.Option.create_None();
        }
      } else {
        return EHBP.Option.create_Some(i);
      }
    };
    static Exponent(s, i) {
      if (((i).isLessThan(new BigNumber((s).length))) && ((_dafny.areEqual((s)[i], new _dafny.CodePoint('e'.codePointAt(0)))) || (_dafny.areEqual((s)[i], new _dafny.CodePoint('E'.codePointAt(0)))))) {
        let _0_j = (((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && ((_dafny.areEqual((s)[(i).plus(_dafny.ONE)], new _dafny.CodePoint('+'.codePointAt(0)))) || (_dafny.areEqual((s)[(i).plus(_dafny.ONE)], new _dafny.CodePoint('-'.codePointAt(0)))))) ? ((i).plus(new BigNumber(2))) : ((i).plus(_dafny.ONE)));
        if (((_0_j).isLessThan(new BigNumber((s).length))) && (EHBPEvents.__default.IsDigit((s)[_0_j]))) {
          return EHBP.Option.create_Some(EHBPEvents.__default.Digits(s, _0_j));
        } else {
          return EHBP.Option.create_None();
        }
      } else {
        return EHBP.Option.create_Some(i);
      }
    };
    static ParseNumber(s, i) {
      let _0_j = ((((i).isLessThan(new BigNumber((s).length))) && (_dafny.areEqual((s)[i], new _dafny.CodePoint('-'.codePointAt(0))))) ? ((i).plus(_dafny.ONE)) : (i));
      if ((_0_j).isEqualTo(new BigNumber((s).length))) {
        return EHBP.Option.create_None();
      } else {
        let _1_k = ((_dafny.areEqual((s)[_0_j], new _dafny.CodePoint('0'.codePointAt(0)))) ? (EHBP.Option.create_Some((_0_j).plus(_dafny.ONE))) : (((EHBPEvents.__default.IsDigit((s)[_0_j])) ? (EHBP.Option.create_Some(EHBPEvents.__default.Digits(s, (_0_j).plus(_dafny.ONE)))) : (EHBP.Option.create_None()))));
        if ((_1_k).is_None) {
          return EHBP.Option.create_None();
        } else {
          let _source0 = EHBPEvents.__default.Frac(s, (_1_k).dtor_value);
          {
            if (_source0.is_None) {
              return EHBP.Option.create_None();
            }
          }
          {
            let _2_f = (_source0).value;
            let _source1 = EHBPEvents.__default.Exponent(s, _2_f);
            {
              if (_source1.is_None) {
                return EHBP.Option.create_None();
              }
            }
            {
              let _3_end = (_source1).value;
              return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JNumber((s).slice(i, _3_end)), _3_end));
            }
          }
        }
      }
    };
    static Literal(s, i, word, value) {
      if ((((i).plus(new BigNumber((word).length))).isLessThanOrEqualTo(new BigNumber((s).length))) && (_dafny.areEqual((s).slice(i, (i).plus(new BigNumber((word).length))), word))) {
        return EHBP.Option.create_Some(_dafny.Tuple.of(value, (i).plus(new BigNumber((word).length))));
      } else {
        return EHBP.Option.create_None();
      }
    };
    static ParseValue(s, i, depth) {
      if ((i).isEqualTo(new BigNumber((s).length))) {
        return EHBP.Option.create_None();
      } else if (((_dafny.areEqual((s)[i], new _dafny.CodePoint('{'.codePointAt(0)))) || (_dafny.areEqual((s)[i], new _dafny.CodePoint('['.codePointAt(0))))) && ((EHBPEvents.__default.MaxJsonDepth).isLessThanOrEqualTo(depth))) {
        return EHBP.Option.create_None();
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('{'.codePointAt(0)))) {
        return EHBPEvents.__default.ParseMembers(s, EHBPEvents.__default.SkipWs(s, (i).plus(_dafny.ONE)), (depth).plus(_dafny.ONE), _dafny.Seq.of(), true);
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('['.codePointAt(0)))) {
        return EHBPEvents.__default.ParseItems(s, EHBPEvents.__default.SkipWs(s, (i).plus(_dafny.ONE)), (depth).plus(_dafny.ONE), _dafny.Seq.of(), true);
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('"'.codePointAt(0)))) {
        let _source0 = EHBPEvents.__default.ParseString(s, (i).plus(_dafny.ONE), _dafny.Seq.of());
        {
          if (_source0.is_None) {
            return EHBP.Option.create_None();
          }
        }
        {
          let value0 = (_source0).value;
          let _0_str = (value0)[0];
          let _1_j = (value0)[1];
          return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JString(_0_str), _1_j));
        }
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('t'.codePointAt(0)))) {
        return EHBPEvents.__default.Literal(s, i, _dafny.Seq.UnicodeFromString("true"), EHBPEvents.Json.create_JBool(true));
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('f'.codePointAt(0)))) {
        return EHBPEvents.__default.Literal(s, i, _dafny.Seq.UnicodeFromString("false"), EHBPEvents.Json.create_JBool(false));
      } else if (_dafny.areEqual((s)[i], new _dafny.CodePoint('n'.codePointAt(0)))) {
        return EHBPEvents.__default.Literal(s, i, _dafny.Seq.UnicodeFromString("null"), EHBPEvents.Json.create_JNull());
      } else {
        return EHBPEvents.__default.ParseNumber(s, i);
      }
    };
    static ItemsFrom(s, i, depth, acc, first) {
      if ((i).isEqualTo(new BigNumber((s).length))) {
        return EHBP.Option.create_None();
      } else if ((first) && (_dafny.areEqual((s)[i], new _dafny.CodePoint(']'.codePointAt(0))))) {
        return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JArray(acc), (i).plus(_dafny.ONE)));
      } else {
        let _source0 = EHBPEvents.__default.ParseValue(s, i, depth);
        {
          if (_source0.is_None) {
            return EHBP.Option.create_None();
          }
        }
        {
          let value0 = (_source0).value;
          let _0_v = (value0)[0];
          let _1_k = (value0)[1];
          let _2_m = EHBPEvents.__default.SkipWs(s, _1_k);
          if ((_2_m).isEqualTo(new BigNumber((s).length))) {
            return EHBP.Option.create_None();
          } else if (_dafny.areEqual((s)[_2_m], new _dafny.CodePoint(','.codePointAt(0)))) {
            return EHBPEvents.__default.ItemsFrom(s, EHBPEvents.__default.SkipWs(s, (_2_m).plus(_dafny.ONE)), depth, _dafny.Seq.Concat(acc, _dafny.Seq.of(_0_v)), false);
          } else if (_dafny.areEqual((s)[_2_m], new _dafny.CodePoint(']'.codePointAt(0)))) {
            return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JArray(_dafny.Seq.Concat(acc, _dafny.Seq.of(_0_v))), (_2_m).plus(_dafny.ONE)));
          } else {
            return EHBP.Option.create_None();
          }
        }
      }
    };
    static ParseItems(s, i, depth, acc, first) {
      let r = EHBP.Option.Default();
      let _0_a;
      let _init0 = function (_1___v14) {
        return EHBPEvents.Json.create_JNull();
      };
      let _nw0 = Array((_dafny.ZERO).toNumber());
      for (let _i0_0 = 0; _i0_0 < new BigNumber(_nw0.length); _i0_0++) {
        _nw0[_i0_0] = _init0(new BigNumber(_i0_0));
      }
      _0_a = _nw0;
      let _2_n;
      let _3_j;
      let _4_f;
      let _rhs0 = _dafny.ZERO;
      let _rhs1 = i;
      let _rhs2 = first;
      _2_n = _rhs0;
      _3_j = _rhs1;
      _4_f = _rhs2;
      while (true) {
        if ((_3_j).isEqualTo(new BigNumber((s).length))) {
          r = EHBP.Option.create_None();
          return r;
        }
        if ((_4_f) && (_dafny.areEqual((s)[_3_j], new _dafny.CodePoint(']'.codePointAt(0))))) {
          r = EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JArray(_dafny.Seq.Concat(acc, _dafny.Seq.of(...(_0_a).slice(0, _2_n)))), (_3_j).plus(_dafny.ONE)));
          return r;
        }
        let _5_r;
        _5_r = EHBPEvents.__default.ParseValue(s, _3_j, depth);
        if ((_5_r).is_None) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _let_tmp_rhs0 = (_5_r).dtor_value;
        let _6_v = (_let_tmp_rhs0)[0];
        let _7_k = (_let_tmp_rhs0)[1];
        let _8_m;
        _8_m = EHBPEvents.__default.SkipWs(s, _7_k);
        if ((_8_m).isEqualTo(new BigNumber((s).length))) {
          r = EHBP.Option.create_None();
          return r;
        }
        if (_dafny.areEqual((s)[_8_m], new _dafny.CodePoint(']'.codePointAt(0)))) {
          r = EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JArray(_dafny.Seq.Concat(_dafny.Seq.Concat(acc, _dafny.Seq.of(...(_0_a).slice(0, _2_n))), _dafny.Seq.of(_6_v))), (_8_m).plus(_dafny.ONE)));
          return r;
        }
        if (!_dafny.areEqual((s)[_8_m], new _dafny.CodePoint(','.codePointAt(0)))) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _out0;
        _out0 = EHBPEvents.__default.Append(_0_a, _2_n, _6_v);
        _0_a = _out0;
        let _rhs3 = (_2_n).plus(_dafny.ONE);
        let _rhs4 = EHBPEvents.__default.SkipWs(s, (_8_m).plus(_dafny.ONE));
        let _rhs5 = false;
        _2_n = _rhs3;
        _3_j = _rhs4;
        _4_f = _rhs5;
      }
      return r;
    }
    static MembersFrom(s, i, depth, acc, first) {
      if ((i).isEqualTo(new BigNumber((s).length))) {
        return EHBP.Option.create_None();
      } else if ((first) && (_dafny.areEqual((s)[i], new _dafny.CodePoint('}'.codePointAt(0))))) {
        return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JObject(acc), (i).plus(_dafny.ONE)));
      } else if (!_dafny.areEqual((s)[i], new _dafny.CodePoint('"'.codePointAt(0)))) {
        return EHBP.Option.create_None();
      } else {
        let _source0 = EHBPEvents.__default.ParseString(s, (i).plus(_dafny.ONE), _dafny.Seq.of());
        {
          if (_source0.is_None) {
            return EHBP.Option.create_None();
          }
        }
        {
          let value0 = (_source0).value;
          let _0_name = (value0)[0];
          let _1_k = (value0)[1];
          let _2_c = EHBPEvents.__default.SkipWs(s, _1_k);
          if (((_2_c).isEqualTo(new BigNumber((s).length))) || (!_dafny.areEqual((s)[_2_c], new _dafny.CodePoint(':'.codePointAt(0))))) {
            return EHBP.Option.create_None();
          } else {
            let _source1 = EHBPEvents.__default.ParseValue(s, EHBPEvents.__default.SkipWs(s, (_2_c).plus(_dafny.ONE)), depth);
            {
              if (_source1.is_None) {
                return EHBP.Option.create_None();
              }
            }
            {
              let value1 = (_source1).value;
              let _3_v = (value1)[0];
              let _4_k2 = (value1)[1];
              let _5_m = EHBPEvents.__default.SkipWs(s, _4_k2);
              if ((_5_m).isEqualTo(new BigNumber((s).length))) {
                return EHBP.Option.create_None();
              } else if (_dafny.areEqual((s)[_5_m], new _dafny.CodePoint(','.codePointAt(0)))) {
                return EHBPEvents.__default.MembersFrom(s, EHBPEvents.__default.SkipWs(s, (_5_m).plus(_dafny.ONE)), depth, _dafny.Seq.Concat(acc, _dafny.Seq.of(_dafny.Tuple.of(_0_name, _3_v))), false);
              } else if (_dafny.areEqual((s)[_5_m], new _dafny.CodePoint('}'.codePointAt(0)))) {
                return EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JObject(_dafny.Seq.Concat(acc, _dafny.Seq.of(_dafny.Tuple.of(_0_name, _3_v)))), (_5_m).plus(_dafny.ONE)));
              } else {
                return EHBP.Option.create_None();
              }
            }
          }
        }
      }
    };
    static ParseMembers(s, i, depth, acc, first) {
      let r = EHBP.Option.Default();
      let _0_a;
      let _init0 = function (_1___v15) {
        return _dafny.Tuple.of(_dafny.Seq.UnicodeFromString(""), EHBPEvents.Json.create_JNull());
      };
      let _nw0 = Array((_dafny.ZERO).toNumber());
      for (let _i0_0 = 0; _i0_0 < new BigNumber(_nw0.length); _i0_0++) {
        _nw0[_i0_0] = _init0(new BigNumber(_i0_0));
      }
      _0_a = _nw0;
      let _2_n;
      let _3_j;
      let _4_f;
      let _rhs0 = _dafny.ZERO;
      let _rhs1 = i;
      let _rhs2 = first;
      _2_n = _rhs0;
      _3_j = _rhs1;
      _4_f = _rhs2;
      while (true) {
        if ((_3_j).isEqualTo(new BigNumber((s).length))) {
          r = EHBP.Option.create_None();
          return r;
        }
        if ((_4_f) && (_dafny.areEqual((s)[_3_j], new _dafny.CodePoint('}'.codePointAt(0))))) {
          r = EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JObject(_dafny.Seq.Concat(acc, _dafny.Seq.of(...(_0_a).slice(0, _2_n)))), (_3_j).plus(_dafny.ONE)));
          return r;
        }
        if (!_dafny.areEqual((s)[_3_j], new _dafny.CodePoint('"'.codePointAt(0)))) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _5_rn;
        _5_rn = EHBPEvents.__default.ParseString(s, (_3_j).plus(_dafny.ONE), _dafny.Seq.of());
        if ((_5_rn).is_None) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _let_tmp_rhs0 = (_5_rn).dtor_value;
        let _6_name = (_let_tmp_rhs0)[0];
        let _7_k = (_let_tmp_rhs0)[1];
        let _8_c;
        _8_c = EHBPEvents.__default.SkipWs(s, _7_k);
        if (((_8_c).isEqualTo(new BigNumber((s).length))) || (!_dafny.areEqual((s)[_8_c], new _dafny.CodePoint(':'.codePointAt(0))))) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _9_r;
        _9_r = EHBPEvents.__default.ParseValue(s, EHBPEvents.__default.SkipWs(s, (_8_c).plus(_dafny.ONE)), depth);
        if ((_9_r).is_None) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _let_tmp_rhs1 = (_9_r).dtor_value;
        let _10_v = (_let_tmp_rhs1)[0];
        let _11_k2 = (_let_tmp_rhs1)[1];
        let _12_m;
        _12_m = EHBPEvents.__default.SkipWs(s, _11_k2);
        if ((_12_m).isEqualTo(new BigNumber((s).length))) {
          r = EHBP.Option.create_None();
          return r;
        }
        if (_dafny.areEqual((s)[_12_m], new _dafny.CodePoint('}'.codePointAt(0)))) {
          r = EHBP.Option.create_Some(_dafny.Tuple.of(EHBPEvents.Json.create_JObject(_dafny.Seq.Concat(_dafny.Seq.Concat(acc, _dafny.Seq.of(...(_0_a).slice(0, _2_n))), _dafny.Seq.of(_dafny.Tuple.of(_6_name, _10_v)))), (_12_m).plus(_dafny.ONE)));
          return r;
        }
        if (!_dafny.areEqual((s)[_12_m], new _dafny.CodePoint(','.codePointAt(0)))) {
          r = EHBP.Option.create_None();
          return r;
        }
        let _out0;
        _out0 = EHBPEvents.__default.Append(_0_a, _2_n, _dafny.Tuple.of(_6_name, _10_v));
        _0_a = _out0;
        let _rhs3 = (_2_n).plus(_dafny.ONE);
        let _rhs4 = EHBPEvents.__default.SkipWs(s, (_12_m).plus(_dafny.ONE));
        let _rhs5 = false;
        _2_n = _rhs3;
        _3_j = _rhs4;
        _4_f = _rhs5;
      }
      return r;
    }
    static Append(a, n, v) {
      let b = [];
      if ((n).isLessThan(new BigNumber((a).length))) {
        (a)[(n)] = v;
        b = a;
        return b;
      }
      let _init0 = ((_0_n, _1_a, _2_v) => function (_3_k) {
        return ((((_dafny.ZERO).isLessThanOrEqualTo(_3_k)) && ((_3_k).isLessThan(_0_n))) ? ((_1_a)[_3_k]) : (_2_v));
      })(n, a, v);
      let _nw0 = Array((((new BigNumber(2)).multipliedBy(n)).plus(_dafny.ONE)).toNumber());
      for (let _i0_0 = 0; _i0_0 < new BigNumber(_nw0.length); _i0_0++) {
        _nw0[_i0_0] = _init0(new BigNumber(_i0_0));
      }
      b = _nw0;
      return b;
    }
    static ParseJson(s) {
      let _source0 = EHBPEvents.__default.ParseValue(s, EHBPEvents.__default.SkipWs(s, _dafny.ZERO), _dafny.ZERO);
      {
        if (_source0.is_None) {
          return EHBP.Option.create_None();
        }
      }
      {
        let value0 = (_source0).value;
        let _0_v = (value0)[0];
        let _1_j = (value0)[1];
        if ((EHBPEvents.__default.SkipWs(s, _1_j)).isEqualTo(new BigNumber((s).length))) {
          return EHBP.Option.create_Some(_0_v);
        } else {
          return EHBP.Option.create_None();
        }
      }
    };
    static Member(members, name) {
      return EHBPEvents.__default.MemberFrom(members, new BigNumber((members).length), name);
    };
    static MemberFrom(members, n, name) {
      TAIL_CALL_START: while (true) {
        if ((n).isEqualTo(_dafny.ZERO)) {
          return EHBP.Option.create_None();
        } else if (_dafny.areEqual(((members)[(n).minus(_dafny.ONE)])[0], name)) {
          return EHBP.Option.create_Some(((members)[(n).minus(_dafny.ONE)])[1]);
        } else {
          let _in0 = members;
          let _in1 = (n).minus(_dafny.ONE);
          let _in2 = name;
          members = _in0;
          n = _in1;
          name = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static StringMember(members, name) {
      let _source0 = EHBPEvents.__default.Member(members, name);
      {
        if (_source0.is_Some) {
          let value0 = (_source0).value;
          if (value0.is_JString) {
            let _0_v = (value0).s;
            return EHBP.Option.create_Some(_0_v);
          }
        }
      }
      {
        return EHBP.Option.create_None();
      }
    };
    static Cont(b) {
      return ((128) <= (b)) && ((b) <= (191));
    };
    static Utf8From(b, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((b).length))) {
          return acc;
        } else {
          let _0_c = (b)[i];
          if ((_0_c) < (128)) {
            let _in0 = b;
            let _in1 = (i).plus(_dafny.ONE);
            let _in2 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((_0_c))));
            b = _in0;
            i = _in1;
            acc = _in2;
            continue TAIL_CALL_START;
          } else if (((((194) <= (_0_c)) && ((_0_c) <= (223))) && (((i).plus(new BigNumber(2))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(i).plus(_dafny.ONE)]))) {
            let _in3 = b;
            let _in4 = (i).plus(new BigNumber(2));
            let _in5 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint(((((new BigNumber(_0_c)).minus(new BigNumber(192))).multipliedBy(new BigNumber(64))).plus((new BigNumber((b)[(i).plus(_dafny.ONE)])).minus(new BigNumber(128)))).toNumber())));
            b = _in3;
            i = _in4;
            acc = _in5;
            continue TAIL_CALL_START;
          } else if ((((((224) <= (_0_c)) && ((_0_c) <= (239))) && (((i).plus(new BigNumber(3))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(i).plus(_dafny.ONE)]))) && (EHBPEvents.__default.Cont((b)[(i).plus(new BigNumber(2))]))) {
            let _1_cp = ((((new BigNumber(_0_c)).minus(new BigNumber(224))).multipliedBy(new BigNumber(4096))).plus(((new BigNumber((b)[(i).plus(_dafny.ONE)])).minus(new BigNumber(128))).multipliedBy(new BigNumber(64)))).plus((new BigNumber((b)[(i).plus(new BigNumber(2))])).minus(new BigNumber(128)));
            if (((_1_cp).isLessThan(new BigNumber(2048))) || (((new BigNumber(55296)).isLessThanOrEqualTo(_1_cp)) && ((_1_cp).isLessThanOrEqualTo(new BigNumber(57343))))) {
              let _in6 = b;
              let _in7 = (i).plus(_dafny.ONE);
              let _in8 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(65533)).toNumber())));
              b = _in6;
              i = _in7;
              acc = _in8;
              continue TAIL_CALL_START;
            } else {
              let _in9 = b;
              let _in10 = (i).plus(new BigNumber(3));
              let _in11 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((_1_cp).toNumber())));
              b = _in9;
              i = _in10;
              acc = _in11;
              continue TAIL_CALL_START;
            }
          } else if (((((((240) <= (_0_c)) && ((_0_c) <= (244))) && (((i).plus(new BigNumber(4))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(i).plus(_dafny.ONE)]))) && (EHBPEvents.__default.Cont((b)[(i).plus(new BigNumber(2))]))) && (EHBPEvents.__default.Cont((b)[(i).plus(new BigNumber(3))]))) {
            let _2_cp = (((((new BigNumber(_0_c)).minus(new BigNumber(240))).multipliedBy(new BigNumber(262144))).plus(((new BigNumber((b)[(i).plus(_dafny.ONE)])).minus(new BigNumber(128))).multipliedBy(new BigNumber(4096)))).plus(((new BigNumber((b)[(i).plus(new BigNumber(2))])).minus(new BigNumber(128))).multipliedBy(new BigNumber(64)))).plus((new BigNumber((b)[(i).plus(new BigNumber(3))])).minus(new BigNumber(128)));
            if (((_2_cp).isLessThan(new BigNumber(65536))) || ((new BigNumber(1114111)).isLessThan(_2_cp))) {
              let _in12 = b;
              let _in13 = (i).plus(_dafny.ONE);
              let _in14 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(65533)).toNumber())));
              b = _in12;
              i = _in13;
              acc = _in14;
              continue TAIL_CALL_START;
            } else {
              let _in15 = b;
              let _in16 = (i).plus(new BigNumber(4));
              let _in17 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((_2_cp).toNumber())));
              b = _in15;
              i = _in16;
              acc = _in17;
              continue TAIL_CALL_START;
            }
          } else {
            let _in18 = b;
            let _in19 = (i).plus(_dafny.ONE);
            let _in20 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new _dafny.CodePoint((new BigNumber(65533)).toNumber())));
            b = _in18;
            i = _in19;
            acc = _in20;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static Utf8(b) {
      let _hresult = _dafny.Seq.UnicodeFromString("");
      let _0_a;
      let _init0 = function (_1___v17) {
        return new _dafny.CodePoint(' '.codePointAt(0));
      };
      let _nw0 = Array((new BigNumber((b).length)).toNumber());
      for (let _i0_0 = 0; _i0_0 < new BigNumber(_nw0.length); _i0_0++) {
        _nw0[_i0_0] = _init0(new BigNumber(_i0_0));
      }
      _0_a = _nw0;
      let _2_i;
      let _3_n;
      let _rhs0 = _dafny.ZERO;
      let _rhs1 = _dafny.ZERO;
      _2_i = _rhs0;
      _3_n = _rhs1;
      while ((_2_i).isLessThan(new BigNumber((b).length))) {
        let _4_c;
        _4_c = (b)[_2_i];
        let _5_cp;
        let _6_w;
        let _rhs2 = new BigNumber(65533);
        let _rhs3 = _dafny.ONE;
        _5_cp = _rhs2;
        _6_w = _rhs3;
        if ((_4_c) < (128)) {
          _5_cp = new BigNumber(_4_c);
        } else if (((((194) <= (_4_c)) && ((_4_c) <= (223))) && (((_2_i).plus(new BigNumber(2))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(_dafny.ONE)]))) {
          let _rhs4 = (((new BigNumber(_4_c)).minus(new BigNumber(192))).multipliedBy(new BigNumber(64))).plus((new BigNumber((b)[(_2_i).plus(_dafny.ONE)])).minus(new BigNumber(128)));
          let _rhs5 = new BigNumber(2);
          _5_cp = _rhs4;
          _6_w = _rhs5;
        } else if ((((((224) <= (_4_c)) && ((_4_c) <= (239))) && (((_2_i).plus(new BigNumber(3))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(_dafny.ONE)]))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(new BigNumber(2))]))) {
          let _7_v;
          _7_v = ((((new BigNumber(_4_c)).minus(new BigNumber(224))).multipliedBy(new BigNumber(4096))).plus(((new BigNumber((b)[(_2_i).plus(_dafny.ONE)])).minus(new BigNumber(128))).multipliedBy(new BigNumber(64)))).plus((new BigNumber((b)[(_2_i).plus(new BigNumber(2))])).minus(new BigNumber(128)));
          if (!(((_7_v).isLessThan(new BigNumber(2048))) || (((new BigNumber(55296)).isLessThanOrEqualTo(_7_v)) && ((_7_v).isLessThanOrEqualTo(new BigNumber(57343)))))) {
            let _rhs6 = _7_v;
            let _rhs7 = new BigNumber(3);
            _5_cp = _rhs6;
            _6_w = _rhs7;
          }
        } else if (((((((240) <= (_4_c)) && ((_4_c) <= (244))) && (((_2_i).plus(new BigNumber(4))).isLessThanOrEqualTo(new BigNumber((b).length)))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(_dafny.ONE)]))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(new BigNumber(2))]))) && (EHBPEvents.__default.Cont((b)[(_2_i).plus(new BigNumber(3))]))) {
          let _8_v;
          _8_v = (((((new BigNumber(_4_c)).minus(new BigNumber(240))).multipliedBy(new BigNumber(262144))).plus(((new BigNumber((b)[(_2_i).plus(_dafny.ONE)])).minus(new BigNumber(128))).multipliedBy(new BigNumber(4096)))).plus(((new BigNumber((b)[(_2_i).plus(new BigNumber(2))])).minus(new BigNumber(128))).multipliedBy(new BigNumber(64)))).plus((new BigNumber((b)[(_2_i).plus(new BigNumber(3))])).minus(new BigNumber(128)));
          if (!(((_8_v).isLessThan(new BigNumber(65536))) || ((new BigNumber(1114111)).isLessThan(_8_v)))) {
            let _rhs8 = _8_v;
            let _rhs9 = new BigNumber(4);
            _5_cp = _rhs8;
            _6_w = _rhs9;
          }
        }
        (_0_a)[(_3_n)] = new _dafny.CodePoint((_5_cp).toNumber());
        let _rhs10 = (_2_i).plus(_6_w);
        let _rhs11 = (_3_n).plus(_dafny.ONE);
        _2_i = _rhs10;
        _3_n = _rhs11;
      }
      _hresult = _dafny.Seq.of(...(_0_a).slice(0, _3_n));
      return _hresult;
      return _hresult;
    }
    static ParseProblem(body) {
      let _source0 = EHBPEvents.__default.ParseJson(EHBPEvents.__default.Utf8(body));
      {
        if (_source0.is_Some) {
          let value0 = (_source0).value;
          if (value0.is_JObject) {
            let _0_members = (value0).members;
            return _dafny.Tuple.of(true, EHBPEvents.__default.StringMember(_0_members, _dafny.Seq.UnicodeFromString("type")), EHBPEvents.__default.StringMember(_0_members, _dafny.Seq.UnicodeFromString("title")));
          }
        }
      }
      {
        return _dafny.Tuple.of(false, EHBP.Option.create_None(), EHBP.Option.create_None());
      }
    };
    static ParseToken(json) {
      let _source0 = EHBPEvents.__default.ParseJson(json);
      {
        if (_source0.is_Some) {
          let value0 = (_source0).value;
          if (value0.is_JObject) {
            let _0_members = (value0).members;
            return _dafny.Tuple.of(EHBPEvents.__default.StringMember(_0_members, _dafny.Seq.UnicodeFromString("exportedSecret")), EHBPEvents.__default.StringMember(_0_members, _dafny.Seq.UnicodeFromString("requestEnc")));
          }
        }
      }
      {
        return _dafny.Tuple.of(EHBP.Option.create_None(), EHBP.Option.create_None());
      }
    };
    static Escape(s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          let _1_c = (s)[_dafny.ZERO];
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((_dafny.areEqual(_1_c, new _dafny.CodePoint('"'.codePointAt(0)))) ? (_dafny.Seq.UnicodeFromString("\\\"")) : (((_dafny.areEqual(_1_c, new _dafny.CodePoint('\\'.codePointAt(0)))) ? (_dafny.Seq.UnicodeFromString("\\\\")) : ((((new BigNumber((_1_c).value)).isLessThan(new BigNumber(32))) ? (_dafny.Seq.Concat(_dafny.Seq.UnicodeFromString("\\u00"), _dafny.Seq.of((EHBP.__default.HexDigits)[_dafny.EuclideanDivision(new BigNumber((_1_c).value), new BigNumber(16))], (EHBP.__default.HexDigits)[(new BigNumber((_1_c).value)).mod(new BigNumber(16))]))) : (_dafny.Seq.of(_1_c))))))));
          let _in0 = (s).slice(_dafny.ONE);
          s = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static FormatToken(exportedSecretHex, requestEncHex) {
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.UnicodeFromString("{\"exportedSecret\":\""), EHBPEvents.__default.Escape(exportedSecretHex)), _dafny.Seq.UnicodeFromString("\",\"requestEnc\":\"")), EHBPEvents.__default.Escape(requestEncHex)), _dafny.Seq.UnicodeFromString("\"}"));
    };
    static SessionApply(store, action) {
      let _source0 = action;
      {
        if (_source0.is_Begin) {
          return EHBPEvents.SessionStore.create_SessionStore(((((store).dtor_generation).isEqualTo(EHBPEvents.__default.MaxSeq)) ? (_dafny.ZERO) : (((store).dtor_generation).plus(_dafny.ONE))), EHBP.Option.create_None());
        }
      }
      {
        if (_source0.is_Publish) {
          let _0_generation = (_source0).generation;
          let _1_token = (_source0).token;
          if ((_0_generation).isEqualTo((store).dtor_generation)) {
            let _2_dt__update__tmp_h0 = store;
            let _3_dt__update_htoken_h0 = EHBP.Option.create_Some(_1_token);
            return EHBPEvents.SessionStore.create_SessionStore((_2_dt__update__tmp_h0).dtor_generation, _3_dt__update_htoken_h0);
          } else {
            return store;
          }
        }
      }
      {
        let _4_generation = (_source0).generation;
        if ((_4_generation).isEqualTo((store).dtor_generation)) {
          let _5_dt__update__tmp_h1 = store;
          let _6_dt__update_htoken_h1 = EHBP.Option.create_None();
          return EHBPEvents.SessionStore.create_SessionStore((_5_dt__update__tmp_h1).dtor_generation, _6_dt__update_htoken_h1);
        } else {
          return store;
        }
      }
    };
    static Frames(d, buf, i, acc) {
      TAIL_CALL_START: while (true) {
        let _pat_let_tv0 = buf;
        let _pat_let_tv1 = i;
        let _pat_let_tv2 = buf;
        let _pat_let_tv3 = i;
        if (((new BigNumber((buf).length)).minus(i)).isLessThan(new BigNumber(4))) {
          return _dafny.Tuple.of(acc, function (_pat_let25_0) {
  return function (_0_dt__update__tmp_h0) {
    return function (_pat_let26_0) {
      return function (_1_dt__update_hpending_h0) {
        return EHBPEvents.Dec.create_Dec(_1_dt__update_hpending_h0, (_0_dt__update__tmp_h0).dtor_next, (_0_dt__update__tmp_h0).dtor_authenticated, (_0_dt__update__tmp_h0).dtor_requireFrame);
      }(_pat_let26_0);
    }((_pat_let_tv0).slice(_pat_let_tv1));
  }(_pat_let25_0);
}(d), EHBP.Option.create_None());
        } else {
          let _2_length = EHBP.__default.U32(buf, i);
          if ((_2_length) === (0)) {
            let _in0 = d;
            let _in1 = buf;
            let _in2 = (i).plus(new BigNumber(4));
            let _in3 = acc;
            d = _in0;
            buf = _in1;
            i = _in2;
            acc = _in3;
            continue TAIL_CALL_START;
          } else if ((_2_length) > (EHBP.__default.MaxChunkBytes)) {
            return _dafny.Tuple.of(acc, d, EHBP.Option.create_Some(EHBP.Code.create_ChunkTooLarge()));
          } else if (((new BigNumber((buf).length)).minus(i)).isLessThan((new BigNumber(4)).plus(new BigNumber(_2_length)))) {
            return _dafny.Tuple.of(acc, function (_pat_let27_0) {
  return function (_3_dt__update__tmp_h1) {
    return function (_pat_let28_0) {
      return function (_4_dt__update_hpending_h1) {
        return EHBPEvents.Dec.create_Dec(_4_dt__update_hpending_h1, (_3_dt__update__tmp_h1).dtor_next, (_3_dt__update__tmp_h1).dtor_authenticated, (_3_dt__update__tmp_h1).dtor_requireFrame);
      }(_pat_let28_0);
    }((_pat_let_tv2).slice(_pat_let_tv3));
  }(_pat_let27_0);
}(d), EHBP.Option.create_None());
          } else if (((d).dtor_next).isEqualTo(EHBPEvents.__default.MaxSeq)) {
            return _dafny.Tuple.of(acc, d, EHBP.Option.create_Some(EHBP.Code.create_SequenceOverflow()));
          } else {
            let _in4 = EHBPEvents.Dec.create_Dec(_dafny.Seq.of(), ((d).dtor_next).plus(_dafny.ONE), true, (d).dtor_requireFrame);
            let _in5 = buf;
            let _in6 = ((i).plus(new BigNumber(4))).plus(new BigNumber(_2_length));
            let _in7 = _dafny.Seq.Concat(acc, _dafny.Seq.of(EHBP.Framed.create_Framed((d).dtor_next, (buf).slice((i).plus(new BigNumber(4)), ((i).plus(new BigNumber(4))).plus(new BigNumber(_2_length))))));
            d = _in4;
            buf = _in5;
            i = _in6;
            acc = _in7;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static FrameNeed(pending) {
      if ((new BigNumber((pending).length)).isLessThan(new BigNumber(4))) {
        return (new BigNumber(4)).minus(new BigNumber((pending).length));
      } else {
        let _0_whole = (new BigNumber(4)).plus(new BigNumber(EHBP.__default.U32(pending, _dafny.ZERO)));
        if ((new BigNumber((pending).length)).isLessThan(_0_whole)) {
          return (_0_whole).minus(new BigNumber((pending).length));
        } else {
          return _dafny.ONE;
        }
      }
    };
    static Push(d, data) {
      return EHBPEvents.__default.PushFrom(d, data, _dafny.ZERO, _dafny.Seq.of());
    };
    static PushFrom(d, data, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber(((d).dtor_pending).length)).isEqualTo(_dafny.ZERO)) {
          return EHBPEvents.__default.Frames(d, data, i, acc);
        } else if ((i).isEqualTo(new BigNumber((data).length))) {
          return _dafny.Tuple.of(acc, d, EHBP.Option.create_None());
        } else {
          let _0_take = EHBPEvents.__default.Min((new BigNumber((data).length)).minus(i), EHBPEvents.__default.FrameNeed((d).dtor_pending));
          let _let_tmp_rhs0 = EHBPEvents.__default.Frames(d, _dafny.Seq.Concat((d).dtor_pending, (data).slice(i, (i).plus(_0_take))), _dafny.ZERO, acc);
          let _1_frames = (_let_tmp_rhs0)[0];
          let _2_next = (_let_tmp_rhs0)[1];
          let _3_err = (_let_tmp_rhs0)[2];
          if ((_3_err).is_Some) {
            return _dafny.Tuple.of(_1_frames, _2_next, _3_err);
          } else {
            let _in0 = _2_next;
            let _in1 = data;
            let _in2 = (i).plus(_0_take);
            let _in3 = _1_frames;
            d = _in0;
            data = _in1;
            i = _in2;
            acc = _in3;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static Finish(d) {
      if ((!(new BigNumber(((d).dtor_pending).length)).isEqualTo(_dafny.ZERO)) || (((d).dtor_requireFrame) && (!((d).dtor_authenticated)))) {
        return EHBP.Option.create_Some(EHBP.Code.create_FramingTruncated());
      } else {
        return EHBP.Option.create_None();
      }
    };
    static Initial(origin, publicKey) {
      return EHBPEvents.State.create_State(EHBPEvents.Phase.create_Idle(), origin, publicKey, _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), _dafny.ZERO, false, EHBP.Token.create_Token(_dafny.Seq.of(), _dafny.Seq.of()), EHBPEvents.__default.NoCtx);
    };
    static ResponseOnly(origin, token) {
      return EHBPEvents.State.create_State(EHBPEvents.Phase.create_Exchanging(EHBPEvents.Upload.create_UpDone(), EHBPEvents.Response.create_AwaitHead(true)), origin, _dafny.Seq.of(), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), _dafny.ZERO, false, token, EHBPEvents.__default.NoCtx);
    };
    static DecryptStart(token, status, headers) {
      return EHBPEvents.__default.Step(EHBPEvents.__default.ResponseOnly(EHBPEvents.__default.NoOrigin, token), EHBPEvents.Event.create_ResponseHead(status, headers, false));
    };
    static DeriveStart(token, responseNonce) {
      return EHBPEvents.__default.Step(EHBPEvents.__default.ResponseOnly(EHBPEvents.__default.NoOrigin, token), EHBPEvents.Event.create_ResponseHead(new BigNumber(200), _dafny.Seq.of(_dafny.Tuple.of(EHBP.__default.ResponseNonceHeader, EHBP.__default.EncodeHex(responseNonce))), false));
    };
    static KeysOf(s) {
      if ((((s).dtor_phase).is_Exchanging) && ((((s).dtor_phase).dtor_response).is_Body)) {
        return EHBP.Option.create_Some(_dafny.Tuple.of(((((s).dtor_phase).dtor_response).dtor_keys).dtor_key, ((((s).dtor_phase).dtor_response).dtor_keys).dtor_baseNonce));
      } else {
        return EHBP.Option.create_None();
      }
    };
    static Contract(s, e, r) {
      return ((!(EHBPEvents.__default.Ends((r)[1])) || ((!(((r)[0]).dtor_published)) && ((((s).dtor_published) ? (EHBPEvents.__default.ClearsOnce((r)[1], (s).dtor_generation)) : (EHBPEvents.__default.NoClear((r)[1])))))) && (!(!(EHBPEvents.__default.Ends((r)[1]))) || (EHBPEvents.__default.NoClear((r)[1])))) && (!(!(EHBPEvents.__default.NoEmit((r)[1]))) || (((((e).is_AeadOpenResult) && ((e).dtor_ok)) && (((s).dtor_phase).is_Exchanging)) && ((((s).dtor_phase).dtor_response).is_Opening)));
    };
    static Ending(s, r) {
      return (((EHBPEvents.__default.Ends((r)[1])) && (!(((r)[0]).dtor_published))) && ((((s).dtor_published) ? (EHBPEvents.__default.ClearsOnce((r)[1], (s).dtor_generation)) : (EHBPEvents.__default.NoClear((r)[1]))))) && (EHBPEvents.__default.NoEmit((r)[1]));
    };
    static End(s, close, last) {
      let _0_phase = function () {
        let _source0 = (s).dtor_phase;
        {
          if (_source0.is_Exchanging) {
            let _1_up = (_source0).upload;
            return EHBPEvents.Phase.create_Exchanging(_1_up, EHBPEvents.Response.create_RespEnded());
          }
        }
        {
          return EHBPEvents.Phase.create_Ended();
        }
      }();
      let _2_g = (s).dtor_generation;
      let _3_acts = (((close) && ((s).dtor_published)) ? (_dafny.Seq.of(EHBPEvents.Action.create_Close(EHBPEvents.Stream.create_ResponseBody()), EHBPEvents.Action.create_ClearToken(_2_g), last)) : (((close) ? (_dafny.Seq.of(EHBPEvents.Action.create_Close(EHBPEvents.Stream.create_ResponseBody()), last)) : ((((s).dtor_published) ? (_dafny.Seq.of(EHBPEvents.Action.create_ClearToken(_2_g), last)) : (_dafny.Seq.of(last)))))));
      return _dafny.Tuple.of(function (_pat_let29_0) {
  return function (_4_dt__update__tmp_h0) {
    return function (_pat_let30_0) {
      return function (_5_dt__update_hpublished_h0) {
        return function (_pat_let31_0) {
          return function (_6_dt__update_hphase_h0) {
            return EHBPEvents.State.create_State(_6_dt__update_hphase_h0, (_4_dt__update__tmp_h0).dtor_origin, (_4_dt__update__tmp_h0).dtor_publicKey, (_4_dt__update__tmp_h0).dtor_verb, (_4_dt__update__tmp_h0).dtor_url, (_4_dt__update__tmp_h0).dtor_headers, (_4_dt__update__tmp_h0).dtor_generation, _5_dt__update_hpublished_h0, (_4_dt__update__tmp_h0).dtor_token, (_4_dt__update__tmp_h0).dtor_ctx);
          }(_pat_let31_0);
        }(_0_phase);
      }(_pat_let30_0);
    }(false);
  }(_pat_let29_0);
}(s), _3_acts);
    };
    static Abort(s, close, code, message) {
      return EHBPEvents.__default.End(s, close, EHBPEvents.Action.create_Fail(code, message));
    };
    static Unexpected(s) {
      return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unexpected event"));
    };
    static Min(a, b) {
      if ((a).isLessThan(b)) {
        return a;
      } else {
        return b;
      }
    };
    static Min32(a, b) {
      if ((a) < (b)) {
        return a;
      } else {
        return b;
      }
    };
    static Piece(chunk, at, n) {
      if (((at) === (0)) && ((new BigNumber(n)).isEqualTo(new BigNumber((chunk).length)))) {
        return chunk;
      } else {
        return (chunk).slice(at, (at) + (n));
      }
    };
    static FrameWrites(ciphertext, end) {
      return _dafny.Seq.of(EHBPEvents.Action.create_Write(EHBP.__default.BE32((ciphertext).length), EHBPEvents.BodyEnd.create_More()), EHBPEvents.Action.create_Write(ciphertext, end));
    };
    static WithUpload(s, up) {
      let _0_dt__update__tmp_h0 = s;
      let _1_dt__update_hphase_h0 = EHBPEvents.Phase.create_Exchanging(up, ((s).dtor_phase).dtor_response);
      return EHBPEvents.State.create_State(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin, (_0_dt__update__tmp_h0).dtor_publicKey, (_0_dt__update__tmp_h0).dtor_verb, (_0_dt__update__tmp_h0).dtor_url, (_0_dt__update__tmp_h0).dtor_headers, (_0_dt__update__tmp_h0).dtor_generation, (_0_dt__update__tmp_h0).dtor_published, (_0_dt__update__tmp_h0).dtor_token, (_0_dt__update__tmp_h0).dtor_ctx);
    };
    static WithResponse(s, rs) {
      let _0_dt__update__tmp_h0 = s;
      let _1_dt__update_hphase_h0 = EHBPEvents.Phase.create_Exchanging(((s).dtor_phase).dtor_upload, rs);
      return EHBPEvents.State.create_State(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin, (_0_dt__update__tmp_h0).dtor_publicKey, (_0_dt__update__tmp_h0).dtor_verb, (_0_dt__update__tmp_h0).dtor_url, (_0_dt__update__tmp_h0).dtor_headers, (_0_dt__update__tmp_h0).dtor_generation, (_0_dt__update__tmp_h0).dtor_published, (_0_dt__update__tmp_h0).dtor_token, (_0_dt__update__tmp_h0).dtor_ctx);
    };
    static SendPlain(s) {
      return _dafny.Tuple.of(function (_pat_let32_0) {
  return function (_0_dt__update__tmp_h0) {
    return function (_pat_let33_0) {
      return function (_1_dt__update_hphase_h0) {
        return EHBPEvents.State.create_State(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin, (_0_dt__update__tmp_h0).dtor_publicKey, (_0_dt__update__tmp_h0).dtor_verb, (_0_dt__update__tmp_h0).dtor_url, (_0_dt__update__tmp_h0).dtor_headers, (_0_dt__update__tmp_h0).dtor_generation, (_0_dt__update__tmp_h0).dtor_published, (_0_dt__update__tmp_h0).dtor_token, (_0_dt__update__tmp_h0).dtor_ctx);
      }(_pat_let33_0);
    }(EHBPEvents.Phase.create_Exchanging(EHBPEvents.Upload.create_NoUpload(), EHBPEvents.Response.create_AwaitHead(false)));
  }(_pat_let32_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_Send((s).dtor_verb, (s).dtor_url, (s).dtor_headers, false)));
    };
    static ForUpload(e) {
      return ((((e).is_Chunk) || ((e).is_StreamFailed)) && (((e).dtor_stream).is_RequestBody)) || ((e).is_AeadSealResult);
    };
    static AbortUpload(s, code) {
      return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(s, EHBPEvents.Upload.create_UpDone()), _dafny.Seq.of(EHBPEvents.Action.create_Write(_dafny.Seq.of(), EHBPEvents.BodyEnd.create_Aborted(code))));
    };
    static Step(s, e) {
      let _pat_let_tv0 = e;
      if ((e).is_CallerClose) {
        return EHBPEvents.__default.End(s, false, EHBPEvents.Action.create_Close(EHBPEvents.Stream.create_ResponseBody()));
      } else {
        let _source0 = (s).dtor_phase;
        {
          if (_source0.is_Idle) {
            if ((e).is_Start) {
              return EHBPEvents.__default.StepStart(s, e);
            } else if ((e).is_DiscoverStart) {
              return _dafny.Tuple.of(function (_pat_let34_0) {
  return function (_0_dt__update__tmp_h0) {
    return function (_pat_let35_0) {
      return function (_1_dt__update_hphase_h0) {
        return EHBPEvents.State.create_State(_1_dt__update_hphase_h0, (_0_dt__update__tmp_h0).dtor_origin, (_0_dt__update__tmp_h0).dtor_publicKey, (_0_dt__update__tmp_h0).dtor_verb, (_0_dt__update__tmp_h0).dtor_url, (_0_dt__update__tmp_h0).dtor_headers, (_0_dt__update__tmp_h0).dtor_generation, (_0_dt__update__tmp_h0).dtor_published, (_0_dt__update__tmp_h0).dtor_token, (_0_dt__update__tmp_h0).dtor_ctx);
      }(_pat_let35_0);
    }(EHBPEvents.Phase.create_DiscAwaitHead());
  }(_pat_let34_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_Send(_dafny.Seq.UnicodeFromString("GET"), _dafny.Seq.Concat(EHBP.__default.OriginUrl((s).dtor_origin), EHBP.__default.KeysPath), _dafny.Seq.of(), false)));
            } else {
              return EHBPEvents.__default.Unexpected(s);
            }
          }
        }
        {
          if (_source0.is_AwaitSession) {
            let _2_hasBody = (_source0).hasBody;
            if (!((e).is_SessionBegun)) {
              return EHBPEvents.__default.Unexpected(s);
            } else {
              let _3_begun = function (_pat_let36_0) {
                return function (_4_dt__update__tmp_h1) {
                  return function (_pat_let37_0) {
                    return function (_5_dt__update_hgeneration_h0) {
                      return EHBPEvents.State.create_State((_4_dt__update__tmp_h1).dtor_phase, (_4_dt__update__tmp_h1).dtor_origin, (_4_dt__update__tmp_h1).dtor_publicKey, (_4_dt__update__tmp_h1).dtor_verb, (_4_dt__update__tmp_h1).dtor_url, (_4_dt__update__tmp_h1).dtor_headers, _5_dt__update_hgeneration_h0, (_4_dt__update__tmp_h1).dtor_published, (_4_dt__update__tmp_h1).dtor_token, (_4_dt__update__tmp_h1).dtor_ctx);
                    }(_pat_let37_0);
                  }((_pat_let_tv0).dtor_generation);
                }(_pat_let36_0);
              }(s);
              if (_2_hasBody) {
                return _dafny.Tuple.of(function (_pat_let38_0) {
  return function (_6_dt__update__tmp_h2) {
    return function (_pat_let39_0) {
      return function (_7_dt__update_hphase_h1) {
        return EHBPEvents.State.create_State(_7_dt__update_hphase_h1, (_6_dt__update__tmp_h2).dtor_origin, (_6_dt__update__tmp_h2).dtor_publicKey, (_6_dt__update__tmp_h2).dtor_verb, (_6_dt__update__tmp_h2).dtor_url, (_6_dt__update__tmp_h2).dtor_headers, (_6_dt__update__tmp_h2).dtor_generation, (_6_dt__update__tmp_h2).dtor_published, (_6_dt__update__tmp_h2).dtor_token, (_6_dt__update__tmp_h2).dtor_ctx);
      }(_pat_let39_0);
    }(EHBPEvents.Phase.create_Peeking(_dafny.ZERO));
  }(_pat_let38_0);
}(_3_begun), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_RequestBody())));
              } else {
                return EHBPEvents.__default.SendPlain(_3_begun);
              }
            }
          }
        }
        {
          if (_source0.is_Peeking) {
            let _8_empty = (_source0).empty;
            let _source1 = e;
            {
              if (_source1.is_StreamFailed) {
                let stream0 = (_source1).stream;
                if (stream0.is_RequestBody) {
                  return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to read request body"));
                }
              }
            }
            {
              if (_source1.is_Chunk) {
                let stream1 = (_source1).stream;
                if (stream1.is_RequestBody) {
                  let _9_data = (_source1).data;
                  let _10_eof = (_source1).eof;
                  if ((EHBPEvents.__default.MaxReadBytes).isLessThan(new BigNumber((_9_data).length))) {
                    return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("request body chunk too large"));
                  } else if ((_dafny.ZERO).isLessThan(new BigNumber((_9_data).length))) {
                    let _source2 = EHBPEvents.__default.SenderStart((s).dtor_publicKey, EHBP.__default.Ascii(EHBP.__default.HpkeRequestInfo));
                    {
                      if (_source2.is_HContinue) {
                        let _11_h = (_source2).h;
                        let _12_a = (_source2).action;
                        return _dafny.Tuple.of(function (_pat_let40_0) {
  return function (_13_dt__update__tmp_h3) {
    return function (_pat_let41_0) {
      return function (_14_dt__update_hphase_h2) {
        return EHBPEvents.State.create_State(_14_dt__update_hphase_h2, (_13_dt__update__tmp_h3).dtor_origin, (_13_dt__update__tmp_h3).dtor_publicKey, (_13_dt__update__tmp_h3).dtor_verb, (_13_dt__update__tmp_h3).dtor_url, (_13_dt__update__tmp_h3).dtor_headers, (_13_dt__update__tmp_h3).dtor_generation, (_13_dt__update__tmp_h3).dtor_published, (_13_dt__update__tmp_h3).dtor_token, (_13_dt__update__tmp_h3).dtor_ctx);
      }(_pat_let41_0);
    }(EHBPEvents.Phase.create_AwaitSetup(_9_data, _10_eof, _11_h));
  }(_pat_let40_0);
}(s), _dafny.Seq.of(_12_a));
                      }
                    }
                    {
                      return EHBPEvents.__default.Unexpected(s);
                    }
                  } else if (_10_eof) {
                    return EHBPEvents.__default.SendPlain(s);
                  } else if (((_8_empty).plus(_dafny.ONE)).isEqualTo(EHBP.__default.MaxEmptyReads)) {
                    return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("request body made no progress"));
                  } else {
                    return _dafny.Tuple.of(function (_pat_let42_0) {
  return function (_15_dt__update__tmp_h4) {
    return function (_pat_let43_0) {
      return function (_16_dt__update_hphase_h3) {
        return EHBPEvents.State.create_State(_16_dt__update_hphase_h3, (_15_dt__update__tmp_h4).dtor_origin, (_15_dt__update__tmp_h4).dtor_publicKey, (_15_dt__update__tmp_h4).dtor_verb, (_15_dt__update__tmp_h4).dtor_url, (_15_dt__update__tmp_h4).dtor_headers, (_15_dt__update__tmp_h4).dtor_generation, (_15_dt__update__tmp_h4).dtor_published, (_15_dt__update__tmp_h4).dtor_token, (_15_dt__update__tmp_h4).dtor_ctx);
      }(_pat_let43_0);
    }(EHBPEvents.Phase.create_Peeking((_8_empty).plus(_dafny.ONE)));
  }(_pat_let42_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_RequestBody())));
                  }
                }
              }
            }
            {
              return EHBPEvents.__default.Unexpected(s);
            }
          }
        }
        {
          if (_source0.is_AwaitSetup) {
            let _17_first = (_source0).first;
            let _18_firstEof = (_source0).firstEof;
            let _19_h = (_source0).hpke;
            let _source3 = EHBPEvents.__default.HpkeStep(_19_h, e);
            {
              if (_source3.is_HFailed) {
                let _20_code = (_source3).code;
                let _21_message = (_source3).message;
                return EHBPEvents.__default.Abort(s, false, _20_code, _21_message);
              }
            }
            {
              if (_source3.is_HContinue) {
                let _22_next = (_source3).h;
                let _23_a = (_source3).action;
                return _dafny.Tuple.of(function (_pat_let44_0) {
  return function (_24_dt__update__tmp_h5) {
    return function (_pat_let45_0) {
      return function (_25_dt__update_hphase_h4) {
        return EHBPEvents.State.create_State(_25_dt__update_hphase_h4, (_24_dt__update__tmp_h5).dtor_origin, (_24_dt__update__tmp_h5).dtor_publicKey, (_24_dt__update__tmp_h5).dtor_verb, (_24_dt__update__tmp_h5).dtor_url, (_24_dt__update__tmp_h5).dtor_headers, (_24_dt__update__tmp_h5).dtor_generation, (_24_dt__update__tmp_h5).dtor_published, (_24_dt__update__tmp_h5).dtor_token, (_24_dt__update__tmp_h5).dtor_ctx);
      }(_pat_let45_0);
    }(EHBPEvents.Phase.create_AwaitSetup(_17_first, _18_firstEof, _22_next));
  }(_pat_let44_0);
}(s), _dafny.Seq.of(_23_a));
              }
            }
            {
              let _26_ctx = (_source3).ctx;
              let _27_enc = (_source3).enc;
              let _28_job = EHBPEvents.__default.ExportJob(_26_ctx, EHBP.__default.Ascii(EHBP.__default.ExportLabel), EHBP.__default.ExportLength);
              return _dafny.Tuple.of(function (_pat_let46_0) {
  return function (_29_dt__update__tmp_h6) {
    return function (_pat_let47_0) {
      return function (_30_dt__update_hctx_h0) {
        return function (_pat_let48_0) {
          return function (_31_dt__update_hphase_h5) {
            return EHBPEvents.State.create_State(_31_dt__update_hphase_h5, (_29_dt__update__tmp_h6).dtor_origin, (_29_dt__update__tmp_h6).dtor_publicKey, (_29_dt__update__tmp_h6).dtor_verb, (_29_dt__update__tmp_h6).dtor_url, (_29_dt__update__tmp_h6).dtor_headers, (_29_dt__update__tmp_h6).dtor_generation, (_29_dt__update__tmp_h6).dtor_published, (_29_dt__update__tmp_h6).dtor_token, _30_dt__update_hctx_h0);
          }(_pat_let48_0);
        }(EHBPEvents.Phase.create_AwaitExport(_17_first, _18_firstEof, _27_enc, _28_job));
      }(_pat_let47_0);
    }(_26_ctx);
  }(_pat_let46_0);
}(s), _dafny.Seq.of(EHBPEvents.__default.JobAction(_28_job)));
            }
          }
        }
        {
          if (_source0.is_AwaitExport) {
            let _32_first = (_source0).first;
            let _33_firstEof = (_source0).firstEof;
            let _34_enc = (_source0).enc;
            let _35_job = (_source0).job;
            let _source4 = EHBPEvents.__default.JobStep(_35_job, e);
            {
              if (_source4.is_JobFailed) {
                let _36_code = (_source4).code;
                let _37_message = (_source4).message;
                return EHBPEvents.__default.Abort(s, false, _36_code, _37_message);
              }
            }
            {
              if (_source4.is_Pending) {
                let _38_next = (_source4).job;
                let _39_a = (_source4).action;
                return _dafny.Tuple.of(function (_pat_let49_0) {
  return function (_40_dt__update__tmp_h7) {
    return function (_pat_let50_0) {
      return function (_41_dt__update_hphase_h6) {
        return EHBPEvents.State.create_State(_41_dt__update_hphase_h6, (_40_dt__update__tmp_h7).dtor_origin, (_40_dt__update__tmp_h7).dtor_publicKey, (_40_dt__update__tmp_h7).dtor_verb, (_40_dt__update__tmp_h7).dtor_url, (_40_dt__update__tmp_h7).dtor_headers, (_40_dt__update__tmp_h7).dtor_generation, (_40_dt__update__tmp_h7).dtor_published, (_40_dt__update__tmp_h7).dtor_token, (_40_dt__update__tmp_h7).dtor_ctx);
      }(_pat_let50_0);
    }(EHBPEvents.Phase.create_AwaitExport(_32_first, _33_firstEof, _34_enc, _38_next));
  }(_pat_let49_0);
}(s), _dafny.Seq.of(_39_a));
              }
            }
            {
              let _42_secret = (_source4).data;
              if (!(new BigNumber((_34_enc).length)).isEqualTo(EHBP.__default.RequestEncLength)) {
                return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("HPKE sender setup failed"));
              } else if (!(new BigNumber((_42_secret).length)).isEqualTo(EHBP.__default.ExportLength)) {
                return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("HPKE export failed"));
              } else {
                let _43_token = EHBP.Token.create_Token(_42_secret, _34_enc);
                let _44_headers = _dafny.Seq.Concat((s).dtor_headers, _dafny.Seq.of(_dafny.Tuple.of(EHBP.__default.EncapsulatedKeyHeader, EHBP.__default.EncodeHex(_34_enc))));
                return _dafny.Tuple.of(function (_pat_let51_0) {
  return function (_45_dt__update__tmp_h8) {
    return function (_pat_let52_0) {
      return function (_46_dt__update_htoken_h0) {
        return function (_pat_let53_0) {
          return function (_47_dt__update_hpublished_h0) {
            return function (_pat_let54_0) {
              return function (_48_dt__update_hphase_h7) {
                return EHBPEvents.State.create_State(_48_dt__update_hphase_h7, (_45_dt__update__tmp_h8).dtor_origin, (_45_dt__update__tmp_h8).dtor_publicKey, (_45_dt__update__tmp_h8).dtor_verb, (_45_dt__update__tmp_h8).dtor_url, (_45_dt__update__tmp_h8).dtor_headers, (_45_dt__update__tmp_h8).dtor_generation, _47_dt__update_hpublished_h0, _46_dt__update_htoken_h0, (_45_dt__update__tmp_h8).dtor_ctx);
              }(_pat_let54_0);
            }(EHBPEvents.Phase.create_Exchanging(EHBPEvents.Upload.create_Sealing(_32_first, 0, _33_firstEof), EHBPEvents.Response.create_AwaitHead(true)));
          }(_pat_let53_0);
        }(true);
      }(_pat_let52_0);
    }(_43_token);
  }(_pat_let51_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_PublishToken((s).dtor_generation, _42_secret, _34_enc), EHBPEvents.Action.create_Send((s).dtor_verb, (s).dtor_url, _44_headers, true), EHBPEvents.__default.SealAction((s).dtor_ctx, EHBPEvents.__default.Piece(_32_first, 0, EHBPEvents.__default.Min32((_32_first).length, EHBP.__default.RequestFrameBytes)))));
              }
            }
          }
        }
        {
          if (_source0.is_Exchanging) {
            let _49_up = (_source0).upload;
            let _50_rs = (_source0).response;
            if (EHBPEvents.__default.ForUpload(e)) {
              return EHBPEvents.__default.StepUpload(s, _49_up, e);
            } else {
              return EHBPEvents.__default.StepResponse(s, _50_rs, e);
            }
          }
        }
        {
          if (_source0.is_DiscAwaitHead) {
            let _source5 = e;
            {
              if (_source5.is_StreamFailed) {
                let stream2 = (_source5).stream;
                if (stream2.is_ResponseBody) {
                  return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to get server public key"));
                }
              }
            }
            {
              if (_source5.is_ResponseHead) {
                let _51_status = (_source5).status;
                let _52_headers = (_source5).headers;
                let _53_redirected = (_source5).redirected;
                if (((_51_status).isLessThan(new BigNumber(100))) || ((new BigNumber(599)).isLessThan(_51_status))) {
                  return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to get server public key"));
                } else {
                  let _source6 = EHBP.__default.ClassifyDiscovery(EHBP.Head.create_Head(_51_status, _52_headers, _53_redirected));
                  {
                    if (_source6.is_Err) {
                      let _54_code = (_source6).code;
                      let _55_message = (_source6).message;
                      return EHBPEvents.__default.Abort(s, true, _54_code, _55_message);
                    }
                  }
                  {
                    return _dafny.Tuple.of(function (_pat_let55_0) {
  return function (_56_dt__update__tmp_h9) {
    return function (_pat_let56_0) {
      return function (_57_dt__update_hphase_h8) {
        return EHBPEvents.State.create_State(_57_dt__update_hphase_h8, (_56_dt__update__tmp_h9).dtor_origin, (_56_dt__update__tmp_h9).dtor_publicKey, (_56_dt__update__tmp_h9).dtor_verb, (_56_dt__update__tmp_h9).dtor_url, (_56_dt__update__tmp_h9).dtor_headers, (_56_dt__update__tmp_h9).dtor_generation, (_56_dt__update__tmp_h9).dtor_published, (_56_dt__update__tmp_h9).dtor_token, (_56_dt__update__tmp_h9).dtor_ctx);
      }(_pat_let56_0);
    }(EHBPEvents.Phase.create_DiscReading(_dafny.Seq.of()));
  }(_pat_let55_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
                  }
                }
              }
            }
            {
              return EHBPEvents.__default.Unexpected(s);
            }
          }
        }
        {
          if (_source0.is_DiscReading) {
            let _58_data = (_source0).data;
            let _source7 = e;
            {
              if (_source7.is_StreamFailed) {
                let stream3 = (_source7).stream;
                if (stream3.is_ResponseBody) {
                  return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to read key configuration"));
                }
              }
            }
            {
              if (_source7.is_Chunk) {
                let stream4 = (_source7).stream;
                if (stream4.is_ResponseBody) {
                  let _59_chunk = (_source7).data;
                  let _60_eof = (_source7).eof;
                  let _61_grown = _dafny.Seq.Concat(_58_data, _59_chunk);
                  if (((new BigNumber((_61_grown).length)).isLessThanOrEqualTo(EHBP.__default.MaxKeyConfigBytes)) && (!(_60_eof))) {
                    return _dafny.Tuple.of(function (_pat_let57_0) {
  return function (_62_dt__update__tmp_h10) {
    return function (_pat_let58_0) {
      return function (_63_dt__update_hphase_h9) {
        return EHBPEvents.State.create_State(_63_dt__update_hphase_h9, (_62_dt__update__tmp_h10).dtor_origin, (_62_dt__update__tmp_h10).dtor_publicKey, (_62_dt__update__tmp_h10).dtor_verb, (_62_dt__update__tmp_h10).dtor_url, (_62_dt__update__tmp_h10).dtor_headers, (_62_dt__update__tmp_h10).dtor_generation, (_62_dt__update__tmp_h10).dtor_published, (_62_dt__update__tmp_h10).dtor_token, (_62_dt__update__tmp_h10).dtor_ctx);
      }(_pat_let58_0);
    }(EHBPEvents.Phase.create_DiscReading(_61_grown));
  }(_pat_let57_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
                  } else {
                    let _source8 = EHBP.__default.ParseConfig(_61_grown);
                    {
                      if (_source8.is_Ok) {
                        let _64_pk = (_source8).value;
                        return EHBPEvents.__default.End(s, true, EHBPEvents.Action.create_Discovered(_64_pk));
                      }
                    }
                    {
                      let _65_code = (_source8).code;
                      let _66_message = (_source8).message;
                      return EHBPEvents.__default.Abort(s, true, _65_code, _66_message);
                    }
                  }
                }
              }
            }
            {
              return EHBPEvents.__default.Unexpected(s);
            }
          }
        }
        {
          return EHBPEvents.__default.Unexpected(s);
        }
      }
    };
    static StepStart(s, e) {
      let _pat_let_tv0 = e;
      let _pat_let_tv1 = e;
      let _pat_let_tv2 = e;
      let _pat_let_tv3 = e;
      let _0_target = EHBP.__default.MakeOrigin((e).dtor_scheme, (e).dtor_host, (((e).dtor_hasPort) ? (EHBP.Option.create_Some((e).dtor_port)) : (EHBP.Option.create_None())), (e).dtor_hasUserinfo);
      let _source0 = EHBP.__default.ValidateRequest((s).dtor_origin, _0_target, (e).dtor_headers);
      {
        if (_source0.is_Err) {
          let _1_code = (_source0).code;
          let _2_message = (_source0).message;
          return EHBPEvents.__default.Abort(s, false, _1_code, _2_message);
        }
      }
      {
        return _dafny.Tuple.of(function (_pat_let59_0) {
  return function (_3_dt__update__tmp_h0) {
    return function (_pat_let60_0) {
      return function (_4_dt__update_hheaders_h0) {
        return function (_pat_let61_0) {
          return function (_5_dt__update_hurl_h0) {
            return function (_pat_let62_0) {
              return function (_6_dt__update_hverb_h0) {
                return function (_pat_let63_0) {
                  return function (_7_dt__update_hphase_h0) {
                    return EHBPEvents.State.create_State(_7_dt__update_hphase_h0, (_3_dt__update__tmp_h0).dtor_origin, (_3_dt__update__tmp_h0).dtor_publicKey, _6_dt__update_hverb_h0, _5_dt__update_hurl_h0, _4_dt__update_hheaders_h0, (_3_dt__update__tmp_h0).dtor_generation, (_3_dt__update__tmp_h0).dtor_published, (_3_dt__update__tmp_h0).dtor_token, (_3_dt__update__tmp_h0).dtor_ctx);
                  }(_pat_let63_0);
                }(EHBPEvents.Phase.create_AwaitSession((_pat_let_tv3).dtor_hasBody));
              }(_pat_let62_0);
            }((_pat_let_tv2).dtor_verb);
          }(_pat_let61_0);
        }((_pat_let_tv1).dtor_url);
      }(_pat_let60_0);
    }(EHBP.__default.DropFraming((_pat_let_tv0).dtor_headers));
  }(_pat_let59_0);
}(s), _dafny.Seq.of(EHBPEvents.Action.create_BeginSession()));
      }
    };
    static StepUpload(s, up, e) {
      let _pat_let_tv0 = s;
      let _source0 = up;
      {
        if (_source0.is_Sealing) {
          let _0_plaintext = (_source0).plaintext;
          let _1_offset = (_source0).offset;
          let _2_eof = (_source0).eof;
          let _3_size = (_0_plaintext).length;
          let _4_at = EHBPEvents.__default.Min32(_1_offset, _3_size);
          let _5_n = EHBPEvents.__default.Min32((_3_size) - (_4_at), EHBP.__default.RequestFrameBytes);
          if (!((e).is_AeadSealResult)) {
            return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
          } else if (!(new BigNumber(((e).dtor_ciphertext).length)).isEqualTo((new BigNumber(_5_n)).plus(EHBP.__default.AeadTagLength))) {
            return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_HpkeSetupFailed());
          } else if ((((s).dtor_ctx).dtor_seqNo).isEqualTo(EHBPEvents.__default.MaxSeq)) {
            return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_SequenceOverflow());
          } else {
            let _6_bumped = function (_pat_let64_0) {
              return function (_7_dt__update__tmp_h0) {
                return function (_pat_let65_0) {
                  return function (_8_dt__update_hctx_h0) {
                    return EHBPEvents.State.create_State((_7_dt__update__tmp_h0).dtor_phase, (_7_dt__update__tmp_h0).dtor_origin, (_7_dt__update__tmp_h0).dtor_publicKey, (_7_dt__update__tmp_h0).dtor_verb, (_7_dt__update__tmp_h0).dtor_url, (_7_dt__update__tmp_h0).dtor_headers, (_7_dt__update__tmp_h0).dtor_generation, (_7_dt__update__tmp_h0).dtor_published, (_7_dt__update__tmp_h0).dtor_token, _8_dt__update_hctx_h0);
                  }(_pat_let65_0);
                }(EHBPEvents.__default.Bump((_pat_let_tv0).dtor_ctx));
              }(_pat_let64_0);
            }(s);
            let _9_next = (_4_at) + (_5_n);
            if ((_9_next) < (_3_size)) {
              return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(_6_bumped, EHBPEvents.Upload.create_Sealing(_0_plaintext, _9_next, _2_eof)), _dafny.Seq.Concat(EHBPEvents.__default.FrameWrites((e).dtor_ciphertext, EHBPEvents.BodyEnd.create_More()), _dafny.Seq.of(EHBPEvents.__default.SealAction((_6_bumped).dtor_ctx, EHBPEvents.__default.Piece(_0_plaintext, _9_next, EHBPEvents.__default.Min32((_3_size) - (_9_next), EHBP.__default.RequestFrameBytes))))));
            } else if (_2_eof) {
              return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(_6_bumped, EHBPEvents.Upload.create_UpDone()), EHBPEvents.__default.FrameWrites((e).dtor_ciphertext, EHBPEvents.BodyEnd.create_Done()));
            } else {
              return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(_6_bumped, EHBPEvents.Upload.create_UpReading(_dafny.ZERO)), _dafny.Seq.Concat(EHBPEvents.__default.FrameWrites((e).dtor_ciphertext, EHBPEvents.BodyEnd.create_More()), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_RequestBody()))));
            }
          }
        }
      }
      {
        if (_source0.is_UpReading) {
          let _10_empty = (_source0).empty;
          let _source1 = e;
          {
            if (_source1.is_StreamFailed) {
              let stream0 = (_source1).stream;
              if (stream0.is_RequestBody) {
                return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
              }
            }
          }
          {
            if (_source1.is_Chunk) {
              let stream1 = (_source1).stream;
              if (stream1.is_RequestBody) {
                let _11_data = (_source1).data;
                let _12_eof = (_source1).eof;
                if ((EHBPEvents.__default.MaxReadBytes).isLessThan(new BigNumber((_11_data).length))) {
                  return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
                } else if ((_dafny.ZERO).isLessThan(new BigNumber((_11_data).length))) {
                  return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(s, EHBPEvents.Upload.create_Sealing(_11_data, 0, _12_eof)), _dafny.Seq.of(EHBPEvents.__default.SealAction((s).dtor_ctx, EHBPEvents.__default.Piece(_11_data, 0, EHBPEvents.__default.Min32((_11_data).length, EHBP.__default.RequestFrameBytes)))));
                } else if (_12_eof) {
                  return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(s, EHBPEvents.Upload.create_UpDone()), _dafny.Seq.of(EHBPEvents.Action.create_Write(_dafny.Seq.of(), EHBPEvents.BodyEnd.create_Done())));
                } else if (((_10_empty).plus(_dafny.ONE)).isEqualTo(EHBP.__default.MaxEmptyReads)) {
                  return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
                } else {
                  return _dafny.Tuple.of(EHBPEvents.__default.WithUpload(s, EHBPEvents.Upload.create_UpReading((_10_empty).plus(_dafny.ONE))), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_RequestBody())));
                }
              }
            }
          }
          {
            return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
          }
        }
      }
      {
        return EHBPEvents.__default.AbortUpload(s, EHBP.Code.create_Transport());
      }
    };
    static StepResponse(s, rs, e) {
      let _source0 = rs;
      {
        if (_source0.is_AwaitHead) {
          let _0_encrypted = (_source0).encrypted;
          let _source1 = e;
          {
            if (_source1.is_StreamFailed) {
              let stream0 = (_source1).stream;
              if (stream0.is_ResponseBody) {
                return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to make request"));
              }
            }
          }
          {
            if (_source1.is_ResponseHead) {
              let _1_status = (_source1).status;
              let _2_headers = (_source1).headers;
              let _3_redirected = (_source1).redirected;
              if ((!(_3_redirected)) && (((_1_status).isLessThan(new BigNumber(100))) || ((new BigNumber(599)).isLessThan(_1_status)))) {
                return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("transport reported an impossible status"));
              } else {
                let _source2 = EHBP.__default.Classify(_0_encrypted, EHBP.Head.create_Head(_1_status, _2_headers, _3_redirected));
                {
                  if (_source2.is_PassThrough) {
                    return EHBPEvents.__default.End(s, false, EHBPEvents.Action.create_Passthrough(_1_status, _2_headers, _dafny.Seq.of()));
                  }
                }
                {
                  if (_source2.is_Refuse) {
                    let _4_code = (_source2).code;
                    let _5_message = (_source2).message;
                    return EHBPEvents.__default.Abort(s, true, _4_code, _5_message);
                  }
                }
                {
                  if (_source2.is_NeedProblemBody) {
                    return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_ProblemReading(_1_status, _2_headers, _dafny.Seq.of())), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
                  }
                }
                {
                  let _6_nonce = (_source2).nonce;
                  let _7_requireFrame = (_source2).requireFrame;
                  if (!(EHBP.__default.ValidToken((s).dtor_token))) {
                    return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("token fields must be 32 bytes"));
                  } else if (!(new BigNumber((_6_nonce).length)).isEqualTo(EHBP.__default.ResponseNonceLength)) {
                    return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_InvalidInput(), _dafny.Seq.UnicodeFromString("response nonce must be 32 bytes"));
                  } else {
                    let _8_job = EHBPEvents.__default.Extract(_dafny.Seq.Concat(((s).dtor_token).dtor_requestEnc, _6_nonce), ((s).dtor_token).dtor_exportedSecret);
                    return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_AwaitKeys(_1_status, _2_headers, _7_requireFrame, _dafny.ZERO, _8_job, _dafny.Seq.of(), _dafny.Seq.of())), _dafny.Seq.of(EHBPEvents.__default.JobAction(_8_job)));
                  }
                }
              }
            }
          }
          {
            return EHBPEvents.__default.Unexpected(s);
          }
        }
      }
      {
        if (_source0.is_ProblemReading) {
          let _9_status = (_source0).status;
          let _10_headers = (_source0).headers;
          let _11_data = (_source0).data;
          let _source3 = e;
          {
            if (_source3.is_StreamFailed) {
              let stream1 = (_source3).stream;
              if (stream1.is_ResponseBody) {
                return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("failed to read problem response"));
              }
            }
          }
          {
            if (_source3.is_Chunk) {
              let stream2 = (_source3).stream;
              if (stream2.is_ResponseBody) {
                let _12_chunk = (_source3).data;
                let _13_eof = (_source3).eof;
                let _14_grown = _dafny.Seq.Concat(_11_data, _12_chunk);
                if (((new BigNumber((_14_grown).length)).isLessThanOrEqualTo((EHBP.__default.MaxProblemBytes).plus(_dafny.ONE))) && (!(_13_eof))) {
                  return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_ProblemReading(_9_status, _10_headers, _14_grown)), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
                } else {
                  let _15_oversized = (EHBP.__default.MaxProblemBytes).isLessThan(new BigNumber((_14_grown).length));
                  let _let_tmp_rhs0 = ((_15_oversized) ? (_dafny.Tuple.of(false, EHBP.Option.create_None(), EHBP.Option.create_None())) : (EHBPEvents.__default.ParseProblem(_14_grown)));
                  let _16_isObject = (_let_tmp_rhs0)[0];
                  let _17_typeValue = (_let_tmp_rhs0)[1];
                  let _18_title = (_let_tmp_rhs0)[2];
                  let _source4 = EHBP.__default.ClassifyProblem(_15_oversized, _16_isObject, _17_typeValue, _18_title);
                  {
                    if (_source4.is_Refuse) {
                      let _19_code = (_source4).code;
                      let _20_message = (_source4).message;
                      return EHBPEvents.__default.Abort(s, true, _19_code, _20_message);
                    }
                  }
                  {
                    if (_source4.is_PassThrough) {
                      return EHBPEvents.__default.End(s, false, EHBPEvents.Action.create_Passthrough(_9_status, _10_headers, _14_grown));
                    }
                  }
                  {
                    return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_Transport(), _dafny.Seq.UnicodeFromString("unreachable"));
                  }
                }
              }
            }
          }
          {
            return EHBPEvents.__default.Unexpected(s);
          }
        }
      }
      {
        if (_source0.is_AwaitKeys) {
          let _21_status = (_source0).status;
          let _22_headers = (_source0).headers;
          let _23_requireFrame = (_source0).requireFrame;
          let _24_stage = (_source0).stage;
          let _25_job = (_source0).job;
          let _26_prk = (_source0).prk;
          let _27_key = (_source0).key;
          let _source5 = EHBPEvents.__default.JobStep(_25_job, e);
          {
            if (_source5.is_JobFailed) {
              let _28_code = (_source5).code;
              let _29_message = (_source5).message;
              return EHBPEvents.__default.Abort(s, true, _28_code, _29_message);
            }
          }
          {
            if (_source5.is_Pending) {
              let _30_next = (_source5).job;
              let _31_a = (_source5).action;
              return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_AwaitKeys(_21_status, _22_headers, _23_requireFrame, _24_stage, _30_next, _26_prk, _27_key)), _dafny.Seq.of(_31_a));
            }
          }
          {
            let _32_out = (_source5).data;
            if ((_24_stage).isEqualTo(_dafny.ZERO)) {
              let _33_next = EHBPEvents.__default.Expand(_32_out, EHBP.__default.Ascii(EHBP.__default.ResponseKeyLabel), EHBP.__default.KeyLength);
              return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_AwaitKeys(_21_status, _22_headers, _23_requireFrame, _dafny.ONE, _33_next, _32_out, _dafny.Seq.of())), _dafny.Seq.of(EHBPEvents.__default.JobAction(_33_next)));
            } else if ((_24_stage).isEqualTo(_dafny.ONE)) {
              let _34_next = EHBPEvents.__default.Expand(_26_prk, EHBP.__default.Ascii(EHBP.__default.ResponseNonceLabel), EHBP.__default.NonceLength);
              return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_AwaitKeys(_21_status, _22_headers, _23_requireFrame, new BigNumber(2), _34_next, _26_prk, _32_out)), _dafny.Seq.of(EHBPEvents.__default.JobAction(_34_next)));
            } else if (((new BigNumber((_27_key).length)).isEqualTo(EHBP.__default.KeyLength)) && ((new BigNumber((_32_out).length)).isEqualTo(EHBP.__default.NonceLength))) {
              let _35_k = _27_key;
              let _36_n = _32_out;
              return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_Body(EHBPEvents.Ctx.create_Ctx(_35_k, _36_n, _dafny.Seq.of(), _dafny.ZERO), EHBPEvents.Dec.create_Dec(_dafny.Seq.of(), _dafny.ZERO, false, _23_requireFrame), false)), _dafny.Seq.of(EHBPEvents.Action.create_Done(_21_status, EHBP.__default.DropFraming(_22_headers))));
            } else {
              return EHBPEvents.__default.Abort(s, true, EHBP.Code.create_HpkeSetupFailed(), _dafny.Seq.UnicodeFromString("HKDF expand returned the wrong length"));
            }
          }
        }
      }
      {
        if (_source0.is_Body) {
          let _37_keys = (_source0).keys;
          let _38_dec = (_source0).dec;
          let _39_done = (_source0).done;
          if (!((e).is_CallerRead)) {
            return EHBPEvents.__default.Unexpected(s);
          } else if (_39_done) {
            return EHBPEvents.__default.End(s, false, EHBPEvents.Action.create_Finished());
          } else {
            return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_BodyReading(_37_keys, _38_dec)), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
          }
        }
      }
      {
        if (_source0.is_BodyReading) {
          let _40_keys = (_source0).keys;
          let _41_dec = (_source0).dec;
          let _source6 = e;
          {
            if (_source6.is_StreamFailed) {
              let stream3 = (_source6).stream;
              if (stream3.is_ResponseBody) {
                return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_FramingTruncated(), _dafny.Seq.UnicodeFromString("response body failed"));
              }
            }
          }
          {
            if (_source6.is_Chunk) {
              let stream4 = (_source6).stream;
              if (stream4.is_ResponseBody) {
                let _42_data = (_source6).data;
                let _43_eof = (_source6).eof;
                let _let_tmp_rhs1 = EHBPEvents.__default.Push(_41_dec, _42_data);
                let _44_frames = (_let_tmp_rhs1)[0];
                let _45_next = (_let_tmp_rhs1)[1];
                let _46_err = (_let_tmp_rhs1)[2];
                if ((_46_err).is_Some) {
                  return EHBPEvents.__default.Abort(s, false, (_46_err).dtor_value, _dafny.Seq.UnicodeFromString(""));
                } else {
                  return EHBPEvents.__default.OpenNext(s, _40_keys, _45_next, _44_frames, _dafny.Seq.of(), _43_eof);
                }
              }
            }
          }
          {
            return EHBPEvents.__default.Unexpected(s);
          }
        }
      }
      {
        if (_source0.is_Opening) {
          let _47_keys = (_source0).keys;
          let _48_dec = (_source0).dec;
          let _49_frames = (_source0).frames;
          let _50_chunks = (_source0).chunks;
          let _51_eof = (_source0).eof;
          if ((!((e).is_AeadOpenResult)) || ((new BigNumber((_49_frames).length)).isEqualTo(_dafny.ZERO))) {
            return EHBPEvents.__default.Unexpected(s);
          } else if (!((e).dtor_ok)) {
            return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), _dafny.Seq.UnicodeFromString("frame failed to authenticate"));
          } else if (!((new BigNumber(((e).dtor_plaintext).length)).plus(EHBP.__default.AeadTagLength)).isEqualTo(new BigNumber((((_49_frames)[_dafny.ZERO]).dtor_ciphertext).length))) {
            return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), _dafny.Seq.UnicodeFromString("AEAD returned the wrong length"));
          } else {
            return EHBPEvents.__default.OpenNext(s, _47_keys, _48_dec, (_49_frames).slice(_dafny.ONE), (((_dafny.ZERO).isLessThan(new BigNumber(((e).dtor_plaintext).length))) ? (_dafny.Seq.Concat(_50_chunks, _dafny.Seq.of((e).dtor_plaintext))) : (_50_chunks)), _51_eof);
          }
        }
      }
      {
        return EHBPEvents.__default.Unexpected(s);
      }
    };
    static Emits(chunks) {
      return _dafny.Seq.Create(new BigNumber((chunks).length), ((_0_chunks) => function (_1_i) {
        return EHBPEvents.Action.create_EmitPlaintext((_0_chunks)[_1_i]);
      })(chunks));
    };
    static OpenNext(s, keys, dec, frames, chunks, eof) {
      if ((_dafny.ZERO).isLessThan(new BigNumber((frames).length))) {
        if ((new BigNumber((((frames)[_dafny.ZERO]).dtor_ciphertext).length)).isLessThan(EHBP.__default.AeadTagLength)) {
          return EHBPEvents.__default.Abort(s, false, EHBP.Code.create_AeadDecryptFailed(), _dafny.Seq.UnicodeFromString("frame shorter than the AEAD tag"));
        } else {
          return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_Opening(keys, dec, frames, chunks, eof)), _dafny.Seq.of(EHBPEvents.Action.create_AeadOpen((keys).dtor_key, EHBP.__default.ComputeNonce((keys).dtor_baseNonce, ((frames)[_dafny.ZERO]).dtor_seqNo), ((frames)[_dafny.ZERO]).dtor_ciphertext)));
        }
      } else if (eof) {
        let _source0 = EHBPEvents.__default.Finish(dec);
        {
          if (_source0.is_Some) {
            let _0_code = (_source0).value;
            return EHBPEvents.__default.Abort(s, false, _0_code, _dafny.Seq.UnicodeFromString(""));
          }
        }
        {
          if ((_dafny.ZERO).isLessThan(new BigNumber((chunks).length))) {
            return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_Body(keys, dec, true)), EHBPEvents.__default.Emits(chunks));
          } else {
            return EHBPEvents.__default.End(s, false, EHBPEvents.Action.create_Finished());
          }
        }
      } else if ((_dafny.ZERO).isLessThan(new BigNumber((chunks).length))) {
        return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_Body(keys, dec, false)), EHBPEvents.__default.Emits(chunks));
      } else {
        return _dafny.Tuple.of(EHBPEvents.__default.WithResponse(s, EHBPEvents.Response.create_BodyReading(keys, dec)), _dafny.Seq.of(EHBPEvents.Action.create_Read(EHBPEvents.Stream.create_ResponseBody())));
      }
    };
    static Hex(s) {
      let _source0 = EHBP.__default.DecodeHex(s);
      {
        if (_source0.is_Some) {
          let _0_b = (_source0).value;
          return _0_b;
        }
      }
      {
        return _dafny.Seq.of();
      }
    };
    static SelfCheckJudge(results) {
      if (!(new BigNumber((results).length)).isEqualTo(new BigNumber((EHBPEvents.__default.SelfCheckActions).length))) {
        return _dafny.Seq.of(_dafny.Seq.UnicodeFromString("self-check: wrong number of results"));
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(((!_dafny.areEqual((results)[_dafny.ZERO], EHBPEvents.Event.create_HmacResult(EHBPEvents.__default.HmacTag))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("HmacSha256: RFC 4231 test case 1"))) : (_dafny.Seq.of())), ((!_dafny.areEqual((results)[_dafny.ONE], EHBPEvents.Event.create_X25519Result(EHBPEvents.__default.AlicePk))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("X25519: RFC 7748 base point"))) : (_dafny.Seq.of()))), ((!_dafny.areEqual((results)[new BigNumber(2)], EHBPEvents.Event.create_X25519Result(EHBPEvents.__default.AliceBobShared))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("X25519: RFC 7748 shared secret"))) : (_dafny.Seq.of()))), ((!_dafny.areEqual((results)[new BigNumber(3)], EHBPEvents.Event.create_AeadSealResult(EHBPEvents.__default.GcmCt))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("AeadSeal: known answer"))) : (_dafny.Seq.of()))), ((!_dafny.areEqual((results)[new BigNumber(4)], EHBPEvents.Event.create_AeadOpenResult(true, EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("ehbp"))))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("AeadOpen: known answer"))) : (_dafny.Seq.of()))), (((!(((results)[new BigNumber(5)]).is_AeadOpenResult)) || (((results)[new BigNumber(5)]).dtor_ok)) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("AeadOpen: accepted a tampered tag"))) : (_dafny.Seq.of()))), (((!(((results)[new BigNumber(6)]).is_AeadOpenResult)) || (((results)[new BigNumber(6)]).dtor_ok)) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("AeadOpen: accepted a frame shorter than the tag"))) : (_dafny.Seq.of()))), (((((!(((results)[new BigNumber(7)]).is_RandomResult)) || (!(((results)[new BigNumber(8)]).is_RandomResult))) || (!(new BigNumber((((results)[new BigNumber(7)]).dtor_data).length)).isEqualTo(new BigNumber(32)))) || (!(new BigNumber((((results)[new BigNumber(8)]).dtor_data).length)).isEqualTo(new BigNumber(32)))) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("RandomBytes: length"))) : (_dafny.Seq.of()))), ((_dafny.areEqual((results)[new BigNumber(7)], (results)[new BigNumber(8)])) ? (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("RandomBytes: repeated output"))) : (_dafny.Seq.of())));
      }
    };
    static Rotr(x, n) {
      return _dafny.BitwiseOr((_dafny.ShiftRight(x, (n).toNumber())).mod(new BigNumber(2).exponentiatedBy(32)), (_dafny.ShiftLeft(x, ((new BigNumber(32)).minus(n)).toNumber())).mod(new BigNumber(2).exponentiatedBy(32)));
    };
    static Word(b, i) {
      return new BigNumber(EHBP.__default.U32(b, i));
    };
    static WordBytes(w) {
      return EHBP.__default.BE32((w).toNumber());
    };
    static MessageSchedule(w) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((w).length)).isEqualTo(new BigNumber(64))) {
          return w;
        } else {
          let _0_s0 = _dafny.BitwiseXor(_dafny.BitwiseXor(EHBPEvents.__default.Rotr((w)[(new BigNumber((w).length)).minus(new BigNumber(15))], new BigNumber(7)), EHBPEvents.__default.Rotr((w)[(new BigNumber((w).length)).minus(new BigNumber(15))], new BigNumber(18))), (_dafny.ShiftRight((w)[(new BigNumber((w).length)).minus(new BigNumber(15))], (new BigNumber(3)).toNumber())).mod(new BigNumber(2).exponentiatedBy(32)));
          let _1_s1 = _dafny.BitwiseXor(_dafny.BitwiseXor(EHBPEvents.__default.Rotr((w)[(new BigNumber((w).length)).minus(new BigNumber(2))], new BigNumber(17)), EHBPEvents.__default.Rotr((w)[(new BigNumber((w).length)).minus(new BigNumber(2))], new BigNumber(19))), (_dafny.ShiftRight((w)[(new BigNumber((w).length)).minus(new BigNumber(2))], (new BigNumber(10)).toNumber())).mod(new BigNumber(2).exponentiatedBy(32)));
          let _in0 = _dafny.Seq.Concat(w, _dafny.Seq.of((((((((w)[(new BigNumber((w).length)).minus(new BigNumber(16))]).plus(_0_s0)).mod(new BigNumber(2).exponentiatedBy(32))).plus((w)[(new BigNumber((w).length)).minus(new BigNumber(7))])).mod(new BigNumber(2).exponentiatedBy(32))).plus(_1_s1)).mod(new BigNumber(2).exponentiatedBy(32))));
          w = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static Rounds(w, t, v) {
      TAIL_CALL_START: while (true) {
        if ((t).isEqualTo(new BigNumber(64))) {
          return v;
        } else {
          let _0_a = (v)[_dafny.ZERO];
          let _1_b = (v)[_dafny.ONE];
          let _2_c = (v)[new BigNumber(2)];
          let _3_d = (v)[new BigNumber(3)];
          let _4_e = (v)[new BigNumber(4)];
          let _5_f = (v)[new BigNumber(5)];
          let _6_g = (v)[new BigNumber(6)];
          let _7_h = (v)[new BigNumber(7)];
          let _8_t1 = ((((((((_7_h).plus(_dafny.BitwiseXor(_dafny.BitwiseXor(EHBPEvents.__default.Rotr(_4_e, new BigNumber(6)), EHBPEvents.__default.Rotr(_4_e, new BigNumber(11))), EHBPEvents.__default.Rotr(_4_e, new BigNumber(25))))).mod(new BigNumber(2).exponentiatedBy(32))).plus(_dafny.BitwiseXor(_dafny.BitwiseAnd(_4_e, _5_f), _dafny.BitwiseAnd((_dafny.BitwiseNot(_4_e, 32)).mod(new BigNumber(2).exponentiatedBy(32)), _6_g)))).mod(new BigNumber(2).exponentiatedBy(32))).plus((EHBPEvents.__default.K256)[t])).mod(new BigNumber(2).exponentiatedBy(32))).plus((w)[t])).mod(new BigNumber(2).exponentiatedBy(32));
          let _9_t2 = ((_dafny.BitwiseXor(_dafny.BitwiseXor(EHBPEvents.__default.Rotr(_0_a, new BigNumber(2)), EHBPEvents.__default.Rotr(_0_a, new BigNumber(13))), EHBPEvents.__default.Rotr(_0_a, new BigNumber(22)))).plus(_dafny.BitwiseXor(_dafny.BitwiseXor(_dafny.BitwiseAnd(_0_a, _1_b), _dafny.BitwiseAnd(_0_a, _2_c)), _dafny.BitwiseAnd(_1_b, _2_c)))).mod(new BigNumber(2).exponentiatedBy(32));
          let _in0 = w;
          let _in1 = (t).plus(_dafny.ONE);
          let _in2 = _dafny.Seq.of(((_8_t1).plus(_9_t2)).mod(new BigNumber(2).exponentiatedBy(32)), _0_a, _1_b, _2_c, ((_3_d).plus(_8_t1)).mod(new BigNumber(2).exponentiatedBy(32)), _4_e, _5_f, _6_g);
          w = _in0;
          t = _in1;
          v = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static Blocks(p, i, h) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((p).length))) {
          return h;
        } else {
          let _0_block = (p).slice(i, (i).plus(new BigNumber(64)));
          let _1_w = EHBPEvents.__default.MessageSchedule(_dafny.Seq.Create(new BigNumber(16), ((_2_block) => function (_3_j) {
            return EHBPEvents.__default.Word(_2_block, (new BigNumber(4)).multipliedBy(_3_j));
          })(_0_block)));
          let _4_v = EHBPEvents.__default.Rounds(_1_w, _dafny.ZERO, h);
          let _in0 = p;
          let _in1 = (i).plus(new BigNumber(64));
          let _in2 = _dafny.Seq.Create(new BigNumber(8), ((_5_h, _6_v) => function (_7_j) {
            return (((_5_h)[_7_j]).plus((_6_v)[_7_j])).mod(new BigNumber(2).exponentiatedBy(32));
          })(h, _4_v));
          p = _in0;
          i = _in1;
          h = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static Sha256(msg) {
      let _0_pad = ((new BigNumber(119)).minus((new BigNumber((msg).length)).mod(new BigNumber(64)))).mod(new BigNumber(64));
      let _1_bits = (new BigNumber((msg).length)).multipliedBy(new BigNumber(8));
      let _2_padded = _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(msg, _dafny.Seq.of(128)), _dafny.Seq.Create(_0_pad, function (_3_i) {
        return (0);
      })), EHBP.__default.BE32(((_dafny.EuclideanDivision(_1_bits, new BigNumber(4294967296))).mod(new BigNumber(4294967296))).toNumber())), EHBP.__default.BE32(((_1_bits).mod(new BigNumber(4294967296))).toNumber()));
      let _4_h = EHBPEvents.__default.Blocks(_2_padded, _dafny.ZERO, EHBPEvents.__default.H256);
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(EHBPEvents.__default.WordBytes((_4_h)[_dafny.ZERO]), EHBPEvents.__default.WordBytes((_4_h)[_dafny.ONE])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(2)])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(3)])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(4)])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(5)])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(6)])), EHBPEvents.__default.WordBytes((_4_h)[new BigNumber(7)]));
    };
    static XorPad(b, p) {
      return _dafny.Seq.Create(new BigNumber((b).length), ((_0_b, _1_p) => function (_2_i) {
        return (_dafny.BitwiseXor(new BigNumber((_0_b)[_2_i]), new BigNumber(_1_p))).toNumber();
      })(b, p));
    };
    static HmacRef(key, data) {
      let _0_k = (((new BigNumber(64)).isLessThan(new BigNumber((key).length))) ? (EHBPEvents.__default.Sha256(key)) : (key));
      let _1_kp = _dafny.Seq.Concat(_0_k, _dafny.Seq.Create((new BigNumber(64)).minus(new BigNumber((_0_k).length)), function (_2_i) {
        return (0);
      }));
      return EHBPEvents.__default.Sha256(_dafny.Seq.Concat(EHBPEvents.__default.XorPad(_1_kp, 92), EHBPEvents.__default.Sha256(_dafny.Seq.Concat(EHBPEvents.__default.XorPad(_1_kp, 54), data))));
    };
    static Pow2(n) {
      let _0___accumulator = _dafny.ONE;
      TAIL_CALL_START: while (true) {
        if ((n).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ONE).multipliedBy(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).multipliedBy(new BigNumber(2));
          let _in0 = (n).minus(_dafny.ONE);
          n = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static PowMod(b, e) {
      if ((e).isEqualTo(_dafny.ZERO)) {
        return (_dafny.ONE).mod(EHBPEvents.__default.P25519);
      } else if (((e).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) {
        let _0_h = EHBPEvents.__default.PowMod(b, _dafny.EuclideanDivision(e, new BigNumber(2)));
        return ((_0_h).multipliedBy(_0_h)).mod(EHBPEvents.__default.P25519);
      } else {
        return ((b).multipliedBy(EHBPEvents.__default.PowMod(b, (e).minus(_dafny.ONE)))).mod(EHBPEvents.__default.P25519);
      }
    };
    static LE(b) {
      if ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.ZERO;
      } else {
        return (new BigNumber((b)[_dafny.ZERO])).plus((new BigNumber(256)).multipliedBy(EHBPEvents.__default.LE((b).slice(_dafny.ONE))));
      }
    };
    static LEBytes(n, length) {
      return _dafny.Seq.Create(length, ((_0_n, _1_length) => function (_2_i) {
        return ((_dafny.EuclideanDivision(_0_n, EHBPEvents.__default.Pow2((new BigNumber(8)).multipliedBy(_2_i)))).mod(new BigNumber(256))).toNumber();
      })(n, length));
    };
    static Clamp(k) {
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of((_dafny.BitwiseAnd(new BigNumber((k)[_dafny.ZERO]), new BigNumber(248))).toNumber()), (k).slice(_dafny.ONE, new BigNumber(31))), _dafny.Seq.of((_dafny.BitwiseOr(_dafny.BitwiseAnd(new BigNumber((k)[new BigNumber(31)]), new BigNumber(127)), new BigNumber(64))).toNumber()));
    };
    static Ladder(k, x1, t, x2, z2, x3, z3, swap) {
      TAIL_CALL_START: while (true) {
        let _0_kt = (_dafny.EuclideanDivision(k, EHBPEvents.__default.Pow2(t))).mod(new BigNumber(2));
        let _1_sw = ((!(swap).isEqualTo(_0_kt)) ? (_dafny.ONE) : (_dafny.ZERO));
        let _let_tmp_rhs0 = (((_1_sw).isEqualTo(_dafny.ONE)) ? (_dafny.Tuple.of(x3, x2)) : (_dafny.Tuple.of(x2, x3)));
        let _2_x2s = (_let_tmp_rhs0)[0];
        let _3_x3s = (_let_tmp_rhs0)[1];
        let _let_tmp_rhs1 = (((_1_sw).isEqualTo(_dafny.ONE)) ? (_dafny.Tuple.of(z3, z2)) : (_dafny.Tuple.of(z2, z3)));
        let _4_z2s = (_let_tmp_rhs1)[0];
        let _5_z3s = (_let_tmp_rhs1)[1];
        let _6_a = ((_2_x2s).plus(_4_z2s)).mod(EHBPEvents.__default.P25519);
        let _7_aa = ((_6_a).multipliedBy(_6_a)).mod(EHBPEvents.__default.P25519);
        let _8_b = ((_2_x2s).minus(_4_z2s)).mod(EHBPEvents.__default.P25519);
        let _9_bb = ((_8_b).multipliedBy(_8_b)).mod(EHBPEvents.__default.P25519);
        let _10_e = ((_7_aa).minus(_9_bb)).mod(EHBPEvents.__default.P25519);
        let _11_c = ((_3_x3s).plus(_5_z3s)).mod(EHBPEvents.__default.P25519);
        let _12_d = ((_3_x3s).minus(_5_z3s)).mod(EHBPEvents.__default.P25519);
        let _13_da = ((_12_d).multipliedBy(_6_a)).mod(EHBPEvents.__default.P25519);
        let _14_cb = ((_11_c).multipliedBy(_8_b)).mod(EHBPEvents.__default.P25519);
        let _15_nx3 = (((_13_da).plus(_14_cb)).multipliedBy((_13_da).plus(_14_cb))).mod(EHBPEvents.__default.P25519);
        let _16_nz3 = ((x1).multipliedBy((((_13_da).minus(_14_cb)).multipliedBy((_13_da).minus(_14_cb))).mod(EHBPEvents.__default.P25519))).mod(EHBPEvents.__default.P25519);
        let _17_nx2 = ((_7_aa).multipliedBy(_9_bb)).mod(EHBPEvents.__default.P25519);
        let _18_nz2 = ((_10_e).multipliedBy(((_7_aa).plus((new BigNumber(121665)).multipliedBy(_10_e))).mod(EHBPEvents.__default.P25519))).mod(EHBPEvents.__default.P25519);
        if ((t).isEqualTo(_dafny.ZERO)) {
          return _dafny.Tuple.of(_17_nx2, _18_nz2, _15_nx3, _16_nz3, _0_kt);
        } else {
          let _in0 = k;
          let _in1 = x1;
          let _in2 = (t).minus(_dafny.ONE);
          let _in3 = _17_nx2;
          let _in4 = _18_nz2;
          let _in5 = _15_nx3;
          let _in6 = _16_nz3;
          let _in7 = _0_kt;
          k = _in0;
          x1 = _in1;
          t = _in2;
          x2 = _in3;
          z2 = _in4;
          x3 = _in5;
          z3 = _in6;
          swap = _in7;
          continue TAIL_CALL_START;
        }
      }
    };
    static X25519Ref(scalar, point) {
      let _0_k = EHBPEvents.__default.LE(EHBPEvents.__default.Clamp(scalar));
      let _1_u = (EHBPEvents.__default.LE(point)).mod(EHBPEvents.__default.Pow2(new BigNumber(255)));
      let _let_tmp_rhs0 = EHBPEvents.__default.Ladder(_0_k, _1_u, new BigNumber(255), _dafny.ONE, _dafny.ZERO, _1_u, _dafny.ONE, _dafny.ZERO);
      let _2_x2 = (_let_tmp_rhs0)[0];
      let _3_z2 = (_let_tmp_rhs0)[1];
      let _4_x3 = (_let_tmp_rhs0)[2];
      let _5_z3 = (_let_tmp_rhs0)[3];
      let _6_swap = (_let_tmp_rhs0)[4];
      let _let_tmp_rhs1 = (((_6_swap).isEqualTo(_dafny.ONE)) ? (_dafny.Tuple.of(_4_x3, _5_z3)) : (_dafny.Tuple.of(_2_x2, _3_z2)));
      let _7_x = (_let_tmp_rhs1)[0];
      let _8_z = (_let_tmp_rhs1)[1];
      return EHBPEvents.__default.LEBytes(((_7_x).multipliedBy(EHBPEvents.__default.PowMod(_8_z, (EHBPEvents.__default.P25519).minus(new BigNumber(2))))).mod(EHBPEvents.__default.P25519), new BigNumber(32));
    };
    static get BasePoint() {
      return _dafny.Seq.Concat(_dafny.Seq.of(9), EHBPEvents.__default.Repeat(new BigNumber(31), 0));
    };
    static get HpkeVersion() {
      return EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("HPKE-v1"));
    };
    static get KemSuiteId() {
      return _dafny.Seq.Concat(EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("KEM")), EHBP.__default.BE16(EHBP.__default.KemX25519));
    };
    static get HpkeSuiteId() {
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("HPKE")), EHBP.__default.BE16(EHBP.__default.KemX25519)), EHBP.__default.BE16(EHBP.__default.KdfHkdfSha256)), EHBP.__default.BE16(EHBP.__default.AeadAes256Gcm));
    };
    static get MaxSeq() {
      return new BigNumber("18446744073709551615");
    };
    static get MaxJsonStringChars() {
      return new BigNumber(1024);
    };
    static get MaxJsonDepth() {
      return new BigNumber(64);
    };
    static get NewSession() {
      return EHBPEvents.SessionStore.create_SessionStore(_dafny.ZERO, EHBP.Option.create_None());
    };
    static get NoCtx() {
      return EHBPEvents.Ctx.create_Ctx(EHBPEvents.__default.Repeat(new BigNumber(32), 0), EHBPEvents.__default.Repeat(new BigNumber(12), 0), _dafny.Seq.of(), _dafny.ZERO);
    };
    static get MaxReadBytes() {
      return new BigNumber(4294967295);
    };
    static get NoOrigin() {
      return EHBP.Origin.create_Origin(_dafny.Seq.UnicodeFromString("https"), _dafny.Seq.UnicodeFromString(""), new BigNumber(443));
    };
    static get GcmKey() {
      return EHBPEvents.__default.Iota(new BigNumber(32));
    };
    static get GcmNonce() {
      return EHBPEvents.__default.Iota(new BigNumber(12));
    };
    static get GcmCt() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("226ab46b72d4be2b87fabbe9dbe0bfc2adbce017"));
    };
    static get AliceSk() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    };
    static get AlicePk() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    };
    static get BobPk() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    };
    static get AliceBobShared() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    };
    static get HmacKey() {
      return EHBPEvents.__default.Repeat(new BigNumber(20), 11);
    };
    static get HmacTag() {
      return EHBPEvents.__default.Hex(_dafny.Seq.UnicodeFromString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    };
    static get SelfCheckActions() {
      return _dafny.Seq.of(EHBPEvents.Action.create_HmacSha256(EHBPEvents.__default.HmacKey, EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("Hi There"))), EHBPEvents.Action.create_X25519(EHBPEvents.__default.AliceSk, EHBPEvents.__default.BasePoint), EHBPEvents.Action.create_X25519(EHBPEvents.__default.AliceSk, EHBPEvents.__default.BobPk), EHBPEvents.Action.create_AeadSeal(EHBPEvents.__default.GcmKey, EHBPEvents.__default.GcmNonce, EHBP.__default.Ascii(_dafny.Seq.UnicodeFromString("ehbp"))), EHBPEvents.Action.create_AeadOpen(EHBPEvents.__default.GcmKey, EHBPEvents.__default.GcmNonce, EHBPEvents.__default.GcmCt), EHBPEvents.Action.create_AeadOpen(EHBPEvents.__default.GcmKey, EHBPEvents.__default.GcmNonce, _dafny.Seq.Concat((EHBPEvents.__default.GcmCt).slice(0, (new BigNumber((EHBPEvents.__default.GcmCt).length)).minus(_dafny.ONE)), _dafny.Seq.of((_dafny.BitwiseXor(new BigNumber((EHBPEvents.__default.GcmCt)[(new BigNumber((EHBPEvents.__default.GcmCt).length)).minus(_dafny.ONE)]), _dafny.ONE)).toNumber()))), EHBPEvents.Action.create_AeadOpen(EHBPEvents.__default.GcmKey, EHBPEvents.__default.GcmNonce, (EHBPEvents.__default.GcmCt).slice(0, new BigNumber(8))), EHBPEvents.Action.create_RandomBytes(new BigNumber(32)), EHBPEvents.Action.create_RandomBytes(new BigNumber(32)));
    };
    static get K256() {
      return _dafny.Seq.of(new BigNumber(1116352408), new BigNumber(1899447441), new BigNumber(3049323471), new BigNumber(3921009573), new BigNumber(961987163), new BigNumber(1508970993), new BigNumber(2453635748), new BigNumber(2870763221), new BigNumber(3624381080), new BigNumber(310598401), new BigNumber(607225278), new BigNumber(1426881987), new BigNumber(1925078388), new BigNumber(2162078206), new BigNumber(2614888103), new BigNumber(3248222580), new BigNumber(3835390401), new BigNumber(4022224774), new BigNumber(264347078), new BigNumber(604807628), new BigNumber(770255983), new BigNumber(1249150122), new BigNumber(1555081692), new BigNumber(1996064986), new BigNumber(2554220882), new BigNumber(2821834349), new BigNumber(2952996808), new BigNumber(3210313671), new BigNumber(3336571891), new BigNumber(3584528711), new BigNumber(113926993), new BigNumber(338241895), new BigNumber(666307205), new BigNumber(773529912), new BigNumber(1294757372), new BigNumber(1396182291), new BigNumber(1695183700), new BigNumber(1986661051), new BigNumber(2177026350), new BigNumber(2456956037), new BigNumber(2730485921), new BigNumber(2820302411), new BigNumber(3259730800), new BigNumber(3345764771), new BigNumber(3516065817), new BigNumber(3600352804), new BigNumber(4094571909), new BigNumber(275423344), new BigNumber(430227734), new BigNumber(506948616), new BigNumber(659060556), new BigNumber(883997877), new BigNumber(958139571), new BigNumber(1322822218), new BigNumber(1537002063), new BigNumber(1747873779), new BigNumber(1955562222), new BigNumber(2024104815), new BigNumber(2227730452), new BigNumber(2361852424), new BigNumber(2428436474), new BigNumber(2756734187), new BigNumber(3204031479), new BigNumber(3329325298));
    };
    static get H256() {
      return _dafny.Seq.of(new BigNumber(1779033703), new BigNumber(3144134277), new BigNumber(1013904242), new BigNumber(2773480762), new BigNumber(1359893119), new BigNumber(2600822924), new BigNumber(528734635), new BigNumber(1541459225));
    };
    static get P25519() {
      return new BigNumber("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    };
  };

  $module.Stream = class Stream {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_RequestBody() {
      let $dt = new Stream(0);
      return $dt;
    }
    static create_ResponseBody() {
      let $dt = new Stream(1);
      return $dt;
    }
    get is_RequestBody() { return this.$tag === 0; }
    get is_ResponseBody() { return this.$tag === 1; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Stream.create_RequestBody();
      yield Stream.create_ResponseBody();
    }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Stream.RequestBody";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Stream.ResponseBody";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Stream.create_RequestBody();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Stream.Default();
        }
      };
    }
  }

  $module.BodyEnd = class BodyEnd {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_More() {
      let $dt = new BodyEnd(0);
      return $dt;
    }
    static create_Done() {
      let $dt = new BodyEnd(1);
      return $dt;
    }
    static create_Aborted(code) {
      let $dt = new BodyEnd(2);
      $dt.code = code;
      return $dt;
    }
    get is_More() { return this.$tag === 0; }
    get is_Done() { return this.$tag === 1; }
    get is_Aborted() { return this.$tag === 2; }
    get dtor_code() { return this.code; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.BodyEnd.More";
      } else if (this.$tag === 1) {
        return "EHBPEvents.BodyEnd.Done";
      } else if (this.$tag === 2) {
        return "EHBPEvents.BodyEnd.Aborted" + "(" + _dafny.toString(this.code) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.code, other.code);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.BodyEnd.create_More();
    }
    static Rtd() {
      return class {
        static get Default() {
          return BodyEnd.Default();
        }
      };
    }
  }

  $module.Event = class Event {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Start(verb, url, scheme, host, port, hasPort, hasUserinfo, headers, hasBody) {
      let $dt = new Event(0);
      $dt.verb = verb;
      $dt.url = url;
      $dt.scheme = scheme;
      $dt.host = host;
      $dt.port = port;
      $dt.hasPort = hasPort;
      $dt.hasUserinfo = hasUserinfo;
      $dt.headers = headers;
      $dt.hasBody = hasBody;
      return $dt;
    }
    static create_DiscoverStart() {
      let $dt = new Event(1);
      return $dt;
    }
    static create_SessionBegun(generation) {
      let $dt = new Event(2);
      $dt.generation = generation;
      return $dt;
    }
    static create_RandomResult(data) {
      let $dt = new Event(3);
      $dt.data = data;
      return $dt;
    }
    static create_X25519Result(point) {
      let $dt = new Event(4);
      $dt.point = point;
      return $dt;
    }
    static create_HmacResult(mac) {
      let $dt = new Event(5);
      $dt.mac = mac;
      return $dt;
    }
    static create_AeadSealResult(ciphertext) {
      let $dt = new Event(6);
      $dt.ciphertext = ciphertext;
      return $dt;
    }
    static create_AeadOpenResult(ok, plaintext) {
      let $dt = new Event(7);
      $dt.ok = ok;
      $dt.plaintext = plaintext;
      return $dt;
    }
    static create_ResponseHead(status, headers, redirected) {
      let $dt = new Event(8);
      $dt.status = status;
      $dt.headers = headers;
      $dt.redirected = redirected;
      return $dt;
    }
    static create_Chunk(stream, data, eof) {
      let $dt = new Event(9);
      $dt.stream = stream;
      $dt.data = data;
      $dt.eof = eof;
      return $dt;
    }
    static create_StreamFailed(stream) {
      let $dt = new Event(10);
      $dt.stream = stream;
      return $dt;
    }
    static create_CallerRead() {
      let $dt = new Event(11);
      return $dt;
    }
    static create_CallerClose() {
      let $dt = new Event(12);
      return $dt;
    }
    get is_Start() { return this.$tag === 0; }
    get is_DiscoverStart() { return this.$tag === 1; }
    get is_SessionBegun() { return this.$tag === 2; }
    get is_RandomResult() { return this.$tag === 3; }
    get is_X25519Result() { return this.$tag === 4; }
    get is_HmacResult() { return this.$tag === 5; }
    get is_AeadSealResult() { return this.$tag === 6; }
    get is_AeadOpenResult() { return this.$tag === 7; }
    get is_ResponseHead() { return this.$tag === 8; }
    get is_Chunk() { return this.$tag === 9; }
    get is_StreamFailed() { return this.$tag === 10; }
    get is_CallerRead() { return this.$tag === 11; }
    get is_CallerClose() { return this.$tag === 12; }
    get dtor_verb() { return this.verb; }
    get dtor_url() { return this.url; }
    get dtor_scheme() { return this.scheme; }
    get dtor_host() { return this.host; }
    get dtor_port() { return this.port; }
    get dtor_hasPort() { return this.hasPort; }
    get dtor_hasUserinfo() { return this.hasUserinfo; }
    get dtor_headers() { return this.headers; }
    get dtor_hasBody() { return this.hasBody; }
    get dtor_generation() { return this.generation; }
    get dtor_data() { return this.data; }
    get dtor_point() { return this.point; }
    get dtor_mac() { return this.mac; }
    get dtor_ciphertext() { return this.ciphertext; }
    get dtor_ok() { return this.ok; }
    get dtor_plaintext() { return this.plaintext; }
    get dtor_status() { return this.status; }
    get dtor_redirected() { return this.redirected; }
    get dtor_stream() { return this.stream; }
    get dtor_eof() { return this.eof; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Event.Start" + "(" + this.verb.toVerbatimString(true) + ", " + this.url.toVerbatimString(true) + ", " + this.scheme.toVerbatimString(true) + ", " + this.host.toVerbatimString(true) + ", " + _dafny.toString(this.port) + ", " + _dafny.toString(this.hasPort) + ", " + _dafny.toString(this.hasUserinfo) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.hasBody) + ")";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Event.DiscoverStart";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Event.SessionBegun" + "(" + _dafny.toString(this.generation) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Event.RandomResult(<redacted>)";
      } else if (this.$tag === 4) {
        return "EHBPEvents.Event.X25519Result(<redacted>)";
      } else if (this.$tag === 5) {
        return "EHBPEvents.Event.HmacResult(<redacted>)";
      } else if (this.$tag === 6) {
        return "EHBPEvents.Event.AeadSealResult" + "(" + _dafny.toString(this.ciphertext) + ")";
      } else if (this.$tag === 7) {
        return "EHBPEvents.Event.AeadOpenResult" + "(" + _dafny.toString(this.ok) + ", " + _dafny.toString(this.plaintext) + ")";
      } else if (this.$tag === 8) {
        return "EHBPEvents.Event.ResponseHead" + "(" + _dafny.toString(this.status) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.redirected) + ")";
      } else if (this.$tag === 9) {
        return "EHBPEvents.Event.Chunk" + "(" + _dafny.toString(this.stream) + ", " + _dafny.toString(this.data) + ", " + _dafny.toString(this.eof) + ")";
      } else if (this.$tag === 10) {
        return "EHBPEvents.Event.StreamFailed" + "(" + _dafny.toString(this.stream) + ")";
      } else if (this.$tag === 11) {
        return "EHBPEvents.Event.CallerRead";
      } else if (this.$tag === 12) {
        return "EHBPEvents.Event.CallerClose";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.url, other.url) && _dafny.areEqual(this.scheme, other.scheme) && _dafny.areEqual(this.host, other.host) && _dafny.areEqual(this.port, other.port) && this.hasPort === other.hasPort && this.hasUserinfo === other.hasUserinfo && _dafny.areEqual(this.headers, other.headers) && this.hasBody === other.hasBody;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.generation, other.generation);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.point, other.point);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.mac, other.mac);
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.ciphertext, other.ciphertext);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && this.ok === other.ok && _dafny.areEqual(this.plaintext, other.plaintext);
      } else if (this.$tag === 8) {
        return other.$tag === 8 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers) && this.redirected === other.redirected;
      } else if (this.$tag === 9) {
        return other.$tag === 9 && _dafny.areEqual(this.stream, other.stream) && _dafny.areEqual(this.data, other.data) && this.eof === other.eof;
      } else if (this.$tag === 10) {
        return other.$tag === 10 && _dafny.areEqual(this.stream, other.stream);
      } else if (this.$tag === 11) {
        return other.$tag === 11;
      } else if (this.$tag === 12) {
        return other.$tag === 12;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Event.create_Start(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.ZERO, false, false, _dafny.Seq.of(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Event.Default();
        }
      };
    }
  }

  $module.Action = class Action {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BeginSession() {
      let $dt = new Action(0);
      return $dt;
    }
    static create_PublishToken(generation, exportedSecret, requestEnc) {
      let $dt = new Action(1);
      $dt.generation = generation;
      $dt.exportedSecret = exportedSecret;
      $dt.requestEnc = requestEnc;
      return $dt;
    }
    static create_ClearToken(generation) {
      let $dt = new Action(2);
      $dt.generation = generation;
      return $dt;
    }
    static create_RandomBytes(length) {
      let $dt = new Action(3);
      $dt.length = length;
      return $dt;
    }
    static create_X25519(scalar, point) {
      let $dt = new Action(4);
      $dt.scalar = scalar;
      $dt.point = point;
      return $dt;
    }
    static create_HmacSha256(key, data) {
      let $dt = new Action(5);
      $dt.key = key;
      $dt.data = data;
      return $dt;
    }
    static create_AeadSeal(key, nonce, plaintext) {
      let $dt = new Action(6);
      $dt.key = key;
      $dt.nonce = nonce;
      $dt.plaintext = plaintext;
      return $dt;
    }
    static create_AeadOpen(key, nonce, ciphertext) {
      let $dt = new Action(7);
      $dt.key = key;
      $dt.nonce = nonce;
      $dt.ciphertext = ciphertext;
      return $dt;
    }
    static create_Send(verb, url, headers, hasBody) {
      let $dt = new Action(8);
      $dt.verb = verb;
      $dt.url = url;
      $dt.headers = headers;
      $dt.hasBody = hasBody;
      return $dt;
    }
    static create_Write(data, end) {
      let $dt = new Action(9);
      $dt.data = data;
      $dt.end = end;
      return $dt;
    }
    static create_Read(stream) {
      let $dt = new Action(10);
      $dt.stream = stream;
      return $dt;
    }
    static create_Close(stream) {
      let $dt = new Action(11);
      $dt.stream = stream;
      return $dt;
    }
    static create_EmitPlaintext(data) {
      let $dt = new Action(12);
      $dt.data = data;
      return $dt;
    }
    static create_Passthrough(status, headers, prefix) {
      let $dt = new Action(13);
      $dt.status = status;
      $dt.headers = headers;
      $dt.prefix = prefix;
      return $dt;
    }
    static create_Done(status, headers) {
      let $dt = new Action(14);
      $dt.status = status;
      $dt.headers = headers;
      return $dt;
    }
    static create_Finished() {
      let $dt = new Action(15);
      return $dt;
    }
    static create_Discovered(publicKey) {
      let $dt = new Action(16);
      $dt.publicKey = publicKey;
      return $dt;
    }
    static create_Fail(code, message) {
      let $dt = new Action(17);
      $dt.code = code;
      $dt.message = message;
      return $dt;
    }
    get is_BeginSession() { return this.$tag === 0; }
    get is_PublishToken() { return this.$tag === 1; }
    get is_ClearToken() { return this.$tag === 2; }
    get is_RandomBytes() { return this.$tag === 3; }
    get is_X25519() { return this.$tag === 4; }
    get is_HmacSha256() { return this.$tag === 5; }
    get is_AeadSeal() { return this.$tag === 6; }
    get is_AeadOpen() { return this.$tag === 7; }
    get is_Send() { return this.$tag === 8; }
    get is_Write() { return this.$tag === 9; }
    get is_Read() { return this.$tag === 10; }
    get is_Close() { return this.$tag === 11; }
    get is_EmitPlaintext() { return this.$tag === 12; }
    get is_Passthrough() { return this.$tag === 13; }
    get is_Done() { return this.$tag === 14; }
    get is_Finished() { return this.$tag === 15; }
    get is_Discovered() { return this.$tag === 16; }
    get is_Fail() { return this.$tag === 17; }
    get dtor_generation() { return this.generation; }
    get dtor_exportedSecret() { return this.exportedSecret; }
    get dtor_requestEnc() { return this.requestEnc; }
    get dtor_length() { return this.length; }
    get dtor_scalar() { return this.scalar; }
    get dtor_point() { return this.point; }
    get dtor_key() { return this.key; }
    get dtor_data() { return this.data; }
    get dtor_nonce() { return this.nonce; }
    get dtor_plaintext() { return this.plaintext; }
    get dtor_ciphertext() { return this.ciphertext; }
    get dtor_verb() { return this.verb; }
    get dtor_url() { return this.url; }
    get dtor_headers() { return this.headers; }
    get dtor_hasBody() { return this.hasBody; }
    get dtor_end() { return this.end; }
    get dtor_stream() { return this.stream; }
    get dtor_status() { return this.status; }
    get dtor_prefix() { return this.prefix; }
    get dtor_publicKey() { return this.publicKey; }
    get dtor_code() { return this.code; }
    get dtor_message() { return this.message; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Action.BeginSession";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Action.PublishToken(<redacted>)";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Action.ClearToken" + "(" + _dafny.toString(this.generation) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Action.RandomBytes" + "(" + _dafny.toString(this.length) + ")";
      } else if (this.$tag === 4) {
        return "EHBPEvents.Action.X25519(<redacted>)";
      } else if (this.$tag === 5) {
        return "EHBPEvents.Action.HmacSha256(<redacted>)";
      } else if (this.$tag === 6) {
        return "EHBPEvents.Action.AeadSeal(<redacted>)";
      } else if (this.$tag === 7) {
        return "EHBPEvents.Action.AeadOpen(<redacted>)";
      } else if (this.$tag === 8) {
        return "EHBPEvents.Action.Send" + "(" + this.verb.toVerbatimString(true) + ", " + this.url.toVerbatimString(true) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.hasBody) + ")";
      } else if (this.$tag === 9) {
        return "EHBPEvents.Action.Write" + "(" + _dafny.toString(this.data) + ", " + _dafny.toString(this.end) + ")";
      } else if (this.$tag === 10) {
        return "EHBPEvents.Action.Read" + "(" + _dafny.toString(this.stream) + ")";
      } else if (this.$tag === 11) {
        return "EHBPEvents.Action.Close" + "(" + _dafny.toString(this.stream) + ")";
      } else if (this.$tag === 12) {
        return "EHBPEvents.Action.EmitPlaintext" + "(" + _dafny.toString(this.data) + ")";
      } else if (this.$tag === 13) {
        return "EHBPEvents.Action.Passthrough" + "(" + _dafny.toString(this.status) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.prefix) + ")";
      } else if (this.$tag === 14) {
        return "EHBPEvents.Action.Done" + "(" + _dafny.toString(this.status) + ", " + _dafny.toString(this.headers) + ")";
      } else if (this.$tag === 15) {
        return "EHBPEvents.Action.Finished";
      } else if (this.$tag === 16) {
        return "EHBPEvents.Action.Discovered" + "(" + _dafny.toString(this.publicKey) + ")";
      } else if (this.$tag === 17) {
        return "EHBPEvents.Action.Fail" + "(" + _dafny.toString(this.code) + ", " + this.message.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.generation, other.generation) && _dafny.areEqual(this.exportedSecret, other.exportedSecret) && _dafny.areEqual(this.requestEnc, other.requestEnc);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.generation, other.generation);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.length, other.length);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.scalar, other.scalar) && _dafny.areEqual(this.point, other.point);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.nonce, other.nonce) && _dafny.areEqual(this.plaintext, other.plaintext);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.nonce, other.nonce) && _dafny.areEqual(this.ciphertext, other.ciphertext);
      } else if (this.$tag === 8) {
        return other.$tag === 8 && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.url, other.url) && _dafny.areEqual(this.headers, other.headers) && this.hasBody === other.hasBody;
      } else if (this.$tag === 9) {
        return other.$tag === 9 && _dafny.areEqual(this.data, other.data) && _dafny.areEqual(this.end, other.end);
      } else if (this.$tag === 10) {
        return other.$tag === 10 && _dafny.areEqual(this.stream, other.stream);
      } else if (this.$tag === 11) {
        return other.$tag === 11 && _dafny.areEqual(this.stream, other.stream);
      } else if (this.$tag === 12) {
        return other.$tag === 12 && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 13) {
        return other.$tag === 13 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers) && _dafny.areEqual(this.prefix, other.prefix);
      } else if (this.$tag === 14) {
        return other.$tag === 14 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers);
      } else if (this.$tag === 15) {
        return other.$tag === 15;
      } else if (this.$tag === 16) {
        return other.$tag === 16 && _dafny.areEqual(this.publicKey, other.publicKey);
      } else if (this.$tag === 17) {
        return other.$tag === 17 && _dafny.areEqual(this.code, other.code) && _dafny.areEqual(this.message, other.message);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Action.create_BeginSession();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Action.Default();
        }
      };
    }
  }

  $module.Performed = class Performed {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Quiet() {
      let $dt = new Performed(0);
      return $dt;
    }
    static create_Got(e) {
      let $dt = new Performed(1);
      $dt.e = e;
      return $dt;
    }
    static create_Stop() {
      let $dt = new Performed(2);
      return $dt;
    }
    get is_Quiet() { return this.$tag === 0; }
    get is_Got() { return this.$tag === 1; }
    get is_Stop() { return this.$tag === 2; }
    get dtor_e() { return this.e; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Performed.Quiet";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Performed.Got" + "(" + _dafny.toString(this.e) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Performed.Stop";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.e, other.e);
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Performed.create_Quiet();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Performed.Default();
        }
      };
    }
  }

  $module.Performer = class Performer {
  };

  $module.Job = class Job {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_JExtract(salt, ikm) {
      let $dt = new Job(0);
      $dt.salt = salt;
      $dt.ikm = ikm;
      return $dt;
    }
    static create_JExpand(prk, info, length, acc, prev, i) {
      let $dt = new Job(1);
      $dt.prk = prk;
      $dt.info = info;
      $dt.length = length;
      $dt.acc = acc;
      $dt.prev = prev;
      $dt.i = i;
      return $dt;
    }
    get is_JExtract() { return this.$tag === 0; }
    get is_JExpand() { return this.$tag === 1; }
    get dtor_salt() { return this.salt; }
    get dtor_ikm() { return this.ikm; }
    get dtor_prk() { return this.prk; }
    get dtor_info() { return this.info; }
    get dtor_length() { return this.length; }
    get dtor_acc() { return this.acc; }
    get dtor_prev() { return this.prev; }
    get dtor_i() { return this.i; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Job.JExtract(<redacted>)";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Job.JExpand(<redacted>)";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.salt, other.salt) && _dafny.areEqual(this.ikm, other.ikm);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.prk, other.prk) && _dafny.areEqual(this.info, other.info) && _dafny.areEqual(this.length, other.length) && _dafny.areEqual(this.acc, other.acc) && _dafny.areEqual(this.prev, other.prev) && this.i === other.i;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Job.create_JExtract(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Job.Default();
        }
      };
    }
  }

  $module.JobOut = class JobOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Pending(job, action) {
      let $dt = new JobOut(0);
      $dt.job = job;
      $dt.action = action;
      return $dt;
    }
    static create_Output(data) {
      let $dt = new JobOut(1);
      $dt.data = data;
      return $dt;
    }
    static create_JobFailed(code, message) {
      let $dt = new JobOut(2);
      $dt.code = code;
      $dt.message = message;
      return $dt;
    }
    get is_Pending() { return this.$tag === 0; }
    get is_Output() { return this.$tag === 1; }
    get is_JobFailed() { return this.$tag === 2; }
    get dtor_job() { return this.job; }
    get dtor_action() { return this.action; }
    get dtor_data() { return this.data; }
    get dtor_code() { return this.code; }
    get dtor_message() { return this.message; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.JobOut.Pending" + "(" + _dafny.toString(this.job) + ", " + _dafny.toString(this.action) + ")";
      } else if (this.$tag === 1) {
        return "EHBPEvents.JobOut.Output(<redacted>)";
      } else if (this.$tag === 2) {
        return "EHBPEvents.JobOut.JobFailed" + "(" + _dafny.toString(this.code) + ", " + this.message.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.job, other.job) && _dafny.areEqual(this.action, other.action);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.code, other.code) && _dafny.areEqual(this.message, other.message);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.JobOut.create_Pending(EHBPEvents.Job.Default(), EHBPEvents.Action.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return JobOut.Default();
        }
      };
    }
  }

  $module.Key = class Key {
    constructor () {
    }
    static get Witness() {
      return _dafny.Seq.Create(new BigNumber(32), function (_0_i) {
    return 0;
  });
    }
    static get Default() {
      return EHBPEvents.Key.Witness;
    }
    static _Is(__source) {
      let _1_b = __source;
      return (new BigNumber((_1_b).length)).isEqualTo(EHBP.__default.KeyLength);
    }
  };

  $module.NonceBase = class NonceBase {
    constructor () {
    }
    static get Witness() {
      return _dafny.Seq.Create(new BigNumber(12), function (_2_i) {
    return 0;
  });
    }
    static get Default() {
      return EHBPEvents.NonceBase.Witness;
    }
    static _Is(__source) {
      let _3_b = __source;
      return (new BigNumber((_3_b).length)).isEqualTo(EHBP.__default.NonceLength);
    }
  };

  $module.Ctx = class Ctx {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ctx(key, baseNonce, exporterSecret, seqNo) {
      let $dt = new Ctx(0);
      $dt.key = key;
      $dt.baseNonce = baseNonce;
      $dt.exporterSecret = exporterSecret;
      $dt.seqNo = seqNo;
      return $dt;
    }
    get is_Ctx() { return this.$tag === 0; }
    get dtor_key() { return this.key; }
    get dtor_baseNonce() { return this.baseNonce; }
    get dtor_exporterSecret() { return this.exporterSecret; }
    get dtor_seqNo() { return this.seqNo; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Ctx.Ctx(<redacted>)";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.baseNonce, other.baseNonce) && _dafny.areEqual(this.exporterSecret, other.exporterSecret) && _dafny.areEqual(this.seqNo, other.seqNo);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Ctx.create_Ctx(EHBPEvents.Key.Default, EHBPEvents.NonceBase.Default, _dafny.Seq.of(), _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Ctx.Default();
        }
      };
    }
  }

  $module.Hpke = class Hpke {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_HRandom(pkR, info) {
      let $dt = new Hpke(0);
      $dt.pkR = pkR;
      $dt.info = info;
      return $dt;
    }
    static create_HEnc(skE, pkR, info) {
      let $dt = new Hpke(1);
      $dt.skE = skE;
      $dt.pkR = pkR;
      $dt.info = info;
      return $dt;
    }
    static create_HDh(enc, pkR, info) {
      let $dt = new Hpke(2);
      $dt.enc = enc;
      $dt.pkR = pkR;
      $dt.info = info;
      return $dt;
    }
    static create_HSchedule(stage, job, enc, pkR, info, shared, pskIdHash, infoHash, secret, key, baseNonce) {
      let $dt = new Hpke(3);
      $dt.stage = stage;
      $dt.job = job;
      $dt.enc = enc;
      $dt.pkR = pkR;
      $dt.info = info;
      $dt.shared = shared;
      $dt.pskIdHash = pskIdHash;
      $dt.infoHash = infoHash;
      $dt.secret = secret;
      $dt.key = key;
      $dt.baseNonce = baseNonce;
      return $dt;
    }
    get is_HRandom() { return this.$tag === 0; }
    get is_HEnc() { return this.$tag === 1; }
    get is_HDh() { return this.$tag === 2; }
    get is_HSchedule() { return this.$tag === 3; }
    get dtor_pkR() { return this.pkR; }
    get dtor_info() { return this.info; }
    get dtor_skE() { return this.skE; }
    get dtor_enc() { return this.enc; }
    get dtor_stage() { return this.stage; }
    get dtor_job() { return this.job; }
    get dtor_shared() { return this.shared; }
    get dtor_pskIdHash() { return this.pskIdHash; }
    get dtor_infoHash() { return this.infoHash; }
    get dtor_secret() { return this.secret; }
    get dtor_key() { return this.key; }
    get dtor_baseNonce() { return this.baseNonce; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Hpke.HRandom" + "(" + _dafny.toString(this.pkR) + ", " + _dafny.toString(this.info) + ")";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Hpke.HEnc(<redacted>)";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Hpke.HDh" + "(" + _dafny.toString(this.enc) + ", " + _dafny.toString(this.pkR) + ", " + _dafny.toString(this.info) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Hpke.HSchedule(<redacted>)";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.pkR, other.pkR) && _dafny.areEqual(this.info, other.info);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.skE, other.skE) && _dafny.areEqual(this.pkR, other.pkR) && _dafny.areEqual(this.info, other.info);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.enc, other.enc) && _dafny.areEqual(this.pkR, other.pkR) && _dafny.areEqual(this.info, other.info);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.stage, other.stage) && _dafny.areEqual(this.job, other.job) && _dafny.areEqual(this.enc, other.enc) && _dafny.areEqual(this.pkR, other.pkR) && _dafny.areEqual(this.info, other.info) && _dafny.areEqual(this.shared, other.shared) && _dafny.areEqual(this.pskIdHash, other.pskIdHash) && _dafny.areEqual(this.infoHash, other.infoHash) && _dafny.areEqual(this.secret, other.secret) && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.baseNonce, other.baseNonce);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Hpke.create_HRandom(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Hpke.Default();
        }
      };
    }
  }

  $module.HpkeOut = class HpkeOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_HContinue(h, action) {
      let $dt = new HpkeOut(0);
      $dt.h = h;
      $dt.action = action;
      return $dt;
    }
    static create_HReady(ctx, enc) {
      let $dt = new HpkeOut(1);
      $dt.ctx = ctx;
      $dt.enc = enc;
      return $dt;
    }
    static create_HFailed(code, message) {
      let $dt = new HpkeOut(2);
      $dt.code = code;
      $dt.message = message;
      return $dt;
    }
    get is_HContinue() { return this.$tag === 0; }
    get is_HReady() { return this.$tag === 1; }
    get is_HFailed() { return this.$tag === 2; }
    get dtor_h() { return this.h; }
    get dtor_action() { return this.action; }
    get dtor_ctx() { return this.ctx; }
    get dtor_enc() { return this.enc; }
    get dtor_code() { return this.code; }
    get dtor_message() { return this.message; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.HpkeOut.HContinue" + "(" + _dafny.toString(this.h) + ", " + _dafny.toString(this.action) + ")";
      } else if (this.$tag === 1) {
        return "EHBPEvents.HpkeOut.HReady" + "(" + _dafny.toString(this.ctx) + ", " + _dafny.toString(this.enc) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.HpkeOut.HFailed" + "(" + _dafny.toString(this.code) + ", " + this.message.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.h, other.h) && _dafny.areEqual(this.action, other.action);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.ctx, other.ctx) && _dafny.areEqual(this.enc, other.enc);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.code, other.code) && _dafny.areEqual(this.message, other.message);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.HpkeOut.create_HContinue(EHBPEvents.Hpke.Default(), EHBPEvents.Action.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return HpkeOut.Default();
        }
      };
    }
  }

  $module.Json = class Json {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_JNull() {
      let $dt = new Json(0);
      return $dt;
    }
    static create_JBool(b) {
      let $dt = new Json(1);
      $dt.b = b;
      return $dt;
    }
    static create_JNumber(raw) {
      let $dt = new Json(2);
      $dt.raw = raw;
      return $dt;
    }
    static create_JString(s) {
      let $dt = new Json(3);
      $dt.s = s;
      return $dt;
    }
    static create_JArray(items) {
      let $dt = new Json(4);
      $dt.items = items;
      return $dt;
    }
    static create_JObject(members) {
      let $dt = new Json(5);
      $dt.members = members;
      return $dt;
    }
    get is_JNull() { return this.$tag === 0; }
    get is_JBool() { return this.$tag === 1; }
    get is_JNumber() { return this.$tag === 2; }
    get is_JString() { return this.$tag === 3; }
    get is_JArray() { return this.$tag === 4; }
    get is_JObject() { return this.$tag === 5; }
    get dtor_b() { return this.b; }
    get dtor_raw() { return this.raw; }
    get dtor_s() { return this.s; }
    get dtor_items() { return this.items; }
    get dtor_members() { return this.members; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Json.JNull";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Json.JBool" + "(" + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Json.JNumber" + "(" + this.raw.toVerbatimString(true) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Json.JString" + "(" + this.s.toVerbatimString(true) + ")";
      } else if (this.$tag === 4) {
        return "EHBPEvents.Json.JArray" + "(" + _dafny.toString(this.items) + ")";
      } else if (this.$tag === 5) {
        return "EHBPEvents.Json.JObject" + "(" + _dafny.toString(this.members) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && this.b === other.b;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.raw, other.raw);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.s, other.s);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.items, other.items);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.members, other.members);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Json.create_JNull();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Json.Default();
        }
      };
    }
  }

  $module.SessionStore = class SessionStore {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_SessionStore(generation, token) {
      let $dt = new SessionStore(0);
      $dt.generation = generation;
      $dt.token = token;
      return $dt;
    }
    get is_SessionStore() { return this.$tag === 0; }
    get dtor_generation() { return this.generation; }
    get dtor_token() { return this.token; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.SessionStore.SessionStore" + "(" + _dafny.toString(this.generation) + ", " + _dafny.toString(this.token) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.generation, other.generation) && _dafny.areEqual(this.token, other.token);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.SessionStore.create_SessionStore(_dafny.ZERO, EHBP.Option.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return SessionStore.Default();
        }
      };
    }
  }

  $module.SessionAction = class SessionAction {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Begin() {
      let $dt = new SessionAction(0);
      return $dt;
    }
    static create_Publish(generation, token) {
      let $dt = new SessionAction(1);
      $dt.generation = generation;
      $dt.token = token;
      return $dt;
    }
    static create_Clear(generation) {
      let $dt = new SessionAction(2);
      $dt.generation = generation;
      return $dt;
    }
    get is_Begin() { return this.$tag === 0; }
    get is_Publish() { return this.$tag === 1; }
    get is_Clear() { return this.$tag === 2; }
    get dtor_generation() { return this.generation; }
    get dtor_token() { return this.token; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.SessionAction.Begin";
      } else if (this.$tag === 1) {
        return "EHBPEvents.SessionAction.Publish" + "(" + _dafny.toString(this.generation) + ", " + _dafny.toString(this.token) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.SessionAction.Clear" + "(" + _dafny.toString(this.generation) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.generation, other.generation) && _dafny.areEqual(this.token, other.token);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.generation, other.generation);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.SessionAction.create_Begin();
    }
    static Rtd() {
      return class {
        static get Default() {
          return SessionAction.Default();
        }
      };
    }
  }

  $module.Dec = class Dec {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Dec(pending, next, authenticated, requireFrame) {
      let $dt = new Dec(0);
      $dt.pending = pending;
      $dt.next = next;
      $dt.authenticated = authenticated;
      $dt.requireFrame = requireFrame;
      return $dt;
    }
    get is_Dec() { return this.$tag === 0; }
    get dtor_pending() { return this.pending; }
    get dtor_next() { return this.next; }
    get dtor_authenticated() { return this.authenticated; }
    get dtor_requireFrame() { return this.requireFrame; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Dec.Dec" + "(" + _dafny.toString(this.pending) + ", " + _dafny.toString(this.next) + ", " + _dafny.toString(this.authenticated) + ", " + _dafny.toString(this.requireFrame) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.pending, other.pending) && _dafny.areEqual(this.next, other.next) && this.authenticated === other.authenticated && this.requireFrame === other.requireFrame;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Dec.create_Dec(_dafny.Seq.of(), _dafny.ZERO, false, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Dec.Default();
        }
      };
    }
  }

  $module.Chunk = class Chunk {
    constructor () {
    }
    static get Witness() {
      return _dafny.Seq.of();
    }
    static get Default() {
      return EHBPEvents.Chunk.Witness;
    }
    static _Is(__source) {
      let _4_b = __source;
      return (new BigNumber((_4_b).length)).isLessThan(new BigNumber(4294967296));
    }
  };

  $module.Upload = class Upload {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_NoUpload() {
      let $dt = new Upload(0);
      return $dt;
    }
    static create_Sealing(plaintext, offset, eof) {
      let $dt = new Upload(1);
      $dt.plaintext = plaintext;
      $dt.offset = offset;
      $dt.eof = eof;
      return $dt;
    }
    static create_UpReading(empty) {
      let $dt = new Upload(2);
      $dt.empty = empty;
      return $dt;
    }
    static create_UpDone() {
      let $dt = new Upload(3);
      return $dt;
    }
    get is_NoUpload() { return this.$tag === 0; }
    get is_Sealing() { return this.$tag === 1; }
    get is_UpReading() { return this.$tag === 2; }
    get is_UpDone() { return this.$tag === 3; }
    get dtor_plaintext() { return this.plaintext; }
    get dtor_offset() { return this.offset; }
    get dtor_eof() { return this.eof; }
    get dtor_empty() { return this.empty; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Upload.NoUpload";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Upload.Sealing" + "(" + _dafny.toString(this.plaintext) + ", " + _dafny.toString(this.offset) + ", " + _dafny.toString(this.eof) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Upload.UpReading" + "(" + _dafny.toString(this.empty) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Upload.UpDone";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.plaintext, other.plaintext) && this.offset === other.offset && this.eof === other.eof;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.empty, other.empty);
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Upload.create_NoUpload();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Upload.Default();
        }
      };
    }
  }

  $module.Response = class Response {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AwaitHead(encrypted) {
      let $dt = new Response(0);
      $dt.encrypted = encrypted;
      return $dt;
    }
    static create_ProblemReading(status, headers, data) {
      let $dt = new Response(1);
      $dt.status = status;
      $dt.headers = headers;
      $dt.data = data;
      return $dt;
    }
    static create_AwaitKeys(status, headers, requireFrame, stage, job, prk, key) {
      let $dt = new Response(2);
      $dt.status = status;
      $dt.headers = headers;
      $dt.requireFrame = requireFrame;
      $dt.stage = stage;
      $dt.job = job;
      $dt.prk = prk;
      $dt.key = key;
      return $dt;
    }
    static create_Body(keys, dec, done) {
      let $dt = new Response(3);
      $dt.keys = keys;
      $dt.dec = dec;
      $dt.done = done;
      return $dt;
    }
    static create_BodyReading(keys, dec) {
      let $dt = new Response(4);
      $dt.keys = keys;
      $dt.dec = dec;
      return $dt;
    }
    static create_Opening(keys, dec, frames, chunks, eof) {
      let $dt = new Response(5);
      $dt.keys = keys;
      $dt.dec = dec;
      $dt.frames = frames;
      $dt.chunks = chunks;
      $dt.eof = eof;
      return $dt;
    }
    static create_RespEnded() {
      let $dt = new Response(6);
      return $dt;
    }
    get is_AwaitHead() { return this.$tag === 0; }
    get is_ProblemReading() { return this.$tag === 1; }
    get is_AwaitKeys() { return this.$tag === 2; }
    get is_Body() { return this.$tag === 3; }
    get is_BodyReading() { return this.$tag === 4; }
    get is_Opening() { return this.$tag === 5; }
    get is_RespEnded() { return this.$tag === 6; }
    get dtor_encrypted() { return this.encrypted; }
    get dtor_status() { return this.status; }
    get dtor_headers() { return this.headers; }
    get dtor_data() { return this.data; }
    get dtor_requireFrame() { return this.requireFrame; }
    get dtor_stage() { return this.stage; }
    get dtor_job() { return this.job; }
    get dtor_prk() { return this.prk; }
    get dtor_key() { return this.key; }
    get dtor_keys() { return this.keys; }
    get dtor_dec() { return this.dec; }
    get dtor_done() { return this.done; }
    get dtor_frames() { return this.frames; }
    get dtor_chunks() { return this.chunks; }
    get dtor_eof() { return this.eof; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Response.AwaitHead" + "(" + _dafny.toString(this.encrypted) + ")";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Response.ProblemReading" + "(" + _dafny.toString(this.status) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.data) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Response.AwaitKeys(<redacted>)";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Response.Body" + "(" + _dafny.toString(this.keys) + ", " + _dafny.toString(this.dec) + ", " + _dafny.toString(this.done) + ")";
      } else if (this.$tag === 4) {
        return "EHBPEvents.Response.BodyReading" + "(" + _dafny.toString(this.keys) + ", " + _dafny.toString(this.dec) + ")";
      } else if (this.$tag === 5) {
        return "EHBPEvents.Response.Opening" + "(" + _dafny.toString(this.keys) + ", " + _dafny.toString(this.dec) + ", " + _dafny.toString(this.frames) + ", " + _dafny.toString(this.chunks) + ", " + _dafny.toString(this.eof) + ")";
      } else if (this.$tag === 6) {
        return "EHBPEvents.Response.RespEnded";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.encrypted === other.encrypted;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers) && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.status, other.status) && _dafny.areEqual(this.headers, other.headers) && this.requireFrame === other.requireFrame && _dafny.areEqual(this.stage, other.stage) && _dafny.areEqual(this.job, other.job) && _dafny.areEqual(this.prk, other.prk) && _dafny.areEqual(this.key, other.key);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.keys, other.keys) && _dafny.areEqual(this.dec, other.dec) && this.done === other.done;
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.keys, other.keys) && _dafny.areEqual(this.dec, other.dec);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.keys, other.keys) && _dafny.areEqual(this.dec, other.dec) && _dafny.areEqual(this.frames, other.frames) && _dafny.areEqual(this.chunks, other.chunks) && this.eof === other.eof;
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Response.create_AwaitHead(false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Response.Default();
        }
      };
    }
  }

  $module.Phase = class Phase {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Idle() {
      let $dt = new Phase(0);
      return $dt;
    }
    static create_AwaitSession(hasBody) {
      let $dt = new Phase(1);
      $dt.hasBody = hasBody;
      return $dt;
    }
    static create_Peeking(empty) {
      let $dt = new Phase(2);
      $dt.empty = empty;
      return $dt;
    }
    static create_AwaitSetup(first, firstEof, hpke) {
      let $dt = new Phase(3);
      $dt.first = first;
      $dt.firstEof = firstEof;
      $dt.hpke = hpke;
      return $dt;
    }
    static create_AwaitExport(first, firstEof, enc, job) {
      let $dt = new Phase(4);
      $dt.first = first;
      $dt.firstEof = firstEof;
      $dt.enc = enc;
      $dt.job = job;
      return $dt;
    }
    static create_Exchanging(upload, response) {
      let $dt = new Phase(5);
      $dt.upload = upload;
      $dt.response = response;
      return $dt;
    }
    static create_DiscAwaitHead() {
      let $dt = new Phase(6);
      return $dt;
    }
    static create_DiscReading(data) {
      let $dt = new Phase(7);
      $dt.data = data;
      return $dt;
    }
    static create_Ended() {
      let $dt = new Phase(8);
      return $dt;
    }
    get is_Idle() { return this.$tag === 0; }
    get is_AwaitSession() { return this.$tag === 1; }
    get is_Peeking() { return this.$tag === 2; }
    get is_AwaitSetup() { return this.$tag === 3; }
    get is_AwaitExport() { return this.$tag === 4; }
    get is_Exchanging() { return this.$tag === 5; }
    get is_DiscAwaitHead() { return this.$tag === 6; }
    get is_DiscReading() { return this.$tag === 7; }
    get is_Ended() { return this.$tag === 8; }
    get dtor_hasBody() { return this.hasBody; }
    get dtor_empty() { return this.empty; }
    get dtor_first() { return this.first; }
    get dtor_firstEof() { return this.firstEof; }
    get dtor_hpke() { return this.hpke; }
    get dtor_enc() { return this.enc; }
    get dtor_job() { return this.job; }
    get dtor_upload() { return this.upload; }
    get dtor_response() { return this.response; }
    get dtor_data() { return this.data; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.Phase.Idle";
      } else if (this.$tag === 1) {
        return "EHBPEvents.Phase.AwaitSession" + "(" + _dafny.toString(this.hasBody) + ")";
      } else if (this.$tag === 2) {
        return "EHBPEvents.Phase.Peeking" + "(" + _dafny.toString(this.empty) + ")";
      } else if (this.$tag === 3) {
        return "EHBPEvents.Phase.AwaitSetup" + "(" + _dafny.toString(this.first) + ", " + _dafny.toString(this.firstEof) + ", " + _dafny.toString(this.hpke) + ")";
      } else if (this.$tag === 4) {
        return "EHBPEvents.Phase.AwaitExport" + "(" + _dafny.toString(this.first) + ", " + _dafny.toString(this.firstEof) + ", " + _dafny.toString(this.enc) + ", " + _dafny.toString(this.job) + ")";
      } else if (this.$tag === 5) {
        return "EHBPEvents.Phase.Exchanging" + "(" + _dafny.toString(this.upload) + ", " + _dafny.toString(this.response) + ")";
      } else if (this.$tag === 6) {
        return "EHBPEvents.Phase.DiscAwaitHead";
      } else if (this.$tag === 7) {
        return "EHBPEvents.Phase.DiscReading" + "(" + _dafny.toString(this.data) + ")";
      } else if (this.$tag === 8) {
        return "EHBPEvents.Phase.Ended";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && this.hasBody === other.hasBody;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.empty, other.empty);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.first, other.first) && this.firstEof === other.firstEof && _dafny.areEqual(this.hpke, other.hpke);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.first, other.first) && this.firstEof === other.firstEof && _dafny.areEqual(this.enc, other.enc) && _dafny.areEqual(this.job, other.job);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.upload, other.upload) && _dafny.areEqual(this.response, other.response);
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.data, other.data);
      } else if (this.$tag === 8) {
        return other.$tag === 8;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.Phase.create_Idle();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Phase.Default();
        }
      };
    }
  }

  $module.State = class State {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_State(phase, origin, publicKey, verb, url, headers, generation, published, token, ctx) {
      let $dt = new State(0);
      $dt.phase = phase;
      $dt.origin = origin;
      $dt.publicKey = publicKey;
      $dt.verb = verb;
      $dt.url = url;
      $dt.headers = headers;
      $dt.generation = generation;
      $dt.published = published;
      $dt.token = token;
      $dt.ctx = ctx;
      return $dt;
    }
    get is_State() { return this.$tag === 0; }
    get dtor_phase() { return this.phase; }
    get dtor_origin() { return this.origin; }
    get dtor_publicKey() { return this.publicKey; }
    get dtor_verb() { return this.verb; }
    get dtor_url() { return this.url; }
    get dtor_headers() { return this.headers; }
    get dtor_generation() { return this.generation; }
    get dtor_published() { return this.published; }
    get dtor_token() { return this.token; }
    get dtor_ctx() { return this.ctx; }
    toString() {
      if (this.$tag === 0) {
        return "EHBPEvents.State.State" + "(" + _dafny.toString(this.phase) + ", " + _dafny.toString(this.origin) + ", " + _dafny.toString(this.publicKey) + ", " + this.verb.toVerbatimString(true) + ", " + this.url.toVerbatimString(true) + ", " + _dafny.toString(this.headers) + ", " + _dafny.toString(this.generation) + ", " + _dafny.toString(this.published) + ", " + _dafny.toString(this.token) + ", " + _dafny.toString(this.ctx) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.phase, other.phase) && _dafny.areEqual(this.origin, other.origin) && _dafny.areEqual(this.publicKey, other.publicKey) && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.url, other.url) && _dafny.areEqual(this.headers, other.headers) && _dafny.areEqual(this.generation, other.generation) && this.published === other.published && _dafny.areEqual(this.token, other.token) && _dafny.areEqual(this.ctx, other.ctx);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return EHBPEvents.State.create_State(EHBPEvents.Phase.Default(), EHBP.Origin.Default(), _dafny.Seq.of(), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), _dafny.ZERO, false, EHBP.Token.Default(), EHBPEvents.Ctx.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return State.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module EHBPEvents
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module
module.exports = { EHBP, EHBPEvents, _dafny };
