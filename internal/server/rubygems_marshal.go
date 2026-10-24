package server

import (
	"bytes"
	"errors"
	"fmt"
)

// A Ruby Marshal 4.8 reader and writer, for the two RubyGems documents a
// profile filters that are not text: the full index files and the dependency
// API. Both are one top-level array, and filtering means dropping elements.
//
// The elements cannot be cut out of the byte stream in place. Marshal writes a
// symbol once and every later use as a back-reference into a table built as
// the stream is read, and does the same for any object written twice, so the
// first element names :name and Gem::Version for every element after it.
// Dropping that element by byte range leaves the rest pointing at entries that
// are no longer there. The document is decoded into a tree and written fresh,
// which rebuilds both tables for what remains.

// rbValue is one decoded Marshal object. tag is the type byte it was read
// under; which other fields carry meaning depends on it.
type rbValue struct {
	tag   byte
	num   int64         // 'i'
	str   string        // '"' and 'f' bytes; ':' name; class or module name for 'o' 'U' 'u' 'e' 'C' 'S'; 'c' 'm' 'M' name; 'l' magnitude
	raw   string        // 'u' payload, '/' source
	flag  byte          // 'l' sign, '/' options
	items []*rbValue    // '[' elements; the wrapped object of 'U' 'e' 'C'
	pairs [][2]*rbValue // '{' '}' entries; 'o' instance variables; 'S' members
	ivars [][2]*rbValue // instance variables an 'I' wrapper attached
	def   *rbValue      // '}' default
}

// rbMaxDepth bounds nesting. The documents read here nest four deep, and a
// stream that nests thousands deep is an attack on the stack, not an index.
const rbMaxDepth = 64

var errRbShape = errors.New("not a Ruby Marshal 4.8 document")

type rbDecoder struct {
	b     []byte
	pos   int
	syms  []string
	objs  []*rbValue
	depth int
}

// rbUnmarshal decodes one Marshal 4.8 stream, which must end where its one
// top-level object does.
func rbUnmarshal(b []byte) (*rbValue, error) {
	if len(b) < 2 || b[0] != 4 || b[1] != 8 {
		return nil, errRbShape
	}
	d := &rbDecoder{b: b, pos: 2}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	if d.pos != len(b) {
		return nil, fmt.Errorf("%w: %d bytes follow the top-level object", errRbShape, len(b)-d.pos)
	}
	return v, nil
}

func (d *rbDecoder) byte() (byte, error) {
	if d.pos >= len(d.b) {
		return 0, fmt.Errorf("%w: truncated at byte %d", errRbShape, d.pos)
	}
	c := d.b[d.pos]
	d.pos++
	return c, nil
}

// long is Ruby's r_long: small values in the type byte itself, larger ones as
// a byte count and that many little-endian bytes.
func (d *rbDecoder) long() (int64, error) {
	c0, err := d.byte()
	if err != nil {
		return 0, err
	}
	c := int8(c0) //nolint:gosec // G115: the type byte is signed in Ruby's format; the wrap is the decoding.
	switch {
	case c == 0:
		return 0, nil
	case c > 4:
		return int64(c) - 5, nil
	case c < -4:
		return int64(c) + 5, nil
	case c > 0:
		var x int64
		for i := 0; i < int(c); i++ {
			b, err := d.byte()
			if err != nil {
				return 0, err
			}
			x |= int64(b) << (8 * i)
		}
		return x, nil
	default:
		x := int64(-1)
		for i := 0; i < int(-c); i++ {
			b, err := d.byte()
			if err != nil {
				return 0, err
			}
			x &^= int64(0xff) << (8 * i)
			x |= int64(b) << (8 * i)
		}
		return x, nil
	}
}

// count is a long used as a length or an element count, held to what the
// rest of the stream could possibly hold so a forged count cannot allocate.
func (d *rbDecoder) count() (int, error) {
	n, err := d.long()
	if err != nil {
		return 0, err
	}
	if n < 0 || n > int64(len(d.b)-d.pos) {
		return 0, fmt.Errorf("%w: count %d at byte %d", errRbShape, n, d.pos)
	}
	return int(n), nil
}

func (d *rbDecoder) bytes() (string, error) {
	n, err := d.count()
	if err != nil {
		return "", err
	}
	s := string(d.b[d.pos : d.pos+n])
	d.pos += n
	return s, nil
}

// register enters an object in the link table. Marshal numbers objects in the
// order their type bytes are read, containers before their contents, which is
// why a container registers before it reads anything.
func (d *rbDecoder) register(v *rbValue) *rbValue {
	d.objs = append(d.objs, v)
	return v
}

func (d *rbDecoder) symbolName() (string, error) {
	v, err := d.value()
	if err != nil {
		return "", err
	}
	if v.tag != ':' {
		return "", fmt.Errorf("%w: a class name at byte %d is not a symbol", errRbShape, d.pos)
	}
	return v.str, nil
}

func (d *rbDecoder) pairs(n int) ([][2]*rbValue, error) {
	out := make([][2]*rbValue, 0, n)
	for range n {
		k, err := d.value()
		if err != nil {
			return nil, err
		}
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		out = append(out, [2]*rbValue{k, v})
	}
	return out, nil
}

func (d *rbDecoder) value() (*rbValue, error) {
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > rbMaxDepth {
		return nil, fmt.Errorf("%w: nested past %d levels", errRbShape, rbMaxDepth)
	}
	tag, err := d.byte()
	if err != nil {
		return nil, err
	}
	v := &rbValue{tag: tag}
	switch tag {
	case '0', 'T', 'F':
		return v, nil
	case 'i':
		v.num, err = d.long()
		return v, err
	case ':':
		if v.str, err = d.bytes(); err != nil {
			return nil, err
		}
		d.syms = append(d.syms, v.str)
		return v, nil
	case ';':
		n, err := d.long()
		if err != nil {
			return nil, err
		}
		if n < 0 || n >= int64(len(d.syms)) {
			return nil, fmt.Errorf("%w: symbol link %d past the %d read", errRbShape, n, len(d.syms))
		}
		return &rbValue{tag: ':', str: d.syms[n]}, nil
	case '@':
		n, err := d.long()
		if err != nil {
			return nil, err
		}
		if n < 0 || n >= int64(len(d.objs)) {
			return nil, fmt.Errorf("%w: object link %d past the %d read", errRbShape, n, len(d.objs))
		}
		return d.objs[n], nil
	case 'I':
		inner, err := d.value()
		if err != nil {
			return nil, err
		}
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		if inner.ivars, err = d.pairs(n); err != nil {
			return nil, err
		}
		return inner, nil
	case '"', 'f', 'c', 'm', 'M':
		v.str, err = d.bytes()
		return d.register(v), err
	case '/':
		if v.raw, err = d.bytes(); err != nil {
			return nil, err
		}
		if v.flag, err = d.byte(); err != nil {
			return nil, err
		}
		return d.register(v), nil
	case 'l':
		if v.flag, err = d.byte(); err != nil {
			return nil, err
		}
		n, err := d.count()
		if err != nil || 2*n > len(d.b)-d.pos {
			return nil, fmt.Errorf("%w: bignum length at byte %d", errRbShape, d.pos)
		}
		v.str = string(d.b[d.pos : d.pos+2*n])
		d.pos += 2 * n
		return d.register(v), nil
	case '[':
		d.register(v)
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		v.items = make([]*rbValue, 0, n)
		for range n {
			e, err := d.value()
			if err != nil {
				return nil, err
			}
			v.items = append(v.items, e)
		}
		return v, nil
	case '{', '}':
		d.register(v)
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		if v.pairs, err = d.pairs(n); err != nil {
			return nil, err
		}
		if tag == '}' {
			v.def, err = d.value()
		}
		return v, err
	case 'o', 'S':
		d.register(v)
		if v.str, err = d.symbolName(); err != nil {
			return nil, err
		}
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		v.pairs, err = d.pairs(n)
		return v, err
	case 'U':
		d.register(v)
		if v.str, err = d.symbolName(); err != nil {
			return nil, err
		}
		data, err := d.value()
		if err != nil {
			return nil, err
		}
		v.items = []*rbValue{data}
		return v, nil
	case 'u':
		if v.str, err = d.symbolName(); err != nil {
			return nil, err
		}
		if v.raw, err = d.bytes(); err != nil {
			return nil, err
		}
		return d.register(v), nil
	case 'e', 'C':
		// A wrapper, not an object: the object it wraps takes the link-table
		// entry, so the wrapper registers nothing.
		if v.str, err = d.symbolName(); err != nil {
			return nil, err
		}
		inner, err := d.value()
		if err != nil {
			return nil, err
		}
		v.items = []*rbValue{inner}
		return v, nil
	}
	return nil, fmt.Errorf("%w: type byte %q at byte %d is not one bodega reads", errRbShape, tag, d.pos-1)
}

type rbEncoder struct {
	buf  bytes.Buffer
	syms map[string]int
	objs map[*rbValue]int
}

// rbMarshal writes v as a Marshal 4.8 stream with its own symbol and link
// tables. An object the decoder reached twice through a link is one pointer,
// and is written once and linked after, as Ruby wrote it.
func rbMarshal(v *rbValue) []byte {
	e := &rbEncoder{syms: map[string]int{}, objs: map[*rbValue]int{}}
	e.buf.Write([]byte{4, 8})
	e.value(v)
	return e.buf.Bytes()
}

// long is Ruby's w_long, the inverse of rbDecoder.long.
func (e *rbEncoder) long(x int64) {
	switch {
	case x == 0:
		e.buf.WriteByte(0)
		return
	case x > 0 && x < 123:
		e.buf.WriteByte(byte(x + 5))
		return
	case x < 0 && x > -124:
		e.buf.WriteByte(byte(x - 5)) //nolint:gosec // G115: -128..-6 written as its two's-complement byte, as w_long does.
		return
	}
	var out [9]byte
	for i := 1; i < len(out); i++ {
		out[i] = byte(x) //nolint:gosec // G115: the low byte, taken on purpose.
		x >>= 8
		if x == 0 {
			out[0] = byte(i)
			e.buf.Write(out[:i+1])
			return
		}
		if x == -1 {
			out[0] = byte(-i) //nolint:gosec // G115: a negative byte count, two's complement, as w_long writes it.
			e.buf.Write(out[:i+1])
			return
		}
	}
}

func (e *rbEncoder) bytes(s string) {
	e.long(int64(len(s)))
	e.buf.WriteString(s)
}

func (e *rbEncoder) symbol(name string, ivars [][2]*rbValue) {
	if i, ok := e.syms[name]; ok {
		e.buf.WriteByte(';')
		e.long(int64(i))
		return
	}
	e.syms[name] = len(e.syms)
	if len(ivars) > 0 {
		e.buf.WriteByte('I')
	}
	e.buf.WriteByte(':')
	e.bytes(name)
	e.writeIvars(ivars)
}

func (e *rbEncoder) writePairs(pairs [][2]*rbValue) {
	e.long(int64(len(pairs)))
	for _, p := range pairs {
		e.value(p[0])
		e.value(p[1])
	}
}

func (e *rbEncoder) writeIvars(ivars [][2]*rbValue) {
	if len(ivars) > 0 {
		e.writePairs(ivars)
	}
}

func (e *rbEncoder) value(v *rbValue) {
	switch v.tag {
	case '0', 'T', 'F':
		e.buf.WriteByte(v.tag)
		return
	case 'i':
		e.buf.WriteByte('i')
		e.long(v.num)
		return
	case ':':
		e.symbol(v.str, v.ivars)
		return
	}
	if i, ok := e.objs[v]; ok {
		e.buf.WriteByte('@')
		e.long(int64(i))
		return
	}
	if len(v.ivars) > 0 {
		e.buf.WriteByte('I')
	}
	if v.tag != 'e' && v.tag != 'C' {
		e.objs[v] = len(e.objs)
	}
	e.buf.WriteByte(v.tag)
	switch v.tag {
	case '"', 'f', 'c', 'm', 'M':
		e.bytes(v.str)
	case '/':
		e.bytes(v.raw)
		e.buf.WriteByte(v.flag)
	case 'l':
		e.buf.WriteByte(v.flag)
		e.long(int64(len(v.str) / 2))
		e.buf.WriteString(v.str)
	case '[':
		e.long(int64(len(v.items)))
		for _, it := range v.items {
			e.value(it)
		}
	case '{', '}':
		e.writePairs(v.pairs)
		if v.tag == '}' {
			e.value(v.def)
		}
	case 'o', 'S':
		e.symbol(v.str, nil)
		e.writePairs(v.pairs)
	case 'U', 'e', 'C':
		e.symbol(v.str, nil)
		e.value(v.items[0])
	case 'u':
		e.symbol(v.str, nil)
		e.bytes(v.raw)
	}
	e.writeIvars(v.ivars)
}

// rbString is the bytes of a Ruby String, and false for anything else.
func rbString(v *rbValue) (string, bool) {
	if v == nil || v.tag != '"' {
		return "", false
	}
	return v.str, true
}

// rbGemVersion is the version a Gem::Version carries. It marshals through
// marshal_dump as a one-element array holding the version string.
func rbGemVersion(v *rbValue) (string, bool) {
	if v == nil || v.tag != 'U' || v.str != "Gem::Version" || len(v.items) != 1 {
		return "", false
	}
	data := v.items[0]
	if data.tag != '[' || len(data.items) < 1 {
		return "", false
	}
	return rbString(data.items[0])
}

// rbHashString is the String a Hash holds under the symbol key, and false
// when it holds none.
func rbHashString(v *rbValue, key string) (string, bool) {
	if v == nil || (v.tag != '{' && v.tag != '}') {
		return "", false
	}
	for _, p := range v.pairs {
		if p[0].tag == ':' && p[0].str == key {
			return rbString(p[1])
		}
	}
	return "", false
}
