// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors

// A second implementation of the signature profile of Kern
// (docs/hybrid-signatures.md), written with the Go standard library alone
// and independently of tests/profile_reference.py. It recomputes every
// value of profile.json and every verdict of ed25519_edge_cases.json,
// verifies the composite signatures of composite_signatures.json, those
// made in Python and those it made itself, refuses what must be refused,
// and fails on the first difference.
//
//	go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json
//
// With -official it runs the official vectors kept whole in the directory
// given, the files tests/test_composite.py runs in Python, and must reach
// the same verdicts: RFC 10073 for the combination Kern uses, NIST and
// Project Wycheproof for ML-DSA-65, Project Wycheproof for Ed25519 under
// the rule of section 2.5.
//
//	go run profile_check.go -official ..
//
// With -schemas it checks the vectors of the schemas of structure version 1
// (docs/api-stability.md, section 9), which tests/schema_vectors.py builds
// with tests/schema_reference.py: the tables of this program were written
// from the document, and must accept and refuse the same objects, compute
// the same roots, charge the same blocks, decide the same proposals and
// release the same payments.
//
//	go run profile_check.go -schemas schemas.json
//
// With -sign it prints the signatures it makes, the list kept under "go"
// in composite_signatures.json:
//
//	go run profile_check.go -sign composite_signatures.json
//
// Needs Go 1.27 or later, for crypto/mldsa. Not part of the node and not
// run by the test suite, which is Python; the continuous integration runs
// the first three commands on every pull request.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------- section 4.3: canonical JSON

func writeString(s string, out *bytes.Buffer) error {
	if !utf8.ValidString(s) {
		return errors.New("string that is not valid UTF-8")
	}
	out.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\f':
			out.WriteString(`\f`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return nil
}

func writeValue(v any, out *bytes.Buffer) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order, which is the order of UTF-8
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeString(k, out); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeValue(t[k], out); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeValue(item, out); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case string:
		return writeString(t, out)
	case json.Number:
		n, err := strconv.ParseInt(t.String(), 10, 64) // no float on the way
		if err != nil {
			return errors.New("not an integer of 64 bits")
		}
		out.WriteString(strconv.FormatInt(n, 10))
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	default:
		return errors.New("value with no canonical form") // null
	}
	return nil
}

func canonicalJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeValue(v, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// parse reads JSON without ever going through a floating point number.
func parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

func decodeCanonical(data []byte) (any, error) {
	v, err := parse(data)
	if err != nil {
		return nil, err
	}
	again, err := canonicalJSON(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, data) {
		return nil, errors.New("not the canonical encoding")
	}
	return v, nil
}

// ---------------------------------------------------------------- section 4.1: one hash function

func h(domain string, network, data []byte) []byte {
	if len(domain) < 1 || len(domain) > 255 || len(network) != 32 {
		panic("domain of 1 to 255 bytes, network identifier of 32 bytes")
	}
	d := sha3.New384()
	d.Write([]byte{byte(len(domain))})
	d.Write([]byte(domain))
	d.Write(network)
	d.Write(data)
	return d.Sum(nil)
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// ---------------------------------------------------------------- section 4.4: Merkle trees

func merkleRoot(network []byte, items [][]byte) []byte {
	n := len(items)
	switch n {
	case 0:
		return h("kern.merkle.empty", network, nil)
	case 1:
		return h("kern.merkle.leaf", network, items[0])
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return h("kern.merkle.node", network, join(merkleRoot(network, items[:k]), merkleRoot(network, items[k:])))
}

// ---------------------------------------------------------------- section 3.2: key derivation

const derivationLabel = "KERN-KEY-DERIVATION-V1"

func hmac512(key, data []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func extract(seed []byte) []byte { return hmac512(make([]byte, 64), seed) }

func info(network []byte, component string) []byte {
	return join([]byte(derivationLabel), []byte{0x01}, network, []byte(component))
}

func derive(seed, network []byte, component string) []byte {
	return hmac512(extract(seed), join(info(network, component), []byte{0x01}))[:32]
}

// ---------------------------------------------------------------- sections 5 and 6

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(data []byte) string {
	n := new(big.Int).SetBytes(data)
	out := ""
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, big.NewInt(58), mod)
		out = string(alphabet[mod.Int64()]) + out
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = "1" + out
	}
	return out
}

func addressFromHash(network, digest []byte) string {
	body := join([]byte{0x7b, 0x03, 0x39}, digest)
	return base58(join(body, h("kern.checksum", network, body)[:4]))
}

func accountAddress(network, publicKey []byte) (string, []byte) {
	digest := h("kern.addr", network, join([]byte{0x01}, publicKey))
	return addressFromHash(network, digest), digest
}

func witnessLeaf(network, transactionID, signature, publicKey, second []byte) []byte {
	flags := byte(0)
	if publicKey != nil {
		flags |= 1
	}
	if second != nil {
		flags |= 2
	}
	return h("kern.witness", network, join(transactionID, []byte{flags}, publicKey, signature, second))
}

func pattern(length, factor, offset int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte((factor*i + offset) % 256)
	}
	return out
}

// ---------------------------------------------------------------- section 5: text forms

func textOf(prefix string, data []byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(data)
}

// decodeText accepts one text per value: the exact prefix, the exact
// length, the 64 characters of base64url and unused bits at zero. The
// bytes are encoded again and compared, which also refuses the line feeds
// that the decoder of the standard library skips.
func decodeText(prefix string, size int, text string) ([]byte, error) {
	if len(text) != len(prefix)+(4*size+2)/3 || !strings.HasPrefix(text, prefix) {
		return nil, errors.New("not the prefix and the length of this text form")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(text[len(prefix):])
	if err != nil {
		return nil, err
	}
	if len(data) != size || textOf(prefix, data) != text {
		return nil, errors.New("not the one text of these bytes")
	}
	return data, nil
}

// ---------------------------------------------------------------- section 4.1: the other byte layouts

// proposerDraw is the first 8 bytes of the hash of the parent hash and of
// the round on 4 bytes, read as an integer.
func proposerDraw(network, parentHash []byte, round uint32) uint64 {
	data := binary.BigEndian.AppendUint32(append([]byte{}, parentHash...), round)
	return binary.BigEndian.Uint64(h("kern.proposer", network, data)[:8])
}

func evmCreate(network, creator []byte, nonce uint64) []byte {
	return h("kern.evm.create", network, binary.BigEndian.AppendUint64(append([]byte{}, creator...), nonce))[:20]
}

func evmCreate2(network, creator, salt, creationCode []byte) []byte {
	return h("kern.evm.create2", network, join(creator, salt, h("kern.evm.code", network, creationCode)))[:20]
}

// evmSigner is what precompile 0x01 returns, after 12 zero bytes, for the
// Ed25519 public key whose signature it has verified.
func evmSigner(network, publicKey []byte) []byte {
	return h("kern.evm.signer", network, publicKey)[:20]
}

// ---------------------------------------------------------------- section 4.6: the state trie and the state root

const keyBits = 384

func bit(key []byte, i int) byte { return key[i/8] >> (7 - uint(i%8)) & 1 }

// trieLeaf states how many bits of the key are left at this depth, then
// those bits, then the length of the value on 4 bytes, then the value.
func trieLeaf(network, key []byte, depth int, value []byte) []byte {
	count := keyBits - depth
	packed := make([]byte, (count+7)/8)
	for i := 0; i < count; i++ {
		packed[i/8] |= bit(key, depth+i) << (7 - uint(i%8))
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(count))
	data = append(data, packed...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(value)))
	return h("kern.trie.leaf", network, append(data, value...))
}

type entry struct{ key, value []byte }

func trieNode(network []byte, entries []entry, depth int) []byte {
	switch len(entries) {
	case 0:
		return make([]byte, 48) // an empty subtree
	case 1:
		return trieLeaf(network, entries[0].key, depth, entries[0].value)
	}
	if depth == keyBits {
		panic("two entries with the same key")
	}
	var left, right []entry
	for _, e := range entries {
		if bit(e.key, depth) == 0 {
			left = append(left, e)
		} else {
			right = append(right, e)
		}
	}
	return h("kern.trie.branch", network, join(trieNode(network, left, depth+1), trieNode(network, right, depth+1)))
}

var accountMaps = []string{"balances", "nonces", "contracts"}

func accountObject(network []byte, state map[string]any, address string) map[string]any {
	of := func(name string) any {
		m, _ := state[name].(map[string]any)
		return m[address]
	}
	out := map[string]any{"balance": json.Number("0"), "nonce": json.Number("0")}
	if v := of("balances"); v != nil {
		out["balance"] = v
	}
	if v := of("nonces"); v != nil {
		out["nonce"] = v
	}
	if contract, ok := of("contracts").(map[string]any); ok {
		storage, err := canonicalJSON(contract["storage"])
		if err != nil {
			panic(err)
		}
		out["code_hash"] = hex.EncodeToString(h("kern.code", network, []byte(contract["code"].(string))))
		out["storage_root"] = hex.EncodeToString(h("kern.storage", network, storage))
	}
	return out
}

func accountsRoot(network []byte, state map[string]any) []byte {
	seen := map[string]bool{}
	for _, name := range accountMaps {
		m, _ := state[name].(map[string]any)
		for address := range m {
			seen[address] = true
		}
	}
	addresses := make([]string, 0, len(seen))
	for address := range seen {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	entries := make([]entry, len(addresses))
	for i, address := range addresses {
		value, err := canonicalJSON(accountObject(network, state, address))
		if err != nil {
			panic(err)
		}
		entries[i] = entry{h("kern.trie.key", network, []byte(address)), value}
	}
	return trieNode(network, entries, 0)
}

// hashedState is the object hashed into the state root: the state itself
// with the function json; with the function trie, the three maps keyed by
// address are replaced by the root of their trie.
func hashedState(network []byte, state map[string]any) []byte {
	hashed := state
	switch state["state_root_function"] {
	case "json":
	case "trie":
		hashed = map[string]any{"accounts_root": hex.EncodeToString(accountsRoot(network, state))}
		for name, value := range state {
			if name != "balances" && name != "nonces" && name != "contracts" {
				hashed[name] = value
			}
		}
	default:
		panic("the state names its root function: json or trie")
	}
	out, err := canonicalJSON(hashed)
	if err != nil {
		panic(err)
	}
	return out
}

// ---------------------------------------------------------------- section 2.5: Ed25519, one verdict

var (
	fieldP, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	orderL, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	curveD    = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
	sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2), fieldP)
)

type point struct{ x, y *big.Int }

func isIdentity(a point) bool { return a.x.Sign() == 0 && a.y.Cmp(big.NewInt(1)) == 0 }

func addPoints(a, b point) point {
	mul := func(u, v *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(u, v), fieldP) }
	k := mul(curveD, mul(mul(a.x, b.x), mul(a.y, b.y)))
	one := big.NewInt(1)
	xNum := new(big.Int).Add(mul(a.x, b.y), mul(b.x, a.y))
	yNum := new(big.Int).Add(mul(a.y, b.y), mul(a.x, b.x))
	xDen := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Add(one, k), fieldP), fieldP)
	yDen := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(one, k), fieldP), fieldP)
	return point{mul(xNum, xDen), mul(yNum, yDen)}
}

func scalarMul(n *big.Int, a point) point {
	result := point{big.NewInt(0), big.NewInt(1)}
	addend := a
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			result = addPoints(result, addend)
		}
		addend = addPoints(addend, addend)
	}
	return result
}

// decodeStrictly follows RFC 8032, section 5.1.3: nil unless b is the one
// encoding of a point of the curve.
func decodeStrictly(b []byte) *point {
	if len(b) != 32 {
		return nil
	}
	le := make([]byte, 32)
	for i := range b {
		le[31-i] = b[i]
	}
	sign := uint(le[0] >> 7)
	le[0] &= 0x7f
	y := new(big.Int).SetBytes(le)
	if y.Cmp(fieldP) >= 0 {
		return nil
	}
	yy := new(big.Int).Mod(new(big.Int).Mul(y, y), fieldP)
	num := new(big.Int).Mod(new(big.Int).Sub(yy, big.NewInt(1)), fieldP)
	den := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(curveD, yy), big.NewInt(1)), fieldP), fieldP)
	xx := new(big.Int).Mod(new(big.Int).Mul(num, den), fieldP)
	x := new(big.Int).Exp(xx, new(big.Int).Rsh(new(big.Int).Add(fieldP, big.NewInt(3)), 3), fieldP)
	if new(big.Int).Mod(new(big.Int).Mul(x, x), fieldP).Cmp(xx) != 0 {
		x.Mod(x.Mul(x, sqrtM1), fieldP)
	}
	if new(big.Int).Mod(new(big.Int).Mul(x, x), fieldP).Cmp(xx) != 0 {
		return nil
	}
	if x.Bit(0) != sign {
		x.Mod(x.Neg(x), fieldP)
	}
	if x.Bit(0) != sign { // x is 0 and the sign bit is set
		return nil
	}
	return &point{x, y}
}

// isAKey is rule 2 alone, the check made when a key is recorded: the
// canonical encoding of a point of the subgroup of prime order, other than
// the identity.
func isAKey(publicKey []byte) bool {
	a := decodeStrictly(publicKey)
	return a != nil && !isIdentity(*a) && isIdentity(scalarMul(orderL, *a))
}

func strictVerify(publicKey, message, signature []byte) bool {
	if len(publicKey) != 32 || len(signature) != 64 {
		return false
	}
	r := decodeStrictly(signature[:32])
	if r == nil || isIdentity(*r) {
		return false
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[31-i] = signature[32+i]
	}
	if new(big.Int).SetBytes(le).Cmp(orderL) >= 0 {
		return false
	}
	if !isAKey(publicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) // the exact equation
}

func lenientVerify(publicKey, message, signature []byte) bool {
	return len(publicKey) == 32 && ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// ---------------------------------------------------------------- section 2.1: composite signatures

const (
	prefix             = "CompositeAlgorithmSignatures2025"
	label              = "COMPSIG-MLDSA65-Ed25519-SHA512"
	mldsaPublicKeySize = 1952
	mldsaSignatureSize = 3309
	publicKeySize      = 1984
	signatureSize      = 3373
)

var purposes = []string{"kern.tx", "kern.header", "kern.propose", "kern.preendorse", "kern.endorse", "kern.batch", "kern.rotate"}

func signingContext(purpose string, network []byte) []byte {
	return join([]byte(purpose), []byte{0}, network)
}

// representative is M' of RFC 10073, section 2.2.
func representative(message, context []byte) []byte {
	digest := sha512.Sum512(message)
	return join([]byte(prefix), []byte(label), []byte{byte(len(context))}, context, digest[:])
}

func compositePublicKey(seed, network []byte) []byte {
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), derive(seed, network, "mldsa65"))
	if err != nil {
		panic(err)
	}
	return join(sk.PublicKey().Bytes(), ed25519.NewKeyFromSeed(derive(seed, network, "ed25519")).Public().(ed25519.PublicKey))
}

// compositeSign signs with both components. ML-DSA is used in its
// deterministic mode so that these signatures can be rebuilt; a node signs
// in the randomized mode.
func compositeSign(seed, network, message, context []byte) []byte {
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), derive(seed, network, "mldsa65"))
	if err != nil {
		panic(err)
	}
	m := representative(message, context)
	first, err := sk.SignDeterministic(m, &mldsa.Options{Context: label})
	if err != nil {
		panic(err)
	}
	return join(first, ed25519.Sign(ed25519.NewKeyFromSeed(derive(seed, network, "ed25519")), m))
}

// compositeVerify is true only if both components are valid: the Ed25519
// one under the rule of section 2.5, the ML-DSA one with the Label as its
// context.
func compositeVerify(publicKey, message, signature, context []byte) bool {
	if len(publicKey) != publicKeySize || len(signature) != signatureSize || len(context) > 255 {
		return false
	}
	m := representative(message, context)
	if !strictVerify(publicKey[mldsaPublicKeySize:], m, signature[mldsaSignatureSize:]) {
		return false
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey[:mldsaPublicKeySize])
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, m, signature[:mldsaSignatureSize], &mldsa.Options{Context: label}) == nil
}

type signed struct {
	Purpose   string `json:"purpose"`
	Signature string `json:"signature"`
}

type signatures struct {
	Seed      string   `json:"seed"`
	NetworkID string   `json:"network_id"`
	Message   string   `json:"message"`
	PublicKey string   `json:"public_key"`
	Python    []signed `json:"python"`
	Go        []signed `json:"go"`
	Invalid   []struct {
		Why       string `json:"why"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	} `json:"invalid"`
}

func readSignatures(path string) signatures {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var s signatures
	if err := json.Unmarshal(raw, &s); err != nil {
		panic(err)
	}
	return s
}

func ownSignatures(s signatures) []signed {
	seed, network, message := unhex(s.Seed), unhex(s.NetworkID), unhex(s.Message)
	out := make([]signed, len(purposes))
	for i, purpose := range purposes {
		out[i] = signed{purpose, hex.EncodeToString(compositeSign(seed, network, message, signingContext(purpose, network)))}
	}
	return out
}

func checkSignatures(s signatures) {
	seed, network, message := unhex(s.Seed), unhex(s.NetworkID), unhex(s.Message)
	publicKey := unhex(s.PublicKey)
	check("composite public key", bytes.Equal(publicKey, compositePublicKey(seed, network)))
	for name, list := range map[string][]signed{"Python": s.Python, "Go": s.Go} {
		check("seven signatures made by "+name, len(list) == len(purposes))
		for i, c := range list {
			signature := unhex(c.Signature)
			check(name+" signature has its purpose", i < len(purposes) && c.Purpose == purposes[i])
			check(name+" signature verifies: "+c.Purpose, compositeVerify(publicKey, message, signature, signingContext(c.Purpose, network)))
			for _, other := range purposes { // and in no other context
				if other != c.Purpose {
					check(name+" signature for "+c.Purpose+" refused for "+other,
						!compositeVerify(publicKey, message, signature, signingContext(other, network)))
				}
			}
		}
	}
	own := ownSignatures(s)
	for i, c := range s.Go {
		check("signature rebuilt byte for byte: "+c.Purpose, i < len(own) && own[i] == c)
	}
	context := signingContext("kern.tx", network)
	for _, c := range s.Invalid {
		key, signature := publicKey, unhex(c.Signature)
		if c.PublicKey != "" {
			key = unhex(c.PublicKey)
		}
		check("refused: "+c.Why, !compositeVerify(key, message, signature, context))
	}
}

// ---------------------------------------------------------------- the official vectors

func mldsaVerifies(publicKey, message, signature, context []byte) bool {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, message, signature, &mldsa.Options{Context: string(context)}) == nil
}

func has(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

// checkOfficial runs the files of RFC 10073, NIST and Project Wycheproof
// kept under dir, and counts what it finds: the figures are the ones the
// Python tests assert on the same files.
func checkOfficial(dir string) {
	var sources struct {
		Files []struct {
			Path   string `json:"path"`
			Bytes  int    `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	read := func(name string, into any) []byte {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			panic(err)
		}
		return raw
	}
	read("SOURCES.json", &sources)
	// load reads a file and checks that it is the one SOURCES.json lists, byte for byte.
	load := func(name string, into any) {
		raw := read(name, into)
		digest := sha256.Sum256(raw)
		listed := false
		for _, f := range sources.Files {
			if f.Path == name {
				listed = f.Bytes == len(raw) && f.SHA256 == hex.EncodeToString(digest[:])
			}
		}
		check("the file SOURCES.json lists, byte for byte: "+name, listed)
	}
	unbase64 := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}

	// RFC 10073: the vector of the combination Kern uses.
	var rfc struct {
		M     string `json:"m"`
		Ctx   string `json:"ctx"`
		Tests []struct {
			TcID         string `json:"tcId"`
			PK           string `json:"pk"`
			SK           string `json:"sk"`
			S            string `json:"s"`
			SWithContext string `json:"sWithContext"`
		} `json:"tests"`
	}
	load("rfc10073/testvectors.json", &rfc)
	message, context := unbase64(rfc.M), unbase64(rfc.Ctx)
	found := 0
	for _, t := range rfc.Tests {
		if t.TcID != "id-MLDSA65-Ed25519-SHA512" {
			continue
		}
		found++
		pk, sk, plain, withContext := unbase64(t.PK), unbase64(t.SK), unbase64(t.S), unbase64(t.SWithContext)
		sizes := len(sk) == 64 && len(pk) == publicKeySize && len(plain) == signatureSize && len(withContext) == signatureSize
		check("RFC 10073: sizes of the private key, the public key and the signatures", sizes && len(context) > 0)
		if !sizes {
			continue
		}
		// Serialization: ML-DSA seed then Ed25519 seed; ML-DSA part then Ed25519 part.
		first, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), sk[:32])
		if err != nil {
			panic(err)
		}
		public := join(first.PublicKey().Bytes(), ed25519.NewKeyFromSeed(sk[32:]).Public().(ed25519.PublicKey))
		check("RFC 10073: the published seeds give the published public key", bytes.Equal(public, pk))
		check("RFC 10073: the published signature verifies", compositeVerify(pk, message, plain, nil))
		check("RFC 10073: the published signature with a context verifies", compositeVerify(pk, message, withContext, context))
		check("RFC 10073: a signature without context is refused with one", !compositeVerify(pk, message, plain, context))
		check("RFC 10073: a signature with a context is refused without it", !compositeVerify(pk, message, withContext, nil))
		check("RFC 10073: another message is refused", !compositeVerify(pk, join(message, []byte(".")), plain, nil))
	}
	check("RFC 10073: 21 combinations, one of them the combination of Kern", len(rfc.Tests) == 21 && found == 1)
	fmt.Println("RFC 10073: id-MLDSA65-Ed25519-SHA512 among", len(rfc.Tests), "combinations: the public key from its seeds, 2 signatures verified, 3 refusals")

	// NIST: key generation and signature verification for ML-DSA-65.
	var keyGen struct {
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID int    `json:"tcId"`
				Seed string `json:"seed"`
				PK   string `json:"pk"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	load("nist-acvp/ML-DSA-keyGen-FIPS204.json", &keyGen)
	nistKeys, groups := 0, 0
	for _, g := range keyGen.TestGroups {
		if g.ParameterSet != "ML-DSA-65" {
			continue
		}
		groups++
		for _, t := range g.Tests {
			sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), unhex(t.Seed))
			check(fmt.Sprintf("NIST key generation %d", t.TcID), err == nil && bytes.Equal(sk.PublicKey().Bytes(), unhex(t.PK)))
			nistKeys++
		}
	}
	check("NIST: one group of 25 keys for ML-DSA-65", groups == 1 && nistKeys == 25)

	var sigVer struct {
		TestGroups []struct {
			ParameterSet       string `json:"parameterSet"`
			SignatureInterface string `json:"signatureInterface"`
			PreHash            string `json:"preHash"`
			Tests              []struct {
				TcID       int    `json:"tcId"`
				TestPassed bool   `json:"testPassed"`
				PK         string `json:"pk"`
				Message    string `json:"message"`
				Context    string `json:"context"`
				Signature  string `json:"signature"`
				Reason     string `json:"reason"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	load("nist-acvp/ML-DSA-sigVer-FIPS204.json", &sigVer)
	nistValid, nistInvalid := 0, 0
	groups = 0
	reasons := map[string]bool{}
	for _, g := range sigVer.TestGroups {
		if g.ParameterSet != "ML-DSA-65" || g.SignatureInterface != "external" || g.PreHash != "pure" {
			continue
		}
		groups++
		for _, t := range g.Tests {
			got := mldsaVerifies(unhex(t.PK), unhex(t.Message), unhex(t.Signature), unhex(t.Context))
			check(fmt.Sprintf("NIST signature verification %d", t.TcID), got == t.TestPassed)
			if t.TestPassed {
				nistValid++
			} else {
				nistInvalid++
				reasons[t.Reason] = true
			}
		}
	}
	check("NIST: one group for ML-DSA-65, external and pure: 3 valid, 12 invalid", groups == 1 && nistValid == 3 && nistInvalid == 12)
	check("NIST: the four ways the invalid cases were made", len(reasons) == 4 && reasons["modified signature - z"] &&
		reasons["modified signature - hint"] && reasons["modified signature - commitment"] && reasons["modified message"])
	fmt.Printf("NIST: %d ML-DSA-65 keys from their seeds, %d signature verifications (%d valid, %d invalid)\n",
		nistKeys, nistValid+nistInvalid, nistValid, nistInvalid)

	// Project Wycheproof: ML-DSA-65, verification.
	var verify struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			PublicKey string `json:"publicKey"`
			Tests     []struct {
				TcID   int      `json:"tcId"`
				Msg    string   `json:"msg"`
				Sig    string   `json:"sig"`
				Ctx    string   `json:"ctx"`
				Result string   `json:"result"`
				Flags  []string `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	load("wycheproof/mldsa_65_verify_test.json", &verify)
	wpValid, wpInvalid := 0, 0
	flags := map[string]int{}
	for _, g := range verify.TestGroups {
		for _, t := range g.Tests {
			got := mldsaVerifies(unhex(g.PublicKey), unhex(t.Msg), unhex(t.Sig), unhex(t.Ctx))
			check(fmt.Sprintf("Wycheproof ML-DSA-65 verification %d", t.TcID), got == (t.Result == "valid"))
			if t.Result == "valid" {
				wpValid++
			} else if t.Result == "invalid" {
				wpInvalid++
			}
			for _, f := range t.Flags {
				flags[f]++
			}
		}
	}
	check("Wycheproof ML-DSA-65: 79 valid and 131 invalid, 210 in all", wpValid == 79 && wpInvalid == 131 && verify.NumberOfTests == 210)
	for _, f := range []string{"InvalidHintsEncoding", "InfinityNormViolation", "IncorrectSignatureLength",
		"IncorrectPublicKeyLength", "InvalidContext", "ZeroPublicKey"} {
		check("Wycheproof ML-DSA-65: cases flagged "+f, flags[f] > 0)
	}

	// Project Wycheproof: ML-DSA-65, keys and signatures from seeds.
	var signSeed struct {
		TestGroups []struct {
			PrivateSeed string `json:"privateSeed"`
			PublicKey   string `json:"publicKey"`
			Tests       []struct {
				TcID   int      `json:"tcId"`
				Msg    *string  `json:"msg"`
				Sig    string   `json:"sig"`
				Ctx    string   `json:"ctx"`
				Result string   `json:"result"`
				Flags  []string `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	load("wycheproof/mldsa_65_sign_seed_test.json", &signSeed)
	seedKeys, refusedSeeds, verified, rebuilt, refusedContexts, withoutMessage := 0, 0, 0, 0, 0, 0
	for _, g := range signSeed.TestGroups {
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), unhex(g.PrivateSeed))
		if err != nil {
			refusedSeeds++
			for _, t := range g.Tests {
				check(fmt.Sprintf("Wycheproof ML-DSA-65: a refused seed has only invalid cases (%d)", t.TcID), t.Result == "invalid")
			}
			continue
		}
		check("Wycheproof ML-DSA-65: the seed gives the published key", bytes.Equal(sk.PublicKey().Bytes(), unhex(g.PublicKey)))
		seedKeys++
		for _, t := range g.Tests {
			if t.Msg == nil { // vectors given as a precomputed digest only
				withoutMessage++
				continue
			}
			msg, ctx := unhex(*t.Msg), unhex(t.Ctx)
			own, err := sk.SignDeterministic(msg, &mldsa.Options{Context: string(ctx)})
			if t.Result == "invalid" {
				check(fmt.Sprintf("Wycheproof ML-DSA-65: signing refused (%d)", t.TcID), err != nil)
				refusedContexts++
				continue
			}
			check(fmt.Sprintf("Wycheproof ML-DSA-65: signature from a seed verifies (%d)", t.TcID),
				err == nil && mldsaVerifies(unhex(g.PublicKey), msg, unhex(t.Sig), ctx))
			verified++
			if !has(t.Flags, "Randomized") { // made without randomness: the same bytes here
				check(fmt.Sprintf("Wycheproof ML-DSA-65: signature rebuilt byte for byte (%d)", t.TcID), bytes.Equal(own, unhex(t.Sig)))
				rebuilt++
			}
		}
	}
	check("Wycheproof ML-DSA-65: 39 keys, 3 refused seeds, 84 signatures, 1 refused context, 17 vectors without a message",
		seedKeys == 39 && refusedSeeds == 3 && verified == 84 && refusedContexts == 1 && withoutMessage == 17)
	check("Wycheproof ML-DSA-65: 83 signatures made without randomness, rebuilt byte for byte", rebuilt == 83)
	fmt.Printf("Wycheproof ML-DSA-65: %d verifications (%d valid, %d invalid); %d keys from their seeds, %d seeds refused, "+
		"%d signatures verified, %d of them rebuilt byte for byte, %d context refused, %d vectors without a message\n",
		wpValid+wpInvalid, wpValid, wpInvalid, seedKeys, refusedSeeds, verified, rebuilt, refusedContexts, withoutMessage)

	// Project Wycheproof: Ed25519, under the rule of section 2.5.
	var eddsa struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			PublicKey struct {
				PK string `json:"pk"`
			} `json:"publicKey"`
			Tests []struct {
				TcID   int      `json:"tcId"`
				Msg    string   `json:"msg"`
				Sig    string   `json:"sig"`
				Result string   `json:"result"`
				Flags  []string `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	load("wycheproof/ed25519_test.json", &eddsa)
	verdicts, leftOpen := map[string]int{}, map[string]int{}
	for _, g := range eddsa.TestGroups {
		pk := unhex(g.PublicKey.PK)
		for _, t := range g.Tests {
			got := strictVerify(pk, unhex(t.Msg), unhex(t.Sig))
			check(fmt.Sprintf("Wycheproof Ed25519 %d, %s", t.TcID, t.Result), got == (t.Result == "valid"))
			verdicts[fmt.Sprintf("%s %t", t.Result, got)]++
			if t.Result == "acceptable" {
				for _, f := range t.Flags {
					leftOpen[f]++
				}
			}
		}
	}
	// What the vectors call valid is accepted, what they call invalid is refused, and the
	// cases they leave to the implementation are all refused: a public key of small or
	// mixed order is not a key.
	check("Wycheproof Ed25519: 117 valid accepted, 64 invalid refused, 29 left open refused",
		len(verdicts) == 3 && verdicts["valid true"] == 117 && verdicts["invalid false"] == 64 &&
			verdicts["acceptable false"] == 29 && eddsa.NumberOfTests == 210)
	check("Wycheproof Ed25519: what is left open is 8 keys of small order and 21 of mixed order",
		len(leftOpen) == 2 && leftOpen["SmallOrderPublicKey"] == 8 && leftOpen["MixedOrderPublicKey"] == 21)
	fmt.Printf("Wycheproof Ed25519: %d valid accepted, %d invalid refused, %d left to the implementation refused "+
		"(%d with a key of small order, %d of mixed order)\n", verdicts["valid true"], verdicts["invalid false"],
		verdicts["acceptable false"], leftOpen["SmallOrderPublicKey"], leftOpen["MixedOrderPublicKey"])
}

// ---------------------------------------------------------------- the schemas of structure version 1
//
// docs/api-stability.md, section 9. Chapter 1 comes first: what is signed
// and what travels. The tables below were written from that section, not
// from tests/schema_reference.py, and the checks are not made in the same
// order: a vector that broke two rules at once would get two answers.
// Chapter 2, what is kept, follows the reception of a text.

const (
	maxJSONNesting           = 64
	maxTransactionNesting    = 32
	maxFrameBytes            = 16777216
	maxTransactionBytes      = 131072
	maxBlockBytes            = 8388608
	maxCertificateSignatures = 1024
	maxCodeBytes             = 65536
	maxValueBytes            = 4096
	maxContractFields        = 256
	maxClaimBytes            = 16384
	maxRecipients            = 64
	maxInt                   = math.MaxInt64
	maxRound                 = math.MaxUint32
)

// A schema answers "" to a value it accepts, or the name of the rule that
// refuses it.
type schema func(v any) string

var schemaNetwork []byte

func integer(low, high int64) schema {
	return func(v any) string {
		n, ok := v.(json.Number)
		if !ok {
			return "wrong_type"
		}
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			if _, isInteger := new(big.Int).SetString(n.String(), 10); isInteger {
				return "out_of_range"
			}
			return "wrong_type"
		}
		if i < low || i > high {
			return "out_of_range"
		}
		return ""
	}
}

func boolean(v any) string {
	if _, ok := v.(bool); !ok {
		return "wrong_type"
	}
	return ""
}

func oneOf(values ...string) schema {
	return func(v any) string {
		s, ok := v.(string)
		if !ok {
			return "wrong_type"
		}
		if !has(values, s) {
			return "bad_text"
		}
		return ""
	}
}

// letters is a string of low to high characters, each allowed at its place.
func letters(low, high int, allowed func(i int, c byte) bool) schema {
	return func(v any) string {
		s, ok := v.(string)
		if !ok {
			return "wrong_type"
		}
		if len(s) < low || len(s) > high {
			return "bad_text"
		}
		for i := 0; i < len(s); i++ {
			if !allowed(i, s[i]) {
				return "bad_text"
			}
		}
		return ""
	}
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isLetter(c byte) bool { return isLower(c) || c >= 'A' && c <= 'Z' }

func hexOf(characters int) schema {
	return letters(characters, characters, func(_ int, c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' })
}

// anyText is any string of low to high bytes of UTF-8.
func anyText(low, high int) schema {
	return func(v any) string {
		s, ok := v.(string)
		if !ok {
			return "wrong_type"
		}
		if !utf8.ValidString(s) || len(s) < low || len(s) > high {
			return "bad_text"
		}
		return ""
	}
}

// addressHash is the hash inside an address of this network, or nil: 75
// characters of base 58 that spell the prefix, a hash, and the checksum of
// both on this network.
func addressHash(network []byte, text string) []byte {
	if len(text) != 75 {
		return nil
	}
	n := new(big.Int)
	for i := 0; i < len(text); i++ {
		digit := strings.IndexByte(alphabet, text[i])
		if digit < 0 {
			return nil
		}
		n.Mul(n, big.NewInt(58)).Add(n, big.NewInt(int64(digit)))
	}
	if n.BitLen() > 8*55 {
		return nil
	}
	raw := n.FillBytes(make([]byte, 55))
	if raw[0] != 0x7b || raw[1] != 0x03 || raw[2] != 0x39 || addressFromHash(network, raw[3:51]) != text {
		return nil
	}
	return raw[3:51]
}

func anAddress(v any) string {
	s, ok := v.(string)
	if !ok {
		return "wrong_type"
	}
	if addressHash(schemaNetwork, s) == nil {
		return "bad_address"
	}
	return ""
}

func aKey(v any) string {
	s, ok := v.(string)
	if !ok {
		return "wrong_type"
	}
	if _, err := decodeText("kpk1.", 1984, s); err != nil {
		return "bad_key"
	}
	return ""
}

func aSignature(v any) string {
	s, ok := v.(string)
	if !ok {
		return "wrong_type"
	}
	if _, err := decodeText("ksig1.", 3373, s); err != nil {
		return "bad_signature"
	}
	return ""
}

// listOf has low to high items; a negative high is no bound of its own.
func listOf(item schema, low, high int) schema {
	return func(v any) string {
		list, ok := v.([]any)
		if !ok {
			return "wrong_type"
		}
		if len(list) < low || high >= 0 && len(list) > high {
			return "out_of_range"
		}
		for _, entry := range list {
			if r := item(entry); r != "" {
				return r
			}
		}
		return ""
	}
}

func sortedNames(m map[string]any) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func mapOf(name, value schema, low, high int) schema {
	return func(v any) string {
		m, ok := v.(map[string]any)
		if !ok {
			return "wrong_type"
		}
		if len(m) < low || len(m) > high {
			return "out_of_range"
		}
		for _, member := range sortedNames(m) {
			if r := value(m[member]); r != "" {
				return r
			}
			if r := name(member); r != "" {
				return r
			}
		}
		return ""
	}
}

type field struct {
	is       schema
	optional bool
}

func required(is schema) field { return field{is, false} }
func optional(is schema) field { return field{is, true} }

// object has the fields given and no other member. The fields are checked
// in the order of their names, then the members that are not fields are
// looked for, then the rules that tie fields together are applied.
func object(fields map[string]field, rules ...func(o map[string]any) string) schema {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return func(v any) string {
		o, ok := v.(map[string]any)
		if !ok {
			return "wrong_type"
		}
		for _, name := range names {
			value, present := o[name]
			if !present {
				if !fields[name].optional {
					return "missing_field"
				}
				continue
			}
			if r := fields[name].is(value); r != "" {
				return r
			}
		}
		for member := range o {
			if _, known := fields[member]; !known {
				return "unknown_field"
			}
		}
		for _, rule := range rules {
			if r := rule(o); r != "" {
				return r
			}
		}
		return ""
	}
}

func hasMember(o map[string]any, name string) bool { _, ok := o[name]; return ok }

func number(v any) int64 {
	n, err := strconv.ParseInt(v.(json.Number).String(), 10, 64)
	if err != nil {
		panic(err)
	}
	return n
}

func depthOf(v any) int {
	deepest := 0
	switch t := v.(type) {
	case map[string]any:
		for _, inner := range t {
			deepest = max(deepest, depthOf(inner))
		}
		return deepest + 1
	case []any:
		for _, inner := range t {
			deepest = max(deepest, depthOf(inner))
		}
		return deepest + 1
	}
	return 0
}

// without is the canonical JSON of an object without some of its members.
func without(o map[string]any, names ...string) []byte {
	kept := map[string]any{}
	for name, value := range o {
		if !has(names, name) {
			kept[name] = value
		}
	}
	encoding, err := canonicalJSON(kept)
	if err != nil {
		panic(err)
	}
	return encoding
}

var (
	aLevel      = integer(0, maxInt)
	aRound      = integer(0, maxRound)
	anAmount    = integer(0, maxInt)
	aHash       = hexOf(96)
	aName       = letters(1, 64, func(i int, c byte) bool { return isLetter(c) || c == '_' || i > 0 && isDigit(c) })
	aChain      = letters(1, 64, func(i int, c byte) bool { return isLower(c) || i > 0 && (isDigit(c) || c == '-') })
	aSchemaName = letters(1, 128, func(_ int, c byte) bool {
		return isLetter(c) || isDigit(c) || c == '.' || c == '-' || c == '_'
	})
	aSubject = letters(1, 256, func(_ int, c byte) bool { return c >= 0x20 && c <= 0x7e })
)

// aValue is what a contract holds in a field or takes as a parameter.
func aValue(v any) string {
	switch t := v.(type) {
	case bool:
		return ""
	case json.Number:
		return integer(math.MinInt64, maxInt)(t)
	case string:
		return anyText(0, maxValueBytes)(t)
	}
	return "wrong_type"
}

var someFields = mapOf(aName, aValue, 0, maxContractFields)

// aClaim is any object of canonical JSON, up to a size.
func aClaim(v any) string {
	if _, ok := v.(map[string]any); !ok {
		return "wrong_type"
	}
	encoding, err := canonicalJSON(v)
	if err != nil {
		return "wrong_type"
	}
	if len(encoding) > maxClaimBytes {
		return "too_long"
	}
	return ""
}

var aVote = object(map[string]field{
	"kind": required(oneOf("preendorse", "endorse")), "level": required(aLevel), "round": required(aRound),
	"block_hash": required(aHash), "validator": required(anAddress), "signature": required(aSignature),
})

var aProposeMessage = object(map[string]field{
	"kind": required(oneOf("propose")), "level": required(aLevel), "round": required(aRound),
	"block_hash": required(aHash), "validator": required(anAddress), "valid_round": optional(aRound),
	"signature": required(aSignature),
}, func(o map[string]any) string {
	if hasMember(o, "valid_round") && number(o["valid_round"]) >= number(o["round"]) {
		return "inconsistent"
	}
	return ""
})

var aCertificate = object(map[string]field{
	"kind": required(oneOf("preendorse", "endorse")), "level": required(aLevel), "round": required(aRound),
	"block_hash": required(aHash), "signatures": required(mapOf(anAddress, aSignature, 1, maxCertificateSignatures)),
})

var someParameters = object(map[string]field{
	"i_min_ppm": optional(integer(0, 1000000)), "i_max_ppm": optional(integer(0, 1000000)),
	"target_staking_ratio_ppm": optional(integer(0, 1000000)), "target_block_time_ms": optional(integer(1, 3600000)),
	"treasury_share_ppm": optional(integer(0, 1000000)), "proposer_bonus_ppm": optional(integer(0, 1000000)),
	"fee_floor_enabled": optional(boolean), "fee_floor_base": optional(integer(0, 1000000000000)),
	"fee_floor_per_byte": optional(integer(0, 1000000000)),
	"max_block_bytes":    optional(integer(maxTransactionBytes, maxBlockBytes)),
}, func(o map[string]any) string {
	if len(o) == 0 {
		return "inconsistent"
	}
	return ""
})

var aProtocolPayload = object(map[string]field{
	"params": optional(someParameters), "swap": optional(oneOf("state_root_function")),
	"to": optional(oneOf("json", "trie")),
}, func(o map[string]any) string {
	if hasMember(o, "swap") != hasMember(o, "to") || !hasMember(o, "swap") && !hasMember(o, "params") {
		return "inconsistent"
	}
	return ""
})

var aTreasuryPayload = object(map[string]field{
	"recipients": required(listOf(object(map[string]field{
		"address": required(anAddress), "amount": required(integer(1, maxInt)),
	}), 1, maxRecipients)),
	"memo": optional(anyText(1, 256)),
}, func(o map[string]any) string {
	total := new(big.Int)
	for _, recipient := range o["recipients"].([]any) {
		total.Add(total, big.NewInt(number(recipient.(map[string]any)["amount"])))
	}
	if !total.IsInt64() {
		return "out_of_range"
	}
	return ""
})

// aProposal is the `params` of governance_propose: the payload is the one
// of its track.
func aProposal(v any) string {
	o, ok := v.(map[string]any)
	if !ok {
		return "wrong_type"
	}
	payload := aProtocolPayload
	if track, _ := o["track"].(string); track == "treasury" {
		payload = aTreasuryPayload
	}
	return object(map[string]field{
		"track": required(oneOf("protocol", "treasury")), "payload": required(payload),
		"salt": required(integer(0, maxInt)),
	})(v)
}

// kinds gives each kind of transaction the fields it has besides the
// common ones.
var kinds = map[string]map[string]schema{
	"transfer":           {"recipient": anAddress, "amount": anAmount},
	"originate":          {"code": anyText(1, maxCodeBytes), "initial_storage": someFields},
	"call":               {"recipient": anAddress, "amount": anAmount, "entry": aName, "params": someFields},
	"governance_propose": {"params": aProposal},
	"governance_vote": {"params": object(map[string]field{
		"track": required(oneOf("protocol", "treasury")), "proposal_id": required(aHash),
		"vote": required(oneOf("yes", "no", "abstain")),
	})},
	"release_payment": {"params": object(map[string]field{"proposal_id": required(aHash)})},
	"cancel_payment":  {"params": object(map[string]field{"proposal_id": required(aHash)})},
	"slash_equivocation": {"params": object(map[string]field{
		"proposal_id": required(aHash), "equivocator": required(anAddress),
	})},
	"slash_consensus_equivocation": {"params": object(map[string]field{
		"msg_a": required(aVote), "msg_b": required(aVote),
	})},
	"delegate_stake": {"amount": integer(1, maxInt), "params": object(map[string]field{
		"validator": required(anAddress),
	})},
	"undelegate_stake": {},
	"attest": {"amount": anAmount, "params": object(map[string]field{
		"schema_id": required(aSchemaName), "subject": required(aSubject), "claim": required(aClaim),
	})},
	"revoke_attestation": {"params": object(map[string]field{"attestation_id": required(aHash)})},
	"slash_attestation_equivocation": {"params": object(map[string]field{
		"attestation_id_1": required(aHash), "attestation_id_2": required(aHash),
	})},
	"rotate_key": {"params": object(map[string]field{"new_public_key": required(aKey)})},
}

func aTransaction(v any) string {
	tx, ok := v.(map[string]any)
	if !ok {
		return "wrong_type"
	}
	if depthOf(v) > maxTransactionNesting {
		return "too_deep"
	}
	if encoding, err := canonicalJSON(v); err != nil {
		return "wrong_type"
	} else if len(encoding) > maxTransactionBytes {
		return "too_long"
	}
	kind, present := tx["kind"]
	if !present {
		return "missing_field"
	}
	name, isText := kind.(string)
	if !isText {
		return "wrong_type"
	}
	own, known := kinds[name]
	if !known {
		return "bad_text"
	}
	fields := map[string]field{
		"kind": required(oneOf(name)), "sender": required(anAddress), "nonce": required(integer(0, maxInt)),
		"fee": required(anAmount), "gas_limit": required(integer(0, maxInt)), "chain_id": required(aChain),
		"signature": required(aSignature), "public_key": optional(aKey),
	}
	for member, is := range own {
		fields[member] = required(is)
	}
	if name == "rotate_key" {
		fields["second_signature"] = required(aSignature)
	}
	return object(fields)(v)
}

var witnessFields = []string{"signature", "public_key", "second_signature"}

func transactionID(tx map[string]any) []byte {
	return h("kern.tx", schemaNetwork, without(tx, witnessFields...))
}

func transactionSize(tx map[string]any) int { return len(without(tx)) }

func bytesOf(o map[string]any, name, prefix string, size int) []byte {
	text, present := o[name]
	if !present {
		return nil
	}
	data, err := decodeText(prefix, size, text.(string))
	if err != nil {
		panic(err)
	}
	return data
}

func witnessLeafOf(tx map[string]any) []byte {
	return witnessLeaf(schemaNetwork, transactionID(tx), bytesOf(tx, "signature", "ksig1.", 3373),
		bytesOf(tx, "public_key", "kpk1.", 1984), bytesOf(tx, "second_signature", "ksig1.", 3373))
}

var aHeader = object(map[string]field{
	"version": required(integer(1, 1)), "level": required(aLevel), "payload_round": required(aRound),
	"timestamp": required(integer(0, maxInt)), "parent_hash": required(aHash), "state_root": required(aHash),
	"txs_root": required(aHash), "witness_root": required(aHash), "proposer": required(anAddress),
	"signature": required(aSignature),
})

func blockHash(header map[string]any) string {
	return hex.EncodeToString(h("kern.block", schemaNetwork, without(header, "signature")))
}

var aBlock = object(map[string]field{
	"header": required(aHeader), "transactions": required(listOf(aTransaction, 0, -1)),
}, func(o map[string]any) string {
	header := o["header"].(map[string]any)
	var ids, leaves [][]byte
	size := 0
	for _, entry := range o["transactions"].([]any) {
		tx := entry.(map[string]any)
		ids, leaves, size = append(ids, transactionID(tx)), append(leaves, witnessLeafOf(tx)), size+transactionSize(tx)
	}
	if hex.EncodeToString(merkleRoot(schemaNetwork, leaves)) != header["witness_root"] ||
		hex.EncodeToString(merkleRoot(schemaNetwork, ids)) != header["txs_root"] {
		return "inconsistent"
	}
	if size > maxBlockBytes {
		return "too_long"
	}
	return ""
})

// certifies is the rule of a block and the certificate that makes it final.
func certifies(o map[string]any) string {
	header := o["block"].(map[string]any)["header"].(map[string]any)
	certificate := o["certificate"].(map[string]any)
	if certificate["block_hash"] != blockHash(header) || number(certificate["level"]) != number(header["level"]) ||
		number(certificate["round"]) < number(header["payload_round"]) || certificate["kind"] != "endorse" {
		return "inconsistent"
	}
	return ""
}

var aFinalBlock = object(map[string]field{"block": required(aBlock), "certificate": required(aCertificate)}, certifies)

var frames = map[string]schema{
	"hello": object(map[string]field{
		"kind": required(oneOf("hello")), "network_id": required(hexOf(64)), "level": required(aLevel),
	}),
	"proposal": object(map[string]field{
		"kind": required(oneOf("proposal")), "block": required(aBlock), "proposal": required(aProposeMessage),
		"proof": optional(aCertificate),
	}, func(o map[string]any) string {
		header := o["block"].(map[string]any)["header"].(map[string]any)
		message := o["proposal"].(map[string]any)
		if hasMember(o, "proof") {
			proof := o["proof"].(map[string]any)
			if !hasMember(message, "valid_round") || proof["kind"] != "preendorse" ||
				number(proof["round"]) != number(message["valid_round"]) ||
				number(proof["level"]) != number(message["level"]) || proof["block_hash"] != message["block_hash"] ||
				number(header["payload_round"]) > number(message["valid_round"]) {
				return "inconsistent"
			}
		} else if hasMember(message, "valid_round") || number(header["payload_round"]) != number(message["round"]) {
			return "inconsistent"
		}
		if message["block_hash"] != blockHash(header) || number(message["level"]) != number(header["level"]) {
			return "inconsistent"
		}
		return ""
	}),
	"consensus": object(map[string]field{"kind": required(oneOf("consensus")), "msg": required(aVote)}),
	"block": object(map[string]field{
		"kind": required(oneOf("block")), "block": required(aBlock), "certificate": required(aCertificate),
	}, certifies),
	"transaction": object(map[string]field{"kind": required(oneOf("transaction")), "tx": required(aTransaction)}),
	"get_blocks": object(map[string]field{
		"kind": required(oneOf("get_blocks")), "from": required(integer(1, maxInt)), "to": required(integer(1, maxInt)),
	}, func(o map[string]any) string {
		if number(o["to"]) < number(o["from"]) {
			return "inconsistent"
		}
		return ""
	}),
	"blocks": object(map[string]field{
		"kind": required(oneOf("blocks")), "blocks": required(listOf(aFinalBlock, 0, -1)),
	}, func(o map[string]any) string {
		blocks := o["blocks"].([]any)
		for i := 1; i < len(blocks); i++ {
			level := func(entry any) int64 {
				return number(entry.(map[string]any)["block"].(map[string]any)["header"].(map[string]any)["level"])
			}
			if level(blocks[i]) != level(blocks[i-1])+1 {
				return "inconsistent"
			}
		}
		return ""
	}),
}

func aFrame(v any) string {
	o, ok := v.(map[string]any)
	if !ok {
		return "wrong_type"
	}
	kind, present := o["kind"]
	if !present {
		return "missing_field"
	}
	name, isText := kind.(string)
	if !isText {
		return "wrong_type"
	}
	frame, known := frames[name]
	if !known {
		return "bad_text"
	}
	if r := frame(v); r != "" {
		return r
	}
	if encoding, err := canonicalJSON(v); err != nil {
		return "wrong_type"
	} else if len(encoding) > maxFrameBytes {
		return "too_long"
	}
	return ""
}

var schemas = map[string]schema{
	"json": func(v any) string {
		if _, err := canonicalJSON(v); err != nil {
			return "wrong_type"
		}
		return ""
	},
	"transaction": aTransaction, "vote": aVote, "propose message": aProposeMessage, "certificate": aCertificate,
	"header": aHeader, "block": aBlock, "final block": aFinalBlock, "frame": aFrame,
	"state": aState, "account": anAccount, "genesis": aGenesis,
}

// nestingOf reads the nesting of a JSON text on its bytes: brackets and
// braces outside strings.
func nestingOf(text []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range text {
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			depth++
			deepest = max(deepest, depth)
		case c == ']' || c == '}':
			depth--
		}
	}
	return deepest
}

// receive is what a node does with bytes that come from outside. A genesis
// is read the same way, and has no bound on its length.
func receive(name string, text []byte) string {
	if name == "frame" && len(text) > maxFrameBytes || name == "transaction" && len(text) > maxTransactionBytes {
		return "too_long"
	}
	if nestingOf(text) > maxJSONNesting {
		return "too_deep"
	}
	value, err := decodeCanonical(text)
	if err != nil {
		return "not_canonical"
	}
	return schemas[name](value)
}

// ---------------------------------------------------------------- chapter 2: what is kept
//
// docs/api-stability.md, sections 9.12 to 9.16: the state, the account of
// the state trie, the key registry, the genesis, and what a block does.
// Written from that text. A rule of this chapter is a sentence of the
// document with a check of its own. An object is refused for its form at
// once; when its form is right every rule is looked at, the object that
// breaks one is `inconsistent`, and `broken` names the sentences it breaks:
// a refused vector names the one sentence it is meant to break.

const maxValidators = 1024
const maxGuardians = 8

type sentence struct {
	text  string
	holds func(o map[string]any) bool
}

var (
	broken    []string // the sentences the last object checked breaks
	sentences []string // every sentence of this chapter that this program checks on an object
)

func rule(text string, holds func(o map[string]any) bool) sentence {
	if !has(sentences, text) {
		sentences = append(sentences, text)
	}
	return sentence{text, holds}
}

// judge answers for an object of a schema, with the sentences it breaks.
func judge(name string, v any) (string, []string) {
	broken = nil
	verdict := schemas[name](v)
	return verdict, broken
}

// ruled is an object of chapter 2. Its fields are checked from the last
// name to the first, then the members that are not fields are looked for,
// then every rule is applied, whether an earlier one was broken or not.
func ruled(fields map[string]field, rules ...sentence) schema {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return func(v any) string {
		o, ok := v.(map[string]any)
		if !ok {
			return "wrong_type"
		}
		inconsistent := false
		for _, name := range names {
			value, present := o[name]
			if !present {
				if !fields[name].optional {
					return "missing_field"
				}
				continue
			}
			switch r := fields[name].is(value); r {
			case "":
			case "inconsistent":
				inconsistent = true
			default:
				return r
			}
		}
		for member := range o {
			if _, known := fields[member]; !known {
				return "unknown_field"
			}
		}
		for _, rule := range rules {
			if !rule.holds(o) {
				broken = append(broken, rule.text)
				inconsistent = true
			}
		}
		if inconsistent {
			return "inconsistent"
		}
		return ""
	}
}

// each applies a schema to every value: a form that is refused answers at
// once, and a rule that is broken is remembered until all have been seen.
func each(values []any, item schema) string {
	inconsistent := false
	for _, value := range values {
		switch r := item(value); r {
		case "":
		case "inconsistent":
			inconsistent = true
		default:
			return r
		}
	}
	if inconsistent {
		return "inconsistent"
	}
	return ""
}

// someOf is a list of low to high items; a negative high is any number.
func someOf(item schema, low, high int) schema {
	return func(v any) string {
		list, ok := v.([]any)
		if !ok {
			return "wrong_type"
		}
		if len(list) < low || high >= 0 && len(list) > high {
			return "out_of_range"
		}
		return each(list, item)
	}
}

// tableOf is a map whose names are data; a negative high is any number of
// entries. The names are checked before the values.
func tableOf(name, value schema, low, high int) schema {
	return func(v any) string {
		m, ok := v.(map[string]any)
		if !ok {
			return "wrong_type"
		}
		if len(m) < low || high >= 0 && len(m) > high {
			return "out_of_range"
		}
		values := make([]any, 0, len(m))
		for _, member := range sortedNames(m) {
			if r := name(member); r != "" {
				return r
			}
			values = append(values, m[member])
		}
		return each(values, value)
	}
}

func listAt(o map[string]any, name string) []any         { list, _ := o[name].([]any); return list }
func mapAt(o map[string]any, name string) map[string]any { m, _ := o[name].(map[string]any); return m }
func textAt(o map[string]any, name string) string        { s, _ := o[name].(string); return s }
func levelAt(o map[string]any, name string) uint64       { return uint64(number(o[name])) }
func amountAt(o map[string]any, name string) *big.Int    { return big.NewInt(number(o[name])) }
func objectsOf(list []any) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, item := range list {
		out[i] = item.(map[string]any)
	}
	return out
}

var (
	aPositive   = integer(1, maxInt)
	aPeriod     = integer(1, maxRound)
	someBallots = tableOf(anAddress, oneOf("yes", "no", "abstain"), 0, maxValidators)
	aCode       = anyText(1, maxCodeBytes)
	aNetwork    = hexOf(64)
)

var aContract = ruled(map[string]field{"code": required(aCode), "storage": required(someFields)})

var aKeyEntry = ruled(map[string]field{"from": required(aLevel), "public_key": required(aKey)})

var aValidator = ruled(map[string]field{"address": required(anAddress), "stake": required(aPositive)})

var aTranche = ruled(map[string]field{"level": required(aLevel), "amount": required(aPositive)})

// The tranches of a delegation: their levels grow, and they add up to it.
var tranchesAddUp = rule("`amount` is the sum of the amounts of `tranches`, whose levels grow.",
	func(o map[string]any) bool {
		total := new(big.Int)
		for i, tranche := range objectsOf(listAt(o, "tranches")) {
			if i > 0 && levelAt(tranche, "level") <= levelAt(listAt(o, "tranches")[i-1].(map[string]any), "level") {
				return false
			}
			total.Add(total, amountAt(tranche, "amount"))
		}
		return total.Cmp(amountAt(o, "amount")) == 0
	})

var aDelegation = ruled(map[string]field{
	"validator": required(anAddress), "amount": required(aPositive), "tranches": required(someOf(aTranche, 1, -1)),
}, tranchesAddUp)

var anUnbonding = ruled(map[string]field{
	"delegator": required(anAddress), "validator": required(anAddress), "amount": required(aPositive),
	"tranches": required(someOf(aTranche, 1, -1)), "unbonding_from": required(aLevel), "release_at": required(aLevel),
}, tranchesAddUp)

var anAttestation = ruled(map[string]field{
	"issuer": required(anAddress), "schema_id": required(aSchemaName), "subject": required(aSubject),
	"claim": required(aClaim), "bond": required(anAmount), "issued_at": required(aLevel),
	"revoked_at": optional(aLevel), "slashed": required(boolean),
},
	rule("An attestation that is slashed holds no bond.", func(o map[string]any) bool {
		return o["slashed"] == false || number(o["bond"]) == 0
	}),
	rule("`revoked_at` is not lower than `issued_at`.", func(o map[string]any) bool {
		return !hasMember(o, "revoked_at") || levelAt(o, "revoked_at") >= levelAt(o, "issued_at")
	}))

var aSlashedVote = ruled(map[string]field{
	"validator": required(anAddress), "kind": required(oneOf("preendorse", "endorse")), "level": required(aLevel),
	"round": required(aRound),
})

var aDoubleVote = ruled(map[string]field{
	"voter": required(anAddress), "phase": required(oneOf("exploration", "adoption")), "level": required(aLevel),
	"punished": required(boolean),
})

// The phases of each track before a proposal is over, with the constant
// that gives the length of each, and the two phases in which it is over.
var (
	phasesOf = map[string][][2]string{
		"protocol": {{"submitted", "protocol_proposal_blocks"}, {"exploration", "protocol_exploration_blocks"},
			{"cooldown", "protocol_cooldown_blocks"}, {"adoption", "protocol_adoption_blocks"}},
		"treasury": {{"submitted", "treasury_proposal_blocks"}, {"voting", "treasury_vote_blocks"},
			{"passed", "treasury_release_blocks"}},
	}
	overIn = map[string][2]string{"protocol": {"activated", "rejected"}, "treasury": {"executed", "rejected"}}
	tracks = []string{"treasury", "protocol"}
)

func isOver(track string, proposal map[string]any) bool {
	return textAt(proposal, "phase") == overIn[track][0] || textAt(proposal, "phase") == overIn[track][1]
}

// overOrBonded: a proposal that is over says since when and holds nothing;
// one that is not holds its bond and has no end.
func overOrBonded(track string) sentence {
	return rule(fmt.Sprintf("`ended_at` is present exactly when `phase` is `%s` or `%s`, and `bond` exactly when it is not.",
		overIn[track][0], overIn[track][1]), func(o map[string]any) bool {
		over := isOver(track, o)
		return hasMember(o, "ended_at") == over && hasMember(o, "bond") != over
	})
}

var aProtocolProposal = ruled(map[string]field{
	"proposal_id": required(aHash), "submitter": required(anAddress), "payload": required(aProtocolPayload),
	"submitted_at": required(aLevel), "ended_at": optional(aLevel), "bond": optional(anAmount),
	"phase":             required(oneOf("submitted", "exploration", "cooldown", "adoption", "activated", "rejected")),
	"exploration_votes": required(someBallots), "adoption_votes": required(someBallots),
	"double_votes": required(someOf(aDoubleVote, 0, 2*maxValidators)),
},
	rule("A voter has one double vote in a phase at most, and a vote in that phase.", func(o map[string]any) bool {
		seen := map[[2]string]bool{}
		for _, double := range objectsOf(listAt(o, "double_votes")) {
			pair := [2]string{textAt(double, "phase"), textAt(double, "voter")}
			if seen[pair] || !hasMember(mapAt(o, pair[0]+"_votes"), pair[1]) {
				return false
			}
			seen[pair] = true
		}
		return true
	}),
	overOrBonded("protocol"))

var aTreasuryProposal = ruled(map[string]field{
	"proposal_id": required(aHash), "submitter": required(anAddress), "payload": required(aTreasuryPayload),
	"submitted_at": required(aLevel), "ended_at": optional(aLevel), "bond": optional(anAmount),
	"phase": required(oneOf("submitted", "voting", "passed", "executed", "rejected")), "votes": required(someBallots),
	"released_by": optional(anAddress),
},
	// A guardian other than the first has released a payment that still waits, and no other proposal.
	rule("`released_by` is present only when `phase` is `passed`.", func(o map[string]any) bool {
		return !hasMember(o, "released_by") || textAt(o, "phase") == "passed"
	}),
	overOrBonded("treasury"))

var theGovernance = ruled(map[string]field{
	"protocol": required(someOf(aProtocolProposal, 0, -1)), "treasury": required(someOf(aTreasuryProposal, 0, -1)),
})

// The ten parameters of a proposal, each with the range it has there, and
// all of them present.
var theParameters = ruled(map[string]field{
	"i_min_ppm": required(integer(0, 1000000)), "i_max_ppm": required(integer(0, 1000000)),
	"target_staking_ratio_ppm": required(integer(0, 1000000)), "target_block_time_ms": required(integer(1, 3600000)),
	"treasury_share_ppm": required(integer(0, 1000000)), "proposer_bonus_ppm": required(integer(0, 1000000)),
	"fee_floor_enabled": required(boolean), "fee_floor_base": required(integer(0, 1000000000000)),
	"fee_floor_per_byte": required(integer(0, 1000000000)),
	"max_block_bytes":    required(integer(maxTransactionBytes, maxBlockBytes)),
}, rule("`i_min_ppm` is not above `i_max_ppm`.", func(o map[string]any) bool {
	return number(o["i_min_ppm"]) <= number(o["i_max_ppm"])
}))

var theConstants = ruled(map[string]field{
	"epoch_blocks": required(aPeriod), "delegation_unbonding_blocks": required(aPeriod),
	"attestation_unbonding_blocks": required(integer(0, maxRound)),
	"protocol_proposal_blocks":     required(aPeriod), "protocol_exploration_blocks": required(aPeriod),
	"protocol_cooldown_blocks": required(aPeriod), "protocol_adoption_blocks": required(aPeriod),
	"treasury_proposal_blocks": required(aPeriod), "treasury_vote_blocks": required(aPeriod),
	"guardian_delay_blocks": required(aPeriod), "treasury_release_blocks": required(aPeriod),
	"protocol_bond": required(anAmount), "treasury_bond": required(anAmount),
},
	// Past the delay the other guardians can release a payment: the delay ends with the wait at the latest.
	rule("`guardian_delay_blocks` is not above `treasury_release_blocks`.", func(o map[string]any) bool {
		return number(o["guardian_delay_blocks"]) <= number(o["treasury_release_blocks"])
	}),
	rule("`delegation_unbonding_blocks` is not lower than `epoch_blocks`.", func(o map[string]any) bool {
		return number(o["delegation_unbonding_blocks"]) >= number(o["epoch_blocks"])
	}))

// endsOf gives the level at which each phase of a proposal ends. A level
// and six periods stay under 2^64, so the sums are made without a sign.
func endsOf(track string, proposal, constants map[string]any) map[string]uint64 {
	ends, level := map[string]uint64{}, levelAt(proposal, "submitted_at")
	for _, phase := range phasesOf[track] {
		level += levelAt(constants, phase[1])
		ends[phase[0]] = level
	}
	return ends
}

// proposalsOf lists the proposals of a state, each with its track.
type tracked struct {
	track    string
	proposal map[string]any
}

func proposalsOf(state map[string]any) []tracked {
	var out []tracked
	for _, track := range tracks {
		for _, proposal := range objectsOf(listAt(mapAt(state, "governance"), track)) {
			out = append(out, tracked{track, proposal})
		}
	}
	return out
}

func validatorsOf(state map[string]any) map[string]bool {
	listed := map[string]bool{}
	for _, validator := range objectsOf(listAt(state, "validators")) {
		listed[textAt(validator, "address")] = true
	}
	return listed
}

func keyBytes(entry any) []byte {
	return bytesOf(entry.(map[string]any), "public_key", "kpk1.", 1984)
}

// everythingIn adds up what exists in a state: what accounts hold and what
// is bonded. Each amount fits 63 bits and their sum may not: it is made
// without a bound.
func everythingIn(state map[string]any) *big.Int {
	total := new(big.Int)
	for _, balance := range mapAt(state, "balances") {
		total.Add(total, big.NewInt(number(balance)))
	}
	for _, validator := range objectsOf(listAt(state, "validators")) {
		total.Add(total, amountAt(validator, "stake"))
	}
	for _, delegation := range mapAt(state, "delegations") {
		total.Add(total, amountAt(delegation.(map[string]any), "amount"))
	}
	for _, leaving := range objectsOf(listAt(state, "delegation_unbonding")) {
		total.Add(total, amountAt(leaving, "amount"))
	}
	for _, attestation := range mapAt(state, "attestations") {
		total.Add(total, amountAt(attestation.(map[string]any), "bond"))
	}
	for _, p := range proposalsOf(state) {
		if hasMember(p.proposal, "bond") {
			total.Add(total, amountAt(p.proposal, "bond"))
		}
	}
	return total
}

var aState = ruled(map[string]field{
	"level": required(aLevel), "chain_id": required(aChain), "state_root_function": required(oneOf("json", "trie")),
	"total_supply": required(anAmount), "treasury_address": required(anAddress),
	"guardians": required(someOf(anAddress, 3, maxGuardians)),
	"balances":  required(tableOf(anAddress, aPositive, 0, -1)), "nonces": required(tableOf(anAddress, aPositive, 0, -1)),
	"contracts":  required(tableOf(anAddress, aContract, 0, -1)),
	"keys":       required(tableOf(anAddress, someOf(aKeyEntry, 1, -1), 0, -1)),
	"validators": required(someOf(aValidator, 1, maxValidators)), "consensus_set": required(someOf(aValidator, 1, maxValidators)),
	"delegations":          required(tableOf(anAddress, aDelegation, 0, -1)),
	"delegation_unbonding": required(someOf(anUnbonding, 0, -1)),
	"attestations":         required(tableOf(aHash, anAttestation, 0, -1)),
	"consensus_slashes":    required(someOf(aSlashedVote, 0, -1)), "governance": required(theGovernance),
	"parameters": required(theParameters), "constants": required(theConstants),
},
	// Votes.
	// A double vote has no check of its own here: its voter has a vote in the same phase.
	rule("A vote and a slashed vote are those of a validator.", func(s map[string]any) bool {
		listed := validatorsOf(s)
		for _, p := range proposalsOf(s) {
			for _, votes := range []string{"votes", "exploration_votes", "adoption_votes"} {
				for voter := range mapAt(p.proposal, votes) {
					if !listed[voter] {
						return false
					}
				}
			}
		}
		for _, vote := range objectsOf(listAt(s, "consensus_slashes")) {
			if !listed[textAt(vote, "validator")] {
				return false
			}
		}
		return true
	}),
	// Proposals.
	rule("A proposal that is over ended less than `delegation_unbonding_blocks` levels before `level`.",
		func(s map[string]any) bool {
			for _, p := range proposalsOf(s) {
				if isOver(p.track, p.proposal) && hasMember(p.proposal, "ended_at") &&
					levelAt(p.proposal, "ended_at")+levelAt(mapAt(s, "constants"), "delegation_unbonding_blocks") <= levelAt(s, "level") {
					return false
				}
			}
			return true
		}),
	// A vote rejects a treasury proposal at the level at which it ends. A payment that passed ends later: a
	// guardian releases or cancels it in a block that follows, or its wait ends.
	rule("A protocol proposal that is over ended when a vote did: at the end of `adoption` if it is activated, of "+
		"`exploration` or of `adoption` if it is rejected. A treasury proposal that is over ended at the end of "+
		"`voting` or while it waited: after the end of `voting` if it is executed, and not after the end of `passed`.",
		func(s map[string]any) bool {
			for _, p := range proposalsOf(s) {
				if !isOver(p.track, p.proposal) || !hasMember(p.proposal, "ended_at") {
					continue
				}
				ends, ended := endsOf(p.track, p.proposal, mapAt(s, "constants")), levelAt(p.proposal, "ended_at")
				rejected := textAt(p.proposal, "phase") == "rejected"
				switch {
				case p.track == "treasury" && ended > ends["passed"]:
					return false
				case p.track == "treasury" && (ended > ends["voting"] || ended == ends["voting"] && rejected):
				case p.track == "protocol" && ended == ends["adoption"]:
				case p.track == "protocol" && ended == ends["exploration"] && rejected:
				default:
					return false
				}
			}
			return true
		}),
	// Payments that wait.
	rule("When `released_by` is present, the end of `voting` plus `guardian_delay_blocks` is not above `level`.",
		func(s map[string]any) bool {
			constants := mapAt(s, "constants")
			for _, payment := range objectsOf(listAt(mapAt(s, "governance"), "treasury")) {
				if hasMember(payment, "released_by") &&
					endsOf("treasury", payment, constants)["voting"]+levelAt(constants, "guardian_delay_blocks") > levelAt(s, "level") {
					return false
				}
			}
			return true
		}),
	rule("`released_by` is a guardian other than the first.", func(s map[string]any) bool {
		for _, payment := range objectsOf(listAt(mapAt(s, "governance"), "treasury")) {
			if !hasMember(payment, "released_by") {
				continue
			}
			another := false
			for i, guardian := range listAt(s, "guardians") {
				another = another || i > 0 && guardian == payment["released_by"]
			}
			if !another {
				return false
			}
		}
		return true
	}),
	rule("A proposal that is not over is in the phase of its level: that phase started at `level` or before, and ends "+
		"above it.", func(s map[string]any) bool {
		for _, p := range proposalsOf(s) {
			if isOver(p.track, p.proposal) {
				continue
			}
			ends, started := endsOf(p.track, p.proposal, mapAt(s, "constants")), levelAt(p.proposal, "submitted_at")
			for _, phase := range phasesOf[p.track] {
				if phase[0] == textAt(p.proposal, "phase") {
					break
				}
				started = ends[phase[0]]
			}
			if started > levelAt(s, "level") || ends[textAt(p.proposal, "phase")] <= levelAt(s, "level") {
				return false
			}
		}
		return true
	}),
	rule("The bond of a proposal is `protocol_bond` or `treasury_bond`, as its track says.", func(s map[string]any) bool {
		for _, p := range proposalsOf(s) {
			if hasMember(p.proposal, "bond") && number(p.proposal["bond"]) != number(mapAt(s, "constants")[p.track+"_bond"]) {
				return false
			}
		}
		return true
	}),
	rule("The proposals of a track are in the order of their submission, and no two have the same `proposal_id`.",
		func(s map[string]any) bool {
			for _, track := range tracks {
				seen, last := map[string]bool{}, uint64(0)
				for _, proposal := range objectsOf(listAt(mapAt(s, "governance"), track)) {
					if seen[textAt(proposal, "proposal_id")] || levelAt(proposal, "submitted_at") < last {
						return false
					}
					seen[textAt(proposal, "proposal_id")], last = true, levelAt(proposal, "submitted_at")
				}
			}
			return true
		}),
	// What is due.
	rule("No two slashed votes are of the same validator, kind, level and round, and none is "+
		"`delegation_unbonding_blocks` levels old or more.", func(s map[string]any) bool {
		seen := map[string]bool{}
		for _, vote := range objectsOf(listAt(s, "consensus_slashes")) {
			offence := string(without(vote))
			if seen[offence] || levelAt(vote, "level")+levelAt(mapAt(s, "constants"), "delegation_unbonding_blocks") <= levelAt(s, "level") {
				return false
			}
			seen[offence] = true
		}
		return true
	}),
	rule("An attestation revoked `attestation_unbonding_blocks` levels before `level`, or earlier, holds no bond.",
		func(s map[string]any) bool {
			for _, value := range mapAt(s, "attestations") {
				attestation := value.(map[string]any)
				if hasMember(attestation, "revoked_at") && number(attestation["bond"]) != 0 &&
					levelAt(attestation, "revoked_at")+levelAt(mapAt(s, "constants"), "attestation_unbonding_blocks") <= levelAt(s, "level") {
					return false
				}
			}
			return true
		}),
	rule("A delegation that is unbonding is released `delegation_unbonding_blocks` levels after `unbonding_from`, at a "+
		"level above `level`, and the list is in the order in which the delegations ended.", func(s map[string]any) bool {
		last := uint64(0)
		for _, leaving := range objectsOf(listAt(s, "delegation_unbonding")) {
			from, release := levelAt(leaving, "unbonding_from"), levelAt(leaving, "release_at")
			if from < last || release <= levelAt(s, "level") ||
				release != from+levelAt(mapAt(s, "constants"), "delegation_unbonding_blocks") {
				return false
			}
			last = from
		}
		return true
	}),
	rule("Nothing happened after `level`: the level of a tranche, `unbonding_from`, `issued_at`, `revoked_at`, the level "+
		"of a slashed vote, `ended_at` and the level of a double vote are not above it.", func(s map[string]any) bool {
		var levels []any
		tranches := func(holding map[string]any) {
			for _, tranche := range objectsOf(listAt(holding, "tranches")) {
				levels = append(levels, tranche["level"])
			}
		}
		for _, delegation := range mapAt(s, "delegations") {
			tranches(delegation.(map[string]any))
		}
		for _, leaving := range objectsOf(listAt(s, "delegation_unbonding")) {
			tranches(leaving)
			levels = append(levels, leaving["unbonding_from"])
		}
		for _, attestation := range mapAt(s, "attestations") {
			levels = append(levels, attestation.(map[string]any)["issued_at"], attestation.(map[string]any)["revoked_at"])
		}
		for _, vote := range objectsOf(listAt(s, "consensus_slashes")) {
			levels = append(levels, vote["level"])
		}
		for _, p := range proposalsOf(s) {
			levels = append(levels, p.proposal["ended_at"])
			for _, double := range objectsOf(listAt(p.proposal, "double_votes")) {
				levels = append(levels, double["level"])
			}
		}
		for _, level := range levels {
			if level != nil && number(level) > number(s["level"]) {
				return false
			}
		}
		return true
	}),
	// Stakes and supply.
	rule("A delegation names a validator other than its delegator, and so does a delegation that is unbonding.",
		func(s map[string]any) bool {
			listed := validatorsOf(s)
			for delegator, delegation := range mapAt(s, "delegations") {
				if to := textAt(delegation.(map[string]any), "validator"); !listed[to] || to == delegator {
					return false
				}
			}
			for _, leaving := range objectsOf(listAt(s, "delegation_unbonding")) {
				if to := textAt(leaving, "validator"); !listed[to] || to == textAt(leaving, "delegator") {
					return false
				}
			}
			return true
		}),
	rule("`total_supply` is the sum of `balances`, of the stakes of `validators`, of the amounts of `delegations` and of "+
		"`delegation_unbonding`, of the bonds of `attestations` and of the bonds of the proposals of `governance`.",
		func(s map[string]any) bool { return everythingIn(s).Cmp(amountAt(s, "total_supply")) == 0 }),
	// Keys.
	rule("A key stands once in `keys`, and no key of an address has the ML-DSA part or the Ed25519 part of an earlier "+
		"key of that address.", func(s map[string]any) bool {
		recorded := map[string]bool{}
		for _, entries := range mapAt(s, "keys") {
			first, second := map[string]bool{}, map[string]bool{}
			for _, entry := range entries.([]any) {
				key := keyBytes(entry)
				mldsa, ed25519 := string(key[:1952]), string(key[1952:])
				if recorded[string(key)] || first[mldsa] || second[ed25519] {
					return false
				}
				recorded[string(key)], first[mldsa], second[ed25519] = true, true, true
			}
		}
		return true
	}),
	rule("The first key of an address is the key whose hash is that address.", func(s map[string]any) bool {
		for address, entries := range mapAt(s, "keys") {
			if hashed, _ := accountAddress(schemaNetwork, keyBytes(entries.([]any)[0])); hashed != address {
				return false
			}
		}
		return true
	}),
	rule("In `keys`, the levels `from` of an address grow, and none is above `level` plus 1.", func(s map[string]any) bool {
		for _, entries := range mapAt(s, "keys") {
			for i, entry := range objectsOf(entries.([]any)) {
				from := levelAt(entry, "from")
				if from > levelAt(s, "level")+1 || i > 0 && from <= levelAt(entries.([]any)[i-1].(map[string]any), "from") {
					return false
				}
			}
		}
		return true
	}),
	rule("Every address of `nonces` is in `keys`, and every address of `keys` is in `nonces` or is a validator.",
		func(s map[string]any) bool {
			listed := validatorsOf(s)
			for address := range mapAt(s, "keys") {
				if !hasMember(mapAt(s, "nonces"), address) && !listed[address] {
					return false
				}
			}
			for address := range mapAt(s, "nonces") {
				if !hasMember(mapAt(s, "keys"), address) {
					return false
				}
			}
			return true
		}),
	// A contract has no key, and so no nonce: an address that has sent a transaction has a key.
	rule("An address of `contracts` is not in `keys`.", func(s map[string]any) bool {
		for address := range mapAt(s, "contracts") {
			if hasMember(mapAt(s, "keys"), address) {
				return false
			}
		}
		return true
	}),
	// The guardians sign, so each is an account; none is a validator, whose key signs at every block.
	rule("A guardian is not `treasury_address`, an address of `contracts` or a validator.", func(s map[string]any) bool {
		listed := validatorsOf(s)
		for _, guardian := range listAt(s, "guardians") {
			address, _ := guardian.(string)
			if address == textAt(s, "treasury_address") || hasMember(mapAt(s, "contracts"), address) || listed[address] {
				return false
			}
		}
		return true
	}),
	rule("`guardians` holds an address once.", func(s map[string]any) bool {
		seen := map[any]bool{}
		for _, guardian := range listAt(s, "guardians") {
			if seen[guardian] {
				return false
			}
			seen[guardian] = true
		}
		return true
	}),
	// The treasury: nobody signs for its address, so that only a payment voted and released moves what it holds.
	rule("`treasury_address` is not in `keys`.", func(s map[string]any) bool {
		return !hasMember(mapAt(s, "keys"), textAt(s, "treasury_address"))
	}),
	// Validators.
	rule("Every validator has a key in `keys`.", func(s map[string]any) bool {
		for address := range validatorsOf(s) {
			if !hasMember(mapAt(s, "keys"), address) {
				return false
			}
		}
		return true
	}),
	rule("The weight of a validator in `consensus_set` is not above its stake plus the amounts delegated to it.",
		func(s map[string]any) bool {
			backing := map[string]*big.Int{}
			for _, validator := range objectsOf(listAt(s, "validators")) {
				if _, twice := backing[textAt(validator, "address")]; !twice {
					backing[textAt(validator, "address")] = amountAt(validator, "stake")
				}
			}
			for _, delegation := range mapAt(s, "delegations") {
				if behind, ok := backing[textAt(delegation.(map[string]any), "validator")]; ok {
					behind.Add(behind, amountAt(delegation.(map[string]any), "amount"))
				}
			}
			for _, weighed := range objectsOf(listAt(s, "consensus_set")) {
				if behind, ok := backing[textAt(weighed, "address")]; ok && amountAt(weighed, "stake").Cmp(behind) > 0 {
					return false
				}
			}
			return true
		}),
	rule("`validators` holds an address once, and `consensus_set` holds the same addresses in the same order.",
		func(s map[string]any) bool {
			listed, weighed := objectsOf(listAt(s, "validators")), objectsOf(listAt(s, "consensus_set"))
			if len(listed) != len(weighed) || len(validatorsOf(s)) != len(listed) {
				return false
			}
			for i := range listed {
				if textAt(listed[i], "address") != textAt(weighed[i], "address") {
					return false
				}
			}
			return true
		}))

var anAccount = ruled(map[string]field{
	"balance": required(anAmount), "nonce": required(integer(0, maxInt)), "code_hash": optional(aHash),
	"storage_root": optional(aHash),
}, rule("`code_hash` and `storage_root` are present together.", func(o map[string]any) bool {
	return hasMember(o, "code_hash") == hasMember(o, "storage_root")
}))

var theGenesis = ruled(map[string]field{
	"version": required(integer(1, 1)), "scheme": required(integer(1, 1)), "network_id": required(aNetwork),
	"timestamp": required(integer(0, maxInt)), "state": required(aState),
},
	rule("`consensus_set` is `validators`.", func(g map[string]any) bool {
		return bytes.Equal(without(map[string]any{"is": mapAt(g, "state")["consensus_set"]}),
			without(map[string]any{"is": mapAt(g, "state")["validators"]}))
	}),
	rule("Each validator has one key, current from level 0.", func(g map[string]any) bool {
		state := mapAt(g, "state")
		for address := range validatorsOf(state) {
			// Every key of a validator is current from level 0: there is then one only, since the levels grow.
			entries, _ := mapAt(state, "keys")[address].([]any)
			for _, entry := range objectsOf(entries) {
				if levelAt(entry, "from") != 0 {
					return false
				}
			}
		}
		return true
	}),
	rule("`nonces`, `contracts`, `delegations`, `delegation_unbonding`, `attestations`, `consensus_slashes` and the two "+
		"lists of `governance` are empty.", func(g map[string]any) bool {
		state := mapAt(g, "state")
		return len(mapAt(state, "nonces"))+len(mapAt(state, "contracts"))+len(mapAt(state, "delegations"))+
			len(listAt(state, "delegation_unbonding"))+len(mapAt(state, "attestations"))+
			len(listAt(state, "consensus_slashes"))+len(proposalsOf(state)) == 0
	}),
	rule("The `level` of `state` is 0.", func(g map[string]any) bool { return number(mapAt(g, "state")["level"]) == 0 }))

// aGenesis is read on the network it names: that identifier is in the
// checksum of every address of its state, whatever network the reader
// had in mind.
func aGenesis(v any) string {
	o, ok := v.(map[string]any)
	if !ok {
		return "wrong_type"
	}
	reader := schemaNetwork
	defer func() { schemaNetwork = reader }()
	if named, present := o["network_id"]; present {
		if r := aNetwork(named); r != "" {
			return r
		}
		schemaNetwork = unhex(named.(string))
	}
	return theGenesis(v)
}

// accountsOf gives the accounts of a state as the state trie holds them:
// one for each address of balances, nonces or contracts.
func accountsOf(network []byte, state map[string]any) map[string]any {
	accounts := map[string]any{}
	for _, name := range accountMaps {
		for address := range mapAt(state, name) {
			accounts[address] = accountObject(network, state, address)
		}
	}
	return accounts
}

// firstHeader gives the nine fields of the block of level 0, which a node
// computes from its genesis, in canonical JSON, and the hash of that block.
func firstHeader(genesis map[string]any) ([]byte, string) {
	network, state := unhex(textAt(genesis, "network_id")), mapAt(genesis, "state")
	nothing := hex.EncodeToString(merkleRoot(network, nil))
	fields, err := canonicalJSON(map[string]any{
		"version": json.Number("1"), "level": json.Number("0"), "payload_round": json.Number("0"),
		"timestamp": genesis["timestamp"], "parent_hash": strings.Repeat("0", 96),
		"state_root": hex.EncodeToString(h("kern.state", network, hashedState(network, state))),
		"txs_root":   nothing, "witness_root": nothing,
		"proposer": textAt(listAt(state, "validators")[0].(map[string]any), "address"),
	})
	if err != nil {
		panic(err)
	}
	return fields, hex.EncodeToString(h("kern.block", network, fields))
}

// ------------------------------------------------- what a block charges

// chargeBlock applies a block of transfers to the balances and the nonces
// of a state, and gives what it leaves, or the rule that makes the block
// invalid and the position of the transaction that breaks it (-1 when the
// rule is about the block as a whole). For each transaction the fee is
// looked at first, then the nonce, the chain, the floor and the sender,
// which is never the treasury address, and the size of the block last: a
// vector breaks one rule, so the order gives one answer.
func chargeBlock(state map[string]any, proposer string, transactions []any) (map[string]any, string, int) {
	parameters := mapAt(state, "parameters")
	balances, nonces := map[string]*big.Int{}, map[string]uint64{}
	for address, balance := range mapAt(state, "balances") {
		balances[address] = big.NewInt(number(balance))
	}
	for address, nonce := range mapAt(state, "nonces") {
		nonces[address] = uint64(number(nonce))
	}
	move := func(address string, by *big.Int) {
		if _, holds := balances[address]; !holds {
			balances[address] = new(big.Int)
		}
		balances[address].Add(balances[address], by)
	}
	held := func(address string) *big.Int {
		if balance, holds := balances[address]; holds {
			return balance
		}
		return new(big.Int)
	}
	failed, size := []any{}, 0
	for i, raw := range transactions {
		tx := raw.(map[string]any)
		sender, fee, amount := textAt(tx, "sender"), amountAt(tx, "fee"), amountAt(tx, "amount")
		if held(sender).Cmp(fee) < 0 {
			return nil, "unpaid_fee", i
		}
		// The nonce is the number of transactions of the sender applied so far, and the last one a state can
		// hold is 2^63 - 1: a sender that has reached it sends nothing more.
		if levelAt(tx, "nonce") != nonces[sender] || nonces[sender] == maxInt {
			return nil, "wrong_nonce", i
		}
		if textAt(tx, "chain_id") != textAt(state, "chain_id") {
			return nil, "wrong_chain", i
		}
		floor := number(parameters["fee_floor_base"]) + number(parameters["fee_floor_per_byte"])*int64(transactionSize(tx))
		if parameters["fee_floor_enabled"] == true && fee.Cmp(big.NewInt(floor)) < 0 {
			return nil, "fee_under_floor", i
		}
		if sender == textAt(state, "treasury_address") {
			return nil, "sent_by_treasury", i
		}
		size += transactionSize(tx)
		move(sender, new(big.Int).Neg(fee))
		move(proposer, fee)
		nonces[sender]++
		if held(sender).Cmp(amount) < 0 {
			failed = append(failed, json.Number(strconv.Itoa(i))) // it stays in the block, and has paid
			continue
		}
		move(sender, new(big.Int).Neg(amount))
		move(textAt(tx, "recipient"), amount)
	}
	if int64(size) > number(parameters["max_block_bytes"]) {
		return nil, "block_too_large", -1
	}
	left, taken := map[string]any{}, map[string]any{}
	for address, balance := range balances {
		if balance.Sign() != 0 { // a balance of zero is not written
			left[address] = json.Number(balance.String())
		}
	}
	for address, nonce := range nonces {
		taken[address] = json.Number(strconv.FormatUint(nonce, 10))
	}
	return map[string]any{"balances": left, "nonces": taken, "failed": failed}, "", -1
}

// ------------------------------------------------- deciding proposals

// decideAll settles the proposals that are decided at a level: the
// protocol track, then the treasury track, each list in its order, and
// each proposal entirely before the next one is looked at. Nothing is paid
// here: a treasury proposal whose vote passes waits for a guardian.
func decideAll(before map[string]any, protocol, treasury []any) map[string]any {
	parameters := map[string]any{}
	for name, value := range mapAt(before, "parameters") {
		parameters[name] = value
	}
	function, holds, burned := before["state_root_function"], amountAt(before, "treasury"), new(big.Int)
	two := big.NewInt(2)
	lose := func(bond *big.Int) {
		half := new(big.Int).Quo(bond, two) // rounded down
		burned.Add(burned, half)
		holds.Add(holds, new(big.Int).Sub(bond, half))
	}
	phases := map[string][]any{"protocol": {}, "treasury": {}}
	for _, proposal := range objectsOf(protocol) {
		payload := mapAt(proposal, "payload")
		lowest, highest := parameters["i_min_ppm"], parameters["i_max_ppm"]
		if set, ok := mapAt(payload, "params")["i_min_ppm"]; ok {
			lowest = set
		}
		if set, ok := mapAt(payload, "params")["i_max_ppm"]; ok {
			highest = set
		}
		if proposal["passes"] != true || number(lowest) > number(highest) {
			lose(amountAt(before, "protocol_bond"))
			phases["protocol"] = append(phases["protocol"], "rejected")
			continue
		}
		for name, value := range mapAt(payload, "params") {
			parameters[name] = value
		}
		if hasMember(payload, "swap") {
			function = payload["to"]
		}
		phases["protocol"] = append(phases["protocol"], "activated")
	}
	for _, proposal := range objectsOf(treasury) {
		// A vote that fails rejects a proposal, and so does a wait that ends: only a vote that passes is left.
		if textAt(proposal, "phase") != "voting" || proposal["passes"] != true {
			lose(amountAt(before, "treasury_bond"))
			phases["treasury"] = append(phases["treasury"], "rejected")
			continue
		}
		phases["treasury"] = append(phases["treasury"], "passed")
	}
	return map[string]any{"protocol": phases["protocol"], "treasury": phases["treasury"], "parameters": parameters,
		"state_root_function": function, "treasury_holds": json.Number(holds.String()), "burned": json.Number(burned.String())}
}

// ------------------------------------------------- what a guardian does

// guardianRules are the rules an operation of a guardian keeps, in the
// order of the document: a vector names the first one that is broken.
var guardianRules = []string{"not_a_guardian", "not_waiting", "not_the_first", "too_early", "released_twice", "unfunded"}

// guardBlock applies the transactions of guardians of one block to the
// payments that wait. Every rule is looked at on its own for each
// operation; an operation that breaks one fails, and changes nothing.
func guardBlock(before map[string]any, operations []any) map[string]any {
	guardians := listAt(before, "guardians")
	level, delay := levelAt(before, "level"), levelAt(before, "guardian_delay_blocks")
	bond, holds, burned := amountAt(before, "treasury_bond"), amountAt(before, "treasury"), new(big.Int)
	payments := map[string]map[string]any{}
	for name, payment := range mapAt(before, "payments") {
		copied := map[string]any{}
		for member, value := range payment.(map[string]any) {
			copied[member] = value
		}
		payments[name] = copied
	}
	did := []any{}
	for _, operation := range objectsOf(operations) {
		sender, release := textAt(operation, "sender"), textAt(operation, "kind") == "release_payment"
		payment, known := payments[textAt(operation, "proposal_id")]
		waits := known && textAt(payment, "phase") == "passed"
		place := -1 // where the sender stands among the guardians: 0 is the first
		for i, guardian := range guardians {
			if guardian == sender && place < 0 {
				place = i
			}
		}
		another := place > 0
		late := waits && level >= levelAt(payment, "voted")+delay
		recorded, _ := payment["released_by"].(string)
		// A release pays when the first guardian sends it, or when a second one of the others does.
		pays := release && waits && (place == 0 || another && late && recorded != "" && recorded != sender)
		breaks := map[string]bool{
			"not_a_guardian": place < 0,
			"not_waiting":    !waits,
			"not_the_first":  !release && place != 0,
			"too_early":      release && another && waits && !late,
			"released_twice": release && another && waits && recorded == sender,
			"unfunded":       pays && amountAt(payment, "total").Cmp(holds) > 0,
		}
		failed := ""
		for _, name := range guardianRules {
			if breaks[name] && failed == "" {
				failed = name
			}
		}
		switch {
		case failed != "":
			did = append(did, failed)
		case !release: // cancelled: its bond goes where the bond of a rejected proposal goes
			half := new(big.Int).Quo(bond, big.NewInt(2))
			burned.Add(burned, half)
			holds.Add(holds, new(big.Int).Sub(bond, half))
			payment["phase"] = "rejected"
			delete(payment, "released_by")
			did = append(did, "cancelled")
		case pays:
			holds.Sub(holds, amountAt(payment, "total"))
			holds.Add(holds, amountAt(payment, "to_itself")) // what the treasury pays itself is still there
			payment["phase"] = "executed"
			delete(payment, "released_by")
			did = append(did, "paid")
		default: // the first release of a guardian other than the first
			payment["released_by"] = sender
			did = append(did, "recorded")
		}
	}
	after := map[string]any{}
	for name, payment := range payments {
		left := map[string]any{"phase": payment["phase"]}
		if released, present := payment["released_by"]; present {
			left["released_by"] = released
		}
		after[name] = left
	}
	return map[string]any{"did": did, "treasury_holds": json.Number(holds.String()),
		"burned": json.Number(burned.String()), "payments": after}
}

// ------------------------------------------------- one request at a time

// exchangeOn follows a connection as the node that asks for blocks sees
// it: a request it would send, a blocks frame it receives, or four bytes
// it reads before a frame.
func exchangeOn(steps []any) []string {
	var verdicts []string
	var waiting []int64 // the first and the last level of the request that waits
	closed := false
	for _, step := range objectsOf(steps) {
		switch {
		case closed:
			verdicts = append(verdicts, "closed")
		case hasMember(step, "prefix"):
			if _, refused := announcedBy(unhex(textAt(step, "prefix"))); refused != "" {
				closed = true
				verdicts = append(verdicts, "refused")
			} else {
				verdicts = append(verdicts, "accepted")
			}
		case hasMember(step, "blocks"):
			var levels []int64
			for _, level := range listAt(step, "blocks") {
				levels = append(levels, number(level))
			}
			if waiting == nil || answerRule(waiting[0], waiting[1], levels) != "" {
				verdicts = append(verdicts, "refused")
			} else {
				waiting = nil
				verdicts = append(verdicts, "accepted")
			}
		case waiting != nil: // a request, while one waits
			verdicts = append(verdicts, "refused")
		default:
			waiting = []int64{number(listAt(step, "ask")[0]), number(listAt(step, "ask")[1])}
			verdicts = append(verdicts, "accepted")
		}
	}
	return verdicts
}

// ---------------------------------------------------------------- the vectors of the schemas

func fillerOf(what string, n int64, length int) []byte {
	return sha3.SumSHAKE256([]byte(fmt.Sprintf("kern schema vectors, %s %d", what, n)), length)
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for name, inner := range t {
			out[name] = deepCopy(inner)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, inner := range t {
			out[i] = deepCopy(inner)
		}
		return out
	}
	return v
}

type schemaVectors struct {
	objects map[string]any // accepted vectors, by name, directives carried out
}

// expand carries out the directives of a value of the file.
func (s *schemaVectors) expand(v any, index int64) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = s.expand(item, index)
		}
		return out
	case map[string]any:
		if len(t) == 1 {
			for name, argument := range t {
				if strings.HasPrefix(name, "$") {
					return s.directive(name, argument, index)
				}
			}
		}
		out := make(map[string]any, len(t))
		for name, item := range t {
			out[name] = s.expand(item, index)
		}
		return out
	}
	return v
}

func (s *schemaVectors) directive(name string, argument any, index int64) any {
	count := func(v any) int64 { return number(s.expand(v, index)) }
	switch name {
	case "$ref":
		object, known := s.objects[argument.(string)]
		if !known {
			panic("no accepted vector named " + argument.(string))
		}
		return deepCopy(object)
	case "$index":
		return json.Number(strconv.FormatInt(index+number(argument), 10))
	case "$key":
		return textOf("kpk1.", fillerOf("key", count(argument), 1984))
	case "$sig":
		return textOf("ksig1.", fillerOf("signature", count(argument), 3373))
	case "$address":
		return addressFromHash(schemaNetwork, fillerOf("address", count(argument), 48))
	case "$account":
		address, _ := accountAddress(schemaNetwork, fillerOf("key", count(argument), 1984))
		return address
	case "$key_of_parts":
		parts := argument.([]any)
		first, second := fillerOf("key", count(parts[0]), 1984), fillerOf("key", count(parts[1]), 1984)
		return textOf("kpk1.", join(first[:1952], second[1952:]))
	case "$canonical":
		encoding, err := canonicalJSON(s.expand(argument, index))
		if err != nil {
			panic(err)
		}
		return string(encoding)
	case "$text":
		parts := argument.([]any)
		return strings.Repeat(parts[1].(string), int(number(parts[0])))
	case "$concat":
		var out strings.Builder
		for _, part := range argument.([]any) {
			switch piece := s.expand(part, index).(type) {
			case string:
				out.WriteString(piece)
			case json.Number:
				out.WriteString(piece.String())
			default:
				panic("a part that is neither a text nor an integer")
			}
		}
		return out.String()
	case "$list":
		parts := argument.([]any)
		out := make([]any, number(parts[0]))
		for i := range out {
			out[i] = s.expand(parts[1], int64(i))
		}
		return out
	case "$map":
		parts := argument.([]any)
		out := map[string]any{}
		for i := int64(0); i < number(parts[0]); i++ {
			out[s.expand(parts[1], i).(string)] = s.expand(parts[2], i)
		}
		return out
	}
	panic("unknown directive " + name)
}

// locate follows a path to the array or object that holds its last step.
func locate(v any, path string) (any, string) {
	steps := strings.Split(path, ".")
	for _, step := range steps[:len(steps)-1] {
		switch t := v.(type) {
		case []any:
			i, _ := strconv.Atoi(step)
			v = t[i]
		case map[string]any:
			v = t[step]
		}
	}
	return v, steps[len(steps)-1]
}

// put replaces what stands at a path, in a copy; a position one past the
// end of a list adds an item. The empty path is the value itself.
func put(v any, path string, value any) any {
	if path == "" {
		return value
	}
	steps := strings.Split(path, ".")
	return putAt(v, steps, value)
}

func putAt(v any, steps []string, value any) any {
	switch t := v.(type) {
	case []any:
		i, _ := strconv.Atoi(steps[0])
		out := append([]any{}, t...)
		if i == len(out) {
			out = append(out, nil)
		}
		if len(steps) == 1 {
			out[i] = value
		} else {
			out[i] = putAt(out[i], steps[1:], value)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t)+1)
		for name, inner := range t {
			out[name] = inner
		}
		if len(steps) == 1 {
			out[steps[0]] = value
		} else {
			out[steps[0]] = putAt(out[steps[0]], steps[1:], value)
		}
		return out
	}
	panic("a path that leads nowhere")
}

// drop removes the member at a path, or the item at that position of a
// list, in a copy.
func drop(v any, path string) any {
	holder, last := locate(v, path)
	var left any
	switch t := holder.(type) {
	case []any:
		i, _ := strconv.Atoi(last)
		left = append(append([]any{}, t[:i]...), t[i+1:]...)
	case map[string]any:
		members := make(map[string]any, len(t))
		for name, inner := range t {
			if name != last {
				members[name] = inner
			}
		}
		left = members
	default:
		panic("a path that leads nowhere")
	}
	if !strings.Contains(path, ".") {
		return left
	}
	return put(v, path[:strings.LastIndex(path, ".")], left)
}

func joinPath(path, step string) string {
	if path == "" {
		return step
	}
	return path + "." + step
}

type mutation struct {
	change, path string
	object       any
}

// mutationsOf lists the objects one change away from an accepted one, as
// the description of the file says.
func mutationsOf(root any, maps, free []string) []mutation {
	var out []mutation
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch t := node.(type) {
		case map[string]any:
			out = append(out, mutation{"x", path, put(root, path, "x")})
			if has(free, path) {
				return
			}
			if !has(maps, path) {
				for _, member := range sortedNames(t) {
					out = append(out, mutation{"remove", joinPath(path, member), drop(root, joinPath(path, member))})
				}
				out = append(out, mutation{"add", path, put(root, joinPath(path, "zz"), json.Number("0"))})
			}
			for _, member := range sortedNames(t) {
				walk(t[member], joinPath(path, member))
			}
		case []any:
			out = append(out, mutation{"x", path, put(root, path, "x")})
			if has(free, path) {
				return
			}
			for i, item := range t {
				walk(item, joinPath(path, strconv.Itoa(i)))
			}
		case bool:
			out = append(out, mutation{"1", path, put(root, path, json.Number("1"))})
		case json.Number:
			out = append(out, mutation{"digits", path, put(root, path, t.String())})
			out = append(out, mutation{"true", path, put(root, path, true)})
		case string:
			out = append(out, mutation{"0", path, put(root, path, json.Number("0"))})
		}
	}
	walk(root, "")
	return out
}

func pinOf(encoding []byte) string {
	digest := sha3.Sum384(encoding)
	return hex.EncodeToString(digest[:8])
}

type schemaVector struct {
	Name      string          `json:"name"`
	Schema    string          `json:"schema"`
	From      string          `json:"from"`
	Remove    []string        `json:"remove"`
	Set       json.RawMessage `json:"set"`
	Object    json.RawMessage `json:"object"`
	Text      json.RawMessage `json:"text"`
	Rule      string          `json:"rule"`
	Why       string          `json:"why"`
	Bytes     int             `json:"bytes"`
	Pin       string          `json:"pin"`
	Prefix    string          `json:"prefix"`
	Signed    string          `json:"signed"`
	Context   string          `json:"context"`
	ID        string          `json:"id"`
	Leaf      string          `json:"witness_leaf"`
	Hash      string          `json:"hash"`
	Proposal  string          `json:"proposal_id"`
	Attested  string          `json:"attestation_id"`
	Breaks    string          `json:"breaks"`
	StateRoot string          `json:"state_root"`
	Accounts  json.RawMessage `json:"accounts"`
	TrieRoot  string          `json:"accounts_root"`
	Hashed    string          `json:"hashed"`
	BlockHash string          `json:"block_hash"`
	Mutations *struct {
		Optional []string `json:"optional"`
		Maps     []string `json:"maps"`
		Free     []string `json:"free"`
	} `json:"mutations"`
}

// ------------------------------------------- the four bytes of a frame

// announcedBy reads the four bytes that precede a frame: how many bytes
// of canonical JSON follow, and the rule that refuses them when that is
// more than a frame holds. The four bytes are a number without a sign,
// most significant byte first, and are not counted in the bound.
func announcedBy(four []byte) (uint64, string) {
	var n uint64
	for _, b := range four {
		n = n<<8 | uint64(b)
	}
	if n > maxFrameBytes {
		return n, "too_long"
	}
	return n, ""
}

// ------------------------------------- a request for blocks, its answer

// A blocks frame that holds no block: {"blocks":[],"kind":"blocks"}.
const emptyBlocksFrame = 29

// answerTo gives the levels of the blocks a node sends in answer to a
// get_blocks from first to last, when it holds the final blocks whose
// sizes held gives. The run it holds from first is found before any size
// is added up, and the sizes are then counted from the bound downward.
func answerTo(held map[int64]int, first, last int64) []int64 {
	run := []int64{}
	for level := first; ; level++ {
		if _, ok := held[level]; !ok {
			break
		}
		run = append(run, level)
		if level == last { // no level above the last one asked for, and no level after the highest there is
			break
		}
	}
	left := maxFrameBytes - emptyBlocksFrame
	for n, level := range run {
		left -= held[level]
		if n > 0 {
			left-- // the comma before every block but the first
		}
		if left < 0 {
			return run[:n]
		}
	}
	return run
}

// answerRule gives the rule that refuses a blocks frame whose blocks are
// of these levels as the answer to a get_blocks from first to last, or
// the empty string. The end is looked at before the start, and the order
// of the levels last.
func answerRule(first, last int64, levels []int64) string {
	if len(levels) == 0 {
		return ""
	}
	for _, level := range levels {
		if level > last {
			return "inconsistent"
		}
	}
	if levels[0] != first {
		return "inconsistent"
	}
	// A level is never negative: one more than the highest level there is wraps
	// around to a negative number, which is the level of no block.
	for n := 1; n < len(levels); n++ {
		if levels[n] != levels[n-1]+1 {
			return "inconsistent"
		}
	}
	return ""
}

// checkSchemas runs the vectors of the schemas with the tables above.
func checkSchemas(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var file struct {
		NetworkID     string         `json:"network_id"`
		Limits        map[string]int `json:"limits"`
		Accepted      []schemaVector `json:"accepted"`
		Refused       []schemaVector `json:"refused"`
		AcceptedTexts []schemaVector `json:"accepted_texts"`
		RefusedTexts  []schemaVector `json:"refused_texts"`
		Prefixes      []struct {
			Prefix    string  `json:"prefix"`
			Announces *uint64 `json:"announces"`
			Rule      string  `json:"rule"`
			Why       string  `json:"why"`
		} `json:"prefixes"`
		Answers []struct {
			Held   [][2]int64 `json:"held"`
			From   int64      `json:"from"`
			To     int64      `json:"to"`
			Levels []int64    `json:"levels"`
			Why    string     `json:"why"`
		} `json:"answers"`
		Replies []struct {
			From   int64   `json:"from"`
			To     int64   `json:"to"`
			Levels []int64 `json:"levels"`
			Rule   string  `json:"rule"`
			Why    string  `json:"why"`
		} `json:"replies"`
		BlockRules map[string]string `json:"block_rules"`
		Charges    []struct {
			Why          string          `json:"why"`
			State        json.RawMessage `json:"state"`
			Proposer     string          `json:"proposer"`
			Transactions json.RawMessage `json:"transactions"`
			Rule         string          `json:"rule"`
			At           *int            `json:"at"`
			Then         json.RawMessage `json:"then"`
		} `json:"charges"`
		Decisions []struct {
			Why      string          `json:"why"`
			Before   json.RawMessage `json:"before"`
			Protocol json.RawMessage `json:"protocol"`
			Treasury json.RawMessage `json:"treasury"`
			Then     json.RawMessage `json:"then"`
		} `json:"decisions"`
		GuardianRules map[string]string `json:"guardian_rules"`
		Payments      []struct {
			Why        string          `json:"why"`
			Before     json.RawMessage `json:"before"`
			Operations json.RawMessage `json:"operations"`
			Then       json.RawMessage `json:"then"`
		} `json:"payments"`
		Exchanges []struct {
			Why      string          `json:"why"`
			Steps    json.RawMessage `json:"steps"`
			Verdicts []string        `json:"verdicts"`
		} `json:"exchanges"`
		Served []struct {
			Why      string     `json:"why"`
			Held     [][2]int64 `json:"held"`
			Requests [][2]int64 `json:"requests"`
			Answers  [][]int64  `json:"answers"`
		} `json:"served"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		panic(err)
	}
	schemaNetwork = unhex(file.NetworkID)
	limits := map[string]int{
		"json_nesting": maxJSONNesting, "transaction_nesting": maxTransactionNesting, "frame_bytes": maxFrameBytes,
		"transaction_bytes": maxTransactionBytes, "block_bytes": maxBlockBytes,
		"certificate_signatures": maxCertificateSignatures, "code_bytes": maxCodeBytes, "value_bytes": maxValueBytes,
		"contract_fields": maxContractFields, "claim_bytes": maxClaimBytes, "recipients": maxRecipients,
		"validators": maxValidators, "guardians": maxGuardians,
	}
	check("the limits of the file are the limits of this program", fmt.Sprint(limits) == fmt.Sprint(file.Limits))

	vectors := schemaVectors{objects: map[string]any{}}
	kept := map[string]string{} // the schema of each accepted vector
	derived, states := 0, 0
	shown := map[string]bool{} // the sentences of chapter 2 that a refused vector breaks, alone
	for _, v := range file.Accepted {
		object := vectors.expand(mustParse(v.Object), 0)
		encoding, err := canonicalJSON(object)
		check("accepted "+v.Name+": the object", err == nil && len(encoding) == v.Bytes && pinOf(encoding) == v.Pin)
		verdict, breaks := judge(v.Schema, object)
		check("accepted "+v.Name, verdict == "" && len(breaks) == 0)
		// A frame travels after four bytes that give the length of its canonical JSON, and nothing else does.
		four := hex.EncodeToString(binary.BigEndian.AppendUint32(nil, uint32(len(encoding))))
		check("accepted "+v.Name+": the four bytes", (v.Schema == "frame" && v.Prefix == four) || (v.Schema != "frame" && v.Prefix == ""))
		vectors.objects[v.Name], kept[v.Name] = object, v.Schema
		o := object.(map[string]any)
		switch v.Schema {
		case "transaction":
			check(v.Name+": identifier", same(transactionID(o), v.ID))
			check(v.Name+": witness leaf", same(witnessLeafOf(o), v.Leaf))
			check(v.Name+": what is signed", v.Signed == "" || string(without(o, witnessFields...)) == v.Signed)
			params, _ := o["params"].(map[string]any)
			if o["kind"] == "governance_propose" {
				id, _ := canonicalJSON(map[string]any{"submitter": o["sender"], "payload": params["payload"], "salt": params["salt"]})
				check(v.Name+": proposal identifier", same(h("kern.gov.id", schemaNetwork, id), v.Proposal))
			}
			if o["kind"] == "attest" {
				id, _ := canonicalJSON(map[string]any{"issuer": o["sender"], "schema_id": params["schema_id"],
					"subject": params["subject"], "claim": params["claim"], "attest_nonce": o["nonce"]})
				check(v.Name+": attestation identifier", same(h("kern.attestation.id", schemaNetwork, id), v.Attested))
			}
		case "header":
			check(v.Name+": hash", blockHash(o) == v.Hash)
			check(v.Name+": what is signed", string(without(o, "signature")) == v.Signed)
		case "vote", "propose message":
			check(v.Name+": what is signed", string(without(o, "signature")) == v.Signed)
			check(v.Name+": context", "kern."+o["kind"].(string) == v.Context && has(purposes, v.Context))
		case "state":
			check(v.Name+": state root", same(h("kern.state", schemaNetwork, hashedState(schemaNetwork, o)), v.StateRoot))
			check(v.Name+": root of the accounts", same(accountsRoot(schemaNetwork, o), v.TrieRoot))
			if v.Accounts != nil {
				mine, _ := canonicalJSON(accountsOf(schemaNetwork, o))
				theirs, _ := canonicalJSON(mustParse(v.Accounts))
				check(v.Name+": accounts", bytes.Equal(mine, theirs))
				for address, account := range accountsOf(schemaNetwork, o) {
					check(v.Name+": the account of "+address, anAccount(account) == "")
				}
				states++
			}
		case "genesis":
			hashed, hash := firstHeader(o)
			check(v.Name+": the nine fields of the block of level 0", string(hashed) == v.Hashed)
			check(v.Name+": the hash of the block of level 0", hash == v.BlockHash)
		}
		if v.Mutations == nil {
			continue
		}
		for _, m := range mutationsOf(object, v.Mutations.Maps, v.Mutations.Free) {
			answer, _ := judge(v.Schema, m.object)
			refused := answer != ""
			expected := !(m.change == "remove" && has(v.Mutations.Optional, m.path))
			check(fmt.Sprintf("%s: %s at %q", v.Name, m.change, m.path), refused == expected)
			derived++
		}
	}
	for _, v := range file.Refused {
		var object any
		name := v.Schema
		if v.From != "" {
			name = kept[v.From]
			object = vectors.objects[v.From]
			for _, path := range v.Remove {
				object = drop(object, path)
			}
			if v.Set != nil {
				values := mustParse(v.Set).(map[string]any)
				for _, path := range sortedNames(values) {
					object = put(object, path, vectors.expand(values[path], 0))
				}
			}
		} else {
			object = vectors.expand(mustParse(v.Object), 0)
		}
		encoding, err := canonicalJSON(object)
		check("refused, "+v.Why+": the object", err == nil && len(encoding) == v.Bytes && pinOf(encoding) == v.Pin)
		verdict, breaks := judge(name, object)
		check("refused, "+v.Why+": "+verdict+", expected "+v.Rule, verdict == v.Rule)
		// A refused state names the one sentence it breaks; this program finds that sentence broken, and no other.
		ofChapter2 := name == "state" || name == "account" || name == "genesis"
		check("refused, "+v.Why+": the sentence it breaks", (v.Breaks != "") == (ofChapter2 && v.Rule == "inconsistent"))
		if v.Breaks != "" {
			check("refused, "+v.Why+": breaks "+fmt.Sprint(breaks), len(breaks) == 1 && breaks[0] == v.Breaks)
			shown[v.Breaks] = true
		}
	}
	for _, text := range sentences {
		check("a refused vector breaks the sentence: "+text, shown[text])
	}
	check("the sentences of chapter 2 that a vector breaks are those this program checks", len(shown) == len(sentences) && states == 1)
	for _, v := range file.AcceptedTexts {
		text := []byte(vectors.expand(mustParse(v.Text), 0).(string))
		check("text, "+v.Why+": the text", len(text) == v.Bytes && pinOf(text) == v.Pin)
		check("text, "+v.Why, receive(v.Schema, text) == "")
		prefix := binary.BigEndian.AppendUint32(nil, uint32(len(text)))
		check("text, "+v.Why+": prefix", v.Prefix == "" || hex.EncodeToString(prefix) == v.Prefix)
	}
	for _, v := range file.RefusedTexts {
		text := []byte(vectors.expand(mustParse(v.Text), 0).(string))
		check("text, "+v.Why+": the text", len(text) == v.Bytes && pinOf(text) == v.Pin)
		check("text, "+v.Why+": "+receive(v.Schema, text)+", expected "+v.Rule, receive(v.Schema, text) == v.Rule)
	}
	for _, v := range file.Prefixes {
		four := unhex(v.Prefix)
		n, rule := announcedBy(four)
		check("four bytes "+v.Prefix+": four of them", len(four) == 4)
		check("four bytes "+v.Prefix+": "+rule+", expected "+v.Rule, rule == v.Rule)
		check("four bytes "+v.Prefix+": what they announce", (v.Announces == nil) == (rule != "") && (v.Announces == nil || *v.Announces == n))
	}
	for _, v := range file.Answers {
		held := map[int64]int{}
		for _, block := range v.Held {
			held[block[0]] = int(block[1])
		}
		levels := answerTo(held, v.From, v.To)
		check("answer, "+v.Why+": "+fmt.Sprint(levels), fmt.Sprint(levels) == fmt.Sprint(v.Levels))
		check("answer, "+v.Why+": an answer to its request", answerRule(v.From, v.To, levels) == "")
	}
	for _, v := range file.Replies {
		rule := answerRule(v.From, v.To, v.Levels)
		check("reply, "+v.Why+": "+rule+", expected "+v.Rule, rule == v.Rule)
	}
	blockRules := []string{"block_too_large", "fee_under_floor", "wrong_chain", "wrong_nonce", "unpaid_fee", "sent_by_treasury"}
	check("the rules of a block are those of this program", fmt.Sprint(sortedNames(asAny(file.BlockRules))) == fmt.Sprint(sortedCopy(blockRules)))
	for _, v := range file.Charges {
		state := mustParse(v.State).(map[string]any)
		transactions := vectors.expand(mustParse(v.Transactions), 0).([]any)
		for _, tx := range transactions {
			check("block, "+v.Why+": a transfer", aTransaction(tx) == "" && tx.(map[string]any)["kind"] == "transfer")
		}
		then, rule, at := chargeBlock(state, v.Proposer, transactions)
		check("block, "+v.Why+": "+rule+", expected "+v.Rule, rule == v.Rule && (rule == "" || has(blockRules, rule)))
		if rule != "" {
			check("block, "+v.Why+": the transaction that breaks the rule", (v.At == nil && at == -1) || (v.At != nil && *v.At == at))
			check("block, "+v.Why+": an invalid block leaves nothing", v.Then == nil)
			continue
		}
		mine, _ := canonicalJSON(then)
		theirs, _ := canonicalJSON(mustParse(v.Then))
		check("block, "+v.Why+": what it leaves", bytes.Equal(mine, theirs))
	}
	for _, v := range file.Decisions {
		then := decideAll(mustParse(v.Before).(map[string]any), mustParse(v.Protocol).([]any), mustParse(v.Treasury).([]any))
		mine, _ := canonicalJSON(then)
		theirs, _ := canonicalJSON(mustParse(v.Then))
		check("decision, "+v.Why, bytes.Equal(mine, theirs))
		check("decision, "+v.Why+": parameters a state can hold", theParameters(then["parameters"]) == "")
	}
	check("the rules of a guardian are those of this program", fmt.Sprint(sortedNames(asAny(file.GuardianRules))) == fmt.Sprint(sortedCopy(guardianRules)))
	for _, v := range file.Payments {
		then := guardBlock(mustParse(v.Before).(map[string]any), mustParse(v.Operations).([]any))
		mine, _ := canonicalJSON(then)
		theirs, _ := canonicalJSON(mustParse(v.Then))
		check("payment, "+v.Why, bytes.Equal(mine, theirs))
	}
	for _, v := range file.Exchanges {
		verdicts := exchangeOn(mustParse(v.Steps).([]any))
		check("exchange, "+v.Why+": "+fmt.Sprint(verdicts), fmt.Sprint(verdicts) == fmt.Sprint(v.Verdicts))
	}
	for _, v := range file.Served {
		held := map[int64]int{}
		for _, block := range v.Held {
			held[block[0]] = int(block[1])
		}
		// One answer for each request, in the order in which the requests came.
		answers := make([][]int64, len(v.Requests))
		for i, request := range v.Requests {
			answers[i] = answerTo(held, request[0], request[1])
		}
		check("served, "+v.Why+": "+fmt.Sprint(answers), fmt.Sprint(answers) == fmt.Sprint(v.Answers))
	}
	if failures == 0 {
		fmt.Printf("schemas: %d objects accepted, %d refused, %d texts, %d objects one change away, %d prefixes, %d answers and %d replies, as the Python reference\n",
			len(file.Accepted), len(file.Refused), len(file.AcceptedTexts)+len(file.RefusedTexts), derived,
			len(file.Prefixes), len(file.Answers), len(file.Replies))
		fmt.Printf("what is kept: %d sentences each broken alone, %d blocks charged, %d decisions, %d blocks of guardians, %d exchanges and %d connections served, as the Python reference\n",
			len(sentences), len(file.Charges), len(file.Decisions), len(file.Payments), len(file.Exchanges), len(file.Served))
	}
}

func asAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for name, value := range m {
		out[name] = value
	}
	return out
}

func sortedCopy(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- the check

type vectors struct {
	NetworkID     string `json:"network_id"`
	CanonicalJSON []struct {
		Value    json.RawMessage `json:"value"`
		Encoding string          `json:"encoding"`
	} `json:"canonical_json"`
	NotCanonical []struct {
		Why   string `json:"why"`
		Bytes string `json:"bytes"`
	} `json:"not_canonical"`
	Hash []struct {
		Domain    string `json:"domain"`
		NetworkID string `json:"network_id"`
		Data      string `json:"data"`
		Digest    string `json:"digest"`
	} `json:"hash"`
	Merkle []struct {
		Items []string `json:"items"`
		Root  string   `json:"root"`
	} `json:"merkle"`
	Derivation []struct {
		Seed       string `json:"seed"`
		NetworkID  string `json:"network_id"`
		Salt       string `json:"salt"`
		PRK        string `json:"prk"`
		Components []struct {
			Name   string `json:"name"`
			Info   string `json:"info"`
			Output string `json:"output"`
		} `json:"components"`
		Composite         string `json:"composite_private"`
		Ed25519           string `json:"ed25519_public_key"`
		Ed25519Standalone string `json:"ed25519_standalone_public_key"`
		MLDSADigest       string `json:"mldsa65_public_key_sha3_384"`
		CompositeDigest   string `json:"composite_public_key_sha3_384"`
		Address           string `json:"address"`
	} `json:"derivation"`
	Contexts []struct {
		Purpose string `json:"purpose"`
		Context string `json:"context"`
	} `json:"contexts"`
	Address struct {
		Address      string `json:"address"`
		OtherNetwork string `json:"address_other_network"`
		Hash         string `json:"hash"`
	} `json:"address"`
	Witness struct {
		TransactionID string            `json:"transaction_id"`
		Leaves        map[string]string `json:"leaves_by_flags"`
	} `json:"witness"`
	ContractAddress struct {
		TransactionID string `json:"transaction_id"`
		Hash          string `json:"hash"`
		Address       string `json:"address"`
	} `json:"contract_address"`
	Proposer []struct {
		ParentHash string `json:"parent_hash"`
		Round      uint32 `json:"round"`
		Data       string `json:"data"`
		Draw       string `json:"draw"`
	} `json:"proposer"`
	EVM struct {
		Creator      string `json:"creator"`
		Nonce        uint64 `json:"nonce"`
		Salt         string `json:"salt"`
		CreationCode string `json:"creation_code"`
		CodeHash     string `json:"code_hash"`
		Create       string `json:"create"`
		Create2      string `json:"create2"`
		SignerKey    string `json:"signer_public_key"`
		Signer       string `json:"signer"`
	} `json:"evm"`
	Objects []struct {
		Domain   string          `json:"domain"`
		Object   json.RawMessage `json:"object"`
		Encoding string          `json:"encoding"`
		Digest   string          `json:"digest"`
	} `json:"objects"`
	Trie struct {
		Accounts []struct {
			Address string          `json:"address"`
			Key     string          `json:"position"`
			Object  json.RawMessage `json:"object"`
			Value   string          `json:"value"`
		} `json:"accounts"`
		Leaves []struct {
			Depth  int    `json:"depth"`
			Digest string `json:"digest"`
		} `json:"leaves"`
		Branch struct {
			Left   string `json:"left"`
			Right  string `json:"right"`
			Digest string `json:"digest"`
		} `json:"branch"`
		Roots []struct {
			Accounts int    `json:"accounts"`
			Root     string `json:"root"`
		} `json:"roots"`
	} `json:"trie"`
	State []struct {
		What   string          `json:"what"`
		State  json.RawMessage `json:"state"`
		Hashed string          `json:"hashed"`
		Root   string          `json:"root"`
	} `json:"state"`
	TextForms struct {
		Accepted []struct {
			Kind   string `json:"kind"`
			Factor int    `json:"factor"`
			Offset int    `json:"offset"`
			Text   string `json:"text"`
		} `json:"accepted"`
		Refused []struct {
			Kind string `json:"kind"`
			Why  string `json:"why"`
			Text string `json:"text"`
		} `json:"refused"`
	} `json:"text_forms"`
}

var failures int

func check(what string, ok bool) {
	if !ok {
		failures++
		fmt.Println("DIFFERENT:", what)
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func same(got []byte, want string) bool { return hex.EncodeToString(got) == want }

func mustParse(data []byte) any {
	v, err := parse(data)
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-sign" {
		out, err := json.MarshalIndent(ownSignatures(readSignatures(os.Args[2])), "", " ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(out))
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-official" {
		checkOfficial(os.Args[2])
		if failures > 0 {
			fmt.Println(failures, "differences")
			os.Exit(1)
		}
		fmt.Println("same verdicts as the Python tests")
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-schemas" {
		checkSchemas(os.Args[2])
		if failures > 0 {
			fmt.Println(failures, "differences")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 4 {
		fmt.Println("usage: go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json")
		fmt.Println("       go run profile_check.go -official directory-of-the-vectors")
		fmt.Println("       go run profile_check.go -schemas schemas.json")
		fmt.Println("       go run profile_check.go -sign composite_signatures.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(err)
	}
	network := unhex(v.NetworkID)
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(0xC0 + i)
	}

	for i, c := range v.CanonicalJSON {
		enc, err := canonicalJSON(mustParse(c.Value))
		check(fmt.Sprintf("canonical encoding %d", i), err == nil && same(enc, c.Encoding))
		_, err = decodeCanonical(unhex(c.Encoding))
		check(fmt.Sprintf("canonical encoding %d decodes", i), err == nil)
	}
	for _, c := range v.NotCanonical {
		_, err := decodeCanonical(unhex(c.Bytes))
		check("refused: "+c.Why, err != nil)
	}
	for _, c := range v.Hash {
		net := network
		if c.NetworkID != "" {
			net = unhex(c.NetworkID)
		}
		check("hash "+c.Domain, same(h(c.Domain, net, unhex(c.Data)), c.Digest))
	}
	for _, c := range v.Merkle {
		items := make([][]byte, len(c.Items))
		for i, item := range c.Items {
			items[i] = unhex(item)
		}
		check(fmt.Sprintf("Merkle root of %d items", len(items)), same(merkleRoot(network, items), c.Root))
	}
	for _, d := range v.Derivation {
		seed, net := unhex(d.Seed), unhex(d.NetworkID)
		check("salt", d.Salt == hex.EncodeToString(make([]byte, 64)))
		check("PRK", same(extract(seed), d.PRK))
		for _, c := range d.Components {
			check("info "+c.Name, same(info(net, c.Name), c.Info))
			check("output "+c.Name, same(derive(seed, net, c.Name), c.Output))
		}
		check("composite private key", same(join(derive(seed, net, "mldsa65"), derive(seed, net, "ed25519")), d.Composite))
		for name, want := range map[string]string{"ed25519": d.Ed25519, "ed25519-standalone": d.Ed25519Standalone} {
			public := ed25519.NewKeyFromSeed(derive(seed, net, name)).Public().(ed25519.PublicKey)
			check("public key "+name, same(public, want))
		}
		// The three values that need ML-DSA.KeyGen_internal, with crypto/mldsa.
		public := compositePublicKey(seed, net)
		mldsaDigest, compositeDigest := sha3.Sum384(public[:mldsaPublicKeySize]), sha3.Sum384(public)
		address, _ := accountAddress(net, public)
		check("ML-DSA public key", len(public) == publicKeySize && same(mldsaDigest[:], d.MLDSADigest))
		check("composite public key", same(compositeDigest[:], d.CompositeDigest) && same(public[mldsaPublicKeySize:], d.Ed25519))
		check("address of the derived key", address == d.Address)
	}
	for _, c := range v.Contexts {
		check("context "+c.Purpose, same(signingContext(c.Purpose, network), c.Context))
	}
	key := pattern(1984, 7, 3)
	address, digest := accountAddress(network, key)
	check("address", address == v.Address.Address && same(digest, v.Address.Hash))
	addressOther, _ := accountAddress(other, key)
	check("address on another network", addressOther == v.Address.OtherNetwork)
	id, sig, second := unhex(v.Witness.TransactionID), pattern(3373, 5, 1), pattern(3373, 3, 2)
	check("transaction identifier", same(h("kern.tx", network, []byte("a transaction")), v.Witness.TransactionID))
	check("witness: signature", same(witnessLeaf(network, id, sig, nil, nil), v.Witness.Leaves["0"]))
	check("witness: key and signature", same(witnessLeaf(network, id, sig, key, nil), v.Witness.Leaves["1"]))
	check("witness: two signatures", same(witnessLeaf(network, id, sig, nil, second), v.Witness.Leaves["2"]))
	check("witness: key and two signatures", same(witnessLeaf(network, id, sig, key, second), v.Witness.Leaves["3"]))

	contractHash := h("kern.addr.contract", network, unhex(v.ContractAddress.TransactionID))
	check("contract address", same(contractHash, v.ContractAddress.Hash) && addressFromHash(network, contractHash) == v.ContractAddress.Address)
	for _, c := range v.Proposer {
		parent := unhex(c.ParentHash)
		check(fmt.Sprintf("proposer draw of round %d", c.Round),
			same(binary.BigEndian.AppendUint32(append([]byte{}, parent...), c.Round), c.Data) &&
				strconv.FormatUint(proposerDraw(network, parent, c.Round), 10) == c.Draw)
	}
	creator, code := unhex(v.EVM.Creator), unhex(v.EVM.CreationCode)
	check("Mini-EVM code hash", same(h("kern.evm.code", network, code), v.EVM.CodeHash))
	check("Mini-EVM CREATE", same(evmCreate(network, creator, v.EVM.Nonce), v.EVM.Create))
	check("Mini-EVM CREATE2", same(evmCreate2(network, creator, unhex(v.EVM.Salt), code), v.EVM.Create2))
	check("Mini-EVM precompile 0x01", same(evmSigner(network, unhex(v.EVM.SignerKey)), v.EVM.Signer) &&
		v.EVM.SignerKey == v.Derivation[0].Ed25519Standalone)
	for _, c := range v.Objects {
		enc, err := canonicalJSON(mustParse(c.Object))
		check("object hashed under "+c.Domain, err == nil && same(enc, c.Encoding) && same(h(c.Domain, network, enc), c.Digest))
	}

	entries := make([]entry, len(v.Trie.Accounts))
	for i, a := range v.Trie.Accounts {
		value, err := canonicalJSON(mustParse(a.Object))
		check("trie key and value of "+a.Address, err == nil && same(value, a.Value) && same(h("kern.trie.key", network, []byte(a.Address)), a.Key))
		entries[i] = entry{unhex(a.Key), unhex(a.Value)}
	}
	for _, c := range v.Trie.Leaves {
		check(fmt.Sprintf("trie leaf at depth %d", c.Depth), same(trieLeaf(network, entries[0].key, c.Depth, entries[0].value), c.Digest))
	}
	check("trie branch", same(h("kern.trie.branch", network, join(unhex(v.Trie.Branch.Left), unhex(v.Trie.Branch.Right))), v.Trie.Branch.Digest))
	for _, c := range v.Trie.Roots {
		check(fmt.Sprintf("trie root of %d accounts", c.Accounts), same(trieNode(network, entries[:c.Accounts], 0), c.Root))
	}
	for _, c := range v.State {
		state := mustParse(c.State).(map[string]any)
		hashed := hashedState(network, state)
		// The states that hold a key registry give their root only.
		check("state root, "+c.What, (c.Hashed == "" || same(hashed, c.Hashed)) && same(h("kern.state", network, hashed), c.Root))
	}

	// Section 5: one text per value.
	type textKind struct {
		prefix string
		size   int
	}
	kinds := map[string]textKind{"public_key": {"kpk1.", publicKeySize}, "signature": {"ksig1.", signatureSize}}
	for _, c := range v.TextForms.Accepted {
		k, known := kinds[c.Kind]
		data := pattern(k.size, c.Factor, c.Offset)
		decoded, err := decodeText(k.prefix, k.size, c.Text)
		check(fmt.Sprintf("text of a %s, bytes (%d, %d)", c.Kind, c.Factor, c.Offset),
			known && textOf(k.prefix, data) == c.Text && err == nil && bytes.Equal(decoded, data))
	}
	for _, c := range v.TextForms.Refused {
		for kind, k := range kinds { // by the decoder of its kind, and by the other one
			_, err := decodeText(k.prefix, k.size, c.Text)
			check("refused as a "+kind+": "+c.Kind+", "+c.Why, err != nil)
		}
	}
	check("text forms are in the vectors", len(v.TextForms.Accepted) > 0 && len(v.TextForms.Refused) > 0)

	raw, err = os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var edge struct {
		Cases []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			Valid     bool   `json:"valid"`
			Lenient   bool   `json:"lenient"`
		} `json:"cases"`
		PublicKeys []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Valid     bool   `json:"valid"`
		} `json:"public_keys"`
	}
	if err := json.Unmarshal(raw, &edge); err != nil {
		panic(err)
	}
	lenientOnly := 0
	for _, c := range edge.Cases {
		pk, msg, sig := unhex(c.PublicKey), unhex(c.Message), unhex(c.Signature)
		check("Ed25519 rule: "+c.Name, strictVerify(pk, msg, sig) == c.Valid)
		check("Ed25519 standard library alone: "+c.Name, lenientVerify(pk, msg, sig) == c.Lenient)
		if c.Lenient && !c.Valid {
			lenientOnly++
		}
	}
	keysRefused := 0
	for _, c := range edge.PublicKeys { // rule 2 alone, the check made when a key is recorded
		check("Ed25519 public key: "+c.Name, isAKey(unhex(c.PublicKey)) == c.Valid)
		if !c.Valid {
			keysRefused++
		}
	}
	check("public keys are in the vectors", len(edge.PublicKeys) > 0)

	s := readSignatures(os.Args[3])
	checkSignatures(s)

	fmt.Printf("%d canonical encodings, %d refusals, %d hashes, %d Merkle roots, %d derivations with their ML-DSA keys, %d contexts, 2 addresses, 4 witness leaves\n",
		len(v.CanonicalJSON), len(v.NotCanonical), len(v.Hash), len(v.Merkle), len(v.Derivation), len(v.Contexts))
	fmt.Printf("1 contract address, %d proposer draws, 3 Mini-EVM addresses, %d objects, %d trie leaves, %d trie roots, %d state roots\n",
		len(v.Proposer), len(v.Objects), len(v.Trie.Leaves), len(v.Trie.Roots), len(v.State))
	fmt.Printf("%d Ed25519 cases, %d of them accepted by the standard library alone and refused by the rule\n", len(edge.Cases), lenientOnly)
	fmt.Printf("%d Ed25519 public keys under rule 2 alone, %d of them refused; %d text forms accepted, %d spellings refused\n",
		len(edge.PublicKeys), keysRefused, len(v.TextForms.Accepted), len(v.TextForms.Refused))
	fmt.Printf("%d composite signatures made in Python and %d made in Go verified, %d invalid cases refused\n",
		len(s.Python), len(s.Go), len(s.Invalid))
	if failures > 0 {
		fmt.Println(failures, "differences")
		os.Exit(1)
	}
	fmt.Println("same values as the Python reference")
}
