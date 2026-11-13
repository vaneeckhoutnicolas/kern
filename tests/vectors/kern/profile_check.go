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
// With -sign it prints the signatures it makes, the list kept under "go"
// in composite_signatures.json:
//
//	go run profile_check.go -sign composite_signatures.json
//
// Needs Go 1.27 or later, for crypto/mldsa. Not part of the node and not
// run by the test suite, which is Python; the continuous integration runs
// the first two commands on every pull request.
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
	if len(os.Args) != 4 {
		fmt.Println("usage: go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json")
		fmt.Println("       go run profile_check.go -official directory-of-the-vectors")
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
