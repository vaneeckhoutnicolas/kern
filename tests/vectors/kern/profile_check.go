// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors

// A second implementation of the signature profile of Kern
// (docs/hybrid-signatures.md), written with the Go standard library alone
// and independently of tests/profile_reference.py. It recomputes every
// value of profile.json and every verdict of ed25519_edge_cases.json, and
// fails on the first difference.
//
//	go run profile_check.go profile.json ed25519_edge_cases.json
//
// Not part of the node and not run by the test suite, which is Python.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
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

func decodeCanonical(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
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
	return h("kern.merkle.node", network, append(merkleRoot(network, items[:k]), merkleRoot(network, items[k:])...))
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
	out := append([]byte(derivationLabel), 0x01)
	out = append(out, network...)
	return append(out, []byte(component)...)
}

func derive(seed, network []byte, component string) []byte {
	return hmac512(extract(seed), append(info(network, component), 0x01))[:32]
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

func accountAddress(network, publicKey []byte) (string, []byte) {
	digest := h("kern.addr", network, append([]byte{0x01}, publicKey...))
	body := append([]byte{0x7b, 0x03, 0x39}, digest...)
	return base58(append(body, h("kern.checksum", network, body)[:4]...)), digest
}

func witnessLeaf(network, transactionID, signature, publicKey, second []byte) []byte {
	flags := byte(0)
	if publicKey != nil {
		flags |= 1
	}
	if second != nil {
		flags |= 2
	}
	data := append(append([]byte{}, transactionID...), flags)
	data = append(data, publicKey...)
	data = append(data, signature...)
	data = append(data, second...)
	return h("kern.witness", network, data)
}

func pattern(length, factor, offset int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte((factor*i + offset) % 256)
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

func strictVerify(publicKey, message, signature []byte) bool {
	if len(publicKey) != 32 || len(signature) != 64 {
		return false
	}
	a, r := decodeStrictly(publicKey), decodeStrictly(signature[:32])
	if a == nil || r == nil {
		return false
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[31-i] = signature[32+i]
	}
	if new(big.Int).SetBytes(le).Cmp(orderL) >= 0 {
		return false
	}
	if isIdentity(*a) || !isIdentity(scalarMul(orderL, *a)) || isIdentity(*r) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) // the exact equation
}

func lenientVerify(publicKey, message, signature []byte) bool {
	return len(publicKey) == 32 && ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
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

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: go run profile_check.go profile.json ed25519_edge_cases.json")
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
		dec := json.NewDecoder(bytes.NewReader(c.Value))
		dec.UseNumber()
		var value any
		if err := dec.Decode(&value); err != nil {
			panic(err)
		}
		enc, err := canonicalJSON(value)
		check(fmt.Sprintf("canonical encoding %d", i), err == nil && hex.EncodeToString(enc) == c.Encoding)
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
		check("hash "+c.Domain, hex.EncodeToString(h(c.Domain, net, unhex(c.Data))) == c.Digest)
	}
	for _, c := range v.Merkle {
		items := make([][]byte, len(c.Items))
		for i, item := range c.Items {
			items[i] = unhex(item)
		}
		check(fmt.Sprintf("Merkle root of %d items", len(items)), hex.EncodeToString(merkleRoot(network, items)) == c.Root)
	}
	for _, d := range v.Derivation {
		seed, net := unhex(d.Seed), unhex(d.NetworkID)
		check("salt", d.Salt == hex.EncodeToString(make([]byte, 64)))
		check("PRK", hex.EncodeToString(extract(seed)) == d.PRK)
		for _, c := range d.Components {
			check("info "+c.Name, hex.EncodeToString(info(net, c.Name)) == c.Info)
			check("output "+c.Name, hex.EncodeToString(derive(seed, net, c.Name)) == c.Output)
		}
		composite := append(derive(seed, net, "mldsa65"), derive(seed, net, "ed25519")...)
		check("composite private key", hex.EncodeToString(composite) == d.Composite)
		for name, want := range map[string]string{"ed25519": d.Ed25519, "ed25519-standalone": d.Ed25519Standalone} {
			public := ed25519.NewKeyFromSeed(derive(seed, net, name)).Public().(ed25519.PublicKey)
			check("public key "+name, hex.EncodeToString(public) == want)
		}
	}
	for _, c := range v.Contexts {
		ctx := append(append([]byte(c.Purpose), 0), network...)
		check("context "+c.Purpose, hex.EncodeToString(ctx) == c.Context)
	}
	key := pattern(1984, 7, 3)
	address, digest := accountAddress(network, key)
	check("address", address == v.Address.Address && hex.EncodeToString(digest) == v.Address.Hash)
	addressOther, _ := accountAddress(other, key)
	check("address on another network", addressOther == v.Address.OtherNetwork)
	id, sig, second := unhex(v.Witness.TransactionID), pattern(3373, 5, 1), pattern(3373, 3, 2)
	check("transaction identifier", hex.EncodeToString(h("kern.tx", network, []byte("a transaction"))) == v.Witness.TransactionID)
	check("witness: signature", hex.EncodeToString(witnessLeaf(network, id, sig, nil, nil)) == v.Witness.Leaves["0"])
	check("witness: key and signature", hex.EncodeToString(witnessLeaf(network, id, sig, key, nil)) == v.Witness.Leaves["1"])
	check("witness: two signatures", hex.EncodeToString(witnessLeaf(network, id, sig, nil, second)) == v.Witness.Leaves["2"])
	check("witness: key and two signatures", hex.EncodeToString(witnessLeaf(network, id, sig, key, second)) == v.Witness.Leaves["3"])

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
	fmt.Printf("%d canonical encodings, %d refusals, %d hashes, %d Merkle roots, %d derivations, %d contexts, 2 addresses, 4 witness leaves\n",
		len(v.CanonicalJSON), len(v.NotCanonical), len(v.Hash), len(v.Merkle), len(v.Derivation), len(v.Contexts))
	fmt.Printf("%d Ed25519 cases, %d of them accepted by the standard library alone and refused by the rule\n", len(edge.Cases), lenientOnly)
	if failures > 0 {
		fmt.Println(failures, "differences")
		os.Exit(1)
	}
	fmt.Println("same values as the Python reference")
}
