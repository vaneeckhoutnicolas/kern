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
// With -sign it prints the signatures it makes, the list kept under "go"
// in composite_signatures.json:
//
//	go run profile_check.go -sign composite_signatures.json
//
// Needs Go 1.27 or later, for crypto/mldsa. Not part of the node and not
// run by the test suite, which is Python; the continuous integration runs
// it on every pull request.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
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
	if len(os.Args) != 4 {
		fmt.Println("usage: go run profile_check.go profile.json ed25519_edge_cases.json composite_signatures.json")
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

	s := readSignatures(os.Args[3])
	checkSignatures(s)

	fmt.Printf("%d canonical encodings, %d refusals, %d hashes, %d Merkle roots, %d derivations with their ML-DSA keys, %d contexts, 2 addresses, 4 witness leaves\n",
		len(v.CanonicalJSON), len(v.NotCanonical), len(v.Hash), len(v.Merkle), len(v.Derivation), len(v.Contexts))
	fmt.Printf("1 contract address, %d proposer draws, 3 Mini-EVM addresses, %d objects, %d trie leaves, %d trie roots, %d state roots\n",
		len(v.Proposer), len(v.Objects), len(v.Trie.Leaves), len(v.Trie.Roots), len(v.State))
	fmt.Printf("%d Ed25519 cases, %d of them accepted by the standard library alone and refused by the rule\n", len(edge.Cases), lenientOnly)
	fmt.Printf("%d composite signatures made in Python and %d made in Go verified, %d invalid cases refused\n",
		len(s.Python), len(s.Go), len(s.Invalid))
	if failures > 0 {
		fmt.Println(failures, "differences")
		os.Exit(1)
	}
	fmt.Println("same values as the Python reference")
}
