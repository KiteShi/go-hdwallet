package hdwallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
)

const (
	// main net
	BtcPublicPrefix  = "0488B21E" //same for Bch
	BtcPrivatePrefix = "0488ADE4" //same for Bch
	BtcPubkeyHash    = "00"

	// test net
	TestBtcPublicPrefix  = "043587CF"
	TestBtcPrivatePrefix = "04358394"
	TestBtcPubkeyHash    = "6F"

	// main net
	LtcPublicPrefix  = "019DA462"
	LtcPrivatePrefix = "019D9CFE"
	LtcPubkeyHash    = "30"

	// test net
	TestLtcPublicPrefix  = "0436F6E1"
	TestLtcPrivatePrefix = "0436EF7D"
	TestLtcPubkeyHash    = "6F"

	DefaultBtcKey = "Bitcoin seed"
	DefaultLtcKey = "Litecoin seed"
)

type WalletGenPrefixes struct {
	PubkeyHash    string
	PublicPrefix  string
	PrivatePrefix string
	Key           string
}

type WalletGenerator struct {
	pubkeyHash []byte
	public     []byte
	private    []byte
	key        []byte
}

// HDWallet defines the components of a hierarchical deterministic wallet
type HDWallet struct {
	Vbytes      []byte //4 bytes
	Depth       uint16 //1 byte
	Fingerprint []byte //4 bytes
	I           []byte //4 bytes
	Chaincode   []byte //32 bytes
	Key         []byte //33 bytes
	walletGen   *WalletGenerator
}

func NewWalletGenerator(prefixes WalletGenPrefixes) (*WalletGenerator, error) {
	pub, err := hex.DecodeString(prefixes.PublicPrefix)
	if err != nil {
		return nil, err
	}
	priv, err := hex.DecodeString(prefixes.PrivatePrefix)
	if err != nil {
		return nil, err
	}
	hash, err := hex.DecodeString(prefixes.PubkeyHash)
	if err != nil {
		return nil, err
	}

	return &WalletGenerator{
		pubkeyHash: hash,
		public:     pub,
		private:    priv,
		key:        []byte(prefixes.Key),
	}, nil
}

func NewDefaultBtcWalletGenerator(test bool) (*WalletGenerator, error) {
	if test {
		return NewWalletGenerator(WalletGenPrefixes{
			PubkeyHash:    TestBtcPubkeyHash,
			PublicPrefix:  TestBtcPublicPrefix,
			PrivatePrefix: TestBtcPrivatePrefix,
			Key:           DefaultBtcKey,
		})
	}

	return NewWalletGenerator(WalletGenPrefixes{
		PubkeyHash:    BtcPubkeyHash,
		PublicPrefix:  BtcPublicPrefix,
		PrivatePrefix: BtcPrivatePrefix,
		Key:           DefaultBtcKey,
	})
}

func NewDefaultBchWalletGenerator(test bool) (*WalletGenerator, error) {
	return NewDefaultBtcWalletGenerator(test)
}

func NewDefaultLtcWalletGenerator(test bool) (*WalletGenerator, error) {
	if test {
		return NewWalletGenerator(WalletGenPrefixes{
			PubkeyHash:    TestLtcPubkeyHash,
			PublicPrefix:  TestLtcPublicPrefix,
			PrivatePrefix: TestLtcPrivatePrefix,
			Key:           DefaultLtcKey,
		})
	}
	return NewWalletGenerator(WalletGenPrefixes{
		PubkeyHash:    LtcPubkeyHash,
		PublicPrefix:  LtcPublicPrefix,
		PrivatePrefix: LtcPrivatePrefix,
		Key:           DefaultLtcKey,
	})
}

// GenSeed returns a random seed with a length measured in bytes.
// The length must be at least 128.
func GenSeed(length int) ([]byte, error) {
	b := make([]byte, length)
	if length < 128 {
		return b, errors.New("length must be at least 128 bits")
	}
	_, err := rand.Read(b)
	return b, err
}

// MasterKey returns a new wallet given a random seed.
func (w *WalletGenerator) MasterKey(seed []byte) (*HDWallet, error) {
	mac := hmac.New(sha512.New, w.key)
	_, err := mac.Write(seed)
	if err != nil {
		return nil, err
	}

	I := mac.Sum(nil)
	secret := I[:len(I)/2]
	chainCode := I[len(I)/2:]
	i := make([]byte, 4)
	fingerprint := make([]byte, 4)
	zero := make([]byte, 1)
	return &HDWallet{
		Vbytes:      w.private,
		Depth:       0,
		Fingerprint: fingerprint,
		I:           i,
		Chaincode:   chainCode,
		Key:         append(zero, secret...),
		walletGen:   w,
	}, nil
}

func (w *WalletGenerator) ByteCheck(dbin []byte) error {
	// check proper length
	if len(dbin) != 82 {
		return errors.New("invalid string")
	}
	// check for correct Public or Private vbytes
	if bytes.Compare(dbin[:4], w.public) != 0 && bytes.Compare(dbin[:4], w.private) != 0 {
		return errors.New("invalid string")
	}
	// if Public, check x coord is on curve
	x, y := expand(dbin[45:78])
	if bytes.Compare(dbin[:4], w.public) == 0 {
		if !onCurve(x, y) {
			return errors.New("invalid string")
		}
	}
	return nil
}

// StringWallet returns a wallet given a base58-encoded extended key
func (w *WalletGenerator) StringWallet(data string) (*HDWallet, error) {
	dbin := base58.Decode(data)
	if err := w.ByteCheck(dbin); err != nil {
		return &HDWallet{}, err
	}
	if bytes.Compare(dblSha256(dbin[:(len(dbin) - 4)])[:4], dbin[(len(dbin)-4):]) != 0 {
		return &HDWallet{}, errors.New("invalid checksum")
	}
	vbytes := dbin[0:4]
	depth := byteToUint16(dbin[4:5])
	fingerprint := dbin[5:9]
	i := dbin[9:13]
	chaincode := dbin[13:45]
	key := dbin[45:78]
	return &HDWallet{
		Vbytes:      vbytes,
		Depth:       depth,
		Fingerprint: fingerprint,
		I:           i,
		Chaincode:   chaincode,
		Key:         key,
		walletGen:   w,
	}, nil
}

//StringAddress returns the Bitcoin address of a base58-encoded extended key.
func (w *WalletGenerator) StringAddress(data string) (string, error) {
	wallet, err := w.StringWallet(data)
	if err != nil {
		return "", err
	} else {
		return wallet.Address(), nil
	}
}

// StringCheck is a validation check of a base58-encoded extended key.
func (w *WalletGenerator) StringCheck(key string) error {
	return w.ByteCheck(base58.Decode(key))
}

// StringChild returns the ith base58-encoded extended key of a base58-encoded extended key.
func (w *WalletGenerator) StringChild(data string, i uint32) (string, error) {
	wallet, err := w.StringWallet(data)
	if err != nil {
		return "", err
	} else {
		wallet, err = wallet.Child(i)
		if err != nil {
			return "", err
		} else {
			return wallet.String(), nil
		}
	}
}

// Address returns bitcoin address represented by wallet w.
func (w *HDWallet) Address() string {
	x, y := expand(w.Key)
	four, _ := hex.DecodeString("04")
	padded_key := append(four, append(x.Bytes(), y.Bytes()...)...)
	addr_1 := append(w.walletGen.pubkeyHash, hash160(padded_key)...)
	chksum := dblSha256(addr_1)
	return base58.Encode(append(addr_1, chksum[:4]...))
}

// Child returns the ith child of wallet w. Values of i >= 2^31
// signify private key derivation. Attempting private key derivation
// with a public key will throw an error.
func (w *HDWallet) Child(i uint32) (*HDWallet, error) {
	var fingerprint, I, newkey []byte
	switch {
	case bytes.Compare(w.Vbytes, w.walletGen.private) == 0:
		pub := privToPub(w.Key)
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			mac.Write(append(w.Key, uint32ToByte(i)...))
		} else {
			mac.Write(append(pub, uint32ToByte(i)...))
		}
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPrivKeys(I[:32], w.Key)
		fingerprint = hash160(privToPub(w.Key))[:4]

	case bytes.Compare(w.Vbytes, w.walletGen.public) == 0:
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			return &HDWallet{}, errors.New("Can't do Private derivation on Public key!")
		}
		mac.Write(append(w.Key, uint32ToByte(i)...))
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPubKeys(privToPub(I[:32]), w.Key)
		fingerprint = hash160(w.Key)[:4]
	}
	return &HDWallet{
		Vbytes:      w.Vbytes,
		Depth:       w.Depth + 1,
		Fingerprint: fingerprint,
		I:           uint32ToByte(i),
		Chaincode:   I[32:],
		Key:         newkey,
		walletGen:   w.walletGen,
	}, nil
}

// Pub returns a new wallet which is the public key version of w.
// If w is a public key, Pub returns a copy of w
func (w *HDWallet) Pub() *HDWallet {
	if bytes.Compare(w.Vbytes, w.walletGen.public) == 0 {
		return &HDWallet{
			Vbytes:      w.Vbytes,
			Depth:       w.Depth,
			Fingerprint: w.Fingerprint,
			I:           w.I,
			Chaincode:   w.Chaincode,
			Key:         w.Key,
			walletGen:   w.walletGen,
		}
	} else {
		return &HDWallet{
			Vbytes:      w.walletGen.public,
			Depth:       w.Depth,
			Fingerprint: w.Fingerprint,
			I:           w.I,
			Chaincode:   w.Chaincode,
			Key:         privToPub(w.Key),
			walletGen:   w.walletGen,
		}
	}
}

// Serialize returns the serialized form of the wallet.
func (w *HDWallet) Serialize() []byte {
	depth := uint16ToByte(uint16(w.Depth % 256))
	//bindata = vbytes||depth||fingerprint||i||chaincode||key
	bindata := make([]byte, 78)
	copy(bindata, w.Vbytes)
	copy(bindata[4:], depth)
	copy(bindata[5:], w.Fingerprint)
	copy(bindata[9:], w.I)
	copy(bindata[13:], w.Chaincode)
	copy(bindata[45:], w.Key)
	chksum := dblSha256(bindata)[:4]
	return append(bindata, chksum...)
}

// String returns the base58-encoded string form of the wallet.
func (w *HDWallet) String() string {
	return base58.Encode(w.Serialize())
}
