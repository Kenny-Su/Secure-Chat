package chatterbox

import (
	"encoding/binary"
	"errors"
)

const HANDSHAKE_CHECK_LABEL byte = 0x11
const ROOT_LABEL = 0x22
const CHAIN_LABEL = 0x33
const KEY_LABEL = 0x44

type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

type Session struct {
	MyDHRatchet      *KeyPair
	PartnerDHRatchet *PublicKey

	SendRootChain    *SymmetricKey
	ReceiveRootChain *SymmetricKey

	SendChain    *SymmetricKey
	ReceiveChain *SymmetricKey

	CachedReceiveKeys map[int]*SymmetricKey

	SendCounter       int
	SendLastUpdate    int
	ReceiveCounter    int
	ReceiveLastUpdate int

	NeedsDHRatchet bool
}

type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("don't have that session open to tear down")
	}

	session := c.Sessions[*partnerIdentity]

	if session.MyDHRatchet != nil {
		session.MyDHRatchet.Zeroize()
	}

	if session.SendRootChain != nil {
		session.SendRootChain.Zeroize()
	}

	if session.ReceiveRootChain != nil {
		session.ReceiveRootChain.Zeroize()
	}

	if session.SendChain != nil {
		session.SendChain.Zeroize()
	}

	if session.ReceiveChain != nil {
		session.ReceiveChain.Zeroize()
	}

	for _, key := range session.CachedReceiveKeys {
		if key != nil {
			key.Zeroize()
		}
	}

	delete(c.Sessions, *partnerIdentity)

	return nil
}

func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("already have session open")
	}

	ephemeralKeypair := GenerateKeyPair()

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKeypair,
		PartnerDHRatchet:  nil,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		SendLastUpdate:    1,
		ReceiveCounter:    0,
		ReceiveLastUpdate: 0,
		NeedsDHRatchet:    false,
	}

	return &ephemeralKeypair.PublicKey, nil
}

func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("already have session open")
	}

	ephemeralKeypair := GenerateKeyPair()

	dh1 := DHCombine(partnerIdentity, &ephemeralKeypair.PrivateKey)
	defer dh1.Zeroize()
	dh2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	defer dh2.Zeroize()
	dh3 := DHCombine(partnerEphemeral, &ephemeralKeypair.PrivateKey)
	defer dh3.Zeroize()

	rootKey := CombineKeys(dh1, dh2, dh3)

	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	sendRootKey := &SymmetricKey{Key: append([]byte(nil), rootKey.Key...)}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKeypair,
		PartnerDHRatchet:  partnerEphemeral,
		SendRootChain:     sendRootKey,
		ReceiveRootChain:  rootKey,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		SendLastUpdate:    1,
		ReceiveCounter:    0,
		ReceiveLastUpdate: 1,
		NeedsDHRatchet:    true,
	}

	return &ephemeralKeypair.PublicKey, checkKey, nil
}

func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("no open session with partner")
	}

	session := c.Sessions[*partnerIdentity]

	dh1 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	defer dh1.Zeroize()
	dh2 := DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey)
	defer dh2.Zeroize()
	dh3 := DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey)
	defer dh3.Zeroize()

	rootKey := CombineKeys(dh1, dh2, dh3)

	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	sendRootKey := &SymmetricKey{Key: append([]byte(nil), rootKey.Key...)}

	session.PartnerDHRatchet = partnerEphemeral
	session.SendRootChain = sendRootKey
	session.ReceiveRootChain = rootKey
	session.SendLastUpdate = 1
	session.ReceiveLastUpdate = 1

	return checkKey, nil
}

func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("no open session with partner")
	}

	session := c.Sessions[*partnerIdentity]

	if session.NeedsDHRatchet {
		newDHRatchet := GenerateKeyPair()

		dhSharedSecret := DHCombine(session.PartnerDHRatchet, &newDHRatchet.PrivateKey)
		defer dhSharedSecret.Zeroize()

		ratchetedRoot := session.ReceiveRootChain.DeriveKey(ROOT_LABEL)
		defer ratchetedRoot.Zeroize()

		newSendRoot := CombineKeys(ratchetedRoot, dhSharedSecret)

		if session.SendRootChain != nil {
			session.SendRootChain.Zeroize()
		}
		session.SendRootChain = newSendRoot

		session.MyDHRatchet.Zeroize()
		session.MyDHRatchet = newDHRatchet

		if session.SendChain != nil {
			session.SendChain.Zeroize()
		}
		session.SendChain = session.SendRootChain.DeriveKey(CHAIN_LABEL)

		session.SendLastUpdate = session.SendCounter + 1

		session.NeedsDHRatchet = false
	}

	if session.SendChain == nil {
		session.SendChain = session.SendRootChain.DeriveKey(CHAIN_LABEL)
	}

	session.SendCounter++

	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
	defer messageKey.Zeroize()

	newSendChain := session.SendChain.DeriveKey(CHAIN_LABEL)
	session.SendChain.Zeroize()
	session.SendChain = newSendChain

	iv := NewIV()

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		Counter:       session.SendCounter,
		LastUpdate:    session.SendLastUpdate,
		NextDHRatchet: &session.MyDHRatchet.PublicKey,
		IV:            iv,
	}

	additionalData := message.EncodeAdditionalData()

	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)

	return message, nil
}

func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("no open session with sender")
	}

	session := c.Sessions[*message.Sender]

	_, keyInCache := session.CachedReceiveKeys[message.Counter]
	if message.Counter <= session.ReceiveCounter && !keyInCache {
		return "", errors.New("message already received - replay attack detected")
	}

	savedReceiveRootChain := session.ReceiveRootChain
	savedReceiveChain := session.ReceiveChain
	savedReceiveCounter := session.ReceiveCounter
	savedReceiveLastUpdate := session.ReceiveLastUpdate
	savedPartnerDHRatchet := session.PartnerDHRatchet
	savedNeedsDHRatchet := session.NeedsDHRatchet

	savedCachedKeys := make(map[int]bool)
	for k := range session.CachedReceiveKeys {
		savedCachedKeys[k] = true
	}

	var oldKeysToZeroize []*SymmetricKey

	needsDHRatchet := false
	if session.PartnerDHRatchet == nil || *message.NextDHRatchet != *session.PartnerDHRatchet {
		needsDHRatchet = true
	}
	if message.LastUpdate > session.ReceiveLastUpdate {
		needsDHRatchet = true
	}

	if needsDHRatchet {
		if session.ReceiveChain == nil {
			session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
		}

		if message.LastUpdate > session.ReceiveLastUpdate {
			for i := session.ReceiveCounter + 1; i < message.LastUpdate; i++ {
				if _, exists := session.CachedReceiveKeys[i]; !exists {
					key := session.ReceiveChain.DeriveKey(KEY_LABEL)
					session.CachedReceiveKeys[i] = key

					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				} else {
					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				}
			}
		}

		baseRoot := session.ReceiveRootChain
		if session.SendRootChain != nil {
			baseRoot = session.SendRootChain
		}

		dhSecret := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)
		defer dhSecret.Zeroize()

		ratchetedRoot := baseRoot.DeriveKey(ROOT_LABEL)
		defer ratchetedRoot.Zeroize()

		oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveRootChain)

		newReceiveRoot := CombineKeys(ratchetedRoot, dhSecret)

		session.ReceiveRootChain = newReceiveRoot

		session.PartnerDHRatchet = message.NextDHRatchet

		if session.ReceiveChain != nil {
			oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
		}
		session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)

		session.ReceiveLastUpdate = message.LastUpdate
		session.ReceiveCounter = message.LastUpdate - 1

		session.NeedsDHRatchet = true
	}

	if session.ReceiveChain == nil {
		session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
	}

	if _, exists := session.CachedReceiveKeys[message.Counter]; !exists {
		if message.LastUpdate != session.ReceiveLastUpdate {
			if session.ReceiveRootChain != savedReceiveRootChain && session.ReceiveRootChain != nil {
				session.ReceiveRootChain.Zeroize()
			}
			if session.ReceiveChain != savedReceiveChain && session.ReceiveChain != nil {
				session.ReceiveChain.Zeroize()
			}
			session.ReceiveRootChain = savedReceiveRootChain
			session.ReceiveChain = savedReceiveChain
			session.ReceiveCounter = savedReceiveCounter
			session.ReceiveLastUpdate = savedReceiveLastUpdate
			session.PartnerDHRatchet = savedPartnerDHRatchet
			session.NeedsDHRatchet = savedNeedsDHRatchet

			for k := range session.CachedReceiveKeys {
				if !savedCachedKeys[k] {
					session.CachedReceiveKeys[k].Zeroize()
					delete(session.CachedReceiveKeys, k)
				}
			}

			return "", errors.New("message from old epoch not in cache")
		}

		for i := session.ReceiveCounter + 1; i <= message.Counter; i++ {
			if _, exists := session.CachedReceiveKeys[i]; !exists {
				key := session.ReceiveChain.DeriveKey(KEY_LABEL)
				session.CachedReceiveKeys[i] = key

				newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
				oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
				session.ReceiveChain = newReceiveChain
			}
		}
	}

	messageKey, exists := session.CachedReceiveKeys[message.Counter]
	if !exists {
		return "", errors.New("message key not found in cache")
	}

	additionalData := message.EncodeAdditionalData()
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)

	if err != nil {
		if session.ReceiveRootChain != savedReceiveRootChain && session.ReceiveRootChain != nil {
			session.ReceiveRootChain.Zeroize()
		}
		if session.ReceiveChain != savedReceiveChain && session.ReceiveChain != nil {
			session.ReceiveChain.Zeroize()
		}

		session.ReceiveRootChain = savedReceiveRootChain
		session.ReceiveChain = savedReceiveChain
		session.ReceiveCounter = savedReceiveCounter
		session.ReceiveLastUpdate = savedReceiveLastUpdate
		session.PartnerDHRatchet = savedPartnerDHRatchet
		session.NeedsDHRatchet = savedNeedsDHRatchet

		for k := range session.CachedReceiveKeys {
			if !savedCachedKeys[k] {
				session.CachedReceiveKeys[k].Zeroize()
				delete(session.CachedReceiveKeys, k)
			}
		}

		return "", err
	}

	delete(session.CachedReceiveKeys, message.Counter)
	messageKey.Zeroize()

	if message.Counter > session.ReceiveCounter {
		session.ReceiveCounter = message.Counter
	}

	for _, key := range oldKeysToZeroize {
		if key != nil {
			key.Zeroize()
		}
	}

	return plaintext, nil
}
