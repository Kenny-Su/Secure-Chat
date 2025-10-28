package chatterbox

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

func PrintFingerprint(fp []byte) string {
	return hex.EncodeToString(fp)
}

const HANDSHAKE_CHECK_LABEL byte = 0x11
const ROOT_LABEL = 0x22
const CHAIN_LABEL = 0x33
const KEY_LABEL = 0x44

type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// HistoricalDHState stores the DH ratchet key and associated root chains
// at a specific point in time, needed for decrypting out-of-order messages
type HistoricalDHState struct {
	DHRatchet        *KeyPair
	SendRootChain    *SymmetricKey
	ReceiveRootChain *SymmetricKey
}

// PartnerHistoricalDHState stores OUR old DH ratchet key and the
// receive chain state, for decrypting old epoch messages from partner
type PartnerHistoricalDHState struct {
	MyDHRatchet      *KeyPair // Our DH key at this epoch (used to compute shared secret)
	ReceiveChain     *SymmetricKey
	ReceiveRootChain *SymmetricKey
	LastUpdate       int
}

type Session struct {
	MyDHRatchet              *KeyPair
	MyDHRatchetHistory       []*HistoricalDHState // Keep history of old states for out-of-order messages
	PartnerDHRatchet         *PublicKey
	PartnerDHRatchetHistory  []*PartnerHistoricalDHState // Partner's old DH keys for old epoch messages

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

	// Zeroize all historical DH states
	for _, oldState := range session.MyDHRatchetHistory {
		if oldState != nil {
			if oldState.DHRatchet != nil {
				oldState.DHRatchet.Zeroize()
			}
			if oldState.SendRootChain != nil {
				oldState.SendRootChain.Zeroize()
			}
			if oldState.ReceiveRootChain != nil {
				oldState.ReceiveRootChain.Zeroize()
			}
		}
	}

	// Zeroize all partner historical DH states
	for _, oldState := range session.PartnerDHRatchetHistory {
		if oldState != nil {
			if oldState.MyDHRatchet != nil {
				oldState.MyDHRatchet.Zeroize()
			}
			if oldState.ReceiveChain != nil {
				oldState.ReceiveChain.Zeroize()
			}
			if oldState.ReceiveRootChain != nil {
				oldState.ReceiveRootChain.Zeroize()
			}
		}
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

		// Save current state to history before updating (for out-of-order messages)
		// Make copies of the root chains since we'll modify the current ones
		historicalState := &HistoricalDHState{
			DHRatchet: session.MyDHRatchet,
			SendRootChain: nil,
			ReceiveRootChain: &SymmetricKey{Key: append([]byte(nil), session.ReceiveRootChain.Key...)},
		}
		if session.SendRootChain != nil {
			historicalState.SendRootChain = &SymmetricKey{Key: append([]byte(nil), session.SendRootChain.Key...)}
		}
		session.MyDHRatchetHistory = append(session.MyDHRatchetHistory, historicalState)

		// Now update current state
		if session.SendRootChain != nil {
			session.SendRootChain.Zeroize()
		}
		session.SendRootChain = newSendRoot
		session.MyDHRatchet = newDHRatchet

		// Keep history size reasonable - limit to last 100 states
		if len(session.MyDHRatchetHistory) > 100 {
			oldest := session.MyDHRatchetHistory[0]
			if oldest != nil {
				if oldest.DHRatchet != nil {
					oldest.DHRatchet.Zeroize()
				}
				if oldest.SendRootChain != nil {
					oldest.SendRootChain.Zeroize()
				}
				if oldest.ReceiveRootChain != nil {
					oldest.ReceiveRootChain.Zeroize()
				}
			}
			session.MyDHRatchetHistory = session.MyDHRatchetHistory[1:]
		}

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

	// Check if this is an old epoch message - if so, we'll handle it differently
	isOldEpoch := message.LastUpdate < session.ReceiveLastUpdate

	// Only check for replay if this is NOT an old epoch message
	// (old epoch messages might have lower counters but still be legitimate)
	_, keyInCache := session.CachedReceiveKeys[message.Counter]
	if !isOldEpoch && message.Counter <= session.ReceiveCounter && !keyInCache {
		return "", errors.New("message already received - replay attack detected")
	}

	savedReceiveRootChain := session.ReceiveRootChain
	savedSendRootChain := session.SendRootChain
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
	success := false
	defer func() {
		if success {
			for _, key := range oldKeysToZeroize {
				if key != nil {
					key.Zeroize()
				}
			}
		}
	}()

	// Don't do DH ratchet for old epoch messages - handle them via historical state instead
	needsDHRatchet := false
	if !isOldEpoch {
		dhKeyChanged := false
		if session.PartnerDHRatchet == nil {
			dhKeyChanged = true
		} else {
			// Compare fingerprints since PublicKey contains pointers
			msgFP := message.NextDHRatchet.Fingerprint()
			partnerFP := session.PartnerDHRatchet.Fingerprint()
			dhKeyChanged = string(msgFP) != string(partnerFP)
		}
		lastUpdateIncreased := message.LastUpdate > session.ReceiveLastUpdate

		if dhKeyChanged {
			needsDHRatchet = true
		}
		if lastUpdateIncreased {
			needsDHRatchet = true
		}
	}

	if needsDHRatchet {
		// Initialize receive chain if needed
		if session.ReceiveChain == nil {
			session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
		}

		// CRITICAL: Cache intermediate keys BEFORE doing DH ratchet
		// If message.lastUpdate > receiveLastUpdate, it means the sender did a DH ratchet
		// but we might have missed earlier messages from the previous epoch
		// Cache keys for those potentially missing messages using the OLD receive chain
		if message.LastUpdate > session.ReceiveLastUpdate {
			for i := session.ReceiveCounter + 1; i < message.LastUpdate; i++ {
				if _, exists := session.CachedReceiveKeys[i]; !exists {
					key := session.ReceiveChain.DeriveKey(KEY_LABEL)
					session.CachedReceiveKeys[i] = key

					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				} else {
					// Key already cached, just advance chain
					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				}
			}
		}

		// Save partner's old DH ratchet and receive chain state for old epoch handling
		// Save AFTER caching intermediate keys but BEFORE doing DH ratchet
		if session.PartnerDHRatchet != nil {
			partnerHistorical := &PartnerHistoricalDHState{
				MyDHRatchet:      session.MyDHRatchet, // Save OUR DH key, not partner's
				ReceiveChain:     &SymmetricKey{Key: append([]byte(nil), session.ReceiveChain.Key...)},
				ReceiveRootChain: &SymmetricKey{Key: append([]byte(nil), session.ReceiveRootChain.Key...)},
				LastUpdate:       session.ReceiveLastUpdate,
			}
			session.PartnerDHRatchetHistory = append(session.PartnerDHRatchetHistory, partnerHistorical)

			// Limit history size - keep enough for deeply out-of-order messages
			if len(session.PartnerDHRatchetHistory) > 100 {
				oldest := session.PartnerDHRatchetHistory[0]
				if oldest != nil {
					if oldest.MyDHRatchet != nil {
						oldest.MyDHRatchet.Zeroize()
					}
					if oldest.ReceiveChain != nil {
						oldest.ReceiveChain.Zeroize()
					}
					if oldest.ReceiveRootChain != nil {
						oldest.ReceiveRootChain.Zeroize()
					}
				}
				session.PartnerDHRatchetHistory = session.PartnerDHRatchetHistory[1:]
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
		// For messages from the current epoch, generate keys normally
		if message.LastUpdate == session.ReceiveLastUpdate {
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
		// For messages from old epochs (lastUpdate < receiveLastUpdate),
		// we can't generate the key from current state.
		// Let decryption fail and trigger historical retry logic below.
	}

	messageKey, exists := session.CachedReceiveKeys[message.Counter]

	// If key not in cache and this is an old epoch message, try partner's historical DH keys
	if !exists && isOldEpoch && len(session.PartnerDHRatchetHistory) > 0 {
		// Try to find the partner historical state that matches this message's DH key and lastUpdate
		for histIdx := len(session.PartnerDHRatchetHistory) - 1; histIdx >= 0; histIdx-- {
			partnerHistorical := session.PartnerDHRatchetHistory[histIdx]

			// Match on lastUpdate
			if partnerHistorical.LastUpdate != message.LastUpdate {
				continue // LastUpdate doesn't match
			}

			// Found matching historical state! Compute DH with historical MY key and current message's partner key
			// Make a copy of the historical receive chain to derive from
			historicalReceiveChain := &SymmetricKey{Key: append([]byte(nil), partnerHistorical.ReceiveChain.Key...)}
			defer historicalReceiveChain.Zeroize()

			// Derive keys from partnerHistorical.LastUpdate to message.Counter
			// We need to find what the receiveCounter was at that historical point
			// It should be LastUpdate - 1
			historicalReceiveCounter := partnerHistorical.LastUpdate - 1

			// Advance the chain to the message counter by deriving intermediate keys
			var tempChain *SymmetricKey = historicalReceiveChain
			var messageKey *SymmetricKey

			for i := historicalReceiveCounter + 1; i <= message.Counter; i++ {
				// Derive the message key
				key := tempChain.DeriveKey(KEY_LABEL)

				// Advance the chain
				newTempChain := tempChain.DeriveKey(CHAIN_LABEL)
				if tempChain != historicalReceiveChain {
					tempChain.Zeroize()
				}
				tempChain = newTempChain

				if i == message.Counter {
					// This is the key we need
					messageKey = key
				} else {
					// This is an intermediate key we don't need, zeroize it
					key.Zeroize()
				}
			}

			if tempChain != historicalReceiveChain {
				tempChain.Zeroize()
			}
			defer messageKey.Zeroize()

			// Try to decrypt
			additionalData := message.EncodeAdditionalData()
			plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)

			if err == nil {
				// Success!
				return plaintext, nil
			}

			// This historical state didn't work, try next one
		}

		// None of the historical states worked
		return "", errors.New("message from old epoch - no matching historical state found")
	}

	if !exists {
		return "", errors.New("message key not found in cache")
	}

	additionalData := message.EncodeAdditionalData()
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)

	if err != nil {
		// If decryption failed and we have historical DH ratchets, try using them
		// This handles the case where needsDHRatchet but we used the wrong current key
		if needsDHRatchet && len(session.MyDHRatchetHistory) > 0 {
			// Try each historical state, starting from most recent
			for histIdx := len(session.MyDHRatchetHistory) - 1; histIdx >= 0; histIdx-- {
				historicalState := session.MyDHRatchetHistory[histIdx]

				// Restore state for retry
				if session.ReceiveRootChain != savedReceiveRootChain && session.ReceiveRootChain != nil {
					session.ReceiveRootChain.Zeroize()
				}
				if session.ReceiveChain != savedReceiveChain && session.ReceiveChain != nil {
					session.ReceiveChain.Zeroize()
				}

				session.ReceiveRootChain = savedReceiveRootChain
				session.SendRootChain = savedSendRootChain
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

				// Try again with this historical DH key - redo the DH ratchet process
				var retryOldKeysToZeroize []*SymmetricKey

				// Redo DH ratchet logic with historical key
				if session.ReceiveChain == nil {
					session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
				}

				if message.LastUpdate > session.ReceiveLastUpdate {
					for i := session.ReceiveCounter + 1; i < message.LastUpdate; i++ {
						if _, exists := session.CachedReceiveKeys[i]; !exists {
							key := session.ReceiveChain.DeriveKey(KEY_LABEL)
							session.CachedReceiveKeys[i] = key

							newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
							retryOldKeysToZeroize = append(retryOldKeysToZeroize, session.ReceiveChain)
							session.ReceiveChain = newReceiveChain
						} else {
							newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
							retryOldKeysToZeroize = append(retryOldKeysToZeroize, session.ReceiveChain)
							session.ReceiveChain = newReceiveChain
						}
					}
				}

				// Use the historical root chains from when this DH key was active
				baseRoot := historicalState.ReceiveRootChain
				if historicalState.SendRootChain != nil {
					baseRoot = historicalState.SendRootChain
				}

				// Use historical DH ratchet key for computation
				dhSecret := DHCombine(message.NextDHRatchet, &historicalState.DHRatchet.PrivateKey)
				ratchetedRoot := baseRoot.DeriveKey(ROOT_LABEL)

				retryOldKeysToZeroize = append(retryOldKeysToZeroize, session.ReceiveRootChain)

				newReceiveRoot := CombineKeys(ratchetedRoot, dhSecret)
				session.ReceiveRootChain = newReceiveRoot

				session.PartnerDHRatchet = message.NextDHRatchet

				if session.ReceiveChain != nil {
					retryOldKeysToZeroize = append(retryOldKeysToZeroize, session.ReceiveChain)
				}
				session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)

				session.ReceiveLastUpdate = message.LastUpdate
				session.ReceiveCounter = message.LastUpdate - 1

				session.NeedsDHRatchet = true

				// Now generate the message key
				if session.ReceiveChain == nil {
					session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
				}

				if _, exists := session.CachedReceiveKeys[message.Counter]; !exists {
					for i := session.ReceiveCounter + 1; i <= message.Counter; i++ {
						if _, exists := session.CachedReceiveKeys[i]; !exists {
							key := session.ReceiveChain.DeriveKey(KEY_LABEL)
							session.CachedReceiveKeys[i] = key

							newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
							retryOldKeysToZeroize = append(retryOldKeysToZeroize, session.ReceiveChain)
							session.ReceiveChain = newReceiveChain
						}
					}
				}

				retryMessageKey, exists := session.CachedReceiveKeys[message.Counter]
				if !exists {
					// Clean up and continue to next key
					dhSecret.Zeroize()
					ratchetedRoot.Zeroize()
					continue
				}

				retryAdditionalData := message.EncodeAdditionalData()
				retryPlaintext, retryErr := retryMessageKey.AuthenticatedDecrypt(message.Ciphertext, retryAdditionalData, message.IV)

				// Clean up DH secrets
				dhSecret.Zeroize()
				ratchetedRoot.Zeroize()

				if retryErr == nil {
					// Success with historical key!
					delete(session.CachedReceiveKeys, message.Counter)
					retryMessageKey.Zeroize()

					if message.Counter > session.ReceiveCounter {
						session.ReceiveCounter = message.Counter
					}

					// Zeroize old keys now that we're successful
					for _, key := range retryOldKeysToZeroize {
						if key != nil {
							key.Zeroize()
						}
					}

					return retryPlaintext, nil
				}

				// This key didn't work, continue to next one
			}
		}

		if session.ReceiveRootChain != savedReceiveRootChain && session.ReceiveRootChain != nil {
			session.ReceiveRootChain.Zeroize()
		}
		if session.ReceiveChain != savedReceiveChain && session.ReceiveChain != nil {
			session.ReceiveChain.Zeroize()
		}

		session.ReceiveRootChain = savedReceiveRootChain
		session.SendRootChain = savedSendRootChain
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

	success = true
	return plaintext, nil
}
