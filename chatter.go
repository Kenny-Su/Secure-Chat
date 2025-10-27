// Package chatterbox implements a secure end-to-end encrypted messaging protocol
// based on the Signal Protocol's Double Ratchet algorithm.
//
// PROTOCOL OVERVIEW:
// ==================
//
// 1. HANDSHAKE (Triple Diffie-Hellman):
//    - Establishes initial shared secret between Alice (initiator) and Bob (responder)
//    - Uses three DH computations: g^(A·b), g^(a·B), g^(a·b)
//    - Provides deniability (no signatures) and forward secrecy
//
// 2. DOUBLE RATCHET:
//    Two layers of key derivation for maximum security:
//
//    a) SYMMETRIC RATCHET (per message):
//       - Chain Key (CK) → Message Key (MK) for encryption
//       - Chain Key ratchets after each message: CK_new = KDF(CK_old)
//       - Provides forward secrecy: old keys are deleted immediately
//       - Each message gets a unique encryption key
//
//    b) DH RATCHET (periodic):
//       - When sides alternate sending, perform new DH exchange
//       - Root Key + New DH Secret → New Root Key → New Chain Key
//       - Provides post-compromise security: future messages safe even if current key leaks
//       - Happens in "turns": Bob first, then Alice, then Bob, etc.
//
// 3. OUT-OF-ORDER DELIVERY:
//    - Messages include Counter and LastUpdate fields
//    - Counter: monotonically increasing sequence number
//    - LastUpdate: marks start of current "epoch" (after DH ratchet)
//    - Receiver caches future message keys when receiving early messages
//    - Receiver looks up cached keys when receiving late messages
//
// 4. SECURITY PROPERTIES:
//    - Forward secrecy: old keys deleted immediately after use
//    - Post-compromise security: DH ratchet restores security after compromise
//    - Replay protection: each message key used only once
//    - Authentication: AES-GCM authenticated encryption with AAD
//    - Deniability: no signatures, anyone can simulate conversation
//    - Error recovery: state reverted if tampered message detected
//
// KEY HIERARCHY:
// ==============
// Root Key (changes per DH ratchet)
//   └─> Chain Key (changes per message)
//        ├─> Message Key (one-time use for encryption)
//        └─> Next Chain Key
//
package chatterbox

import (
	"encoding/binary"
	"errors"
)

// Labels used for key derivation function (KDF) to derive different types of keys
// Each label ensures derived keys are cryptographically independent
const HANDSHAKE_CHECK_LABEL byte = 0x11 // Label for deriving handshake verification key
const ROOT_LABEL = 0x22                  // Label for ratcheting the root key
const CHAIN_LABEL = 0x33                 // Label for deriving/ratcheting chain keys
const KEY_LABEL = 0x44                   // Label for deriving message keys from chain

// Chatter represents a participant in the secure messaging protocol
type Chatter struct {
	Identity *KeyPair                  // Long-term identity key pair (public and private keys)
	Sessions map[PublicKey]*Session    // Active sessions with other users, keyed by their public key
}

// Session maintains the cryptographic state for a conversation with one partner
// Implements the Double Ratchet algorithm for forward secrecy and post-compromise security
type Session struct {
	// Diffie-Hellman ratchet state (asymmetric cryptography)
	MyDHRatchet       *KeyPair      // Our current ephemeral DH key pair (changes periodically)
	PartnerDHRatchet  *PublicKey    // Partner's current ephemeral DH public key

	// Root keys (separate for sending and receiving to handle out-of-order messages)
	SendRootChain     *SymmetricKey  // Root chain for sending (can advance independently)
	ReceiveRootChain  *SymmetricKey  // Root chain for receiving (can lag behind)

	// Symmetric ratchet chains (derive message keys)
	SendChain         *SymmetricKey  // Current sending chain key (ratchets after each message)
	ReceiveChain      *SymmetricKey  // Current receiving chain key (ratchets after each message)

	// Out-of-order message handling
	CachedReceiveKeys map[int]*SymmetricKey  // Pre-computed message keys for messages not yet received

	// Message counters (for replay protection and ordering)
	SendCounter       int  // Monotonically increasing counter for messages we send
	SendLastUpdate    int  // Counter value where current send epoch started (after last DH ratchet)
	ReceiveCounter    int  // Highest counter received from partner so far
	ReceiveLastUpdate int  // Partner's current epoch start counter (from their LastUpdate field)

	// State tracking
	NeedsDHRatchet    bool // True when it's our turn to generate a new DH ratchet key
}

// Message represents an encrypted message sent between two parties
type Message struct {
	Sender        *PublicKey   // Identity public key of the sender
	Receiver      *PublicKey   // Identity public key of the intended receiver
	NextDHRatchet *PublicKey   // Sender's current ephemeral DH public key (for DH ratchet)
	Counter       int          // Sequence number of this message (monotonically increasing)
	LastUpdate    int          // Sequence number where sender's current epoch started
	Ciphertext    []byte       // Encrypted message content (includes authentication tag)
	IV            []byte       // Initialization vector for AES-GCM encryption
}

// EncodeAdditionalData encodes message metadata as Additional Authenticated Data (AAD)
// for AES-GCM encryption. This data is authenticated but not encrypted, protecting
// message integrity even though these fields must be sent in plaintext.
// Prevents tampering with: sender/receiver identities, DH ratchet key, counter, and epoch
func (m *Message) EncodeAdditionalData() []byte {
	// Buffer contains: Counter(4) + LastUpdate(4) + Sender(32) + Receiver(32) + NextDHRatchet(32)
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	// Encode counters in little-endian format
	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	// Append public key fingerprints (cryptographic hashes of the keys)
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

// NewChatter creates a new Chatter instance with a freshly generated identity key pair
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()  // Generate long-term identity key (stays constant)
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession terminates a session with a partner and securely erases all key material
// Critical for security: ensures keys cannot be recovered from memory after session ends
// After calling this, a new handshake is required to communicate with this partner again
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("don't have that session open to tear down")
	}

	session := c.Sessions[*partnerIdentity]

	// Zeroize all key material in the session
	// Overwrites the key bytes in memory to prevent recovery
	if session.MyDHRatchet != nil {
		session.MyDHRatchet.Zeroize()  // Erase our DH private key
	}

	if session.SendRootChain != nil {
		session.SendRootChain.Zeroize()  // Erase sending root key
	}

	if session.ReceiveRootChain != nil {
		session.ReceiveRootChain.Zeroize()  // Erase receiving root key
	}

	if session.SendChain != nil {
		session.SendChain.Zeroize()  // Erase sending chain key
	}

	if session.ReceiveChain != nil {
		session.ReceiveChain.Zeroize()  // Erase receiving chain key
	}

	// Zeroize all cached receive keys (for out-of-order messages)
	for _, key := range session.CachedReceiveKeys {
		if key != nil {
			key.Zeroize()
		}
	}

	// Remove the session from our map
	delete(c.Sessions, *partnerIdentity)

	return nil
}

// InitiateHandshake begins a new session as the initiator (Alice's role)
// Part 1 of the Triple Diffie-Hellman (3DH) handshake
// Alice generates an ephemeral key and sends its public part to Bob
// Returns: Alice's ephemeral public key to send to Bob
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("already have session open")
	}

	// Generate a fresh ephemeral key pair for this session (g^a in protocol description)
	ephemeralKeypair := GenerateKeyPair()

	// Create initial session state (waiting for Bob's response)
	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKeypair,  // Our ephemeral key (g^a)
		PartnerDHRatchet:  nil,                // Don't know Bob's yet
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,                  // No messages sent yet
		SendLastUpdate:    1,                  // First message will be #1
		ReceiveCounter:    0,
		ReceiveLastUpdate: 0,
		NeedsDHRatchet:    false,              // Alice doesn't DH ratchet first
	}

	return &ephemeralKeypair.PublicKey, nil
}

// ReturnHandshake responds to an initiated handshake as the responder (Bob's role)
// Part 2 of the Triple Diffie-Hellman (3DH) handshake
// Bob receives Alice's ephemeral key, generates his own, and computes the shared secret
// Returns: Bob's ephemeral public key to send to Alice, and a check key for verification
func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("already have session open")
	}

	// Generate Bob's ephemeral key pair (g^b in protocol description)
	ephemeralKeypair := GenerateKeyPair()

	// Triple Diffie-Hellman: compute three shared secrets and combine them
	// Bob is responder: combine as g^(A·b), g^(a·B), g^(a·b) in this order
	// partnerIdentity = A (Alice's identity public key)
	// partnerEphemeral = a (Alice's ephemeral public key)
	// c.Identity = B (Bob's identity private key)
	// ephemeralKeypair = b (Bob's ephemeral private key)
	dh1 := DHCombine(partnerIdentity, &ephemeralKeypair.PrivateKey)      // g^(A·b)
	dh2 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)           // g^(a·B)
	dh3 := DHCombine(partnerEphemeral, &ephemeralKeypair.PrivateKey)     // g^(a·b)

	// Combine all three DH outputs into a single root key
	rootKey := CombineKeys(dh1, dh2, dh3)

	// Derive a check key for both parties to verify handshake success
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	// Zeroize temporary DH secrets (forward secrecy - no longer needed)
	dh1.Zeroize()
	dh2.Zeroize()
	dh3.Zeroize()

	// Create a copy for sending (send and receive chains can diverge with out-of-order messages)
	sendRootKey := &SymmetricKey{Key: append([]byte(nil), rootKey.Key...)}

	// Create session with initial state
	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKeypair,   // Bob's ephemeral key (g^b)
		PartnerDHRatchet:  partnerEphemeral,   // Alice's ephemeral key (g^a)
		SendRootChain:     sendRootKey,        // For deriving sending keys
		ReceiveRootChain:  rootKey,            // For deriving receiving keys
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		SendLastUpdate:    1,                  // Bob's first message will be #1
		ReceiveCounter:    0,
		ReceiveLastUpdate: 1,                  // Alice (initiator) will send with LastUpdate=1
		NeedsDHRatchet:    true,               // Bob DH ratchets before his first message
	}

	return &ephemeralKeypair.PublicKey, checkKey, nil
}

// FinalizeHandshake completes the handshake as the initiator (Alice's role)
// Part 3 of the Triple Diffie-Hellman (3DH) handshake
// Alice receives Bob's ephemeral key and computes the same shared secret
// Returns: A check key for verification (should match Bob's)
func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("no open session with partner")
	}

	session := c.Sessions[*partnerIdentity]

	// Triple Diffie-Hellman: compute the same three shared secrets as Bob
	// Alice is initiator: combine as g^(A·b), g^(a·B), g^(a·b) in this order
	// partnerEphemeral = b (Bob's ephemeral public key)
	// c.Identity = A (Alice's identity private key)
	// session.MyDHRatchet = a (Alice's ephemeral private key)
	// partnerIdentity = B (Bob's identity public key)
	dh1 := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)            // g^(A·b)
	dh2 := DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey)    // g^(a·B)
	dh3 := DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey)   // g^(a·b)

	// Combine all three DH outputs - should match what Bob computed
	rootKey := CombineKeys(dh1, dh2, dh3)

	// Derive check key - should match Bob's check key for verification
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	// Zeroize temporary DH secrets (forward secrecy)
	dh1.Zeroize()
	dh2.Zeroize()
	dh3.Zeroize()

	// Create a copy for sending (send and receive chains can diverge)
	sendRootKey := &SymmetricKey{Key: append([]byte(nil), rootKey.Key...)}

	// Complete the session setup
	session.PartnerDHRatchet = partnerEphemeral  // Now we know Bob's ephemeral key (g^b)
	session.SendRootChain = sendRootKey
	session.ReceiveRootChain = rootKey
	session.SendLastUpdate = 1
	session.ReceiveLastUpdate = 1

	return checkKey, nil
}

// SendMessage encrypts and sends a message to a partner
// Implements the Double Ratchet algorithm: symmetric ratchet (per message) + DH ratchet (periodic)
// The symmetric ratchet provides forward secrecy by deriving a new key for each message
// The DH ratchet provides post-compromise security by periodically refreshing the root key
func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("no open session with partner")
	}

	session := c.Sessions[*partnerIdentity]

	// ============= DIFFIE-HELLMAN RATCHET (if needed) =============
	// Periodically refresh the root key using a new DH computation
	// This happens when it's our turn (after receiving partner's new DH key)
	if session.NeedsDHRatchet {
		// Generate a fresh DH ratchet key pair
		// This will be combined with partner's DH key to create a new shared secret
		newDHRatchet := GenerateKeyPair()

		// Compute new DH shared secret: combine partner's public key with our new private key
		dhSharedSecret := DHCombine(session.PartnerDHRatchet, &newDHRatchet.PrivateKey)

		// Ratchet the root key: derive a fresh root, then combine with new DH secret
		// This creates: newRoot = KDF(KDF(oldRoot), DHSecret)
		ratchetedRoot := session.ReceiveRootChain.DeriveKey(ROOT_LABEL)

		// Note: Don't zeroize ReceiveRootChain yet - we might still need it for receiving
		// out-of-order messages from the previous epoch
		newSendRoot := CombineKeys(ratchetedRoot, dhSharedSecret)

		// Zeroize temporary values (forward secrecy)
		ratchetedRoot.Zeroize()
		dhSharedSecret.Zeroize()

		// Update our sending root chain with the new value
		if session.SendRootChain != nil {
			session.SendRootChain.Zeroize()  // Delete old sending root
		}
		session.SendRootChain = newSendRoot

		// Replace our DH ratchet key (partner will see this new public key)
		session.MyDHRatchet.Zeroize()  // Delete old private key
		session.MyDHRatchet = newDHRatchet

		// Derive a fresh sending chain from the new root
		if session.SendChain != nil {
			session.SendChain.Zeroize()  // Delete old chain
		}
		session.SendChain = session.SendRootChain.DeriveKey(CHAIN_LABEL)

		// Mark the start of a new epoch - next message starts the new epoch
		session.SendLastUpdate = session.SendCounter + 1

		session.NeedsDHRatchet = false
	}

	// ============= INITIALIZE SEND CHAIN (first message only) =============
	// On the very first message, derive the initial sending chain from root key
	if session.SendChain == nil {
		session.SendChain = session.SendRootChain.DeriveKey(CHAIN_LABEL)
	}

	// ============= SYMMETRIC RATCHET =============
	// Increment message counter (monotonically increasing, never resets)
	session.SendCounter++

	// Derive this message's encryption key from the chain key
	// Each message gets a unique key for forward secrecy
	messageKey := session.SendChain.DeriveKey(KEY_LABEL)

	// Ratchet the send chain forward for the next message
	// Old chain key is zeroized, new chain key derives next message key
	newSendChain := session.SendChain.DeriveKey(CHAIN_LABEL)
	session.SendChain.Zeroize()  // Delete old chain (forward secrecy)
	session.SendChain = newSendChain

	// ============= PREPARE MESSAGE =============
	// Generate a random initialization vector for AES-GCM
	iv := NewIV()

	// Create message structure with metadata
	message := &Message{
		Sender:        &c.Identity.PublicKey,         // Our identity (so receiver knows who sent it)
		Receiver:      partnerIdentity,               // Partner's identity (for authentication)
		Counter:       session.SendCounter,           // This message's sequence number
		LastUpdate:    session.SendLastUpdate,        // When current epoch started
		NextDHRatchet: &session.MyDHRatchet.PublicKey, // Our current DH public key
		IV:            iv,                             // Random IV for encryption
	}

	// ============= ENCRYPT MESSAGE =============
	// Encode metadata as Additional Authenticated Data (AAD)
	// AAD is authenticated but not encrypted - protects integrity of metadata
	additionalData := message.EncodeAdditionalData()

	// Encrypt plaintext using AES-GCM authenticated encryption
	// This produces ciphertext + authentication tag
	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)

	// Zeroize the message key immediately after use (forward secrecy)
	messageKey.Zeroize()

	return message, nil
}

// ReceiveMessage decrypts and processes a message from a partner
// Handles: out-of-order delivery, DH ratcheting, replay protection, and error recovery
// This is the most complex function due to handling all edge cases while maintaining
// cryptographic security properties (forward secrecy, post-compromise security)
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("no open session with sender")
	}

	session := c.Sessions[*message.Sender]

	// ============= REPLAY PROTECTION =============
	// Detect replay attacks: message already received and decrypted
	// If counter <= highest seen AND key not in cache, it means we already processed it
	_, keyInCache := session.CachedReceiveKeys[message.Counter]
	if message.Counter <= session.ReceiveCounter && !keyInCache {
		return "", errors.New("message already received - replay attack detected")
	}

	// ============= ERROR RECOVERY: SAVE STATE =============
	// Save all session state before modifications
	// If decryption fails (tampered message), we must revert to this saved state
	// Otherwise an attacker could corrupt our session by sending bad messages
	savedReceiveRootChain := session.ReceiveRootChain
	savedReceiveChain := session.ReceiveChain
	savedReceiveCounter := session.ReceiveCounter
	savedReceiveLastUpdate := session.ReceiveLastUpdate
	savedPartnerDHRatchet := session.PartnerDHRatchet
	savedNeedsDHRatchet := session.NeedsDHRatchet

	// Track which keys were already cached before processing this message
	// Used to clean up newly cached keys if we need to revert
	savedCachedKeys := make(map[int]bool)
	for k := range session.CachedReceiveKeys {
		savedCachedKeys[k] = true
	}

	// Track keys that should be zeroized on successful completion
	// We defer zeroization until after verifying the message decrypts correctly
	var oldKeysToZeroize []*SymmetricKey

	// ============= DETECT IF DH RATCHET NEEDED =============
	// DH ratchet is needed if:
	// 1. Partner sent a new DH public key (different from what we have), OR
	// 2. Partner started a new epoch (LastUpdate increased)
	needsDHRatchet := false
	if session.PartnerDHRatchet == nil || *message.NextDHRatchet != *session.PartnerDHRatchet {
		needsDHRatchet = true  // Partner has a new DH key
	}
	if message.LastUpdate > session.ReceiveLastUpdate {
		needsDHRatchet = true  // Partner started new epoch
	}

	// ============= PERFORM DH RATCHET (if needed) =============
	if needsDHRatchet {
		// Initialize receive chain if this is the first time
		if session.ReceiveChain == nil {
			session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
		}

		// ===== HANDLE OUT-OF-ORDER: Cache keys from old epoch =====
		// If partner's LastUpdate > our ReceiveLastUpdate, they started a new epoch
		// We need to cache keys for any missing messages from the OLD epoch
		// Example: We received messages 1,2,3. Partner starts new epoch at message 6.
		//          We receive message 6. We need to cache keys for messages 4,5.
		if message.LastUpdate > session.ReceiveLastUpdate {
			// Generate and cache keys for messages we haven't received yet (from old epoch)
			for i := session.ReceiveCounter + 1; i < message.LastUpdate; i++ {
				if _, exists := session.CachedReceiveKeys[i]; !exists {
					// Derive message key and cache it for future out-of-order delivery
					key := session.ReceiveChain.DeriveKey(KEY_LABEL)
					session.CachedReceiveKeys[i] = key

					// Ratchet the receive chain forward
					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				} else {
					// Key already cached (shouldn't happen normally), just advance chain
					newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
					oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
					session.ReceiveChain = newReceiveChain
				}
			}
		}

		// ===== Perform the actual DH ratchet =====
		// Partner ratcheted from THEIR ReceiveRootChain (what they last got from us)
		// We must use the corresponding root: SendRootChain if we've sent, else ReceiveRootChain
		baseRoot := session.ReceiveRootChain
		if session.SendRootChain != nil {
			baseRoot = session.SendRootChain  // Use what we last sent
		}

		// Compute new DH shared secret with partner's new public key and our private key
		dhSecret := DHCombine(message.NextDHRatchet, &session.MyDHRatchet.PrivateKey)

		// Ratchet root, then combine with new DH secret
		ratchetedRoot := baseRoot.DeriveKey(ROOT_LABEL)

		// Mark old receive root for zeroization (but defer until decryption succeeds)
		oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveRootChain)

		// Create new receive root key
		newReceiveRoot := CombineKeys(ratchetedRoot, dhSecret)
		ratchetedRoot.Zeroize()  // Zeroize temporary value immediately
		dhSecret.Zeroize()

		// Update receive root chain
		session.ReceiveRootChain = newReceiveRoot

		// Update partner's DH public key
		session.PartnerDHRatchet = message.NextDHRatchet

		// Derive new receive chain from new root
		if session.ReceiveChain != nil {
			oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
		}
		session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)

		// Update receive tracking - we're now in the new epoch
		session.ReceiveLastUpdate = message.LastUpdate
		session.ReceiveCounter = message.LastUpdate - 1  // Last counter before new epoch starts

		// Mark that it's now our turn to DH ratchet
		session.NeedsDHRatchet = true
	}

	// ============= INITIALIZE RECEIVE CHAIN (first message only) =============
	if session.ReceiveChain == nil {
		session.ReceiveChain = session.ReceiveRootChain.DeriveKey(CHAIN_LABEL)
	}

	// ============= HANDLE OUT-OF-ORDER: Generate keys up to message.Counter =====
	// If message.Counter > ReceiveCounter, we need to generate and cache keys
	// for all messages between ReceiveCounter+1 and message.Counter
	if _, exists := session.CachedReceiveKeys[message.Counter]; !exists {
		// Verify message is from current epoch
		// We can't generate keys for old epochs (chain has moved forward)
		if message.LastUpdate != session.ReceiveLastUpdate {
			// ERROR: Message from old epoch that we didn't cache
			// This shouldn't happen if sender is following protocol
			// REVERT ALL STATE CHANGES to prevent corruption
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

			// Remove newly cached keys (they were derived incorrectly)
			for k := range session.CachedReceiveKeys {
				if !savedCachedKeys[k] {
					session.CachedReceiveKeys[k].Zeroize()
					delete(session.CachedReceiveKeys, k)
				}
			}

			return "", errors.New("message from old epoch not in cache")
		}

		// Generate and cache keys for all missing messages up to this one
		// Example: ReceiveCounter=3, message.Counter=7
		//          Generate keys for messages 4,5,6,7
		for i := session.ReceiveCounter + 1; i <= message.Counter; i++ {
			if _, exists := session.CachedReceiveKeys[i]; !exists {
				// Derive message key from chain
				key := session.ReceiveChain.DeriveKey(KEY_LABEL)
				session.CachedReceiveKeys[i] = key

				// Ratchet chain forward
				newReceiveChain := session.ReceiveChain.DeriveKey(CHAIN_LABEL)
				oldKeysToZeroize = append(oldKeysToZeroize, session.ReceiveChain)
				session.ReceiveChain = newReceiveChain
			}
		}
	}

	// ============= RETRIEVE MESSAGE KEY =============
	// At this point, the key for this message should be cached
	messageKey, exists := session.CachedReceiveKeys[message.Counter]
	if !exists {
		// This should never happen if logic above is correct
		return "", errors.New("message key not found in cache")
	}

	// ============= DECRYPT AND VERIFY MESSAGE =============
	// Use AES-GCM authenticated decryption
	// Verifies both ciphertext integrity and additional data (metadata) integrity
	additionalData := message.EncodeAdditionalData()
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)

	// ============= ERROR RECOVERY: REVERT ON DECRYPTION FAILURE =============
	if err != nil {
		// CRITICAL: Decryption failed (tampered message or wrong key)
		// Must revert ALL state changes to prevent attacker from corrupting session
		// This ensures an attacker can't manipulate our state by sending bad messages

		// Zeroize any new keys we created (they were derived incorrectly)
		if session.ReceiveRootChain != savedReceiveRootChain && session.ReceiveRootChain != nil {
			session.ReceiveRootChain.Zeroize()
		}
		if session.ReceiveChain != savedReceiveChain && session.ReceiveChain != nil {
			session.ReceiveChain.Zeroize()
		}

		// Restore all saved state
		session.ReceiveRootChain = savedReceiveRootChain
		session.ReceiveChain = savedReceiveChain
		session.ReceiveCounter = savedReceiveCounter
		session.ReceiveLastUpdate = savedReceiveLastUpdate
		session.PartnerDHRatchet = savedPartnerDHRatchet
		session.NeedsDHRatchet = savedNeedsDHRatchet

		// Remove any keys we cached during this failed attempt
		for k := range session.CachedReceiveKeys {
			if !savedCachedKeys[k] {
				session.CachedReceiveKeys[k].Zeroize()
				delete(session.CachedReceiveKeys, k)
			}
		}

		return "", err
	}

	// ============= SUCCESS: COMMIT ALL CHANGES =============
	// Decryption succeeded - the message is authentic and hasn't been tampered with
	// Now we can safely commit all state changes and clean up old keys

	// Delete and zeroize the used message key (forward secrecy)
	// Message keys are single-use only - prevents replay if this key leaks
	delete(session.CachedReceiveKeys, message.Counter)
	messageKey.Zeroize()

	// Update ReceiveCounter to track highest message number seen
	// Used for replay protection
	if message.Counter > session.ReceiveCounter {
		session.ReceiveCounter = message.Counter
	}

	// Zeroize all old keys that have been replaced (forward secrecy)
	// These were collected in oldKeysToZeroize during processing
	for _, key := range oldKeysToZeroize {
		if key != nil {
			key.Zeroize()
		}
	}

	return plaintext, nil
}
