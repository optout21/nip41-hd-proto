/// Key management logic
///
use crate::hd::{ChainCode, XPriv, XPub};
use bip39::Mnemonic;
use rand::{thread_rng, RngCore};
use secp256k1::{Parity, SecretKey, XOnlyPublicKey};

/// Keys at a given level: an extended key ('visible' key and 'hidden' chaincode)
#[derive(Clone, Debug)]
struct LevelKeys {
    xpriv: XPriv,
}

impl LevelKeys {
    pub fn vis_pubkey(&self) -> XOnlyPublicKey {
        self.xpriv.public_key()
    }

    pub fn hid_chaincode(&self) -> ChainCode {
        self.xpriv.chaincode()
    }

    pub fn secret_key(&self) -> SecretKey {
        self.xpriv.secret_key()
    }
}

/// Default number of pre-generated key levels
pub const N_DEFAULT: usize = 256;

/// Complete state of NIP-41 keys
pub struct KeyState {
    /// The N key levels
    k: Vec<LevelKeys>,
    /// Number of discarded levels, initially 0
    l: usize,
    /// The BIP39 entropy used to generate this set
    entropy: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no invalidated pubkey yet
    #[error("There is no invalidated pubkey yet")]
    NoInvalidatedKey,
    /// No more levels left, ran out of pre-defined keys
    #[error("No more levels left, ran out of pre-defined keys")]
    NoMoreKeyLevels,
    /// Error processing BIP39 mnemonic
    #[error(transparent)]
    Bip39(#[from] bip39::Error),
    /// Nostr key error
    #[error(transparent)]
    NostrKey(#[from] nostr::key::Error),
    /// Nostr event builder error (key?)
    #[error(transparent)]
    EventBuilder(#[from] nostr::event::builder::Error),
    /// File error (not found)
    #[error(transparent)]
    FileNotFound(#[from] std::io::Error),
    /// File parse error
    #[error("File parse error")]
    FileParse,
    /// Nostr client error
    #[error(transparent)]
    NostrClient(#[from] nostr_sdk::client::Error),
    /// Hex parse error
    #[error(transparent)]
    HexParse(#[from] hex::FromHexError),
    /// Internal key format error
    #[error("Internal key format error")]
    KeyFormatInternal(#[from] crate::hd::Error),
}

/// Info describing the invalidation of a pubkey
pub struct InvalidationInfo {
    /// The currently invalidated pubkey (visible)
    pub invalid_vis: XOnlyPublicKey,
    /// The new valid pubkey (visible)
    pub new_vis: XOnlyPublicKey,
    /// The hidden counterpart of the new pubkey
    pub new_hid: ChainCode,
    /// List of all previous invalidated keys (including the one invalidated just now, plus any earlier ones)
    pub all_invalid: Vec<XOnlyPublicKey>,
}

impl KeyState {
    /// Obtain the current visible pubkey
    pub fn current_pubkey(&self) -> XOnlyPublicKey {
        self.k[self.levels() - 1 - self.l].vis_pubkey()
    }

    /// Obtain the previously used invalid pubkey, if there is one.
    pub fn previous_pubkey(&self) -> Option<XOnlyPublicKey> {
        if self.l == 0 {
            None
        } else {
            Some(self.k[self.levels() - self.l].vis_pubkey())
        }
    }

    /// Obtain the current secret key; security sensitive!
    pub fn current_secret_key(&self) -> SecretKey {
        self.k[self.levels() - 1 - self.l].secret_key()
    }

    pub fn levels(&self) -> usize {
        self.k.len()
    }

    pub fn current_level(&self) -> usize {
        self.l
    }

    pub fn get_entropy(&self) -> Vec<u8> {
        self.entropy.to_owned()
    }

    /// Invalidate the current key; reveal it's secret counterpart,
    /// and (optionally) switch to a new one (the previous one in the pre-generated levels).
    /// Returns these pubkeys:
    /// - the key being invalidated
    /// - its hidden counterpart
    /// - the new key
    /// - a list of all previous invalidated keys (including the one invalidated just now, plus any earlier ones)
    pub fn invalidate(&mut self) -> Result<InvalidationInfo, Error> {
        if self.l >= self.levels() - 1 {
            // No more keys to invalidate to
            return Err(Error::NoMoreKeyLevels);
        }
        // Switch to 'previous' key
        self.l = self.l + 1;
        self.invalidate_prev()
    }

    /// Return the info from the invalidation of the previous pubkey (when the current pubkey was switched to).
    /// If there was no invalidation, error is returned
    pub fn invalidate_prev(&self) -> Result<InvalidationInfo, Error> {
        if self.l == 0 {
            Err(Error::NoInvalidatedKey)
        } else {
            let index_cur = self.levels() - 1 - self.l;
            let index_prev = self.levels() - self.l;
            Ok(InvalidationInfo {
                invalid_vis: self.k[index_prev].vis_pubkey(),
                new_vis: self.k[index_cur].vis_pubkey(),
                new_hid: self.k[index_cur].hid_chaincode(),
                all_invalid: self.k[index_prev..self.levels()]
                    .to_vec()
                    .iter()
                    .map(|kl| kl.vis_pubkey())
                    .collect(),
            })
        }
    }
}

/// Key operations
pub struct KeyManager {}

impl KeyManager {
    pub fn default() -> Self {
        Self {}
    }

    /// Generate a new random state
    pub fn generate_random(&self) -> Result<KeyState, Error> {
        let entropy = Self::generate_random_entropy();
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        self.generate_from_mnemonic_internal(&mnemonic, 0)
    }

    pub fn generate_random_entropy() -> Vec<u8> {
        let mut entropy: [u8; 32] = [0; 32];
        thread_rng().fill_bytes(&mut entropy);
        entropy.to_vec()
    }

    /// Generate state from a BIP-39 mnemonic (string)
    pub fn generate_from_mnemonic(&self, mnemonic_str: &str) -> Result<KeyState, Error> {
        let mnemonic = Mnemonic::parse(mnemonic_str)?;
        self.generate_from_mnemonic_internal(&mnemonic, 0)
    }

    /// Generate state from a BIP-39 mnemonic entropy
    pub fn generate_from_mnemonic_entropy(
        &self,
        entropy: Vec<u8>,
        current_level: usize,
    ) -> Result<KeyState, Error> {
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        self.generate_from_mnemonic_internal(&mnemonic, current_level)
    }

    /// Generate state from a BIP-39 mnemonic (struct)
    fn generate_from_mnemonic_internal(
        &self,
        mnemonic: &Mnemonic,
        current_level: usize,
    ) -> Result<KeyState, Error> {
        let seed = mnemonic.to_seed("");
        self.generate_from_master_seed(seed, current_level, mnemonic.to_entropy())
    }

    /// Generate state from a 64-byte master seed
    fn generate_from_master_seed(
        &self,
        master_seed: [u8; 64],
        current_level: usize,
        entropy: Vec<u8>,
    ) -> Result<KeyState, Error> {
        // Derive initial value, using derivation path "m/44'/1237'/41'"
        let xpriv_0 = XPriv::from_seed(&master_seed.to_vec())?
            .derive_child(44, true)?
            .derive_child(1237, true)?
            .derive_child(41, true)?;
        self.generate_levels_internal(xpriv_0, N_DEFAULT, current_level, entropy)
    }

    /// Generate state
    fn generate_levels_internal(
        &self,
        xpriv_0: XPriv,
        no_levels: usize,
        current_level: usize,
        entropy: Vec<u8>,
    ) -> Result<KeyState, Error> {
        let mut keys: Vec<LevelKeys> = Vec::new();

        let mut current = LevelKeys { xpriv: xpriv_0 };
        keys.push(current.clone());

        for _i in 1..no_levels {
            let next = self.next_level(&current)?;
            keys.push(next.clone());
            current = next;
        }

        Ok(KeyState {
            k: keys,
            l: current_level,
            entropy,
        })
    }

    /// Generate next level from previous one
    fn next_level(&self, prev: &LevelKeys) -> Result<LevelKeys, Error> {
        let xpriv_next = prev.xpriv.derive_child(41, false)?;
        Ok(LevelKeys { xpriv: xpriv_next })
    }

    /// Perform verification of a newly rotated key. Internal version with parity input.
    fn verify_parity(
        &self,
        invalid_vis: &XOnlyPublicKey,
        new_vis: &XOnlyPublicKey,
        new_vis_parity: Parity,
        new_hid: &ChainCode,
    ) -> bool {
        let new_xpriv =
            match XPub::from_parts(new_vis.public_key(new_vis_parity), &new_hid.to_bytes()) {
                Err(_) => return false,
                Ok(pk) => pk,
            };
        let prev_xpriv = match new_xpriv.derive_child(41) {
            Err(_) => return false,
            Ok(xp) => xp,
        };
        // Compare
        *invalid_vis == prev_xpriv.pubkey()
    }

    /// Perform verification of a newly rotated key.
    pub fn verify(
        &self,
        invalid_vis: &XOnlyPublicKey,
        new_vis: &XOnlyPublicKey,
        new_hid: &ChainCode,
    ) -> bool {
        // Try with both parities
        self.verify_parity(invalid_vis, new_vis, Parity::Odd, new_hid)
            || self.verify_parity(invalid_vis, new_vis, Parity::Even, new_hid)
    }
}

#[cfg(test)]
mod test {
    use super::{Error, KeyManager, LevelKeys, XPriv};
    use secp256k1::Secp256k1;

    /// Some constant, random-generated keys
    const SEED1: &str = "4a452d8daa6e997ff65bf681262a61b5cadb0ec65989adc594f52cabc96747a19fc6b21bc4db3d9dad553beadc56156b38c377a92d6952dcd2f5d2fe874a2985";
    const MNEMO1: &str = "oil oil oil oil oil oil oil oil oil oil oil oil";

    fn default_keyset_1_and_2() -> LevelKeys {
        LevelKeys {
            xpriv: XPriv::from_seed(&hex::decode(SEED1).unwrap())
                .unwrap()
                .derive_child(44, true)
                .unwrap()
                .derive_child(1237, true)
                .unwrap()
                .derive_child(41, true)
                .unwrap(),
        }
    }

    #[test]
    fn generate_random_get_current() {
        let mgr = KeyManager::default();
        let state = mgr.generate_random().unwrap();

        assert_eq!(state.levels(), 256);

        let sk = state.current_secret_key();
        let pk = state.current_pubkey();
        // check sk-pk
        let secp = Secp256k1::new();
        assert_eq!(
            sk.public_key(&secp).x_only_public_key().0.serialize(),
            pk.serialize()
        );
    }

    #[test]
    fn invalidate_and_verify() {
        let mgr = KeyManager::default();
        let mut state = mgr.generate_random().unwrap();
        let pre_curr = state.current_pubkey();

        // no invalidated yet
        match state.invalidate_prev() {
            Err(Error::NoInvalidatedKey) => {}
            _ => panic!("Did not get expected error"),
        }

        // do invalidate current key
        let inv_info = state.invalidate().unwrap();
        assert_eq!(inv_info.invalid_vis, pre_curr);
        assert_eq!(inv_info.all_invalid.len(), 1);
        assert_eq!(inv_info.all_invalid[0], pre_curr);
        // current has changed
        assert_eq!(state.current_pubkey(), inv_info.new_vis);

        // verify
        let verify_result = mgr.verify(&inv_info.invalid_vis, &inv_info.new_vis, &inv_info.new_hid);
        assert!(verify_result);

        // Same invalidation info can be retrieved
        let inv_info2 = state.invalidate_prev().unwrap();
        assert_eq!(inv_info2.new_vis, inv_info.new_vis);
    }

    #[test]
    fn invalidate_and_verify_many() {
        let mgr = KeyManager::default();
        let mut state = mgr.generate_random().unwrap();
        assert_eq!(state.levels(), 256);
        // do 255 invalidates
        for i in 0..256 - 1 {
            let pk = state.current_pubkey();
            let inv_info = state.invalidate().unwrap();
            assert_eq!(inv_info.invalid_vis, pk);
            assert_eq!(inv_info.all_invalid.len(), i + 1);
            // verify
            let verify_result =
                mgr.verify(&inv_info.invalid_vis, &inv_info.new_vis, &inv_info.new_hid);
            assert!(verify_result);
        }
        // try another one, should fail
        match state.invalidate() {
            Err(Error::NoMoreKeyLevels) => {}
            _ => panic!("Did not get expected error"),
        }
    }

    #[test]
    fn verify() {
        let mgr = KeyManager::default();
        let current = default_keyset_1_and_2();

        let next = mgr.next_level(&current).unwrap();

        let verify_result = mgr.verify(
            &next.vis_pubkey(),
            &current.vis_pubkey(),
            &current.hid_chaincode(),
        );
        assert!(verify_result);

        // Invoking verify with wrong value should return false
        assert!(!mgr.verify(
            &next.vis_pubkey(),
            &current.vis_pubkey(),
            // this is the wrong value here
            &next.hid_chaincode(),
        ));
    }

    #[test]
    fn generate_mnemonic() {
        let mgr = KeyManager::default();
        let state1 = mgr.generate_from_mnemonic(MNEMO1).unwrap();

        let pk1 = state1.current_pubkey();
        assert_eq!(
            hex::encode(pk1.serialize()),
            "6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd"
        );

        // Generate again. result should be same (deterministic)
        let state2 = mgr.generate_from_mnemonic(MNEMO1).unwrap();
        let pk2 = state2.current_pubkey();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn generate_master_seed() {
        let master_seed: [u8; 64] = hex::decode(SEED1).unwrap().try_into().unwrap();

        let mgr = KeyManager::default();
        let state1 = mgr
            .generate_from_master_seed(master_seed, 0, Vec::new())
            .unwrap();

        let pk1 = state1.current_pubkey();
        assert_eq!(
            hex::encode(pk1.serialize()),
            "713a8707663397094dcad7045b45df0c6c28b3ca850ffb57dcec8557b2ad6eae"
        );

        // Generate again. result should be same (deterministic)
        let state2 = mgr
            .generate_from_master_seed(master_seed, 0, Vec::new())
            .unwrap();
        let pk2 = state2.current_pubkey();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn manager_next_level() {
        let mgr = KeyManager::default();
        let current = default_keyset_1_and_2();

        let next = mgr.next_level(&current).unwrap();
        assert_eq!(
            hex::encode(next.xpriv.to_bytes()),
            "5a09947c65fdfcc5aaafe4b84c13646a9c3b11e2e1330bf69fc6478c2af8143150773cfc5c70b5f60d70b41efaa0333efb7d67f5687fc7f35b3f0a6658f99b75"
        );
    }
}
