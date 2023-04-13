/// Hierarchical Derivation implementation (Bip32 subset)
///
use hmac::{Hmac, Mac};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::Sha512;

/// HMAC with SHA-512
type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Debug)]
pub struct XPriv {
    privkey: SecretKey,
    chaincode: ChainCode,
    /// private Secp256k1 context
    secp_context: Secp256k1<All>,
}

pub struct XPub {
    pubkey: PublicKey,
    chaincode: ChainCode,
    /// private Secp256k1 context
    secp_context: Secp256k1<All>,
}

#[derive(Copy, Clone, Debug)]
pub struct ChainCode([u8; 32]);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Internal key format")]
    KeyErrorInternal,
    #[error(transparent)]
    SecpKey(#[from] secp256k1::Error),
}

impl ChainCode {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<&[u8]> for ChainCode {
    type Error = crate::hd::Error;

    fn try_from(arr: &[u8]) -> Result<Self, Error> {
        Ok(ChainCode(
            TryInto::<[u8; 32]>::try_into(arr).map_err(|_| Error::KeyErrorInternal)?,
        ))
    }
}

impl TryFrom<&Vec<u8>> for ChainCode {
    type Error = crate::hd::Error;

    fn try_from(vec: &Vec<u8>) -> Result<Self, Error> {
        Ok(ChainCode(
            TryInto::<[u8; 32]>::try_into(vec.as_slice()).map_err(|_| Error::KeyErrorInternal)?,
        ))
    }
}

/// Derivation domain separator for BIP39 keys.
const BIP39_DOMAIN_SEPARATOR: [u8; 12] = [
    0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64,
];

impl XPriv {
    pub fn from_seed(seed: &Vec<u8>) -> Result<Self, Error> {
        let mut hmac = HmacSha512::new_from_slice(&BIP39_DOMAIN_SEPARATOR).unwrap();
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();
        Ok(XPriv {
            privkey: SecretKey::from_slice(&result[0..32]).map_err(|_| Error::KeyErrorInternal)?,
            chaincode: ChainCode(
                result[32..64]
                    .try_into()
                    .map_err(|_| Error::KeyErrorInternal)?,
            ),
            secp_context: Secp256k1::new(),
        })
    }

    pub fn secret_key(&self) -> SecretKey {
        self.privkey
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.privkey
            .public_key(&self.secp_context)
            .x_only_public_key()
            .0
    }

    pub fn chaincode(&self) -> ChainCode {
        self.chaincode
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec1 = self.secret_key().secret_bytes().to_vec();
        let mut vec2 = self.chaincode.0.to_vec();
        vec1.append(&mut vec2);
        vec1
    }

    pub fn derive_child(&self, child_number: u32, child_is_hardened: bool) -> Result<Self, Error> {
        let mut hmac = HmacSha512::new_from_slice(&self.chaincode.0).unwrap();

        if child_is_hardened {
            hmac.update(&[0]);
            hmac.update(&self.privkey.secret_bytes());
        } else {
            hmac.update(&self.privkey.public_key(&self.secp_context).serialize());
        }
        hmac.update(&child_number.to_be_bytes());

        let result = hmac.finalize().into_bytes();

        let first32: [u8; 32] = result[0..32]
            .try_into()
            .map_err(|_| Error::KeyErrorInternal)?;
        let privkey = self
            .privkey
            .add_tweak(&Scalar::from_be_bytes(first32).map_err(|_| Error::KeyErrorInternal)?)
            .map_err(|_| Error::KeyErrorInternal)?;
        SecretKey::from_slice(&result[0..32]).map_err(|_| Error::KeyErrorInternal)?;

        Ok(XPriv {
            privkey,
            chaincode: ChainCode(
                result[32..64]
                    .try_into()
                    .map_err(|_| Error::KeyErrorInternal)?,
            ),
            secp_context: Secp256k1::new(),
        })
    }

    #[cfg(test)]
    pub fn to_xpub(&self) -> XPub {
        XPub {
            pubkey: self.privkey.public_key(&self.secp_context),
            chaincode: self.chaincode,
            secp_context: Secp256k1::new(),
        }
    }
}

impl XPub {
    pub fn from_parts(pubkey: PublicKey, chaincode_bytes: &Vec<u8>) -> Result<Self, Error> {
        let chaincode = ChainCode::try_from(chaincode_bytes)?;
        Ok(Self {
            pubkey,
            chaincode,
            secp_context: Secp256k1::new(),
        })
    }

    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.pubkey.x_only_public_key().0
    }

    pub fn derive_child(&self, child_number: u32) -> Result<XPub, Error> {
        let mut hmac =
            HmacSha512::new_from_slice(&self.chaincode.0).map_err(|_| Error::KeyErrorInternal)?;

        hmac.update(&self.pubkey.serialize());
        hmac.update(&child_number.to_be_bytes());

        let result = hmac.finalize().into_bytes();

        let first32: [u8; 32] = result[0..32]
            .try_into()
            .map_err(|_| Error::KeyErrorInternal)?;
        let pubkey = self
            .pubkey
            .add_exp_tweak(
                &self.secp_context,
                &Scalar::from_be_bytes(first32).map_err(|_| Error::KeyErrorInternal)?,
            )
            .map_err(|_| Error::KeyErrorInternal)?;

        Ok(XPub {
            pubkey,
            chaincode: ChainCode(
                result[32..64]
                    .try_into()
                    .map_err(|_| Error::KeyErrorInternal)?,
            ),
            secp_context: Secp256k1::new(),
        })
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec1 = self.pubkey.serialize().to_vec();
        let mut vec2 = self.chaincode.0.to_vec();
        vec1.append(&mut vec2);
        vec1
    }
}

#[cfg(test)]
mod test {
    use super::{ChainCode, PublicKey, XPriv, XPub};
    use bip32::{ChildNumber, XPrv};

    /// Some constant, random-generated keys
    const KEY1: &str = "0b441d3662962b4060e15801da6edbf017c14574a03ce8076ceb565fbdad12c1";
    const SEED1: &str = "4a452d8daa6e997ff65bf681262a61b5cadb0ec65989adc594f52cabc96747a19fc6b21bc4db3d9dad553beadc56156b38c377a92d6952dcd2f5d2fe874a2985";

    #[test]
    fn hd_xpriv_from_seed_impl_direct() {
        // Using direct implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv1 = XPriv::from_seed(&master_seed).unwrap();
        assert_eq!(
            hex::encode(xpriv1.to_bytes()),
            "5e0c39eeeaf17b5faf923534d593590b9cd5c2e8667522697ed269afb301ae4ca72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
    }

    #[test]
    fn hd_xpriv_from_seed_impl_bip32() {
        // Using bip32 implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xprv1 = XPrv::new(master_seed).unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xprv1.to_bytes()), hex::encode(xprv1.attrs().chain_code)),
            "5e0c39eeeaf17b5faf923534d593590b9cd5c2e8667522697ed269afb301ae4c_a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
    }

    #[test]
    fn hd_xpriv_derive_child_impl_direct() {
        // Using direct implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv1 = XPriv::from_seed(&master_seed).unwrap();
        let xpriv2 = xpriv1.derive_child(41, false).unwrap();
        assert_eq!(
            hex::encode(xpriv2.to_bytes()),
            "aa47723a923532e164b01f0288bd6f3af05cd2973e1e090f4a3809c9a078b20f172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
    }

    #[test]
    fn hd_xpriv_derive_child_impl_bip32() {
        // Using bip32 implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xprv1 = XPrv::new(&master_seed).unwrap();
        let xprv2 = xprv1
            .derive_child(ChildNumber::new(41, false).unwrap())
            .unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xprv2.to_bytes()), hex::encode(xprv2.attrs().chain_code)),
            "aa47723a923532e164b01f0288bd6f3af05cd2973e1e090f4a3809c9a078b20f_172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
    }

    #[test]
    fn hd_xpriv_to_xpub() {
        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv = XPriv::from_seed(&master_seed).unwrap();
        let xpub = xpriv.to_xpub();
        assert_eq!(
            hex::encode(xpub.to_bytes()),
            "023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
    }

    #[test]
    fn chaincode_frombytes() {
        let cc = ChainCode::try_from(hex::decode(KEY1).unwrap().as_slice()).unwrap();
        assert_eq!(hex::encode(cc.to_bytes()), KEY1);
    }

    #[test]
    fn hd_xpub_from_parts() {
        let xpub1 = XPub::from_parts(
            PublicKey::from_slice(
                &hex::decode("023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004")
                    .unwrap(),
            )
            .unwrap(),
            &hex::decode("a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(xpub1.to_bytes()),
            "023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );

        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv = XPriv::from_seed(&master_seed).unwrap();
        let xpub2 = xpriv.to_xpub();
        assert_eq!(
            hex::encode(xpub2.to_bytes()),
            "023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );

        assert_eq!(hex::encode(xpub1.to_bytes()), hex::encode(xpub2.to_bytes()),);
    }

    #[test]
    fn hd_xpub_derive_child_impl_direct() {
        // Using direct implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv1 = XPriv::from_seed(&master_seed).unwrap();
        let xpub1 = xpriv1.to_xpub();
        let xpub2 = xpub1.derive_child(41).unwrap();
        assert_eq!(
            hex::encode(xpub2.to_bytes()),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
    }

    #[test]
    fn hd_xpub_derive_child_impl_bip32() {
        // Using bip32 implementation
        let master_seed = hex::decode(SEED1).unwrap();
        let xprv1 = XPrv::new(&master_seed).unwrap();
        let xpub1 = xprv1.public_key();
        let xpub2 = xpub1
            .derive_child(ChildNumber::new(41, false).unwrap())
            .unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xpub2.to_bytes()), hex::encode(xpub2.attrs().chain_code)),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d_172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
    }

    #[test]
    fn hd_derive_diamond_impl_direct() {
        // Diamond derivation, using direct implementation:
        // xprv1 --derive--> xprv2 --> xpub2
        // xprv1 --> xpub1 --derive--> xpub2
        // Works only with non-hardened derivation, as hardened derivation is not defined on XPubs
        let master_seed = hex::decode(SEED1).unwrap();
        let xpriv1 = XPriv::from_seed(&master_seed).unwrap();
        assert_eq!(
            hex::encode(xpriv1.to_bytes()),
            "5e0c39eeeaf17b5faf923534d593590b9cd5c2e8667522697ed269afb301ae4ca72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
        let xpriv2 = xpriv1.derive_child(41, false).unwrap();
        assert_eq!(
            hex::encode(xpriv2.to_bytes()),
            "aa47723a923532e164b01f0288bd6f3af05cd2973e1e090f4a3809c9a078b20f172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
        let xpub2 = xpriv2.to_xpub();
        assert_eq!(
            hex::encode(xpub2.to_bytes()),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );

        let xpub1 = xpriv1.to_xpub();
        assert_eq!(
            hex::encode(xpub1.to_bytes()),
            "023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
        let xpub2_2 = xpub1.derive_child(41).unwrap();
        assert_eq!(
            hex::encode(xpub2_2.to_bytes()),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );

        // xpub2 == xpub2_2
        assert_eq!(
            hex::encode(xpub2_2.to_bytes()),
            hex::encode(xpub2.to_bytes()),
        );
    }

    #[test]
    fn hd_derive_diamond_impl_bip32() {
        // Diamond derivation, using bip32 implementation:
        // xprv1 --derive--> xprv2 --> xpub2
        // xprv1 --> xpub1 --derive--> xpub2
        // Works only with non-hardened derivation, as hardened derivation is not defined on XPubs
        let master_seed = hex::decode(SEED1).unwrap();
        let xprv1 = XPrv::new(master_seed).unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xprv1.to_bytes()), hex::encode(xprv1.attrs().chain_code)),
            "5e0c39eeeaf17b5faf923534d593590b9cd5c2e8667522697ed269afb301ae4c_a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
        let xprv2 = xprv1
            .derive_child(ChildNumber::new(41, false).unwrap())
            .unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xprv2.to_bytes()), hex::encode(xprv2.attrs().chain_code)),
            "aa47723a923532e164b01f0288bd6f3af05cd2973e1e090f4a3809c9a078b20f_172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );
        let xpub2 = xprv2.public_key();
        assert_eq!(
            format!("{}_{}", hex::encode(xpub2.to_bytes()), hex::encode(xpub2.attrs().chain_code)),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d_172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );

        let xpub1 = xprv1.public_key();
        assert_eq!(
            format!("{}_{}", hex::encode(xpub1.to_bytes()), hex::encode(xpub1.attrs().chain_code)),
            "023e30affdce3499613549efb2c27f3015ced69cca9cc2f47203ef581b56d8c004_a72f6cb00c43ba80a6e6506996a5202b91d043f326ba1fc4bd7d7de84077984c"
        );
        let xpub2_2 = xpub1
            .derive_child(ChildNumber::new(41, false).unwrap())
            .unwrap();
        assert_eq!(
            format!("{}_{}", hex::encode(xpub2_2.to_bytes()), hex::encode(xpub2_2.attrs().chain_code)),
            "02f3a1dc285e6845d7879a019c74497b82c5cc22d37c1351c15f6a8a8c4be0756d_172d568e1e4fa4db4fc814183d494e6b783d4f4317b8ad0b1bd7f682162698b7"
        );

        // xpub2 == xpub2_2
        assert_eq!(
            format!(
                "{}_{}",
                hex::encode(xpub2_2.to_bytes()),
                hex::encode(xpub2_2.attrs().chain_code)
            ),
            format!(
                "{}_{}",
                hex::encode(xpub2.to_bytes()),
                hex::encode(xpub2.attrs().chain_code)
            ),
        );
    }
}
