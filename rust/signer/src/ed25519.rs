// Originally developed in https://github.com/polkadot-js/wasm
// forked at commit 141a067b853b22548777a2da127bf63651c353a7

//use std::convert::TryFrom;
use base58::ToBase58;
use bip39::{Language, Mnemonic};
use codec::Encode;//, Decode};
use regex::Regex;
use substrate_bip39::seed_from_entropy;
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signer as _};
//use wasm_bindgen::prelude::*;
use lazy_static::lazy_static;

pub struct KeyPair(Keypair);
type Seed = [u8; 32];

//const SIGNING_CTX: &[u8] = b"substrate";
const JUNCTION_ID_LEN: usize = 32;
//const CHAIN_CODE_LENGTH: usize = 32;
//const MINI_SECRET_KEY_LENGTH: usize = 32;

impl KeyPair {
	pub fn from_bip39_phrase(phrase: &str, password: Option<&str>) -> Option<KeyPair> {
		let mnemonic = Mnemonic::from_phrase(phrase, Language::English).ok()?;
		let big_seed=seed_from_entropy(mnemonic.entropy(), password.unwrap_or("")).ok()?;
        let mut seed = Seed::default();
        seed.copy_from_slice(&big_seed[0..32]);
        let secret = SecretKey::from_bytes(&big_seed[0..32]).ok()?;
        let public = PublicKey::from(&secret);
		Some(KeyPair(Keypair{secret, public}))
	}
/*
	fn derive_secret_key(&self, path: impl Iterator<Item=DeriveJunction>) -> Option<MiniSecretKey> {
		let mut result: SecretKey = self.0.secret.clone();
		let mut path_peekable = path.peekable();
		let mut derived_result: Option<MiniSecretKey> = None;
		while let Some(derive_junction) = path_peekable.next() {
			if path_peekable.peek().is_some() {
				result = match derive_junction {
	        		DeriveJunction::Soft(cc) => return crate::Error::SoftKeyUnsupported,
    		    	DeriveJunction::Hard(cc) => derive_hard_junction(&acc, cc),
				}
			}
			let last_chain_code = derive_junction.unwrap_inner();
			let (derived_mini_secret_key, _) = result.hard_derive_mini_secret_key(Some(ChainCode(last_chain_code)), b"");
			derived_result = Some(derived_mini_secret_key);
		}

		derived_result
	}
*//*
	pub fn get_derived_secret(suri: &str) -> Option<[u8; MINI_SECRET_KEY_LENGTH]> {
		lazy_static! {
			static ref RE_SURI: Regex = {
				Regex::new(r"^(?P<phrase>\w+( \w+)*)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$")
					.expect("constructed from known-good static value; qed")
			};
			static ref RE_JUNCTION: Regex =
				Regex::new(r"/(/?[^/]+)").expect("constructed from known-good static value; qed");
		}
		let cap = RE_SURI.captures(suri)?;
		let paths = RE_JUNCTION
			.captures_iter(&cap["path"])
			.map(|j| DeriveJunction::from(&j[1]));
		let pair = Self::from_bip39_phrase(
			cap.name("phrase").map(|p| p.as_str())?,
			cap.name("password").map(|p| p.as_str()),
		)?;
		let mini_secret_key = pair.derive_secret_key(paths)?;
		Some(*mini_secret_key.as_bytes())
	}
*/

	// Should match implementation at https://github.com/paritytech/substrate/blob/master/core/primitives/src/crypto.rs#L653-L682
	pub fn from_suri(suri: &str) -> Option<KeyPair> {
		lazy_static! {
			static ref RE_SURI: Regex = {
				Regex::new(r"^(?P<phrase>\w+( \w+)*)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$")
					.expect("constructed from known-good static value; qed")
			};
			static ref RE_JUNCTION: Regex =
				Regex::new(r"/(/?[^/]+)").expect("constructed from known-good static value; qed");
		}
		let cap = RE_SURI.captures(suri)?;
		let paths = RE_JUNCTION
			.captures_iter(&cap["path"])
			.map(|j| DeriveJunction::from(&j[1]));
		let pair = Self::from_bip39_phrase(
			cap.name("phrase").map(|p| p.as_str())?,
			cap.name("password").map(|p| p.as_str()),
		)?;
		Some(pair.derive(paths))
	}

	fn derive(&self, path: impl Iterator<Item=DeriveJunction>) -> Self {
		let mut acc= self.0.secret.to_bytes();
		for j in path {
            match j {
			    DeriveJunction::Soft(_cc) => panic!("soft signature not supported"),
			    DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
            }
        };
        let secret = SecretKey::from_bytes(&acc).unwrap();
        let public = PublicKey::from(&secret);
		KeyPair(Keypair{secret, public})
	}

	pub fn ss58_address(&self, prefix: u8) -> String {
		let mut v = vec![prefix];
		v.extend_from_slice(&self.0.public.to_bytes());
		let r = ss58hash(&v);
		v.extend_from_slice(&r.as_bytes()[0..2]);
		v.to_base58()
	}

	pub fn sign(&self, message: &[u8]) -> [u8; 64] {
		self.0.sign(message).to_bytes()
	}
/*
	pub fn verify_signature(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> crate::result::Result<bool> {
		let context = schnorrkel::signing_context(SIGNING_CTX);
		let signature =
			Signature::from_bytes(signature).map_err(|e| crate::result::Error::Signature(e))?;
		Ok(self.0.verify(context.bytes(&message), &signature).is_ok())
	}*/
}

fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
	("Ed25519HDKD", secret_seed, cc).using_encoded(|data| {
		let mut res = [0u8; 32];
		res.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
		res
	})
}

/// A since derivation junction description. It is the single parameter used when creating
/// a new secret key from an existing secret key and, in the case of `SoftRaw` and `SoftIndex`
/// a new public key from an existing public key.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
enum DeriveJunction {
	/// Soft (vanilla) derivation. Public keys have a correspondent derivation.
	Soft([u8; JUNCTION_ID_LEN]),
	/// Hard ("hardened") derivation. Public keys do not have a correspondent derivation.
	Hard([u8; JUNCTION_ID_LEN]),
}

impl DeriveJunction {

	/// Consume self to return a hard derive junction with the same chain code.
	fn harden(self) -> Self {
		DeriveJunction::Hard(self.unwrap_inner())
	}

	/// Create a new soft (vanilla) DeriveJunction from a given, encodable, value.
	///
	/// If you need a hard junction, use `hard()`.
	fn soft<T: Encode>(index: T) -> Self {
		let mut cc: [u8; JUNCTION_ID_LEN] = Default::default();
		index.using_encoded(|data| {
			if data.len() > JUNCTION_ID_LEN {
				let hash_result = blake2_rfc::blake2b::blake2b(JUNCTION_ID_LEN, &[], data);
				let hash = hash_result.as_bytes();
				cc.copy_from_slice(hash);
			} else {
				cc[0..data.len()].copy_from_slice(data);
			}
		});
		DeriveJunction::Soft(cc)
	}

	/// Consume self to return the chain code.
	fn unwrap_inner(self) -> [u8; JUNCTION_ID_LEN] {
		match self {
			DeriveJunction::Hard(c) | DeriveJunction::Soft(c) => c,
		}
	}
}

impl<T: AsRef<str>> From<T> for DeriveJunction {
	fn from(j: T) -> DeriveJunction {
		let j = j.as_ref();
		let (code, hard) = if j.starts_with("/") {
			(&j[1..], true)
		} else {
			(j, false)
		};

		let res = if let Ok(n) = str::parse::<u64>(code) {
			// number
			DeriveJunction::soft(n)
		} else {
			// something else
			DeriveJunction::soft(code)
		};

		if hard {
			res.harden()
		} else {
			res
		}
	}
}

fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
	const PREFIX: &[u8] = b"SS58PRE";

	let mut context = blake2_rfc::blake2b::Blake2b::new(64);
	context.update(PREFIX);
	context.update(data);
	context.finalize()
}
/*
/// Keypair helper function.
fn create_from_pair(pair: &[u8]) -> Keypair {
	match Keypair::from_bytes(pair) {
		Ok(pair) => return pair,
		Err(_) => panic!("Provided pair is invalid.")
	}
}

/// Keypair helper function
fn create_from_parts(pubkey: &[u8], seckey: &[u8]) -> Keypair {
	let mut pair = vec![];

	pair.extend_from_slice(seckey);
	pair.extend_from_slice(pubkey);

	create_from_pair(&pair)
}

/// Keypair helper function.
fn create_from_seed(seed: &[u8]) -> Keypair {
	let seckey = SecretKey::from_bytes(seed).unwrap();
	let pubkey: PublicKey = (&seckey).into();

	create_from_parts(pubkey.as_bytes(), seed)
}

/// PublicKey helper
fn create_public(pubkey: &[u8]) -> PublicKey {
	match PublicKey::from_bytes(pubkey) {
		Ok(pubkey) => return pubkey,
		Err(_) => panic!("Provided public key is invalid.")
	}
}

/// Generate a key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes.
#[wasm_bindgen]
pub fn ext_ed_from_seed(seed: &[u8]) -> Vec<u8> {
	create_from_seed(seed)
		.to_bytes()
		.to_vec()
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * pubkey: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
///
/// * returned vector is the signature consisting of 64 bytes.
#[wasm_bindgen]
pub fn ext_ed_sign(pubkey: &[u8], seckey: &[u8], message: &[u8]) -> Vec<u8> {
	create_from_parts(pubkey, seckey)
		.sign(message)
		.to_bytes()
		.to_vec()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 32 element
#[wasm_bindgen]
pub fn ext_ed_verify(signature: &[u8], message: &[u8], pubkey: &[u8]) -> bool {
	let signature = match Signature::try_from(signature) {
		Ok(signature) => signature,
		Err(_) => return false
	};

	create_public(pubkey)
		.verify(message, &signature)
		.is_ok()
}

#[cfg(test)]
pub mod tests {
	extern crate rand;

	use hex_literal::hex;
	use super::*;
	use ed25519_dalek::{SIGNATURE_LENGTH, KEYPAIR_LENGTH, SECRET_KEY_LENGTH};

	fn generate_random_seed() -> Vec<u8> {
		(0..32).map(|_| rand::random::<u8>() ).collect()
	}

	#[test]
	fn can_create_keypair() {
		let seed = generate_random_seed();
		let keypair = ext_ed_from_seed(seed.as_slice());

		assert!(keypair.len() == KEYPAIR_LENGTH);
	}

	#[test]
	fn creates_pair_from_known() {
		let seed = b"12345678901234567890123456789012";
		let expected = hex!("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee");
		let keypair = ext_ed_from_seed(seed);
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}

	#[test]
	fn can_sign_message() {
		let seed = generate_random_seed();
		let keypair = ext_ed_from_seed(seed.as_slice());
		let private = &keypair[0..SECRET_KEY_LENGTH];
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_ed_sign(public, private, message);

		assert!(signature.len() == SIGNATURE_LENGTH);
	}

	#[test]
	fn can_verify_message() {
		let seed = generate_random_seed();
		let keypair = ext_ed_from_seed(seed.as_slice());
		let private = &keypair[0..SECRET_KEY_LENGTH];
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let signature = ext_ed_sign(public, private, message);
		let is_valid = ext_ed_verify(&signature[..], message, public);

		assert!(is_valid);
	}

	#[test]
	fn can_verify_known() {
		let public = hex!("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee");
		let message = b"this is a message";
		let signature = hex!("90588f3f512496f2dd40571d162e8182860081c74e2085316e7c4396918f07da412ee029978e4dd714057fe973bd9e7d645148bf7b66680d67c93227cde95202");
		let is_valid = ext_ed_verify(&signature, message, &public);

		assert!(is_valid);
	}

	#[test]
	fn can_verify_known_wrong() {
		let public = hex!("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee");
		let message = b"this is a message";
		let signature = &[0u8; 64];
		let is_valid = ext_ed_verify(signature, message, &public);

		assert_eq!(is_valid, false);
	}
}*/
