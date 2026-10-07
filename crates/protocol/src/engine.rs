use std::collections::{BTreeMap, HashMap};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crypto_box::{aead::OsRng, PublicKey, SecretKey};
use ed25519_dalek::{Verifier, VerifyingKey};
use frost_ed25519 as frost;
use rand::rngs::OsRng as RandOsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ClientMsg, Error, GroupDto, SealedPackage, ServerMsg};

type R1Secret = frost::keys::dkg::round1::SecretPackage;
type R1Package = frost::keys::dkg::round1::Package;
type R2Secret = frost::keys::dkg::round2::SecretPackage;
type R2Package = frost::keys::dkg::round2::Package;
type KeyPackage = frost::keys::KeyPackage;
type PublicKeyPackage = frost::keys::PublicKeyPackage;
type SigningNonces = frost::round1::SigningNonces;
type SigningCommitments = frost::round1::SigningCommitments;
type SignatureShare = frost::round2::SignatureShare;

/// X25519 device key. Round-2 DKG packages are sealed to this key so the relay
/// cannot reconstruct the polynomial shares.
#[derive(Clone)]
pub struct DeviceKey {
    secret: SecretKey,
}

impl DeviceKey {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_hex(hex_value: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_value.trim())
            .map_err(|_| Error::msg("секрет устройства не является hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::msg("секрет устройства должен быть 32 байта"))?;
        Ok(Self {
            secret: SecretKey::from_bytes(bytes),
        })
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.secret.public_key().as_bytes())
    }

    pub fn seal_to(&self, recipient_public_hex: &str, plaintext: &[u8]) -> Result<String, Error> {
        let recipient = parse_public(recipient_public_hex)?;
        let sealed = recipient
            .seal(&mut OsRng, plaintext)
            .map_err(|_| Error::msg("не удалось зашифровать пакет DKG"))?;
        let _ = self;
        Ok(B64.encode(sealed))
    }

    pub fn open(&self, ciphertext_b64: &str) -> Result<Vec<u8>, Error> {
        let bytes = B64
            .decode(ciphertext_b64.trim())
            .map_err(|_| Error::msg("шифртекст DKG не является base64"))?;
        self.secret
            .unseal(&bytes)
            .map_err(|_| Error::msg("не удалось расшифровать пакет DKG"))
    }
}

fn parse_public(hex_value: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(hex_value.trim())
        .map_err(|_| Error::msg("публичный ключ устройства не является hex"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::msg("публичный ключ устройства должен быть 32 байта"))?;
    Ok(PublicKey::from(bytes))
}

fn ident(value: u16) -> Result<frost::Identifier, Error> {
    if value == 0 {
        return Err(Error::msg("идентификатор FROST не может быть 0"));
    }
    frost::Identifier::try_from(value)
        .map_err(|err| Error::msg(format!("идентификатор FROST: {err}")))
}

fn ident_to_u16(id: frost::Identifier) -> Result<u16, Error> {
    let bytes = id.serialize();
    if bytes.len() != 32 || bytes[2..].iter().any(|byte| *byte != 0) {
        return Err(Error::msg("идентификатор FROST вне диапазона u16"));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn to_json<T: Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|err| Error::msg(format!("сериализация: {err}")))
}

fn from_json<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, Error> {
    serde_json::from_str(value).map_err(|err| Error::msg(format!("разбор пакета: {err}")))
}

pub fn package_verifying_key_hex(public_key_package_json: &str) -> Result<String, Error> {
    let package: PublicKeyPackage = from_json(public_key_package_json)?;
    let bytes = package
        .verifying_key()
        .serialize()
        .map_err(|err| Error::msg(format!("ключ проверки: {err}")))?;
    Ok(hex::encode(bytes))
}

pub fn aggregate_signature(
    message: &[u8],
    commitments: &[(u16, String)],
    shares: &[(u16, String)],
    public_key_package_json: &str,
) -> Result<String, Error> {
    let mut commitment_map = BTreeMap::new();
    for (id, json) in commitments {
        commitment_map.insert(ident(*id)?, from_json::<SigningCommitments>(json)?);
    }
    let mut share_map = BTreeMap::new();
    for (id, json) in shares {
        share_map.insert(ident(*id)?, from_json::<SignatureShare>(json)?);
    }
    let pubkey: PublicKeyPackage = from_json(public_key_package_json)?;
    let signing_package = frost::SigningPackage::new(commitment_map, message);
    let signature = frost::aggregate(&signing_package, &share_map, &pubkey)
        .map_err(|err| Error::msg(format!("сборка подписи: {err}")))?;
    pubkey
        .verifying_key()
        .verify(message, &signature)
        .map_err(|err| Error::msg(format!("подпись не прошла проверку FROST: {err}")))?;
    let bytes = signature
        .serialize()
        .map_err(|err| Error::msg(format!("сериализация подписи: {err}")))?;
    Ok(hex::encode(bytes))
}

pub fn verify_ed25519(
    verifying_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), Error> {
    let vk_bytes =
        hex::decode(verifying_key_hex).map_err(|_| Error::msg("ключ проверки не является hex"))?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|_| Error::msg("подпись не является hex"))?;
    let vk_bytes: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| Error::msg("ключ проверки Ed25519 должен быть 32 байта"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::msg("подпись Ed25519 должна быть 64 байта"))?;
    let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|err| Error::msg(format!("ключ Ed25519: {err}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::msg("подпись не прошла проверку Ed25519"))
}

pub fn message_preview(bytes: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return String::new();
    };
    if text
        .chars()
        .any(|ch| ch != '\n' && ch != '\t' && ch.is_control())
    {
        return String::new();
    }
    let count = text.chars().count();
    if count <= 180 {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(180).collect::<String>())
    }
}

/// One participant's DKG state. Secrets stay in this process (and in SQLite).
pub struct DkgLocal {
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    round1_secret: Option<R1Secret>,
    round2_secret: Option<R2Secret>,
    round1_in: BTreeMap<frost::Identifier, R1Package>,
    round2_in: BTreeMap<frost::Identifier, R2Package>,
    round2_started: bool,
    key: Option<KeyPackage>,
    pubkey: Option<PublicKeyPackage>,
}

#[derive(Serialize, Deserialize)]
struct DkgBlob {
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    round1_secret: Option<String>,
    round2_secret: Option<String>,
    round1_in: Vec<(u16, String)>,
    round2_in: Vec<(u16, String)>,
    round2_started: bool,
    key: Option<String>,
    pubkey: Option<String>,
}

impl DkgLocal {
    pub fn new(identifier: u16, max_signers: u16, min_signers: u16) -> Result<Self, Error> {
        let _ = ident(identifier)?;
        if min_signers < 2 || min_signers > max_signers {
            return Err(Error::msg("порог должен быть от 2 до числа участников"));
        }
        Ok(Self {
            identifier,
            max_signers,
            min_signers,
            round1_secret: None,
            round2_secret: None,
            round1_in: BTreeMap::new(),
            round2_in: BTreeMap::new(),
            round2_started: false,
            key: None,
            pubkey: None,
        })
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn key_json(&self) -> Result<Option<String>, Error> {
        self.key.as_ref().map(to_json).transpose()
    }

    pub fn pubkey_json(&self) -> Result<Option<String>, Error> {
        self.pubkey.as_ref().map(to_json).transpose()
    }

    /// Broadcast package for round 1. `None` once it has already been produced.
    pub fn start(&mut self) -> Result<Option<R1Package>, Error> {
        if self.round1_secret.is_some() || self.key.is_some() {
            return Ok(None);
        }
        let (secret, package) = frost::keys::dkg::part1(
            ident(self.identifier)?,
            self.max_signers,
            self.min_signers,
            &mut RandOsRng,
        )
        .map_err(|err| Error::msg(format!("DKG раунд 1: {err}")))?;
        self.round1_secret = Some(secret);
        Ok(Some(package))
    }

    /// Returns round-2 packages addressed by participant identifier, once.
    pub fn push_round1(
        &mut self,
        from: u16,
        package_json: &str,
    ) -> Result<Option<Vec<(u16, String)>>, Error> {
        if from == self.identifier || self.key.is_some() {
            return Ok(None);
        }
        let package: R1Package = from_json(package_json)?;
        self.round1_in.entry(ident(from)?).or_insert(package);
        if self.round2_started || self.round1_in.len() != usize::from(self.max_signers - 1) {
            return Ok(None);
        }
        let secret = self
            .round1_secret
            .take()
            .ok_or_else(|| Error::msg("нет секрета раунда 1"))?;
        let (secret, packages) = frost::keys::dkg::part2(secret, &self.round1_in)
            .map_err(|err| Error::msg(format!("DKG раунд 2: {err}")))?;
        self.round2_secret = Some(secret);
        self.round2_started = true;
        let mut encoded = Vec::new();
        for (id, package) in packages {
            encoded.push((ident_to_u16(id)?, to_json(&package)?));
        }
        Ok(Some(encoded))
    }

    pub fn push_round2(&mut self, from: u16, package_json: &str) -> Result<Option<String>, Error> {
        if from == self.identifier || self.pubkey.is_some() {
            return Ok(None);
        }
        let package: R2Package = from_json(package_json)?;
        self.round2_in.entry(ident(from)?).or_insert(package);
        if self.round2_in.len() != usize::from(self.max_signers - 1) {
            return Ok(None);
        }
        let secret = self
            .round2_secret
            .as_ref()
            .ok_or_else(|| Error::msg("нет секрета раунда 2"))?;
        let (key, pubkey) = frost::keys::dkg::part3(secret, &self.round1_in, &self.round2_in)
            .map_err(|err| Error::msg(format!("DKG финал: {err}")))?;
        let json = to_json(&pubkey)?;
        self.key = Some(key);
        self.pubkey = Some(pubkey);
        Ok(Some(json))
    }

    pub fn export(&self) -> Result<String, Error> {
        let blob = DkgBlob {
            identifier: self.identifier,
            max_signers: self.max_signers,
            min_signers: self.min_signers,
            round1_secret: self.round1_secret.as_ref().map(to_json).transpose()?,
            round2_secret: self.round2_secret.as_ref().map(to_json).transpose()?,
            round1_in: self
                .round1_in
                .iter()
                .map(|(id, package)| Ok((ident_to_u16(*id)?, to_json(package)?)))
                .collect::<Result<Vec<_>, Error>>()?,
            round2_in: self
                .round2_in
                .iter()
                .map(|(id, package)| Ok((ident_to_u16(*id)?, to_json(package)?)))
                .collect::<Result<Vec<_>, Error>>()?,
            round2_started: self.round2_started,
            key: self.key_json()?,
            pubkey: self.pubkey_json()?,
        };
        to_json(&blob)
    }

    pub fn import(blob: &str) -> Result<Self, Error> {
        let blob: DkgBlob = from_json(blob)?;
        let mut round1_in = BTreeMap::new();
        for (id, json) in blob.round1_in {
            round1_in.insert(ident(id)?, from_json(&json)?);
        }
        let mut round2_in = BTreeMap::new();
        for (id, json) in blob.round2_in {
            round2_in.insert(ident(id)?, from_json(&json)?);
        }
        Ok(Self {
            identifier: blob.identifier,
            max_signers: blob.max_signers,
            min_signers: blob.min_signers,
            round1_secret: blob.round1_secret.as_deref().map(from_json).transpose()?,
            round2_secret: blob.round2_secret.as_deref().map(from_json).transpose()?,
            round1_in,
            round2_in,
            round2_started: blob.round2_started,
            key: blob.key.as_deref().map(from_json).transpose()?,
            pubkey: blob.pubkey.as_deref().map(from_json).transpose()?,
        })
    }
}

struct SignLocal {
    message: Vec<u8>,
    signers: Vec<u16>,
    nonces: SigningNonces,
    commitments: BTreeMap<frost::Identifier, SigningCommitments>,
    share_sent: bool,
}

#[derive(Serialize, Deserialize)]
struct SignBlob {
    message_hex: String,
    signers: Vec<u16>,
    nonces: String,
    commitments: Vec<(u16, String)>,
    share_sent: bool,
}

impl SignLocal {
    fn export(&self) -> Result<String, Error> {
        let blob = SignBlob {
            message_hex: hex::encode(&self.message),
            signers: self.signers.clone(),
            nonces: to_json(&self.nonces)?,
            commitments: self
                .commitments
                .iter()
                .map(|(id, commitment)| Ok((ident_to_u16(*id)?, to_json(commitment)?)))
                .collect::<Result<Vec<_>, Error>>()?,
            share_sent: self.share_sent,
        };
        to_json(&blob)
    }

    fn import(blob: &str) -> Result<Self, Error> {
        let blob: SignBlob = from_json(blob)?;
        let mut commitments = BTreeMap::new();
        for (id, json) in blob.commitments {
            commitments.insert(ident(id)?, from_json(&json)?);
        }
        Ok(Self {
            message: hex::decode(&blob.message_hex)
                .map_err(|_| Error::msg("сообщение подписи повреждено"))?,
            signers: blob.signers,
            nonces: from_json(&blob.nonces)?,
            commitments,
            share_sent: blob.share_sent,
        })
    }
}

/// Per-group ceremony driver used by the desktop app.
pub struct Participant {
    device: DeviceKey,
    group: GroupDto,
    dkg: Option<DkgLocal>,
    key: Option<KeyPackage>,
    pubkey_json: Option<String>,
    signs: HashMap<Uuid, SignLocal>,
}

impl Participant {
    pub fn new(device: DeviceKey, group: GroupDto) -> Self {
        Self {
            device,
            group,
            dkg: None,
            key: None,
            pubkey_json: None,
            signs: HashMap::new(),
        }
    }

    pub fn has_share(&self) -> bool {
        self.key.is_some()
    }

    pub fn group_id(&self) -> Uuid {
        self.group.id
    }

    pub fn set_group(&mut self, group: GroupDto) -> Result<Vec<ClientMsg>, Error> {
        self.group = group;
        self.resend_public()
    }

    pub fn install_share(&mut self, key_json: &str, pubkey_json: &str) -> Result<(), Error> {
        self.key = Some(from_json(key_json)?);
        self.pubkey_json = Some(pubkey_json.to_string());
        Ok(())
    }

    pub fn export(&self) -> Result<ParticipantBlobDto, Error> {
        Ok(ParticipantBlobDto {
            dkg: self.dkg.as_ref().map(|dkg| dkg.export()).transpose()?,
            key: self.key.as_ref().map(to_json).transpose()?,
            pubkey: self.pubkey_json.clone(),
            signs: self
                .signs
                .iter()
                .map(|(id, session)| Ok((*id, session.export()?)))
                .collect::<Result<Vec<_>, Error>>()?,
        })
    }

    pub fn import_state(&mut self, state: &ParticipantBlobDto) -> Result<(), Error> {
        self.dkg = state.dkg.as_deref().map(DkgLocal::import).transpose()?;
        self.key = state.key.as_deref().map(from_json).transpose()?;
        self.pubkey_json = state.pubkey.clone();
        self.signs.clear();
        for (id, blob) in &state.signs {
            self.signs.insert(*id, SignLocal::import(blob)?);
        }
        Ok(())
    }

    pub fn handle(&mut self, msg: &ServerMsg) -> Result<Vec<ClientMsg>, Error> {
        match msg {
            ServerMsg::DkgStarted { group_id } if *group_id == self.group.id => {
                self.on_dkg_started()
            }
            ServerMsg::DkgRound1 {
                group_id,
                from,
                package,
            } if *group_id == self.group.id => self.on_dkg_round1(*from, package),
            ServerMsg::DkgRound2 {
                group_id,
                from,
                ciphertext,
            } if *group_id == self.group.id => self.on_dkg_round2(*from, ciphertext),
            ServerMsg::SignStarted {
                request_id,
                group_id,
                signers,
                message_hex,
            } if *group_id == self.group.id => {
                self.on_sign_started(*request_id, signers, message_hex)
            }
            ServerMsg::SignCommitment {
                request_id,
                from,
                commitment,
            } => self.on_commitment(*request_id, *from, commitment),
            _ => Ok(Vec::new()),
        }
    }

    fn resend_public(&self) -> Result<Vec<ClientMsg>, Error> {
        if self.group.status == "dkg" {
            if let Some(pubkey) = &self.pubkey_json {
                return Ok(vec![ClientMsg::DkgPublic {
                    group_id: self.group.id,
                    public_key_package: pubkey.clone(),
                }]);
            }
        }
        Ok(Vec::new())
    }

    fn on_dkg_started(&mut self) -> Result<Vec<ClientMsg>, Error> {
        if self.key.is_some() {
            return self.resend_public();
        }
        let my_id = self
            .group
            .my_identifier
            .ok_or_else(|| Error::msg("вы не участник этой группы"))?;
        if self.dkg.is_none() {
            self.dkg = Some(DkgLocal::new(
                my_id,
                self.group.max_signers,
                self.group.threshold,
            )?);
        }
        let dkg = self.dkg.as_mut().expect("dkg session");
        let Some(package) = dkg.start()? else {
            return Ok(Vec::new());
        };
        Ok(vec![ClientMsg::DkgRound1 {
            group_id: self.group.id,
            package: to_json(&package)?,
        }])
    }

    fn on_dkg_round1(&mut self, from: u16, package: &str) -> Result<Vec<ClientMsg>, Error> {
        let Some(dkg) = self.dkg.as_mut() else {
            return Ok(Vec::new());
        };
        let Some(packages) = dkg.push_round1(from, package)? else {
            return Ok(Vec::new());
        };
        let mut sealed = Vec::new();
        for (to, json) in packages {
            let recipient = self
                .group
                .members
                .iter()
                .find(|member| member.identifier == to)
                .and_then(|member| member.box_public_hex.as_deref())
                .ok_or_else(|| Error::msg(format!("нет ключа устройства участника {to}")))?;
            sealed.push(SealedPackage {
                to,
                ciphertext: self.device.seal_to(recipient, json.as_bytes())?,
            });
        }
        Ok(vec![ClientMsg::DkgRound2 {
            group_id: self.group.id,
            packages: sealed,
        }])
    }

    fn on_dkg_round2(&mut self, from: u16, ciphertext: &str) -> Result<Vec<ClientMsg>, Error> {
        let plaintext = self.device.open(ciphertext)?;
        let json = String::from_utf8(plaintext)
            .map_err(|_| Error::msg("пакет DKG не является текстом"))?;
        let (pubkey, key_json) = {
            let Some(dkg) = self.dkg.as_mut() else {
                return Ok(Vec::new());
            };
            let Some(pubkey) = dkg.push_round2(from, &json)? else {
                return Ok(Vec::new());
            };
            let key_json = dkg
                .key_json()?
                .ok_or_else(|| Error::msg("нет доли ключа после DKG"))?;
            (pubkey, key_json)
        };
        self.key = Some(from_json(&key_json)?);
        self.pubkey_json = Some(pubkey.clone());
        Ok(vec![ClientMsg::DkgPublic {
            group_id: self.group.id,
            public_key_package: pubkey,
        }])
    }

    fn on_sign_started(
        &mut self,
        request_id: Uuid,
        signers: &[u16],
        message_hex: &str,
    ) -> Result<Vec<ClientMsg>, Error> {
        if self.signs.contains_key(&request_id) {
            return Ok(Vec::new());
        }
        let Some(my_id) = self.group.my_identifier else {
            return Ok(Vec::new());
        };
        if !signers.contains(&my_id) {
            return Ok(Vec::new());
        }
        let Some(key) = self.key.as_ref() else {
            return Ok(vec![ClientMsg::SignAbort {
                request_id,
                reason: "на этом устройстве нет доли ключа".into(),
            }]);
        };
        let message = hex::decode(message_hex)
            .map_err(|_| Error::msg("сообщение на подпись не является hex"))?;
        let (nonces, commitment) = frost::round1::commit(key.signing_share(), &mut RandOsRng);
        let mut session = SignLocal {
            message,
            signers: signers.to_vec(),
            nonces,
            commitments: BTreeMap::new(),
            share_sent: false,
        };
        session
            .commitments
            .insert(ident(my_id)?, commitment.clone());
        self.signs.insert(request_id, session);
        Ok(vec![ClientMsg::SignCommitment {
            request_id,
            commitment: to_json(&commitment)?,
        }])
    }

    fn on_commitment(
        &mut self,
        request_id: Uuid,
        from: u16,
        commitment_json: &str,
    ) -> Result<Vec<ClientMsg>, Error> {
        let Some(my_id) = self.group.my_identifier else {
            return Ok(Vec::new());
        };
        let Some(key) = self.key.clone() else {
            return Ok(Vec::new());
        };
        let Some(session) = self.signs.get_mut(&request_id) else {
            return Ok(Vec::new());
        };
        if session.share_sent || !session.signers.contains(&from) {
            return Ok(Vec::new());
        }
        let commitment: SigningCommitments = from_json(commitment_json)?;
        session
            .commitments
            .entry(ident(from)?)
            .or_insert(commitment);
        if session.commitments.len() != session.signers.len() {
            return Ok(Vec::new());
        }
        let signing_package =
            frost::SigningPackage::new(session.commitments.clone(), &session.message);
        let share = frost::round2::sign(&signing_package, &session.nonces, &key)
            .map_err(|err| Error::msg(format!("доля подписи: {err}")))?;
        session.share_sent = true;
        let _ = my_id;
        Ok(vec![ClientMsg::SignShare {
            request_id,
            share: to_json(&share)?,
        }])
    }
}

/// Serializable ceremony state stored in the client SQLite database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantBlobDto {
    pub dkg: Option<String>,
    pub key: Option<String>,
    pub pubkey: Option<String>,
    pub signs: Vec<(Uuid, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemberDto;

    #[test]
    fn device_seal_roundtrip() {
        let alice = DeviceKey::generate();
        let bob = DeviceKey::generate();
        let sealed = alice.seal_to(&bob.public_hex(), b"share").unwrap();
        assert_eq!(bob.open(&sealed).unwrap(), b"share");
    }

    #[test]
    fn frost_signature_verifies_as_ed25519() {
        let alice_key = DeviceKey::generate();
        let bob_key = DeviceKey::generate();
        let group_id = Uuid::new_v4();
        let creator = Uuid::new_v4();
        let alice_id = Uuid::new_v4();
        let bob_id = Uuid::new_v4();
        let members = vec![
            MemberDto {
                user_id: alice_id,
                username: "alice".into(),
                identifier: 1,
                box_public_hex: Some(alice_key.public_hex()),
            },
            MemberDto {
                user_id: bob_id,
                username: "bob".into(),
                identifier: 2,
                box_public_hex: Some(bob_key.public_hex()),
            },
        ];
        let group_for = |identifier| GroupDto {
            id: group_id,
            name: "demo".into(),
            threshold: 2,
            max_signers: 2,
            status: "dkg".into(),
            api_token: None,
            verifying_key_hex: None,
            created_by: creator,
            i_created: identifier == 1,
            my_identifier: Some(identifier),
            members: members.clone(),
        };
        let mut alice = Participant::new(alice_key, group_for(1));
        let mut bob = Participant::new(bob_key, group_for(2));
        let started = ServerMsg::DkgStarted { group_id };
        let mut alice_out = alice.handle(&started).unwrap();
        let mut bob_out = bob.handle(&started).unwrap();
        deliver(&mut alice, &mut bob, &mut alice_out, &mut bob_out);
        assert!(alice.has_share());
        assert!(bob.has_share());

        let message = b"hello frost";
        let request_id = Uuid::new_v4();
        let started = ServerMsg::SignStarted {
            request_id,
            group_id,
            signers: vec![1, 2],
            message_hex: hex::encode(message),
        };
        let mut alice_out = alice.handle(&started).unwrap();
        let mut bob_out = bob.handle(&started).unwrap();
        let shares = deliver(&mut alice, &mut bob, &mut alice_out, &mut bob_out);

        let pubkey = alice.pubkey_json.clone().unwrap();
        let session = alice.signs.values().next().unwrap();
        let commitments = session
            .commitments
            .iter()
            .map(|(id, commitment)| (ident_to_u16(*id).unwrap(), to_json(commitment).unwrap()))
            .collect::<Vec<_>>();
        let signature = aggregate_signature(message, &commitments, &shares, &pubkey).unwrap();
        let vk = package_verifying_key_hex(&pubkey).unwrap();
        verify_ed25519(&vk, message, &signature).unwrap();

        let blob = alice.export().unwrap();
        let json = serde_json::to_string(&blob).unwrap();
        let restored: ParticipantBlobDto = serde_json::from_str(&json).unwrap();
        let mut copy = Participant::new(alice.device.clone(), group_for(1));
        copy.import_state(&restored).unwrap();
        assert!(copy.has_share());
    }

    fn deliver(
        alice: &mut Participant,
        bob: &mut Participant,
        alice_out: &mut Vec<ClientMsg>,
        bob_out: &mut Vec<ClientMsg>,
    ) -> Vec<(u16, String)> {
        let mut shares = Vec::new();
        let mut guard = 0;
        while guard < 12 {
            guard += 1;
            for msg in alice_out.iter() {
                if let ClientMsg::SignShare { share, .. } = msg {
                    shares.push((1, share.clone()));
                }
            }
            for msg in bob_out.iter() {
                if let ClientMsg::SignShare { share, .. } = msg {
                    shares.push((2, share.clone()));
                }
            }
            let mut next_alice = Vec::new();
            let mut next_bob = Vec::new();
            let pending_alice = std::mem::take(alice_out);
            let pending_bob = std::mem::take(bob_out);
            if pending_alice.is_empty() && pending_bob.is_empty() {
                break;
            }
            for msg in pending_alice {
                relay(&msg, 1, bob, &mut next_bob);
            }
            for msg in pending_bob {
                relay(&msg, 2, alice, &mut next_alice);
            }
            *alice_out = next_alice;
            *bob_out = next_bob;
        }
        shares
    }

    fn relay(msg: &ClientMsg, from: u16, peer: &mut Participant, outgoing: &mut Vec<ClientMsg>) {
        let group_id = peer.group_id();
        let server = match msg {
            ClientMsg::DkgRound1 { package, .. } => ServerMsg::DkgRound1 {
                group_id,
                from,
                package: package.clone(),
            },
            ClientMsg::DkgRound2 { packages, .. } => {
                let mine = packages
                    .iter()
                    .find(|package| package.to == peer.group.my_identifier.unwrap());
                if let Some(package) = mine {
                    ServerMsg::DkgRound2 {
                        group_id,
                        from,
                        ciphertext: package.ciphertext.clone(),
                    }
                } else {
                    return;
                }
            }
            ClientMsg::SignCommitment {
                request_id,
                commitment,
                ..
            } => ServerMsg::SignCommitment {
                request_id: *request_id,
                from,
                commitment: commitment.clone(),
            },
            ClientMsg::SignShare { .. } | ClientMsg::DkgPublic { .. } => return,
            other => panic!("unexpected relay {other:?}"),
        };
        outgoing.extend(peer.handle(&server).unwrap());
    }
}
