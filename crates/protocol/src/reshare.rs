//! FROST share refresh for a new committee.
//!
//! Stayers run the refresh DKG: a sharing of zero is added to their shares, so
//! the group key stays the same and a removed party's old share no longer lies
//! on the polynomial. A new party then receives a share through the repairable
//! scheme. No party ever interpolates the group secret. One party's old and new
//! shares sit at the same identifier, so they are not two points of one polynomial.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::traits::Identity;
use frost_ed25519 as frost;
use rand::rngs::OsRng as RandOsRng;
use serde::{Deserialize, Serialize};

use crate::engine::{from_json, ident, ident_to_u16, to_json};
use crate::Error;

type R1Secret = frost::keys::dkg::round1::SecretPackage;
type R1Package = frost::keys::dkg::round1::Package;
type R2Secret = frost::keys::dkg::round2::SecretPackage;
type R2Package = frost::keys::dkg::round2::Package;
type KeyPackage = frost::keys::KeyPackage;
type PublicKeyPackage = frost::keys::PublicKeyPackage;
type Delta = frost::keys::repairable::Delta;
type Sigma = frost::keys::repairable::Sigma;

/// Plaintext the participant still has to seal or broadcast.
#[derive(Debug)]
pub(crate) enum ReshareOut {
    Round1(String),
    Round2(Vec<(u16, String)>),
    RefreshPublic(String),
    Deltas {
        joiner: u16,
        packages: Vec<(u16, String)>,
    },
    Sigma {
        joiner: u16,
        sigma: String,
        commitment: String,
    },
    Verifying {
        joiner: u16,
        share: String,
    },
    Public(String),
}

pub(crate) struct ReshareSession {
    generation: u32,
    identifier: u16,
    threshold: u16,
    stayers: Vec<u16>,
    joiners: Vec<u16>,
    box_keys: BTreeMap<u16, String>,
    joiner: bool,
    round1_secret: Option<R1Secret>,
    round2_secret: Option<R2Secret>,
    round1_in: BTreeMap<frost::Identifier, R1Package>,
    round2_in: BTreeMap<frost::Identifier, R2Package>,
    round2_started: bool,
    old_key: Option<KeyPackage>,
    old_pubkey: Option<PublicKeyPackage>,
    refreshed_key: Option<KeyPackage>,
    refreshed_pubkey: Option<PublicKeyPackage>,
    own_deltas: BTreeMap<u16, BTreeMap<frost::Identifier, Delta>>,
    incoming_deltas: BTreeMap<u16, BTreeMap<frost::Identifier, Delta>>,
    sigma_sent: BTreeSet<u16>,
    commitments: BTreeMap<u16, BTreeMap<u16, String>>,
    sigmas: BTreeMap<u16, Vec<Sigma>>,
    sigma_from: BTreeMap<u16, BTreeSet<u16>>,
    joiner_key: Option<KeyPackage>,
    verifying: BTreeMap<u16, String>,
    verifying_sent: bool,
    final_pubkey: Option<String>,
    final_sent: bool,
}

#[derive(Serialize, Deserialize)]
struct ReshareBlob {
    generation: u32,
    identifier: u16,
    threshold: u16,
    stayers: Vec<u16>,
    joiners: Vec<u16>,
    box_keys: Vec<(u16, String)>,
    joiner: bool,
    round1_secret: Option<String>,
    round2_secret: Option<String>,
    round1_in: Vec<(u16, String)>,
    round2_in: Vec<(u16, String)>,
    round2_started: bool,
    old_key: Option<String>,
    old_pubkey: Option<String>,
    refreshed_key: Option<String>,
    refreshed_pubkey: Option<String>,
    own_deltas: Vec<(u16, Vec<(u16, String)>)>,
    incoming_deltas: Vec<(u16, Vec<(u16, String)>)>,
    sigma_sent: Vec<u16>,
    commitments: Vec<(u16, Vec<(u16, String)>)>,
    sigmas: Vec<(u16, Vec<String>)>,
    sigma_from: Vec<(u16, Vec<u16>)>,
    joiner_key: Option<String>,
    verifying: Vec<(u16, String)>,
    verifying_sent: bool,
    final_pubkey: Option<String>,
    final_sent: bool,
}

impl ReshareSession {
    pub(crate) fn new(
        generation: u32,
        identifier: u16,
        threshold: u16,
        mut stayers: Vec<u16>,
        mut joiners: Vec<u16>,
        box_keys: BTreeMap<u16, String>,
    ) -> Result<Self, Error> {
        stayers.sort_unstable();
        stayers.dedup();
        joiners.sort_unstable();
        joiners.dedup();
        if stayers.len() < 2 || threshold < 2 || usize::from(threshold) > stayers.len() {
            return Err(Error::msg(
                "после удаления участников порог должен выполняться",
            ));
        }
        if stayers.len() + joiners.len() > 16 {
            return Err(Error::msg("в группе не больше 16 участников"));
        }
        if joiners.iter().any(|id| stayers.contains(id)) {
            return Err(Error::msg("новый участник уже есть в группе"));
        }
        let joiner = joiners.contains(&identifier);
        if !joiner && !stayers.contains(&identifier) {
            return Err(Error::msg("вы не участвуете в пересчёте долей"));
        }
        let _ = ident(identifier)?;
        Ok(Self {
            generation,
            identifier,
            threshold,
            stayers,
            joiners,
            box_keys,
            joiner,
            round1_secret: None,
            round2_secret: None,
            round1_in: BTreeMap::new(),
            round2_in: BTreeMap::new(),
            round2_started: false,
            old_key: None,
            old_pubkey: None,
            refreshed_key: None,
            refreshed_pubkey: None,
            own_deltas: BTreeMap::new(),
            incoming_deltas: BTreeMap::new(),
            sigma_sent: BTreeSet::new(),
            commitments: BTreeMap::new(),
            sigmas: BTreeMap::new(),
            sigma_from: BTreeMap::new(),
            joiner_key: None,
            verifying: BTreeMap::new(),
            verifying_sent: false,
            final_pubkey: None,
            final_sent: false,
        })
    }

    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) fn box_key(&self, identifier: u16) -> Option<&str> {
        self.box_keys.get(&identifier).map(String::as_str)
    }

    /// Stayer opens the refresh DKG. A joiner only waits for the repair phase.
    pub(crate) fn start(
        &mut self,
        old_key_json: Option<&str>,
        old_pubkey_json: Option<&str>,
    ) -> Result<Vec<ReshareOut>, Error> {
        if self.round1_secret.is_some() || self.refreshed_key.is_some() || self.joiner {
            return self.pending();
        }
        let old_key: KeyPackage =
            from_json(old_key_json.ok_or_else(|| Error::msg("нет доли для пересчёта"))?)?;
        let old_pubkey: PublicKeyPackage =
            from_json(old_pubkey_json.ok_or_else(|| Error::msg("нет публичного пакета группы"))?)?;
        if *old_key.min_signers() != self.threshold {
            return Err(Error::msg("порог доли не совпадает с группой"));
        }
        let (secret, package) = frost::keys::refresh::refresh_dkg_part1(
            ident(self.identifier)?,
            u16::try_from(self.stayers.len()).unwrap_or(u16::MAX),
            self.threshold,
            RandOsRng,
        )
        .map_err(|err| Error::msg(format!("решаринг, раунд 1: {err}")))?;
        self.round1_secret = Some(secret);
        self.old_key = Some(old_key);
        self.old_pubkey = Some(old_pubkey);
        Ok(vec![ReshareOut::Round1(to_json(&package)?)])
    }

    pub(crate) fn push_round1(
        &mut self,
        from: u16,
        package_json: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if self.joiner || from == self.identifier || self.refreshed_key.is_some() {
            return Ok(Vec::new());
        }
        if !self.stayers.contains(&from) {
            return Err(Error::msg("пакет решаринга от участника вне комитета"));
        }
        let package: R1Package = from_json(package_json)?;
        self.round1_in.entry(ident(from)?).or_insert(package);
        if self.round2_started || self.round1_in.len() + 1 != self.stayers.len() {
            return Ok(Vec::new());
        }
        let secret = self
            .round1_secret
            .take()
            .ok_or_else(|| Error::msg("нет секрета раунда 1 решаринга"))?;
        let (secret, packages) = frost::keys::refresh::refresh_dkg_part2(secret, &self.round1_in)
            .map_err(|err| Error::msg(format!("решаринг, раунд 2: {err}")))?;
        self.round2_secret = Some(secret);
        self.round2_started = true;
        let mut encoded = Vec::new();
        for (id, package) in packages {
            encoded.push((ident_to_u16(id)?, to_json(&package)?));
        }
        Ok(vec![ReshareOut::Round2(encoded)])
    }

    pub(crate) fn push_round2(
        &mut self,
        from: u16,
        package_json: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if self.joiner || from == self.identifier || self.refreshed_pubkey.is_some() {
            return Ok(Vec::new());
        }
        let package: R2Package = from_json(package_json)?;
        self.round2_in.entry(ident(from)?).or_insert(package);
        if self.round2_in.len() + 1 != self.stayers.len() {
            return Ok(Vec::new());
        }
        let secret = self
            .round2_secret
            .as_ref()
            .ok_or_else(|| Error::msg("нет секрета раунда 2 решаринга"))?;
        let old_key = self
            .old_key
            .clone()
            .ok_or_else(|| Error::msg("нет прежней доли"))?;
        let old_pubkey = self
            .old_pubkey
            .clone()
            .ok_or_else(|| Error::msg("нет прежнего публичного пакета"))?;
        let expected = package_key_hex(&to_json(&old_pubkey)?)?;
        let (key, pubkey) = frost::keys::refresh::refresh_dkg_shares(
            secret,
            &self.round1_in,
            &self.round2_in,
            old_pubkey,
            old_key,
        )
        .map_err(|err| Error::msg(format!("решаринг, финал: {err}")))?;
        let json = to_json(&pubkey)?;
        if package_key_hex(&json)? != expected {
            return Err(Error::msg("пересчёт изменил ключ группы"));
        }
        let ids = signer_ids(&pubkey)?;
        if ids != self.stayers {
            return Err(Error::msg("публичный пакет не совпал с составом"));
        }
        self.refreshed_key = Some(key);
        self.refreshed_pubkey = Some(pubkey);
        if self.joiners.is_empty() {
            self.final_pubkey = Some(json.clone());
        }
        Ok(vec![ReshareOut::RefreshPublic(json)])
    }

    pub(crate) fn on_repair(&mut self, pubkey_json: &str) -> Result<Vec<ReshareOut>, Error> {
        let agreed = crate::canonical_public_package(pubkey_json)?;
        if let Some(current) = &self.refreshed_pubkey {
            if crate::canonical_public_package(&to_json(current)?)? != agreed {
                return Err(Error::msg("публичный пакет пересчёта не совпал"));
            }
        }
        let pubkey: PublicKeyPackage = from_json(pubkey_json)?;
        if self.joiner {
            if self.refreshed_pubkey.is_none() {
                self.refreshed_pubkey = Some(pubkey);
            }
            return Ok(Vec::new());
        }
        if self.refreshed_key.is_none() {
            return Err(Error::msg("ремонт доли до окончания пересчёта"));
        }
        if self.joiners.is_empty() {
            return Ok(Vec::new());
        }
        if self.own_deltas.len() == self.joiners.len() {
            return self.pending();
        }
        self.refreshed_pubkey = Some(pubkey);
        let key = self
            .refreshed_key
            .clone()
            .ok_or_else(|| Error::msg("нет обновлённой доли"))?;
        let helpers = self.helper_ids()?;
        let mut outs = Vec::new();
        for joiner in self.joiners.clone() {
            if self.own_deltas.contains_key(&joiner) {
                continue;
            }
            let deltas = frost::keys::repairable::repair_share_part1::<frost::Ed25519Sha512, _>(
                &helpers,
                &key,
                &mut RandOsRng,
                ident(joiner)?,
            )
            .map_err(|err| Error::msg(format!("выдача доли: {err}")))?;
            let mut packages = Vec::new();
            let mut stored = BTreeMap::new();
            for (id, delta) in deltas {
                let identifier = ident_to_u16(id)?;
                if identifier == self.identifier {
                    stored.insert(id, delta);
                } else {
                    packages.push((identifier, to_json(&delta)?));
                    stored.insert(id, delta);
                }
            }
            self.own_deltas.insert(joiner, stored);
            outs.push(ReshareOut::Deltas { joiner, packages });
            outs.extend(self.try_sigma(joiner)?);
        }
        Ok(outs)
    }

    pub(crate) fn push_delta(
        &mut self,
        joiner: u16,
        from: u16,
        package_json: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if self.joiner || from == self.identifier || !self.joiners.contains(&joiner) {
            return Ok(Vec::new());
        }
        let delta: Delta = from_json(package_json)?;
        self.incoming_deltas
            .entry(joiner)
            .or_default()
            .entry(ident(from)?)
            .or_insert(delta);
        self.try_sigma(joiner)
    }

    pub(crate) fn push_sigma(
        &mut self,
        joiner: u16,
        from: u16,
        sigma_json: &str,
        commitment_hex: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if !self.joiner || joiner != self.identifier {
            return Ok(Vec::new());
        }
        self.note_commitment(joiner, from, commitment_hex)?;
        if self.sigma_from.entry(joiner).or_default().contains(&from) {
            return self.try_final();
        }
        let sigma: Sigma = from_json(sigma_json)?;
        let got = commitment_hex_of_sigma(&sigma)?;
        if got != commitment_hex {
            return Err(Error::msg(
                "обязательство сигмы не совпало с полученной долей",
            ));
        }
        self.sigma_from.entry(joiner).or_default().insert(from);
        self.sigmas.entry(joiner).or_default().push(sigma);
        if self.sigma_from.get(&joiner).map(BTreeSet::len).unwrap_or(0) != self.stayers.len() {
            return Ok(Vec::new());
        }
        let pubkey = self
            .refreshed_pubkey
            .clone()
            .ok_or_else(|| Error::msg("нет публичного пакета для новой доли"))?;
        let sigmas = self.sigmas.get(&joiner).cloned().unwrap_or_default();
        let key =
            frost::keys::repairable::repair_share_part3(&sigmas, ident(self.identifier)?, &pubkey)
                .map_err(|err| Error::msg(format!("сборка новой доли: {err}")))?;
        let share = verifying_hex(key.verifying_share())?;
        let Some(commitments) = self.commitment_list(joiner)? else {
            return Err(Error::msg("собраны не все обязательства"));
        };
        let expected = sum_commitment_hex(commitments)?;
        if share != expected {
            return Err(Error::msg(
                "новая доля не совпала с обязательствами участников",
            ));
        }
        self.joiner_key = Some(key);
        self.verifying.insert(joiner, share.clone());
        self.verifying_sent = true;
        let mut outs = vec![ReshareOut::Verifying { joiner, share }];
        outs.extend(self.try_final()?);
        Ok(outs)
    }

    pub(crate) fn push_commitment(
        &mut self,
        joiner: u16,
        from: u16,
        commitment_hex: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if !self.joiners.contains(&joiner) || !self.stayers.contains(&from) {
            return Ok(Vec::new());
        }
        self.note_commitment(joiner, from, commitment_hex)?;
        self.try_final()
    }

    pub(crate) fn push_verifying(
        &mut self,
        joiner: u16,
        share_hex: &str,
    ) -> Result<Vec<ReshareOut>, Error> {
        if !self.joiners.contains(&joiner) {
            return Err(Error::msg("доля проверки для неизвестного участника"));
        }
        if let Some(previous) = self.verifying.get(&joiner) {
            if previous != share_hex {
                return Err(Error::msg("участники разошлись в новой доле проверки"));
            }
        } else {
            self.verifying.insert(joiner, share_hex.to_string());
        }
        self.try_final()
    }

    /// Moves the refreshed share out. `None` when this completion was already applied.
    pub(crate) fn finish(&mut self) -> Result<Option<(String, String)>, Error> {
        let Some(pubkey) = self.final_pubkey.clone() else {
            return Err(Error::msg("пересчёт ещё не собрал публичный пакет"));
        };
        let key_json = if self.joiner {
            to_json(
                self.joiner_key
                    .as_ref()
                    .ok_or_else(|| Error::msg("новая доля не собрана"))?,
            )?
        } else {
            to_json(
                self.refreshed_key
                    .as_ref()
                    .ok_or_else(|| Error::msg("обновлённая доля не собрана"))?,
            )?
        };
        Ok(Some((key_json, pubkey)))
    }

    pub(crate) fn export(&self) -> Result<String, Error> {
        let blob = ReshareBlob {
            generation: self.generation,
            identifier: self.identifier,
            threshold: self.threshold,
            stayers: self.stayers.clone(),
            joiners: self.joiners.clone(),
            box_keys: self
                .box_keys
                .iter()
                .map(|(id, key)| (*id, key.clone()))
                .collect(),
            joiner: self.joiner,
            round1_secret: self.round1_secret.as_ref().map(to_json).transpose()?,
            round2_secret: self.round2_secret.as_ref().map(to_json).transpose()?,
            round1_in: encode_map(&self.round1_in)?,
            round2_in: encode_map(&self.round2_in)?,
            round2_started: self.round2_started,
            old_key: self.old_key.as_ref().map(to_json).transpose()?,
            old_pubkey: self.old_pubkey.as_ref().map(to_json).transpose()?,
            refreshed_key: self.refreshed_key.as_ref().map(to_json).transpose()?,
            refreshed_pubkey: self.refreshed_pubkey.as_ref().map(to_json).transpose()?,
            own_deltas: encode_deltas(&self.own_deltas)?,
            incoming_deltas: encode_deltas(&self.incoming_deltas)?,
            sigma_sent: self.sigma_sent.iter().copied().collect(),
            commitments: self
                .commitments
                .iter()
                .map(|(joiner, froms)| {
                    Ok((
                        *joiner,
                        froms
                            .iter()
                            .map(|(id, hex_value)| (*id, hex_value.clone()))
                            .collect(),
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?,
            sigmas: self
                .sigmas
                .iter()
                .map(|(joiner, sigmas)| {
                    let encoded = sigmas
                        .iter()
                        .map(to_json)
                        .collect::<Result<Vec<_>, Error>>()?;
                    Ok((*joiner, encoded))
                })
                .collect::<Result<Vec<_>, Error>>()?,
            sigma_from: self
                .sigma_from
                .iter()
                .map(|(joiner, froms)| (*joiner, froms.iter().copied().collect()))
                .collect(),
            joiner_key: self.joiner_key.as_ref().map(to_json).transpose()?,
            verifying: self
                .verifying
                .iter()
                .map(|(id, hex_value)| (*id, hex_value.clone()))
                .collect(),
            verifying_sent: self.verifying_sent,
            final_pubkey: self.final_pubkey.clone(),
            final_sent: self.final_sent,
        };
        to_json(&blob)
    }

    pub(crate) fn import(blob: &str) -> Result<Self, Error> {
        let blob: ReshareBlob = from_json(blob)?;
        let mut box_keys = BTreeMap::new();
        for (id, key) in blob.box_keys {
            box_keys.insert(id, key);
        }
        Ok(Self {
            generation: blob.generation,
            identifier: blob.identifier,
            threshold: blob.threshold,
            stayers: blob.stayers,
            joiners: blob.joiners,
            box_keys,
            joiner: blob.joiner,
            round1_secret: blob.round1_secret.as_deref().map(from_json).transpose()?,
            round2_secret: blob.round2_secret.as_deref().map(from_json).transpose()?,
            round1_in: decode_map(blob.round1_in)?,
            round2_in: decode_map(blob.round2_in)?,
            round2_started: blob.round2_started,
            old_key: blob.old_key.as_deref().map(from_json).transpose()?,
            old_pubkey: blob.old_pubkey.as_deref().map(from_json).transpose()?,
            refreshed_key: blob.refreshed_key.as_deref().map(from_json).transpose()?,
            refreshed_pubkey: blob
                .refreshed_pubkey
                .as_deref()
                .map(from_json)
                .transpose()?,
            own_deltas: decode_deltas(blob.own_deltas)?,
            incoming_deltas: decode_deltas(blob.incoming_deltas)?,
            sigma_sent: blob.sigma_sent.into_iter().collect(),
            commitments: blob
                .commitments
                .into_iter()
                .map(|(joiner, froms)| (joiner, froms.into_iter().collect()))
                .collect(),
            sigmas: blob
                .sigmas
                .into_iter()
                .map(|(joiner, values)| {
                    let sigmas = values
                        .iter()
                        .map(|json| from_json(json))
                        .collect::<Result<Vec<_>, Error>>()?;
                    Ok((joiner, sigmas))
                })
                .collect::<Result<BTreeMap<_, _>, Error>>()?,
            sigma_from: blob
                .sigma_from
                .into_iter()
                .map(|(joiner, froms)| (joiner, froms.into_iter().collect()))
                .collect(),
            joiner_key: blob.joiner_key.as_deref().map(from_json).transpose()?,
            verifying: blob.verifying.into_iter().collect(),
            verifying_sent: blob.verifying_sent,
            final_pubkey: blob.final_pubkey,
            final_sent: blob.final_sent,
        })
    }

    pub(crate) fn pending(&self) -> Result<Vec<ReshareOut>, Error> {
        let mut outs = Vec::new();
        if let Some(pubkey) = &self.refreshed_pubkey {
            if !self.joiner && self.own_deltas.is_empty() {
                outs.push(ReshareOut::RefreshPublic(to_json(pubkey)?));
            }
        }
        if let Some(pubkey) = &self.final_pubkey {
            if !self.final_sent {
                outs.push(ReshareOut::Public(pubkey.clone()));
            }
        }
        Ok(outs)
    }

    fn helper_ids(&self) -> Result<Vec<frost::Identifier>, Error> {
        self.stayers.iter().copied().map(ident).collect()
    }

    fn try_sigma(&mut self, joiner: u16) -> Result<Vec<ReshareOut>, Error> {
        if self.sigma_sent.contains(&joiner) {
            return Ok(Vec::new());
        }
        let self_id = ident(self.identifier)?;
        let deltas = {
            let Some(own) = self.own_deltas.get(&joiner) else {
                return Ok(Vec::new());
            };
            let incoming = self
                .incoming_deltas
                .get(&joiner)
                .map(BTreeMap::len)
                .unwrap_or(0);
            // One self-delta plus one sealed delta from every other stayer.
            if incoming + 1 != self.stayers.len() {
                return Ok(Vec::new());
            }
            let Some(mine) = own.get(&self_id).copied() else {
                return Err(Error::msg("нет своей дельты"));
            };
            let mut deltas = vec![mine];
            if let Some(received) = self.incoming_deltas.get(&joiner) {
                deltas.extend(received.values().copied());
            }
            deltas
        };
        if deltas.len() != self.stayers.len() {
            return Ok(Vec::new());
        }
        let sigma = frost::keys::repairable::repair_share_part2(&deltas);
        let commitment = commitment_hex_of_sigma(&sigma)?;
        self.commitments
            .entry(joiner)
            .or_default()
            .insert(self.identifier, commitment.clone());
        self.sigma_sent.insert(joiner);
        Ok(vec![ReshareOut::Sigma {
            joiner,
            sigma: to_json(&sigma)?,
            commitment,
        }])
    }

    fn note_commitment(
        &mut self,
        joiner: u16,
        from: u16,
        commitment_hex: &str,
    ) -> Result<(), Error> {
        let slot = self.commitments.entry(joiner).or_default();
        if let Some(previous) = slot.get(&from) {
            if previous != commitment_hex {
                return Err(Error::msg("обязательство сигмы изменилось"));
            }
        } else {
            slot.insert(from, commitment_hex.to_string());
        }
        Ok(())
    }

    fn commitment_list(&self, joiner: u16) -> Result<Option<Vec<String>>, Error> {
        let Some(froms) = self.commitments.get(&joiner) else {
            return Ok(None);
        };
        if froms.len() != self.stayers.len() {
            return Ok(None);
        }
        Ok(Some(froms.values().cloned().collect()))
    }

    fn try_final(&mut self) -> Result<Vec<ReshareOut>, Error> {
        if self.final_sent {
            return Ok(Vec::new());
        }
        if self.verifying.len() != self.joiners.len() {
            return Ok(Vec::new());
        }
        if self.joiners.is_empty() {
            return Ok(Vec::new());
        }
        let Some(base) = self.refreshed_pubkey.clone() else {
            return Ok(Vec::new());
        };
        for joiner in &self.joiners {
            let share = self
                .verifying
                .get(joiner)
                .ok_or_else(|| Error::msg("нет доли проверки нового участника"))?;
            let Some(commitments) = self.commitment_list(*joiner)? else {
                return Ok(Vec::new());
            };
            let expected = sum_commitment_hex(commitments)?;
            if share != &expected {
                return Err(Error::msg("доля проверки нового участника не сходится"));
            }
        }
        let mut shares = base.verifying_shares().clone();
        for (joiner, hex_value) in &self.verifying {
            let bytes =
                hex::decode(hex_value).map_err(|_| Error::msg("доля проверки не является hex"))?;
            let verifying = frost::keys::VerifyingShare::deserialize(&bytes)
                .map_err(|err| Error::msg(format!("доля проверки: {err}")))?;
            shares.insert(ident(*joiner)?, verifying);
        }
        let pubkey = PublicKeyPackage::new(shares, *base.verifying_key(), base.min_signers());
        let json = to_json(&pubkey)?;
        if package_key_hex(&json)? != package_key_hex(&to_json(&base)?)? {
            return Err(Error::msg("добавление участника изменило ключ группы"));
        }
        self.final_pubkey = Some(json.clone());
        self.final_sent = true;
        Ok(vec![ReshareOut::Public(json)])
    }
}

fn encode_map<T: Serialize>(
    map: &BTreeMap<frost::Identifier, T>,
) -> Result<Vec<(u16, String)>, Error> {
    map.iter()
        .map(|(id, value)| Ok((ident_to_u16(*id)?, to_json(value)?)))
        .collect()
}

fn decode_map<T: for<'de> Deserialize<'de>>(
    rows: Vec<(u16, String)>,
) -> Result<BTreeMap<frost::Identifier, T>, Error> {
    let mut map = BTreeMap::new();
    for (id, json) in rows {
        map.insert(ident(id)?, from_json(&json)?);
    }
    Ok(map)
}

type DeltaMap = BTreeMap<u16, BTreeMap<frost::Identifier, Delta>>;
type PackedDeltas = Vec<(u16, Vec<(u16, String)>)>;

fn encode_deltas(map: &DeltaMap) -> Result<PackedDeltas, Error> {
    map.iter()
        .map(|(joiner, deltas)| Ok((*joiner, encode_map(deltas)?)))
        .collect()
}

fn decode_deltas(rows: PackedDeltas) -> Result<DeltaMap, Error> {
    let mut map = BTreeMap::new();
    for (joiner, deltas) in rows {
        map.insert(joiner, decode_map(deltas)?);
    }
    Ok(map)
}

fn signer_ids(package: &PublicKeyPackage) -> Result<Vec<u16>, Error> {
    let mut ids = Vec::new();
    for id in package.verifying_shares().keys() {
        ids.push(ident_to_u16(*id)?);
    }
    ids.sort_unstable();
    Ok(ids)
}

fn package_key_hex(json: &str) -> Result<String, Error> {
    crate::package_verifying_key_hex(json)
}

fn verifying_hex(share: &frost::keys::VerifyingShare) -> Result<String, Error> {
    let bytes = share
        .serialize()
        .map_err(|err| Error::msg(format!("доля проверки: {err}")))?;
    Ok(hex::encode(bytes))
}

fn commitment_hex_of_sigma(sigma: &Sigma) -> Result<String, Error> {
    let signing = frost::keys::SigningShare::deserialize(&sigma.serialize())
        .map_err(|err| Error::msg(format!("сигма: {err}")))?;
    verifying_hex(&frost::keys::VerifyingShare::from(signing))
}

/// Sum of compressed Edwards points. Each commitment is `g` raised to one sigma,
/// and the sum is the new verifying share. The sigmas themselves stay sealed.
pub(crate) fn sum_commitment_hex(points: Vec<String>) -> Result<String, Error> {
    let mut acc = EdwardsPoint::identity();
    for hex_value in points {
        let bytes = hex::decode(hex_value.trim())
            .map_err(|_| Error::msg("обязательство не является hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::msg("обязательство должно быть 32 байта"))?;
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or_else(|| Error::msg("обязательство не является точкой Ed25519"))?;
        if !point.is_torsion_free() {
            return Err(Error::msg("обязательство вне простого порядка"));
        }
        acc += point;
    }
    if !acc.is_torsion_free() || acc == EdwardsPoint::identity() {
        return Err(Error::msg("сумма обязательств выродилась"));
    }
    Ok(hex::encode(acc.compress().to_bytes()))
}

#[cfg(test)]
mod tests {
    use frost::keys::KeyPackage;

    use super::*;
    use crate::{
        aggregate_signature, package_verifying_key_hex, verify_ed25519, ClientMsg, DeviceKey,
        GroupDto, MemberDto, Participant, RosterKey, ServerMsg,
    };

    struct Party {
        id: u16,
        device: DeviceKey,
        participant: Participant,
        out: Vec<ClientMsg>,
    }

    struct World {
        group_id: uuid::Uuid,
        parties: Vec<Party>,
        transcript: String,
        refresh: Vec<(u16, String)>,
        publics: Vec<(u16, String)>,
        commitments: Vec<(u16, String)>,
        shares: Vec<(u16, String)>,
        vk: String,
    }

    #[test]
    fn reshare_never_assembles_the_group_secret() {
        let mut world = World::dkg();
        let secret = world.secret_from(&[1, 2]);
        world.hide(&secret);
        world.sign(&[1, 2], b"before-reshare");

        world.begin(1, &[1, 2], &[]);
        world.run();
        assert_eq!(
            world.refresh.len(),
            2,
            "оба оставшихся участника опубликовали пересчёт"
        );
        assert_eq!(
            crate::canonical_public_package(&world.refresh[0].1).unwrap(),
            crate::canonical_public_package(&world.refresh[1].1).unwrap()
        );
        let old = [world.key(1), world.key(2), world.key(3)];
        world.complete(&[1, 2]);
        let kept = [world.key(1), world.key(2)];
        assert_eq!(secret_bytes(&kept), secret);
        assert!(reconstruct(&[old[0].clone(), kept[0].clone()]).is_err());
        let mixed = secret_bytes(&[old[2].clone(), kept[0].clone()]);
        if mixed == secret {
            panic!("старая доля ушедшего и новая доля оставшегося собрали секрет");
        }
        world.hide(&secret);
        world.sign(&[1, 2], b"after-remove");

        world.begin(2, &[1, 2], &[4]);
        world.run();
        assert_eq!(world.refresh.len(), 2);
        let package = world.refresh[0].1.clone();
        world.repair(&package);
        world.run();
        assert_eq!(
            world.publics.len(),
            3,
            "новый участник тоже собрал публичный пакет"
        );
        world.complete(&[1, 2, 4]);
        let with_new = [world.key(1), world.key(4)];
        assert_eq!(secret_bytes(&with_new), secret);
        if world.key(4).signing_share().serialize() == secret {
            panic!("новая доля совпала с секретом группы");
        }
        world.hide(&secret);
        world.sign(&[1, 4], b"after-add");
    }

    impl World {
        fn dkg() -> Self {
            let group_id = uuid::Uuid::new_v4();
            let creator = uuid::Uuid::new_v4();
            let devices: Vec<(u16, DeviceKey, uuid::Uuid)> = (1..=3)
                .map(|id| (id, DeviceKey::generate(), uuid::Uuid::new_v4()))
                .collect();
            let members: Vec<MemberDto> = devices
                .iter()
                .map(|(id, device, user)| MemberDto {
                    user_id: *user,
                    username: format!("p{id}"),
                    identifier: *id,
                    box_public_hex: Some(device.public_hex()),
                    participation_accepted: true,
                })
                .collect();
            let mut parties = Vec::new();
            for (id, device, _) in devices {
                let group = group_dto(group_id, creator, id, 3, &members);
                let participant = Participant::new(device.clone(), group);
                parties.push(Party {
                    id,
                    device,
                    participant,
                    out: Vec::new(),
                });
            }
            let mut world = Self {
                group_id,
                parties,
                transcript: String::new(),
                refresh: Vec::new(),
                publics: Vec::new(),
                commitments: Vec::new(),
                shares: Vec::new(),
                vk: String::new(),
            };
            let started = ServerMsg::DkgStarted { group_id };
            for id in [1, 2, 3] {
                world.push(id, started.clone());
            }
            world.run();
            assert!(world
                .parties
                .iter()
                .all(|party| party.participant.has_share()));
            world.vk = package_verifying_key_hex(&world.pubkey(1)).unwrap();
            world
        }

        fn begin(&mut self, generation: u32, stayers: &[u16], joiners: &[u16]) {
            self.refresh.clear();
            self.publics.clear();
            for id in joiners {
                if self.parties.iter().any(|party| party.id == *id) {
                    continue;
                }
                let device = DeviceKey::generate();
                let user = uuid::Uuid::new_v4();
                let members = vec![MemberDto {
                    user_id: user,
                    username: format!("p{id}"),
                    identifier: *id,
                    box_public_hex: Some(device.public_hex()),
                    participation_accepted: true,
                }];
                let group = group_dto(self.group_id, uuid::Uuid::new_v4(), *id, 2, &members);
                self.parties.push(Party {
                    id: *id,
                    device: device.clone(),
                    participant: Participant::new(device, group),
                    out: Vec::new(),
                });
            }
            let mut keys = Vec::new();
            for id in stayers.iter().chain(joiners) {
                let party = self.party(*id);
                keys.push(RosterKey {
                    identifier: *id,
                    box_public_hex: party.device.public_hex(),
                });
            }
            let started = ServerMsg::ReshareStarted {
                group_id: self.group_id,
                generation,
                threshold: 2,
                stayers: stayers.to_vec(),
                joiners: joiners.to_vec(),
                keys,
            };
            for id in stayers.iter().chain(joiners) {
                self.push(*id, started.clone());
            }
        }

        fn repair(&mut self, package: &str) {
            let ids: Vec<u16> = self.parties.iter().map(|party| party.id).collect();
            let message = ServerMsg::ReshareRepair {
                group_id: self.group_id,
                public_key_package: package.to_string(),
            };
            for id in ids {
                if self.party(id).participant.has_share() || id == 4 {
                    self.push(id, message.clone());
                }
            }
        }

        fn complete(&mut self, ids: &[u16]) {
            let message = ServerMsg::ReshareCompleted {
                group_id: self.group_id,
                verifying_key_hex: self.vk.clone(),
            };
            for id in ids {
                self.push(*id, message.clone());
            }
            let now = package_verifying_key_hex(&self.pubkey(ids[0])).unwrap();
            assert_eq!(now, self.vk, "пересчёт сменил ключ группы");
        }

        fn sign(&mut self, signers: &[u16], message: &[u8]) {
            self.commitments.clear();
            self.shares.clear();
            let request_id = uuid::Uuid::new_v4();
            let started = ServerMsg::SignStarted {
                request_id,
                group_id: self.group_id,
                signers: signers.to_vec(),
                message_hex: hex::encode(message),
            };
            for id in signers {
                self.push(*id, started.clone());
            }
            self.run();
            assert_eq!(self.shares.len(), signers.len());
            let signature = aggregate_signature(
                message,
                &self.commitments,
                &self.shares,
                &self.pubkey(signers[0]),
            )
            .unwrap();
            verify_ed25519(&self.vk, message, &signature).unwrap();
        }

        fn run(&mut self) {
            for _ in 0..80 {
                let batch: Vec<(u16, Vec<ClientMsg>)> = self
                    .parties
                    .iter_mut()
                    .map(|party| (party.id, std::mem::take(&mut party.out)))
                    .collect();
                if batch.iter().all(|(_, messages)| messages.is_empty()) {
                    return;
                }
                for (from, messages) in batch {
                    for message in messages {
                        self.note(&message);
                        self.relay(from, message);
                    }
                }
            }
            panic!("церемония не сошлась");
        }

        fn relay(&mut self, from: u16, message: ClientMsg) {
            let group_id = self.group_id;
            match message {
                ClientMsg::DkgRound1 { package, .. } => {
                    self.broadcast(
                        from,
                        ServerMsg::DkgRound1 {
                            group_id,
                            from,
                            package,
                        },
                    );
                }
                ClientMsg::ReshareRound1 { package, .. } => {
                    self.broadcast(
                        from,
                        ServerMsg::ReshareRound1 {
                            group_id,
                            from,
                            package,
                        },
                    );
                }
                ClientMsg::DkgRound2 { packages, .. } => {
                    for package in packages {
                        self.push(
                            package.to,
                            ServerMsg::DkgRound2 {
                                group_id,
                                from,
                                ciphertext: package.ciphertext,
                            },
                        );
                    }
                }
                ClientMsg::ReshareRound2 { packages, .. } => {
                    for package in packages {
                        self.push(
                            package.to,
                            ServerMsg::ReshareRound2 {
                                group_id,
                                from,
                                ciphertext: package.ciphertext,
                            },
                        );
                    }
                }
                ClientMsg::ReshareRefreshPublic {
                    public_key_package, ..
                } => self.refresh.push((from, public_key_package)),
                ClientMsg::ReshareDelta {
                    joiner, packages, ..
                } => {
                    for package in packages {
                        self.push(
                            package.to,
                            ServerMsg::ReshareDelta {
                                group_id,
                                joiner,
                                from,
                                ciphertext: package.ciphertext,
                            },
                        );
                    }
                }
                ClientMsg::ReshareSigma {
                    joiner,
                    ciphertext,
                    commitment,
                    ..
                } => {
                    let joiner_id = joiner;
                    self.push(
                        joiner_id,
                        ServerMsg::ReshareSigma {
                            group_id,
                            joiner,
                            from,
                            ciphertext,
                            commitment: commitment.clone(),
                        },
                    );
                    self.broadcast(
                        from,
                        ServerMsg::ReshareSigmaCommit {
                            group_id,
                            joiner,
                            from,
                            commitment,
                        },
                    );
                }
                ClientMsg::ReshareVerifying {
                    joiner,
                    verifying_share,
                    ..
                } => self.broadcast(
                    from,
                    ServerMsg::ReshareVerifying {
                        group_id,
                        joiner,
                        verifying_share,
                    },
                ),
                ClientMsg::ResharePublic {
                    public_key_package, ..
                } => self.publics.push((from, public_key_package)),
                ClientMsg::SignCommitment {
                    request_id,
                    commitment,
                    ..
                } => {
                    self.commitments.push((from, commitment.clone()));
                    self.broadcast(
                        from,
                        ServerMsg::SignCommitment {
                            request_id,
                            from,
                            commitment,
                        },
                    );
                }
                ClientMsg::SignShare { share, .. } => self.shares.push((from, share)),
                ClientMsg::SignAbort { reason, .. } | ClientMsg::ReshareAbort { reason, .. } => {
                    panic!("участник прервал церемонию: {reason}");
                }
                ClientMsg::DkgPublic { .. } | ClientMsg::DkgAbort { .. } => {}
                ClientMsg::SignApprove { .. } | ClientMsg::SignReject { .. } => {}
            }
        }

        fn broadcast(&mut self, from: u16, message: ServerMsg) {
            let ids: Vec<u16> = self
                .parties
                .iter()
                .map(|party| party.id)
                .filter(|id| *id != from)
                .collect();
            for id in ids {
                self.push(id, message.clone());
            }
        }

        fn push(&mut self, id: u16, message: ServerMsg) {
            let Some(party) = self.parties.iter_mut().find(|party| party.id == id) else {
                return;
            };
            match party.participant.handle(&message) {
                Ok(messages) => party.out.extend(messages),
                Err(err) => panic!("участник {id}: {err}"),
            }
        }

        fn note(&mut self, message: &ClientMsg) {
            self.transcript
                .push_str(&serde_json::to_string(message).unwrap());
            self.transcript.push('\n');
        }

        fn hide(&mut self, secret: &[u8]) {
            let encoded = hex::encode(secret);
            for party in &self.parties {
                let blob = party.participant.export().unwrap();
                self.transcript
                    .push_str(&serde_json::to_string(&blob).unwrap());
                if let Some(key) = blob.key {
                    let package: KeyPackage = serde_json::from_str(&key).unwrap();
                    if package.signing_share().serialize() == secret {
                        panic!("доля участника {} совпала с секретом группы", party.id);
                    }
                }
            }
            if self.transcript.contains(&encoded) {
                panic!("секрет группы появился в сообщениях или сохранённых долях");
            }
        }

        fn secret_from(&self, ids: &[u16]) -> Vec<u8> {
            let keys: Vec<KeyPackage> = ids.iter().map(|id| self.key(*id)).collect();
            secret_bytes(&keys)
        }

        fn key(&self, id: u16) -> KeyPackage {
            let json = self
                .party(id)
                .participant
                .export()
                .unwrap()
                .key
                .unwrap_or_else(|| panic!("у участника {id} нет доли"));
            serde_json::from_str(&json).unwrap()
        }

        fn pubkey(&self, id: u16) -> String {
            self.party(id)
                .participant
                .export()
                .unwrap()
                .pubkey
                .unwrap_or_else(|| panic!("у участника {id} нет публичного пакета"))
        }

        fn party(&self, id: u16) -> &Party {
            self.parties.iter().find(|party| party.id == id).unwrap()
        }
    }

    fn reconstruct(keys: &[KeyPackage]) -> Result<frost::SigningKey, frost::Error> {
        frost::keys::reconstruct(keys)
    }

    fn secret_bytes(keys: &[KeyPackage]) -> Vec<u8> {
        reconstruct(keys).expect("реконструкция доли").serialize()
    }

    fn group_dto(
        id: uuid::Uuid,
        created_by: uuid::Uuid,
        identifier: u16,
        max_signers: u16,
        members: &[MemberDto],
    ) -> GroupDto {
        GroupDto {
            id,
            name: "treasury".into(),
            threshold: 2,
            max_signers,
            status: "dkg".into(),
            api_token: None,
            verifying_key_hex: None,
            solana_address: None,
            created_by,
            i_created: false,
            my_identifier: Some(identifier),
            members: members.to_vec(),
        }
    }
}
