//! Shared types and the FROST Ed25519 ceremony for the desktop client and the server.
//!
//! Key shares and DKG round-2 plaintexts never appear in these wire messages.
//! Round 2 is sealed to the recipient's device key. The server can relay the
//! ciphertext and, later, aggregate signature shares, which are public inputs
//! of the FROST coordinator.

mod certificate;
mod engine;
mod reshare;

pub use certificate::{
    canonical_public_key, verify_certificate_login, CertificateFile, CertificateLogin,
    CertificateMaterial,
};
pub use engine::{
    aggregate_signature, canonical_public_package, message_preview, message_text,
    package_signer_ids, package_verifying_key_hex, recode_hex, verify_ed25519, DeviceKey, DkgLocal,
    HdIdentity, Participant, ParticipantBlobDto,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub const MAX_SIGNERS: u16 = 16;
pub const ROLE_SIGNER: &str = "signer";
pub const ROLE_ADMIN: &str = "admin";

pub fn canonical_role(value: &str) -> Option<&'static str> {
    match value.trim().to_lowercase().as_str() {
        "signer" | "подписант" => Some(ROLE_SIGNER),
        "admin" | "админ" | "администратор" => Some(ROLE_ADMIN),
        _ => None,
    }
}

pub fn role_title(role: &str) -> &'static str {
    match role {
        ROLE_ADMIN => "админ",
        ROLE_SIGNER => "подписант",
        _ => "",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberDto {
    pub user_id: Uuid,
    pub username: String,
    pub identifier: u16,
    pub box_public_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupDto {
    pub id: Uuid,
    pub name: String,
    pub threshold: u16,
    pub max_signers: u16,
    pub status: String,
    pub api_token: Option<String>,
    pub verifying_key_hex: Option<String>,
    pub solana_address: Option<String>,
    pub created_by: Uuid,
    pub i_created: bool,
    pub my_identifier: Option<u16>,
    pub members: Vec<MemberDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequestDto {
    pub id: Uuid,
    pub group_id: Uuid,
    pub group_name: String,
    pub message_hex: String,
    pub message_preview: String,
    pub status: String,
    pub signature_hex: Option<String>,
    pub error: Option<String>,
    pub approvals: u16,
    pub threshold: u16,
    pub my_decision: Option<String>,
    pub created_at: String,
    /// Solana transfer details. `None` is retained only for requests created
    /// by older clients while they are being migrated.
    pub transaction: Option<SolanaTransferDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaTransferDto {
    pub recipient: String,
    pub lamports: u64,
    pub transaction_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedPackage {
    pub to: u16,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerDto {
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub threshold: u16,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareRequest {
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One row of the group membership history. `kind` is `member_added` or `member_removed`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEventDto {
    pub id: Uuid,
    pub group_id: Uuid,
    pub kind: String,
    pub actor: String,
    pub subject: String,
    pub created_at: String,
}

/// Device key of one party in a reshare, keyed by FROST identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RosterKey {
    pub identifier: u16,
    pub box_public_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyRequest {
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSignBody {
    pub message_hex: Option<String>,
    pub message_utf8: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSolanaTransferBody {
    pub recipient: String,
    pub lamports: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStatusResponse {
    pub request_id: Uuid,
    pub status: String,
    pub signature_hex: Option<String>,
    pub error: Option<String>,
}

/// Messages the desktop client sends on the relay socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    DkgRound1 {
        group_id: Uuid,
        package: String,
    },
    DkgRound2 {
        group_id: Uuid,
        packages: Vec<SealedPackage>,
    },
    DkgPublic {
        group_id: Uuid,
        public_key_package: String,
    },
    DkgAbort {
        group_id: Uuid,
        reason: String,
    },
    SignApprove {
        request_id: Uuid,
    },
    SignReject {
        request_id: Uuid,
    },
    SignCommitment {
        request_id: Uuid,
        commitment: String,
    },
    SignShare {
        request_id: Uuid,
        share: String,
    },
    SignAbort {
        request_id: Uuid,
        reason: String,
    },
    ReshareRound1 {
        group_id: Uuid,
        package: String,
    },
    ReshareRound2 {
        group_id: Uuid,
        packages: Vec<SealedPackage>,
    },
    ReshareRefreshPublic {
        group_id: Uuid,
        public_key_package: String,
    },
    ReshareDelta {
        group_id: Uuid,
        joiner: u16,
        packages: Vec<SealedPackage>,
    },
    ReshareSigma {
        group_id: Uuid,
        joiner: u16,
        ciphertext: String,
        commitment: String,
    },
    ReshareVerifying {
        group_id: Uuid,
        joiner: u16,
        verifying_share: String,
    },
    ResharePublic {
        group_id: Uuid,
        public_key_package: String,
    },
    ReshareAbort {
        group_id: Uuid,
        reason: String,
    },
}

/// Messages the server sends on the relay socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Hello {
        user_id: Uuid,
        username: String,
    },
    Error {
        message: String,
    },
    Snapshot {
        groups: Vec<GroupDto>,
        requests: Vec<SignRequestDto>,
    },
    GroupUpdated {
        group: GroupDto,
    },
    DkgStarted {
        group_id: Uuid,
    },
    DkgRound1 {
        group_id: Uuid,
        from: u16,
        package: String,
    },
    DkgRound2 {
        group_id: Uuid,
        from: u16,
        ciphertext: String,
    },
    DkgCompleted {
        group_id: Uuid,
        verifying_key_hex: String,
    },
    DkgFailed {
        group_id: Uuid,
        message: String,
    },
    SignRequest {
        request: SignRequestDto,
    },
    SignStarted {
        request_id: Uuid,
        group_id: Uuid,
        signers: Vec<u16>,
        message_hex: String,
    },
    SignCommitment {
        request_id: Uuid,
        from: u16,
        commitment: String,
    },
    SignCompleted {
        request_id: Uuid,
        signature_hex: String,
    },
    SignFailed {
        request_id: Uuid,
        message: String,
    },
    ReshareStarted {
        group_id: Uuid,
        generation: u32,
        threshold: u16,
        stayers: Vec<u16>,
        joiners: Vec<u16>,
        keys: Vec<RosterKey>,
    },
    ReshareRound1 {
        group_id: Uuid,
        from: u16,
        package: String,
    },
    ReshareRound2 {
        group_id: Uuid,
        from: u16,
        ciphertext: String,
    },
    ReshareRepair {
        group_id: Uuid,
        public_key_package: String,
    },
    ReshareDelta {
        group_id: Uuid,
        joiner: u16,
        from: u16,
        ciphertext: String,
    },
    ReshareSigma {
        group_id: Uuid,
        joiner: u16,
        from: u16,
        ciphertext: String,
        commitment: String,
    },
    ReshareSigmaCommit {
        group_id: Uuid,
        joiner: u16,
        from: u16,
        commitment: String,
    },
    ReshareVerifying {
        group_id: Uuid,
        joiner: u16,
        verifying_share: String,
    },
    ReshareCompleted {
        group_id: Uuid,
        verifying_key_hex: String,
    },
    ReshareFailed {
        group_id: Uuid,
        message: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
}

impl Error {
    pub fn msg(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

pub fn decode_sign_message(body: &CreateSignBody) -> Result<Vec<u8>, Error> {
    match (&body.message_hex, &body.message_utf8) {
        (Some(hex_value), None) => {
            let bytes = hex::decode(hex_value.trim())
                .map_err(|_| Error::msg("message_hex не является hex"))?;
            check_len(bytes)
        }
        (None, Some(text)) => check_len(text.as_bytes().to_vec()),
        _ => Err(Error::msg(
            "укажите ровно одно из полей message_hex или message_utf8",
        )),
    }
}

fn check_len(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_LEN {
        return Err(Error::msg(format!(
            "длина сообщения должна быть от 1 до {MAX_MESSAGE_LEN} байт"
        )));
    }
    Ok(bytes)
}
