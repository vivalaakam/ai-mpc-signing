ALTER TABLE signing_requests ADD COLUMN solana_recipient TEXT;
ALTER TABLE signing_requests ADD COLUMN solana_lamports BIGINT;
ALTER TABLE signing_requests ADD COLUMN transaction_signature TEXT;

ALTER TABLE signing_requests ADD CONSTRAINT signing_requests_solana_transfer_chk CHECK (
    (solana_recipient IS NULL AND solana_lamports IS NULL)
    OR (solana_recipient IS NOT NULL AND solana_lamports IS NOT NULL AND solana_lamports > 0)
);
