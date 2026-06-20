# Kurrent Invoice Design

A lightweight invoice format for the Kurrent latest-state channel protocol.

This note specifies the wire format and signing model. The note does not
specify the recovery or rebinding surface for paid invoices; those live in
the Kurrent state-update protocol, not the invoice itself.

## Scope

A **Kurrent invoice (KI)** is a single-party signed offer that commits to
the terms under which the recipient will accept a state update carrying a
specific hashlock payment. The invoice is the channel-side analogue of
BOLT 11: it carries the payment hash, amount, and the channel-state
identity required to redeem the payment off-chain.

The invoice is consumed by a single hop only. There is no onion routing,
no route hints, and no MPP. Kurrent channels are bilateral latest-state
channels, so the invoice never travels further than the payer.

## What we keep from BOLT 11

- **Bech32 encoding** for URL- and QR-friendly string form.
- **Payment hash as the hashlock primitive**. SHA256(preimage) =
  payment_hash; reveal of preimage is the receipt.
- **Description / description_hash** as UTF-8 metadata. Two flavours to
  cover short descriptions inline and longer ones by hash.
- **Expiry**, in DAA blocks rather than seconds. Kurrent's Δ window is
  DAA-relative sequence maturity, so wall-clock expiry would lie.

## What we drop from BOLT 11

- **Route hints (`r` tag)**. There is no onion routing in a bilateral
  channel. The payer already knows the channel outpoint.
- **Payment secret (`s` tag) for probing protection**. Probing attacks
  require forwarding through intermediate hops. Direct payment has no
  probe oracle.
- **`min_final_cltv` (`c` tag)**. There are no HTLCs in a Kurrent
  latest-state channel. Cltv does not apply.
- **Fallback addresses (`f` tag)**. The on-chain fallback for a Kurrent
  channel is cooperative close with the latest contested state, not a
  separate address form. Any Kurrent `SettlementOutput` is the fallback
  by construction.
- **MPP feature bits (`9` tag)**. Multi-part payment requires splitting
  across channels. A bilateral channel is one path.
- **Recoverable ECDSA**. Kurrent already uses BIP-340 Schnorr. The
  recipient's x-only pubkey is carried in the invoice explicitly; the
  verifier does not need to recover it from a signature.
- **Feature bits**. Channel features are negotiated at channel open and
  pinned by `network_profile`. The invoice does not need a feature
  vector.

## What we add beyond BOLT 11

- **`channel_id`** binding. The invoice names the exact bilateral
  channel it applies to. A payer holding an invoice against
  `channel_id_X` cannot redeem it on `channel_id_Y`.
- **`state_number`** binding. The invoice names the minimum state number
  the recipient will accept for the payment-carrying state. This lifts
  directly from eltoo's latest-state discipline; eltoo itself does not
  define invoices, but the state-update semantics it specifies carry
  over unchanged.
- **`amount_sompi`** with Kurrent base-unit precision. 1 sompi = 1
  Kaspa base unit. The amount is the minimum settlement value the
  recipient commits to accept.
- **Single-party Schnorr signature** with domain separation matching the
  rest of the Kurrent protocol suite (`DOMAIN_INVOICE_V1` etc.).
- **`network_profile`** as an explicit TLV. Mirrors the
  `KurrentChannelConfig.network_profile` field so a payment signed for
  `simnet-0.15` cannot be replayed on `mainnet-0.15`.

## Wire format

```
KI ::= HRP || "1" || data_part || checksum

HRP ::= "kikaspa"       # Kaspa mainnet
     |  "kikaspat"      # Kaspa testnet
     |  "kikaspar"      # Kaspa simnet (research harness)
     |  "kikasprt"      # Kaspa regtest
     |  "kikaspaidn"    # Kaspa devnet

data_part ::= TLV_SEQ || schnorr_sig(64 bytes)

TLV_SEQ ::= TLV*
TLV     ::= tag(1) || length(1) || data(length)

checksum ::= bech32m checksum (BIP-350), 6 characters
```

`data_part` is 5-bit-converted (bech32 data alphabet) before encoding;
`bech32m` (`x` = `0x2BC830A3` per BIP-350) is the checksum constant,
chosen over `bech32` to avoid the BIP-173 length-extension malleability
issue. Lightning still uses bech32 for backwards compatibility with the
BOLT 11 ecosystem; new protocols should adopt bech32m.

## Field set

| Tag  | Field             | Length      | Required | Meaning                                              |
| ---- | ----------------- | ----------- | -------- | ---------------------------------------------------- |
| 0x01 | `payment_hash`    | 32          | yes      | SHA256 of preimage. Hashlock.                        |
| 0x03 | `channel_id`      | 32          | yes      | Kurrent channel identity.                            |
| 0x05 | `state_number`    | 8 (BE u64)  | yes      | Minimum state number accepted.                       |
| 0x07 | `amount_sompi`    | 8 (BE u64)  | yes      | Minimum settlement value.                            |
| 0x09 | `recipient_xonly` | 32          | yes      | Recipient's per-state-update x-only pubkey.          |
| 0x0B | `payer_secret`    | 32          | no       | Anti-replay token binding this invoice to a payer.   |
| 0x0D | `expiry_daa`      | 4 (BE u32)  | no       | DAA blocks after timestamp until invoice expires.    |
| 0x0F | `description`     | 1..639      | no       | UTF-8 short description. Mutually exclusive with 0x11.|
| 0x11 | `description_hash`| 32          | no       | SHA256 of long description. Mutually exclusive with 0x0F. |
| 0x13 | `metadata`        | variable    | no       | Opaque TLV for protocol extensions. Forward-compatible.|
| 0x15 | `network_profile` | 1..64       | no       | Profile name from `KurrentChannelConfig.network_profile`. |

Unknown tags: a reader MUST skip them silently. The signer MUST NOT
include duplicate tags. The verifier MUST reject the invoice if any
required tag is missing or any tag carries an illegal length.

The 5-bit bech32 encoding of the data part is unambiguous: each byte of
each TLV is encoded by the standard 8-to-5 bit regrouping used in BIP-173.

## Signing model

The invoice is signed by the **recipient alone**, using the recipient's
per-state-update secret key. The recipient is committing:

> *I will accept a state update on `channel_id` that lifts the channel to
> `state_number` (or higher), distributes `amount_sompi` to me, and
> reveals a preimage under `payment_hash`. I bind this offer to the
> expiry, network profile, and (if present) payer_secret named in this
> invoice.*

The signing message is:

```
message = SHA256(
    "KURRENT_INVOICE_V1"          # domain separator (16 bytes ASCII)
  || u16_be(protocol_version)      # Kurrent protocol_version
  || HRP_as_utf8                  # bech32 HRP bytes
  || data_part_pre_signature      # TLV_SEQ bytes, no signature, no checksum
)
```

`protocol_version` is the Kurrent protocol version constant, not the
invoice's own version. The version is fixed at signing time and pinned
by the verifier's channel config; it does not appear as a TLV.

The signature is BIP-340 Schnorr, 64 bytes, placed after the TLV_SEQ and
before the bech32m checksum.

The recipient's verification key is `recipient_xonly` (TLV 0x09). It is
included in the invoice itself and is the pubkey the verifier recovers
from the channel config (the party's per-state-update x-only pubkey, not
the MuSig2 aggregate). The aggregate MuSig2 key appears only on the
on-chain contest output and on the joint signatures for state updates;
it is not the invoice signer's key.

### Why recipient signs alone, not jointly

A Kurrent invoice is an offer, not a state update. The recipient
commits unilaterally to terms; the payer accepts the offer by signing a
new state that satisfies those terms. Joint signing would only be
required if the invoice itself were a state update, which it is not.

The recipient's unilateral commitment is binding because the payer can
hold the signed invoice as evidence. If the recipient later refuses to
co-sign a state update that satisfies the invoice terms, the payer can
demonstrate that the recipient committed to those exact terms.

## Verification

A verifier accepts a KI if and only if:

1. The bech32m checksum is valid.
2. The HRP matches the verifier's expected network.
3. Every required TLV is present with the correct length.
4. `payment_hash`, `channel_id`, `state_number`, `amount_sompi`,
   `recipient_xonly` are present.
5. If `description` is present, it is valid UTF-8; if `description_hash`
   is present, it is 32 bytes; exactly one of `description` /
   `description_hash` is present, not both.
6. If `expiry_daa` is present, the current DAA score is below
   `timestamp + expiry_daa`.
7. If `network_profile` is present, it equals the verifier's channel
   network profile.
8. If `payer_secret` is present, it matches the verifier's local
   payer-nonce for this invoice.
9. The Schnorr signature verifies against `recipient_xonly` over the
   signing message above.
10. `recipient_xonly` matches the channel's recorded recipient
    per-state-update pubkey for `channel_id`.

The verifier MUST reject an invoice that fails any of these checks.

## Interaction with Kurrent state updates

A paid invoice transitions through three steps:

1. **Offer**. The recipient publishes the KI. The payer receives it
   out-of-band (QR, deep link, copy-paste).
2. **Update**. The payer constructs a new Kurrent state
   `state_number'` (with `state_number' >= state_number`) whose
   settlement distribution reflects `amount_sompi` to the recipient, and
   whose state root binds `payment_hash` as a hashlock witness. The
   payer signs unilaterally and submits both signatures to the
   recipient.
3. **Settle**. Once the new state is jointly signed, the payer reveals
   the preimage in the settlement witness, satisfying the hashlock. The
   settlement distribution transfers `amount_sompi` to the recipient.

The invoice is **not** the state update. The state update is a
separate Kurrent protocol object (`KurrentState`), domain-tagged
`KURRENT_STATE_V1`, and jointly signed. The invoice is the offer that
gives the state update meaning.

## Interop with LN preimage swaps

A Kurrent invoice is compatible with the existing `LnSwapEvidence`
preimage flow: the same `payment_hash` from a KI can be presented to an
LN node via `addinvoice`, paid by the LN counterparty, and the preimage
delivered back to the Kurrent payer. The `swap_id` ties the two legs.

The KI for an `ln-to-kaspa` leg carries the same `payment_hash` as the
LN invoice; the Kurrent recipient is the `kaspa` side. The KI for a
`kaspa-to-ln` leg carries the same `payment_hash` as the LN invoice
already issued by the LN recipient. Neither leg needs a different
invoice format.

## Worked example (byte-level)

```
HRP:             kikaspar           # simnet
protocol_version: 0x0001

TLVs:
  01 20 <32 bytes payment_hash>
  03 20 <32 bytes channel_id>
  05 08 00 00 00 00 00 00 00 2a   # state_number = 42
  07 08 00 00 00 00 00 00 03 e8   # amount_sompi = 1000
  09 20 <32 bytes recipient_xonly>
  0d 04 00 00 02 58              # expiry_daa = 600 DAA blocks
  15 06 's''i''m''n''e''t'        # network_profile

schnorr_sig:
  64 bytes over
    message = SHA256(
      "KURRENT_INVOICE_V1"
      || 0x00 0x01
      || "kikaspar" utf8
      || data_part_pre_signature
    )

bech32m encoding:
  HRP + "1" + 5-bit groups + 6-char checksum
```

The full encoded string is in the 600-character range for this example,
dominated by the three 32-byte fields.

## Open questions and named protocol-specification requirements

This design note is a research-architecture claim. Production
protocol-specification work must additionally satisfy the following
named requirements, which the note itself does not fill:

1. **`channel_id` derivation**. The note names `channel_id` as a
   required TLV but does not specify its derivation. The protocol
   specification must fix a deterministic commitment over
   `protocol_version`, `network_profile`, `funding_outpoint`,
   `participant_set_commitment` so the same channel always resolves to
   the same `channel_id` across all parties.
2. **`recipient_xonly` derivation**. The note assumes the recipient has
   a per-state-update x-only pubkey distinct from the MuSig2
   aggregate. The protocol specification must specify the key
   derivation, the per-state rotation rule, and the recovery path when
   the recipient's key is compromised.
3. **Expiry semantics under DAA**. `expiry_daa = 0` means no expiry;
   the note states the default but does not specify what happens when
   a payer attempts to settle a state update past the expiry window.
   The protocol specification must fix whether the recipient's
   commitment is silently voided, whether a separate `void_invoice`
   witness is required, or whether the recipient is bound until
   challenge expiry regardless of the invoice's own expiry.
4. **Replay protection across invoices**. The optional `payer_secret`
   binds an invoice to a specific payer nonce. The protocol
   specification must specify how the recipient tracks issued
   `(payment_hash, payer_secret)` pairs and rejects re-issue attempts
   that would put the same preimage at risk of replay.
5. **Bech32m vs bech32 interop**. The note picks bech32m. Any tool
   that needs to interoperate with both Kurrent and BOLT 11 invoices
   must implement both. The protocol specification must specify
   whether a single payment flow can carry a Kurrent invoice for the
   Kurrent leg and a BOLT 11 invoice for the LN leg, or whether the
   two formats must share a single encoding choice.
6. **Byte-level canonicalisation**. The TLV order, the bech32 8-to-5
   bit regrouping, and the checksum input format must all be fixed in
   a reference implementation. The note specifies the structure but
   defers the bit-packing implementation detail.

## What this note does not address

- **Invoice revocation**. A recipient may want to revoke an unpaid
  invoice before it is redeemed. The note does not specify a
  revocation protocol; this is a separate protocol surface.
- **Watchtower forwarding**. A payer may want to share an invoice with
  a watchtower before paying. The note does not address watchtower
  key management.
- **Hash-time-locked contracts (HTLCs)**. Kurrent does not use HTLCs.
  The hashlock is realised through the state-update witness, not
  through a separate HTLC output.