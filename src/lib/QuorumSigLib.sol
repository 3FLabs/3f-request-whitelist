// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/// @title  QuorumSigLib
/// @notice EIP-712 / EIP-1271 quorum signature primitives used by
///         `RequestWhitelist`. Factored out so the verification logic can
///         be reasoned about in isolation from the rest of the contract.
///
/// @dev    Validator de-duplication relies on a single-word bitmap keyed by
///         the validator's index in the enumerable set. That limits the
///         validator set to 256 entries; consumers must enforce the cap via
///         `MAX_VALIDATORS` whenever they grow the set.
library QuorumSigLib {
  using EnumerableSetLib for EnumerableSetLib.AddressSet;

  /// @notice Hard cap on validator-set size, dictated by the dedup bitmap.
  uint256 internal constant MAX_VALIDATORS = 256;

  // ──────────────────────────────────────────────────────────────────────────
  // Types
  // ──────────────────────────────────────────────────────────────────────────

  /// @notice One validator signature bound to a specific signer and that
  ///         signer's current on-chain nonce.
  /// @param  validator Address the signature must recover against (or, for
  ///                   ERC-1271 signers, the contract whose
  ///                   `isValidSignature` must return the magic value).
  /// @param  nonce     Validator's nonce at the time of signing. The
  ///                   contract rejects the sig if this does not equal the
  ///                   validator's current on-chain nonce, and advances
  ///                   the on-chain nonce by one on successful use so the
  ///                   same sig can never be replayed. A validator
  ///                   producing multiple concurrent sigs must pre-allocate
  ///                   sequential nonces; those sigs are consumed in order.
  /// @param  signature Raw 65-byte ECDSA payload or an opaque blob the
  ///                   ERC-1271 signer contract understands.
  struct Sig {
    address validator;
    uint256 nonce;
    bytes signature;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Errors
  // ──────────────────────────────────────────────────────────────────────────

  /// @notice Reverts when `block.timestamp` is past the call's `deadline`.
  error SignatureExpired();
  /// @notice Reverts when the caller supplied fewer sigs than the current quorum.
  error QuorumNotMet();
  /// @notice Reverts when a sig references an address outside the validator set.
  error NotValidator();
  /// @notice Reverts when a sig's embedded nonce differs from the validator's
  ///         stored nonce (i.e. the validator has rotated out this sig).
  error NonceMismatch();
  /// @notice Reverts when two sigs in one call reference the same validator.
  error DuplicateSignature();
  /// @notice Reverts when the signature fails ECDSA / ERC-1271 recovery
  ///         against the expected digest.
  error SignatureInvalid();

  // ──────────────────────────────────────────────────────────────────────────
  // Verification primitives
  // ──────────────────────────────────────────────────────────────────────────

  /// @notice Reverts if the deadline has passed or fewer than `required`
  ///         signatures were supplied. Intended as the cheap pre-flight
  ///         before entering the per-signature loop.
  /// @dev    Factored out so the outer verifiers don't duplicate this pair
  ///         of checks. Pure-view: reads only `block.timestamp`.
  /// @param  deadline The unix timestamp beyond which sigs are stale.
  /// @param  sigsLen  Length of the sigs array provided by the caller.
  /// @param  required The quorum threshold read from contract state.
  function assertDeadlineAndQuorum(uint256 deadline, uint256 sigsLen, uint256 required) internal view {
    if (block.timestamp > deadline) revert SignatureExpired();
    if (sigsLen < required) revert QuorumNotMet();
  }

  /// @notice Validates a single signature against `digest`, consumes the
  ///         validator's nonce, and folds the validator's bit into the
  ///         caller's dedup bitmap.
  /// @dev    Fails, in order, on: non-member validator, stale nonce, repeat
  ///         signer within the same call, invalid signature. Uses
  ///         `SignatureCheckerLib` so both raw ECDSA signatures from EOAs
  ///         and ERC-1271 contract signatures are handled transparently.
  ///
  ///         The validator's stored nonce is advanced to `s.nonce + 1` on
  ///         successful verification so each signature is single-use. A
  ///         validator producing multiple in-flight sigs must pre-allocate
  ///         distinct sequential nonces; submissions then consume them in
  ///         order.
  /// @param  validators Storage pointer to the whitelist's validator set.
  /// @param  nonces     Storage pointer to the per-validator nonce mapping.
  /// @param  digest     The EIP-712 digest this signature should attest to.
  /// @param  s          The signature entry to validate.
  /// @param  seen       Bitmap of validator indices already credited in
  ///                    this call, as produced by earlier invocations.
  /// @return The updated bitmap with this validator's bit set.
  function assertSigValid(
    EnumerableSetLib.AddressSet storage validators,
    mapping(address => uint256) storage nonces,
    bytes32 digest,
    Sig calldata s,
    uint256 seen
  ) internal returns (uint256) {
    // `indexOf` returns `type(uint256).max` when the validator is not in
    // the set; any real index is < MAX_VALIDATORS (256).
    uint256 idx = validators.indexOf(s.validator);
    if (idx == type(uint256).max) revert NotValidator();

    // Dedup is a call-local concern — check it before the nonce so that
    // repeating the same signer in one call always surfaces as
    // `DuplicateSignature`, regardless of what nonces the submitter
    // attached.
    uint256 bit = 1 << idx;
    if (seen & bit != 0) revert DuplicateSignature();

    if (s.nonce != nonces[s.validator]) revert NonceMismatch();

    // The calldata variant skips a memory copy of the signature payload.
    if (!SignatureCheckerLib.isValidSignatureNowCalldata(s.validator, digest, s.signature)) {
      revert SignatureInvalid();
    }

    // Consume the nonce on use so this exact sig can never be replayed.
    unchecked {
      nonces[s.validator] = s.nonce + 1;
    }
    return seen | bit;
  }
}
