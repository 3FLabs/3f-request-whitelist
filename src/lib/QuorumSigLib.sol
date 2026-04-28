// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/// @title  QuorumSigLib
/// @notice EIP-712 / EIP-1271 quorum signature primitives used by
///         `RequestWhitelist`. Factored out so the verification logic can
///         be reasoned about in isolation from the rest of the contract.
///
/// @dev    Two independent bitmaps are used:
///           - A *call-local* bitmap, keyed by each validator's index in
///             the enumerable set, prevents the same validator from being
///             credited twice in one call. That limits the validator set
///             to 256 entries; consumers must enforce the cap via
///             `MAX_VALIDATORS` whenever they grow the set.
///           - A *per-validator, persistent* bitmap (stored in
///             `RequestWhitelist`'s `StorageLayout.validatorNonceBitmap`) marks
///             which nonces each validator has already consumed. Each
///             word holds 256 bits; nonce `n` maps to bit `n % 256` of
///             word `n / 256`. Because any previously-consumed nonce
///             permanently sets its bit, signatures can be submitted in
///             any order and each remains single-use.
///         A per-validator `nonceFloor` scalar is the mass-invalidate
///         lever: signatures with `nonce < floor` are rejected
///         (`NonceBelowFloor`), so a validator that suspects key
///         compromise can invalidate the entire low range in one SSTORE
///         without having to touch any bitmap words.
library QuorumSigLib {
  using EnumerableSetLib for EnumerableSetLib.AddressSet;

  /// @notice Hard cap on validator-set size, dictated by the call-local
  ///         dedup bitmap.
  uint256 internal constant MAX_VALIDATORS = 256;

  // ──────────────────────────────────────────────────────────────────────────
  // Types
  // ──────────────────────────────────────────────────────────────────────────

  /// @notice One validator signature bound to a specific signer and a
  ///         signer-chosen nonce.
  /// @param  validator Address the signature must recover against (or, for
  ///                   ERC-1271 signers, the contract whose
  ///                   `isValidSignature` must return the magic value).
  /// @param  nonce     Validator-chosen nonce. The contract accepts any
  ///                   nonce at or above the validator's current
  ///                   `nonceFloor` that has not yet been consumed, in
  ///                   any submission order — with one exception:
  ///                   `nonce == type(uint256).max` is reserved as the
  ///                   "retired-validator" sentinel and is always
  ///                   rejected `NonceBelowFloor`, regardless of the
  ///                   floor value. The bit for this nonce is set on
  ///                   successful use so the same sig can never be
  ///                   replayed. Validators are free to allocate
  ///                   sequentially (simplest), use random / time-based
  ///                   nonces (fine too), or skip ranges — only the
  ///                   "not-below-floor, not-already-consumed, not the
  ///                   max-sentinel" invariant is enforced.
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
  /// @notice Reverts when a sig's nonce is strictly below the
  ///         validator's current `nonceFloor` (i.e. the mass-invalidate
  ///         lever has been pulled past this point), or when the nonce
  ///         is the reserved `type(uint256).max` retired-validator
  ///         sentinel.
  error NonceBelowFloor();
  /// @notice Reverts when a sig's nonce has already been consumed by a
  ///         prior successful verification.
  error NonceConsumed();
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
  ///         sig's nonce in the validator's persistent bitmap, and folds
  ///         the validator's index into the caller's call-local dedup
  ///         bitmap.
  /// @dev    Check order:
  ///           1. Validator is in the enumerable set (cheap).
  ///           2. Call-local dedup — same validator not already credited
  ///              in this call (memory-only).
  ///           3. Nonce is at or above the validator's current floor
  ///              and is not the `type(uint256).max` sentinel.
  ///           4. Nonce has not already been consumed.
  ///           5. ECDSA / ERC-1271 signature recovers to the digest.
  ///         The persistent bitmap bit is set only *after* the signature
  ///         verifies, so a revert on step 5 leaves the nonce
  ///         unconsumed and the sig can be re-submitted.
  ///
  ///         The max-nonce sentinel rejection in step 3 is what makes
  ///         removed-validator floor saturation airtight: setting the
  ///         floor to `type(uint256).max` would otherwise still leave
  ///         exactly one usable nonce (`floor` itself, since the floor
  ///         check is strict-less-than). With the sentinel rejected,
  ///         removal truly retires the address.
  /// @param  validators        Storage pointer to the whitelist's
  ///                           validator set.
  /// @param  nonceFloors       Storage pointer to the per-validator
  ///                           `nonceFloor` mapping. Sigs below this
  ///                           value are rejected.
  /// @param  nonceBitmaps      Storage pointer to the per-validator,
  ///                           per-word bitmap of consumed nonces.
  ///                           `nonceBitmaps[v][n >> 8]` holds bit
  ///                           `n & 0xff` for nonce `n`.
  /// @param  digest            The EIP-712 digest this signature should
  ///                           attest to.
  /// @param  s                 The signature entry to validate.
  /// @param  seen              Call-local bitmap of validator indices
  ///                           already credited in this call.
  /// @return The updated call-local bitmap with this validator's bit set.
  function assertSigValid(
    EnumerableSetLib.AddressSet storage validators,
    mapping(address => uint256) storage nonceFloors,
    mapping(address => mapping(uint256 => uint256)) storage nonceBitmaps,
    bytes32 digest,
    Sig calldata s,
    uint256 seen
  ) internal returns (uint256) {
    // `indexOf` returns `type(uint256).max` when the validator is not in
    // the set; any real index is < MAX_VALIDATORS (256).
    uint256 idx = validators.indexOf(s.validator);
    if (idx == type(uint256).max) revert NotValidator();

    // Call-local dedup first — repeating the same signer in one call is
    // always `DuplicateSignature`, regardless of nonce bookkeeping.
    uint256 bit = 1 << idx;
    if (seen & bit != 0) revert DuplicateSignature();

    if (s.nonce < nonceFloors[s.validator]) revert NonceBelowFloor();
    // `type(uint256).max` is reserved as the retired-validator sentinel.
    // Without this branch, `_removeValidator`'s floor saturation would
    // still leave one usable nonce (the floor itself, since the floor
    // check is strict-less-than) — the sentinel closes that gap.
    if (s.nonce == type(uint256).max) revert NonceBelowFloor();

    // `n >> 8` is `n / 256`; `1 << (n & 0xff)` is the bit for `n % 256`.
    uint256 word = s.nonce >> 8;
    uint256 mask = 1 << (s.nonce & 0xff);
    uint256 currentWord = nonceBitmaps[s.validator][word];
    if (currentWord & mask != 0) revert NonceConsumed();

    // Verify the signature before persisting the consumption, so a bad
    // sig accidentally paired with a fresh nonce leaves the nonce
    // available for a legitimate retry.
    if (!SignatureCheckerLib.isValidSignatureNowCalldata(s.validator, digest, s.signature)) {
      revert SignatureInvalid();
    }

    nonceBitmaps[s.validator][word] = currentWord | mask;
    return seen | bit;
  }
}
