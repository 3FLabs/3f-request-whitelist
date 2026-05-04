// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  WhitelistErrors
/// @notice All contract-level errors thrown by `RequestWhitelist`.
///         Signature-verification errors live separately in
///         `QuorumSigLib`; everything else — init guards, pause state,
///         admin paths, role / quorum invariants — is collected here.
library WhitelistErrors {
  /// @notice Reverts when the registry is currently paused.
  error ContractPaused();

  /// @notice Reverts when the caller is not a compliance officer.
  error NotCompliance();

  /// @notice Reverts when a validator calls `setValidatorNonceFloor`
  ///         with a non-strictly-increasing value. The nonce floor can
  ///         only move forward — shrinking it would re-expose
  ///         previously invalidated signatures.
  error NewNonceNotIncreasing();

  /// @notice Reverts when `pauseFor` would not strictly extend the
  ///         current pause window (e.g. `pauseFor(0)` or a duration
  ///         smaller than the remaining pause).
  error PauseNotExtended();

  /// @notice Reverts when `setQuorum` / `setQuorumBySig` is called with
  ///         the current quorum value. Refused so quorum-sig submitters
  ///         can't spend a validator nonce batch on a no-op.
  error QuorumUnchanged();

  /// @notice Reverts from a `*BySig` admin path while the owner is still
  ///         set — those paths are only available after renouncement.
  error OwnerStillSet();

  /// @notice Reverts when `initialize` is passed `address(0)` as owner.
  error OwnerIsZero();

  /// @notice Reverts when the quorum would leave the contract unusable —
  ///         either 0 or greater than or equal to the current validator
  ///         count. The strict `quorum < validators.length` invariant
  ///         is enforced both on `_setQuorum` and on `_removeValidator`
  ///         (which rejects a removal that would leave `length <= quorum`).
  error QuorumOutOfRange();

  /// @notice Reverts when adding a validator would exceed `MAX_VALIDATORS`.
  error ValidatorLimitReached();

  /// @notice Reverts when adding an address that's already a validator.
  error DuplicateValidator();

  /// @notice Reverts when `initialize` is passed an empty validator array.
  error EmptyValidators();

  /// @notice Reverts on any attempt to set a critical address to the zero
  ///         address (validators, compliance officers).
  error ZeroAddress();
}
