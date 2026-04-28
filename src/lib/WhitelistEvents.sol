// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  WhitelistEvents
/// @notice All events emitted by `RequestWhitelist`. Collected here so
///         indexers and downstream integrators have a single import to
///         bind their ABI against.
/// @dev    Events are recorded under the emitting contract's address, not
///         the library's. Solidity 0.8.22+ is required to emit
///         library-declared events.
library WhitelistEvents {
  /// @notice Emitted once per target that transitioned to the whitelisted
  ///         state within a call to `whitelist`.
  /// @param  target The address just marked as whitelisted.
  event Whitelisted(address indexed target);

  /// @notice Emitted once per target that transitioned to the
  ///         non-whitelisted state within a call to `unwhitelist`.
  /// @param  target The address just cleared.
  event Unwhitelisted(address indexed target);

  /// @notice Emitted whenever a new validator joins the set.
  /// @param  validator The validator address just added.
  event ValidatorAdded(address indexed validator);

  /// @notice Emitted whenever a validator leaves the set.
  /// @param  validator The validator address just removed.
  event ValidatorRemoved(address indexed validator);

  /// @notice Emitted on every successful quorum change.
  /// @param  quorum The new required quorum.
  event QuorumSet(uint16 quorum);

  /// @notice Emitted on every grant or revoke of the compliance role.
  /// @param  officer The address whose compliance status changed.
  /// @param  enabled The new flag value.
  event ComplianceOfficerSet(address indexed officer, bool enabled);

  /// @notice Emitted whenever a validator bumps their own nonce floor
  ///         via `setValidatorNonceFloor`, or whenever
  ///         `_removeValidator` saturates the floor to
  ///         `type(uint256).max` on removal.
  /// @param  validator The validator whose floor changed.
  /// @param  newFloor  The new on-chain nonce floor value.
  event ValidatorNonceSet(address indexed validator, uint256 newFloor);

  /// @notice Emitted whenever `pausedUntil` moves forward (either a new
  ///         pause or an extension of an existing one).
  /// @param  until The current value of `pausedUntil` after the update.
  event Paused(uint48 until);

  /// @notice Emitted when a compliance officer cancels the pause early.
  event Unpaused();
}
