// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  IWhitelist
/// @notice Minimal read interface for the `RequestWhitelist` registry.
///         Downstream consumers that only need authorship attestation
///         import this and stay decoupled from the rest of the contract.
interface IWhitelist {
  /// @notice Returns true iff `a` has been attested by a validator quorum.
  /// @dev    Returns false while the registry is paused, regardless of prior
  ///         state. This is the circuit-breaker guarantee operators rely on
  ///         to cut off misbehaving targets in a single call.
  /// @param  a The address whose attestation status is being queried.
  /// @return Whether `a` is currently considered whitelisted.
  function isWhitelisted(address a) external view returns (bool);
}
