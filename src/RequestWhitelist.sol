// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "solady/utils/Initializable.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

import {IWhitelist} from "./IWhitelist.sol";
import {QuorumSigLib} from "./lib/QuorumSigLib.sol";
import {WhitelistErrors} from "./lib/WhitelistErrors.sol";
import {WhitelistEvents} from "./lib/WhitelistEvents.sol";

/// @title  RequestWhitelist
/// @notice On-chain attestation registry. Two parallel write paths feed
///         the underlying `isWhitelisted[a]` bit: the trusted owner can
///         flip it directly (`whitelist` / `unwhitelist`), and a quorum
///         of validators can flip it via signed batches
///         (`whitelistBySig` / `unwhitelistBySig`). Validators are the
///         distributed automation lane; the owner is the trusted-multisig
///         escape hatch. Both paths converge on the same storage bit and
///         the same events. Consumers call `isWhitelisted(address)` (see
///         `IWhitelist`) as the single source of truth.
///
///         A compliance role can freeze the registry for a bounded
///         window. While frozen, `isWhitelisted` reports one of the
///         `Paused*` variants — never `Whitelisted` — and every
///         **whitelisting** call (`whitelist`, `whitelistBySig`) reverts
///         with `ContractPaused`. **Unwhitelisting** (`unwhitelist`,
///         `unwhitelistBySig`) deliberately remains callable while
///         paused: revoking attestations is a fail-safe that must not be
///         blocked by the circuit breaker.
///
///         Owner-side admin paths (`addValidator`, `removeValidator`,
///         `setQuorum`, `setComplianceOfficer`) are gated by
///         `whenNotPaused`; the validator-self lever
///         (`setValidatorNonceFloor`), the post-renounce `*BySig` admin
///         twins, and the owner-only `revokeAllRoles` recovery hook
///         remain reachable during pause so the circuit breaker cannot
///         lock out the recovery it was built to enable.
///
///         Phase model: while `owner() != address(0)` (Phase 1) both
///         the owner-direct and the sig paths are open. After
///         `renounceOwnership()` (Phase 2) the owner-direct paths are
///         permanently unreachable (the `onlyOwner` modifier reverts
///         once the slot is zero); only the sig path remains, governed
///         by the validator quorum.
///
///         The contract is factory- and proxy-agnostic: deploy the
///         implementation once, put it behind any ERC-1967 proxy, and call
///         `initialize` through the proxy.
///
/// @dev    Inherits solady's `Initializable`, `Ownable` and `EIP712`.
///         Signature verification is delegated to `QuorumSigLib`, which in
///         turn uses `SignatureCheckerLib` so both ECDSA (EOA) and ERC-1271
///         (contract) signers are handled transparently.
///
///         All mutable state lives in a single ERC-7201 namespaced struct;
///         `Ownable` and `Initializable` use their own hardcoded high-slot
///         constants, which cannot collide.
contract RequestWhitelist is IWhitelist, Initializable, Ownable, EIP712 {
  using EnumerableSetLib for EnumerableSetLib.AddressSet;

  // ───────────────────────────────────────────────────────────────────────────
  // Storage (ERC-7201)
  // ───────────────────────────────────────────────────────────────────────────

  /// @notice Hard cap on validator-set size; surfaced so clients can query
  ///         it instead of hard-coding. Determined by `QuorumSigLib`'s
  ///         single-word bitmap dedup.
  uint256 public constant MAX_VALIDATORS = QuorumSigLib.MAX_VALIDATORS;

  /// @custom:storage-location erc7201:3f.storage.RequestWhitelist
  /// @dev Slot 0 packs the two admin scalars and leaves 26 free bytes for
  ///      future flags added in later versions. Dynamic members (the set
  ///      and the mappings) each anchor their own base slot and therefore
  ///      don't perturb slot 0 when they grow.
  ///
  ///      Nonce accounting (see `QuorumSigLib`):
  ///        - `validatorNonceFloor[v]` — every sig at a nonce below this
  ///          value is rejected `NonceBelowFloor`. Raised by the
  ///          validator themselves via `setValidatorNonceFloor` as the
  ///          mass-invalidate lever, and forced to `type(uint256).max`
  ///          in `_removeValidator` so that removal permanently burns
  ///          the nonce space for that address. `QuorumSigLib` also
  ///          rejects `nonce == type(uint256).max` outright, so a
  ///          retired address can never produce a usable sig (closes
  ///          the re-add replay window with no exception).
  ///        - `validatorNonceBitmap[v][word]` — packed 256-bit word of
  ///          consumed nonces; bit `n & 0xff` of word `n >> 8` is set
  ///          once nonce `n` has been successfully verified for
  ///          validator `v`. Sigs can therefore be submitted in any
  ///          order, each is single-use, and two submitters racing the
  ///          same nonce produce one `ok` and one `NonceConsumed`.
  struct StorageLayout {
    uint16 quorum; // minimum number of distinct validator sigs required
    uint48 pausedUntil; // unix seconds; 0 == not paused
    EnumerableSetLib.AddressSet validators;
    mapping(address => uint256) validatorNonceFloor;
    mapping(address => bool) isComplianceOfficer;
    mapping(address => bool) isWhitelisted;
    mapping(address => mapping(uint256 => uint256)) validatorNonceBitmap;
  }

  // keccak256(abi.encode(uint256(keccak256("3f.storage.RequestWhitelist")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant _STORAGE_SLOT = 0x9e193f57867c54cb61bb3037d351387081a88b862376ceddfd961cec2c798100;

  // ───────────────────────────────────────────────────────────────────────────
  // EIP-712 type hashes & action ids
  // ───────────────────────────────────────────────────────────────────────────

  /// @dev Signed by validators when adding addresses to the whitelist.
  bytes32 private constant _WHITELIST_TYPEHASH =
    keccak256("WhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  /// @dev Signed by validators when removing addresses from the whitelist.
  bytes32 private constant _UNWHITELIST_TYPEHASH =
    keccak256("UnwhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  /// @dev Signed by validators when performing admin actions after the
  ///      owner has been renounced. The signed struct embeds an `actionId`
  ///      and abi-encoded `data` so wallet UIs can show which action is
  ///      being approved.
  bytes32 private constant _ADMIN_TYPEHASH =
    keccak256("AdminRequest(bytes32 actionId,bytes data,uint256 deadline,address validator,uint256 nonce)");

  /// @notice Action id for `addValidatorBySig`.
  bytes32 public constant ACTION_ADD_VALIDATOR = keccak256("ADD_VALIDATOR");
  /// @notice Action id for `removeValidatorBySig`.
  bytes32 public constant ACTION_REMOVE_VALIDATOR = keccak256("REMOVE_VALIDATOR");
  /// @notice Action id for `setQuorumBySig`.
  bytes32 public constant ACTION_SET_QUORUM = keccak256("SET_QUORUM");
  /// @notice Action id for `setComplianceOfficerBySig`.
  bytes32 public constant ACTION_SET_COMPLIANCE = keccak256("SET_COMPLIANCE_OFFICER");

  // Events live in `./lib/WhitelistEvents.sol`; errors live in
  // `./lib/WhitelistErrors.sol`. Signature-verification errors belong to
  // `./lib/QuorumSigLib.sol`.

  // ───────────────────────────────────────────────────────────────────────────
  // Modifiers
  // ───────────────────────────────────────────────────────────────────────────

  /// @dev Reverts with `ContractPaused` when the pause window is active.
  modifier whenNotPaused() {
    if (block.timestamp < _getStorage().pausedUntil) revert WhitelistErrors.ContractPaused();
    _;
  }

  /// @dev Reverts with `NotCompliance` if the caller is not a compliance
  ///      officer at the time of the call.
  modifier onlyCompliance() {
    if (!_getStorage().isComplianceOfficer[msg.sender]) revert WhitelistErrors.NotCompliance();
    _;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Constructor & initializer
  // ───────────────────────────────────────────────────────────────────────────

  /// @dev Locks the implementation so nobody can call `initialize` on it
  ///      directly. Only a proxy delegatecalling into this code can run
  ///      the initializer, which operates on the proxy's storage.
  constructor() {
    _disableInitializers();
  }

  /// @notice One-shot initialiser. The proxy must call this exactly once.
  /// @dev    After this call returns, `owner_` holds every admin power;
  ///         hand control to the validator quorum by later calling
  ///         `renounceOwnership()`.
  /// @param  owner_              Initial owner; `address(0)` is rejected.
  /// @param  validators_         Initial validator set, 1..`MAX_VALIDATORS`
  ///                             elements, no duplicates, no zero.
  /// @param  quorum_             Minimum number of distinct signatures to
  ///                             whitelist / unwhitelist / admin-by-sig.
  ///                             Must satisfy `1 <= quorum_ < validators_.length`
  ///                             (strictly less than the validator count, so
  ///                             at least one non-coalition validator can always
  ///                             block a quorum-sized capture).
  /// @param  complianceOfficers_ Initial compliance officers permitted to
  ///                             pause and unpause the registry.
  function initialize(
    address owner_,
    address[] calldata validators_,
    uint16 quorum_,
    address[] calldata complianceOfficers_
  ) external initializer {
    if (owner_ == address(0)) revert WhitelistErrors.OwnerIsZero();
    if (validators_.length == 0) revert WhitelistErrors.EmptyValidators();
    _initializeOwner(owner_);

    StorageLayout storage $ = _getStorage();
    for (uint256 i; i < validators_.length; ++i) {
      _addValidator($, validators_[i]);
    }
    _setQuorum($, quorum_);
    for (uint256 i; i < complianceOfficers_.length; ++i) {
      _setComplianceOfficer($, complianceOfficers_[i], true);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // View functions
  // ───────────────────────────────────────────────────────────────────────────

  /// @notice Returns the full validator set in internal storage order.
  /// @dev    Order is not guaranteed stable across add/remove — solady's
  ///         `EnumerableSetLib` uses pop-and-swap.
  function validators() external view returns (address[] memory) {
    return _getStorage().validators.values();
  }

  /// @notice Number of validators currently in the set.
  function validatorsLength() external view returns (uint256) {
    return _getStorage().validators.length();
  }

  /// @notice Returns the validator at storage index `i`.
  /// @param  i The set index to look up.
  function validatorAt(uint256 i) external view returns (address) {
    return _getStorage().validators.at(i);
  }

  /// @notice True iff `a` is in the validator set.
  /// @param  a The address to check.
  function isValidator(address a) external view returns (bool) {
    return _getStorage().validators.contains(a);
  }

  /// @notice Current quorum value — the minimum number of valid sigs
  ///         required to whitelist, unwhitelist, or change admin state.
  function quorum() external view returns (uint16) {
    return _getStorage().quorum;
  }

  /// @notice Current nonce floor for `v`. Signatures at a nonce strictly
  ///         below this value are rejected `NonceBelowFloor`. The floor
  ///         is the mass-invalidate lever — validators raise it via
  ///         `setValidatorNonceFloor`, and `_removeValidator` saturates
  ///         it to `type(uint256).max` to permanently burn the nonce
  ///         space for a removed address (and `QuorumSigLib` separately
  ///         rejects `nonce == type(uint256).max`, so the saturated
  ///         floor leaves no usable nonce).
  /// @param  v The validator address.
  function validatorNonceFloor(address v) external view returns (uint256) {
    return _getStorage().validatorNonceFloor[v];
  }

  /// @notice Whether nonce `n` has already been consumed by `v`. True
  ///         iff bit `n & 0xff` of word `n >> 8` in `v`'s bitmap is
  ///         set. Does not consider the floor — a nonce below the
  ///         current floor reads `false` here even though any sig at
  ///         that nonce is unusable.
  /// @param  v The validator address.
  /// @param  n The nonce to inspect.
  function isNonceConsumed(address v, uint256 n) external view returns (bool) {
    return _getStorage().validatorNonceBitmap[v][n >> 8] & (1 << (n & 0xff)) != 0;
  }

  /// @notice True iff `a` can currently pause or unpause the registry.
  /// @param  a The address to check.
  function isComplianceOfficer(address a) external view returns (bool) {
    return _getStorage().isComplianceOfficer[a];
  }

  /// @inheritdoc IWhitelist
  /// @dev    While `block.timestamp < pausedUntil` the function returns
  ///         one of the paused variants even for previously-whitelisted
  ///         targets; this is the circuit-breaker guarantee the operator
  ///         relies on. Integrators must treat anything other than
  ///         `WhitelistStatus.Whitelisted` as "do not authorise".
  function isWhitelisted(address a) external view returns (WhitelistStatus) {
    StorageLayout storage $ = _getStorage();
    bool listed = $.isWhitelisted[a];
    if (block.timestamp < $.pausedUntil) {
      return listed ? WhitelistStatus.PausedWhitelisted : WhitelistStatus.PausedNotWhitelisted;
    }
    return listed ? WhitelistStatus.Whitelisted : WhitelistStatus.NotWhitelisted;
  }

  /// @notice Unix timestamp at which the current pause (if any) ends.
  ///         Zero means the registry has never been paused, or the pause
  ///         has been explicitly cleared via `unpause`.
  function pausedUntil() external view returns (uint48) {
    return _getStorage().pausedUntil;
  }

  /// @notice Whether the registry is currently paused.
  function isPaused() external view returns (bool) {
    return block.timestamp < _getStorage().pausedUntil;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // State-changing external functions
  // ───────────────────────────────────────────────────────────────────────────

  /// @notice Flips `targets` to the whitelisted state. Owner-only
  ///         direct path — no validator signatures required. Sig-based
  ///         submitters use `whitelistBySig` instead.
  /// @dev    `whenNotPaused`: while paused, `isWhitelisted` is masked to
  ///         the `Paused*` variants anyway, so flipping bits during
  ///         pause would be invisible to integrators and arguably
  ///         misleading. Mirrors the `whenNotPaused` gate on
  ///         `whitelistBySig`.
  ///
  ///         Available only in Phase 1 — once `owner()` is renounced,
  ///         `onlyOwner` reverts and this entry point is permanently
  ///         unreachable; quorum-signed `whitelistBySig` remains.
  /// @param  targets Addresses to whitelist. Already-whitelisted entries
  ///                 are silently skipped (so the call stays idempotent
  ///                 and emits one event per actual flip).
  function whitelist(address[] calldata targets) external onlyOwner whenNotPaused {
    StorageLayout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if (!$.isWhitelisted[targets[i]]) {
        $.isWhitelisted[targets[i]] = true;
        emit WhitelistEvents.Whitelisted(targets[i]);
      }
    }
  }

  /// @notice Flips `targets` to the non-whitelisted state. Owner-only
  ///         direct path — no validator signatures required. Sig-based
  ///         submitters use `unwhitelistBySig` instead.
  /// @dev    Intentionally **not** `whenNotPaused`: revoking
  ///         attestations is a fail-safe that must work even while the
  ///         circuit breaker is active. Mirrors the absence of
  ///         `whenNotPaused` on `unwhitelistBySig`. Available only in
  ///         Phase 1 — once `owner()` is renounced, `onlyOwner` reverts
  ///         and this entry point is permanently unreachable.
  /// @param  targets Addresses to remove from the whitelist. Addresses
  ///                 that weren't whitelisted are silently skipped.
  function unwhitelist(address[] calldata targets) external onlyOwner {
    StorageLayout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if ($.isWhitelisted[targets[i]]) {
        $.isWhitelisted[targets[i]] = false;
        emit WhitelistEvents.Unwhitelisted(targets[i]);
      }
    }
  }

  /// @notice Flips `targets` to the whitelisted state via a quorum of
  ///         validator signatures. Open to any submitter — the
  ///         signatures are the access control, not the caller. The
  ///         owner-direct twin is `whitelist(address[])`.
  /// @dev    `whenNotPaused`: same rationale as the owner-direct
  ///         twin — flipping bits during pause is invisible to
  ///         integrators (`isWhitelisted` reads as `Paused*`) so the
  ///         contract refuses to accept signatures it could not
  ///         meaningfully act on.
  /// @param  targets  Addresses to whitelist. Already-whitelisted entries
  ///                  are silently skipped.
  /// @param  deadline Unix timestamp beyond which the sigs stop being valid.
  /// @param  sigs     Validator sigs covering the batch. `sigs.length >= quorum`.
  function whitelistBySig(address[] calldata targets, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    external
    whenNotPaused
  {
    _verifyBatchQuorum(_WHITELIST_TYPEHASH, targets, deadline, sigs);
    StorageLayout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if (!$.isWhitelisted[targets[i]]) {
        $.isWhitelisted[targets[i]] = true;
        emit WhitelistEvents.Whitelisted(targets[i]);
      }
    }
  }

  /// @notice Flips `targets` to the non-whitelisted state via a quorum
  ///         of validator signatures. Open to any submitter. The
  ///         owner-direct twin is `unwhitelist(address[])`.
  /// @dev    Intentionally **not** `whenNotPaused`: revoking
  ///         attestations is a fail-safe and must remain reachable
  ///         while the circuit breaker is active. Mirrors the absence
  ///         of `whenNotPaused` on `unwhitelist(address[])`.
  /// @param  targets  Addresses to remove from the whitelist. Addresses
  ///                  that weren't whitelisted are silently skipped.
  /// @param  deadline Unix timestamp beyond which the sigs stop being valid.
  /// @param  sigs     Validator sigs covering the batch. `sigs.length >= quorum`.
  function unwhitelistBySig(address[] calldata targets, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external {
    _verifyBatchQuorum(_UNWHITELIST_TYPEHASH, targets, deadline, sigs);
    StorageLayout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if ($.isWhitelisted[targets[i]]) {
        $.isWhitelisted[targets[i]] = false;
        emit WhitelistEvents.Unwhitelisted(targets[i]);
      }
    }
  }

  /// @notice Sets the pause to expire `secondsDuration` seconds from
  ///         the current `block.timestamp` — but only if that target is
  ///         strictly later than the existing `pausedUntil`.
  /// @dev    Not "extend-by"; the new `pausedUntil` is computed from
  ///         the current `block.timestamp`, not from the existing
  ///         `pausedUntil`. Extend-only in the sense that any call
  ///         which would not move `pausedUntil` strictly forward
  ///         reverts `PauseNotExtended` (covers `pauseFor(0)` and any
  ///         duration that lands at or before the existing window).
  ///         To shorten a pause, use `unpause` and re-issue.
  ///         `block.timestamp + secondsDuration` saturates at
  ///         `uint48.max`.
  /// @param  secondsDuration Seconds from `block.timestamp` to the new
  ///                         pause expiry.
  function pauseFor(uint256 secondsDuration) external onlyCompliance {
    StorageLayout storage $ = _getStorage();
    uint256 newUntil;
    unchecked {
      newUntil =
        secondsDuration > type(uint48).max - block.timestamp ? type(uint48).max : block.timestamp + secondsDuration;
    }
    // Revert on any call that wouldn't produce an actually-paused state
    // strictly beyond the current `pausedUntil`. Covers both `pauseFor(0)`
    // (newUntil == block.timestamp, so `whenNotPaused` wouldn't even
    // fire) and any duration shorter than the remaining pause.
    if (newUntil <= block.timestamp || newUntil <= $.pausedUntil) {
      revert WhitelistErrors.PauseNotExtended();
    }
    // The saturation above clamps `newUntil` to `type(uint48).max`, so
    // the downcast is lossless by construction.
    // forge-lint: disable-next-line(unsafe-typecast)
    $.pausedUntil = uint48(newUntil);
    // forge-lint: disable-next-line(unsafe-typecast)
    emit WhitelistEvents.Paused(uint48(newUntil));
  }

  /// @notice Cancels the current pause immediately. Complements the
  ///         extend-only `pauseFor` — the only way to shorten a pause.
  ///         No-op when the registry is not currently paused.
  function unpause() external onlyCompliance {
    StorageLayout storage $ = _getStorage();
    if ($.pausedUntil != 0) {
      $.pausedUntil = 0;
      emit WhitelistEvents.Unpaused();
    }
  }

  /// @notice A validator raises their own nonce floor. Every signature
  ///         they have previously produced at a nonce strictly below
  ///         the new floor becomes unusable — submitters will see
  ///         `NonceBelowFloor`. This is the mass-invalidate lever when
  ///         a key is suspected compromised or the validator wants to
  ///         cancel a queue of pre-signed sigs in bulk.
  /// @dev    Not `whenNotPaused`: a validator who suspects key
  ///         compromise must be able to self-invalidate their sigs
  ///         even while the registry is paused — pausing is the signal
  ///         that something is wrong, not a reason to freeze recovery.
  ///         The new value must be strictly greater than the current
  ///         one; the floor can only move forward so an accidental
  ///         rewrite cannot re-expose previously invalidated
  ///         signatures. The caller must currently be a validator.
  /// @param  newFloor The new nonce floor. Sigs at nonces strictly
  ///                  below `newFloor` are rejected `NonceBelowFloor`
  ///                  thereafter.
  function setValidatorNonceFloor(uint256 newFloor) external {
    StorageLayout storage $ = _getStorage();
    if (!$.validators.contains(msg.sender)) revert QuorumSigLib.NotValidator();
    if (newFloor <= $.validatorNonceFloor[msg.sender]) revert WhitelistErrors.NewNonceNotIncreasing();
    $.validatorNonceFloor[msg.sender] = newFloor;
    emit WhitelistEvents.ValidatorNonceSet(msg.sender, newFloor);
  }

  // ----- Admin: owner path --------------------------------------------------

  /// @notice Adds `v` to the validator set. Owner-only.
  /// @param  v The address to grant validator status to.
  function addValidator(address v) external onlyOwner whenNotPaused {
    _addValidator(_getStorage(), v);
  }

  /// @notice Removes `v` from the validator set. Owner-only.
  /// @dev    Saturates `validatorNonceFloor[v]` to `type(uint256).max`,
  ///         which combined with `QuorumSigLib`'s explicit rejection of
  ///         `nonce == type(uint256).max` permanently retires the
  ///         address: every pre-signed sig becomes unusable, and the
  ///         strict-increase rule on the floor means a re-add at the
  ///         same address cannot resurrect the old nonce space.
  ///         Operators wanting to re-admit a removed party must use a
  ///         new address. Reverts `NotValidator` if `v` is not in the
  ///         set, or `QuorumOutOfRange` if removing it would leave the
  ///         set at or below the current quorum.
  /// @param  v The validator to revoke.
  function removeValidator(address v) external onlyOwner whenNotPaused {
    if (!_removeValidator(_getStorage(), v)) revert QuorumSigLib.NotValidator();
  }

  /// @notice Sets a new quorum. Owner-only. The new value must satisfy
  ///         `1 <= q < validators.length` (strictly less than the
  ///         validator count).
  /// @param  q The new required quorum.
  function setQuorum(uint16 q) external onlyOwner whenNotPaused {
    _setQuorum(_getStorage(), q);
  }

  /// @notice Grants (`on = true`) or revokes (`on = false`) the compliance
  ///         role for `a`. Owner-only.
  /// @param  a  The address whose compliance flag to flip.
  /// @param  on The new flag value.
  function setComplianceOfficer(address a, bool on) external onlyOwner whenNotPaused {
    _setComplianceOfficer(_getStorage(), a, on);
  }

  /// @notice Strips both the validator role and the compliance-officer
  ///         role from `a` in a single call. Incident-response tool for
  ///         the common case where the same address wears both hats
  ///         and rotating them separately leaves an exploitable window
  ///         where the attacker still holds one role.
  /// @dev    Owner-only; available only in Phase 1. Post-renounce,
  ///         operators combine `removeValidatorBySig` with
  ///         `setComplianceOfficerBySig(a, false)`. Silently skips
  ///         either role if `a` does not currently hold it — the goal
  ///         is a clean "remove everything" op, not per-role
  ///         precision. When the validator role is present, behaves
  ///         identically to `removeValidator` (including saturating
  ///         the nonce floor to `type(uint256).max`).
  ///
  ///         Intentionally **not** `whenNotPaused`, unlike the other
  ///         owner admin paths (`addValidator`, `removeValidator`,
  ///         `setQuorum`, `setComplianceOfficer`). It is the only
  ///         owner-side recovery hook available during pause: if the
  ///         compliance officer who triggered the pause is themselves
  ///         the rogue actor, the owner needs a way to strip them
  ///         without first having to wait the pause out.
  ///
  ///         Quorum-boundary caveat: if removing `a` as a validator
  ///         would leave the set at or below quorum, the call reverts
  ///         `QuorumOutOfRange` and **neither** role is cleared. When
  ///         `a` is dual-role and at the boundary, lower the quorum
  ///         first (or call `setComplianceOfficer(a, false)` separately
  ///         and accept that the validator stays).
  /// @param  a The address to fully revoke.
  function revokeAllRoles(address a) external onlyOwner {
    StorageLayout storage $ = _getStorage();
    _removeValidator($, a);
    if ($.isComplianceOfficer[a]) _setComplianceOfficer($, a, false);
  }

  // ----- Admin: quorum-sig path (available only after renouncement) --------

  /// @notice `addValidator` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @dev    Not `whenNotPaused`: pause freezes *whitelisting*, not
  ///         *administration*. The circuit breaker exists to buy the
  ///         quorum time to rotate; blocking rotation would defeat its
  ///         own purpose.
  /// @param  v        The validator to add.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function addValidatorBySig(address v, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_ADD_VALIDATOR, abi.encode(v), deadline, sigs);
    _addValidator(_getStorage(), v);
  }

  /// @notice `removeValidator` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @dev    Not `whenNotPaused`; see `addValidatorBySig` for rationale.
  /// @param  v        The validator to remove.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function removeValidatorBySig(address v, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_REMOVE_VALIDATOR, abi.encode(v), deadline, sigs);
    if (!_removeValidator(_getStorage(), v)) revert QuorumSigLib.NotValidator();
  }

  /// @notice `setQuorum` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @dev    Not `whenNotPaused`; see `addValidatorBySig` for rationale.
  /// @param  q        The new quorum.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function setQuorumBySig(uint16 q, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_SET_QUORUM, abi.encode(q), deadline, sigs);
    _setQuorum(_getStorage(), q);
  }

  /// @notice `setComplianceOfficer` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @dev    Not `whenNotPaused`; without this escape hatch, a rogue
  ///         compliance officer calling `pauseFor(max)` could otherwise
  ///         lock the registry forever because the quorum would have no
  ///         way to swap them out.
  /// @param  a        The address whose compliance flag to flip.
  /// @param  on       The new flag value.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function setComplianceOfficerBySig(address a, bool on, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_SET_COMPLIANCE, abi.encode(a, on), deadline, sigs);
    _setComplianceOfficer(_getStorage(), a, on);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // EIP-712 hooks (solady)
  // ───────────────────────────────────────────────────────────────────────────

  /// @dev Returns the EIP-712 domain name and version. Stable for every
  ///      instance of v1 of this contract; downstream integrators can
  ///      cache the typed-data domain given (chainId, verifyingContract).
  function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
    return ("3fRequestWhitelist", "1");
  }

  /// @dev Returning `true` forces solady's EIP712 to recompute the domain
  ///      separator on every call instead of using the cache built at
  ///      construction time. The constructor runs on the implementation
  ///      whose `address(this)` and `block.chainid` are the wrong values
  ///      for the proxy, so the cache would yield a bad separator.
  function _domainNameAndVersionMayChange() internal pure override returns (bool) {
    return true;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Internal helpers
  // ───────────────────────────────────────────────────────────────────────────

  /// @dev Returns a storage pointer to the ERC-7201 layout at the pre-
  ///      computed slot constant. Kept `private pure` — the pointer is the
  ///      only moving part; actual reads happen through the returned ref.
  function _getStorage() private pure returns (StorageLayout storage $) {
    bytes32 s = _STORAGE_SLOT;
    assembly {
      $.slot := s
    }
  }

  /// @dev Reverts with `OwnerStillSet` if the owner slot is still non-zero.
  ///      Used as the gate on every `*BySig` admin path.
  function _requireRenounced() private view {
    if (owner() != address(0)) revert WhitelistErrors.OwnerStillSet();
  }

  // ----- EIP-712 helpers ---------------------------------------------------

  /// @dev EIP-712 hashes a dynamic array as `keccak256` over the concatenation
  ///      of each element's 32-byte encoding. For `address[]` the calldata
  ///      layout already stores each element as a 32-byte word — but Yul's
  ///      `keccak256` reads from memory, so we `calldatacopy` the packed
  ///      region into scratch memory and hash that.
  function _hashAddressArray(address[] calldata targets) private pure returns (bytes32 h) {
    assembly {
      let fp := mload(0x40)
      let len := mul(targets.length, 0x20)
      calldatacopy(fp, targets.offset, len)
      h := keccak256(fp, len)
    }
  }

  // ----- Quorum verification -----------------------------------------------

  /// @dev Common verifier for `whitelist` / `unwhitelist`. Delegates the
  ///      per-sig checks to `QuorumSigLib.assertSigValid`; the loop here
  ///      just constructs each validator's struct hash and its EIP-712
  ///      digest. The per-validator digest is intentional — it binds each
  ///      sig to the signer's address and nonce cryptographically instead
  ///      of relying on out-of-band pairings.
  function _verifyBatchQuorum(
    bytes32 typehash,
    address[] calldata targets,
    uint256 deadline,
    QuorumSigLib.Sig[] calldata sigs
  ) private {
    StorageLayout storage $ = _getStorage();
    QuorumSigLib.assertDeadlineAndQuorum(deadline, sigs.length, $.quorum);

    bytes32 targetsHash = _hashAddressArray(targets);
    uint256 seen;
    for (uint256 i; i < sigs.length; ++i) {
      QuorumSigLib.Sig calldata s = sigs[i];
      bytes32 structHash = keccak256(abi.encode(typehash, targetsHash, deadline, s.validator, s.nonce));
      seen = QuorumSigLib.assertSigValid(
        $.validators, $.validatorNonceFloor, $.validatorNonceBitmap, _hashTypedData(structHash), s, seen
      );
    }
  }

  /// @dev Verifier for the post-renouncement admin path. The struct hash
  ///      format differs from the batch path because `AdminRequest` has a
  ///      different member layout (`actionId` + `bytes data` instead of a
  ///      `address[]` targets field).
  function _verifyAdminQuorum(bytes32 actionId, bytes memory data, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    private
  {
    StorageLayout storage $ = _getStorage();
    QuorumSigLib.assertDeadlineAndQuorum(deadline, sigs.length, $.quorum);

    bytes32 dataHash = keccak256(data);
    uint256 seen;
    for (uint256 i; i < sigs.length; ++i) {
      QuorumSigLib.Sig calldata s = sigs[i];
      bytes32 structHash = keccak256(abi.encode(_ADMIN_TYPEHASH, actionId, dataHash, deadline, s.validator, s.nonce));
      seen = QuorumSigLib.assertSigValid(
        $.validators, $.validatorNonceFloor, $.validatorNonceBitmap, _hashTypedData(structHash), s, seen
      );
    }
  }

  // ----- Mutators (shared by owner and quorum paths) ------------------------

  /// @dev Shared add-validator logic. Enforces the `MAX_VALIDATORS` cap that
  ///      `QuorumSigLib`'s dedup bitmap depends on, rejects the zero
  ///      address, and rejects duplicates.
  function _addValidator(StorageLayout storage $, address v) private {
    if (v == address(0)) revert WhitelistErrors.ZeroAddress();
    if ($.validators.length() >= MAX_VALIDATORS) revert WhitelistErrors.ValidatorLimitReached();
    if (!$.validators.add(v)) revert WhitelistErrors.DuplicateValidator();
    emit WhitelistEvents.ValidatorAdded(v);
  }

  /// @dev Shared remove-validator logic. Returns `true` if the address
  ///      was a validator and was removed; returns `false` (no-op) if
  ///      `v` was not in the set. Callers that want strict semantics
  ///      (`removeValidator`, `removeValidatorBySig`) wrap and revert
  ///      `NotValidator` on `false`; `revokeAllRoles` ignores the
  ///      return so the call gracefully degrades to a no-op for the
  ///      validator side and still falls through to the compliance
  ///      strip.
  ///
  ///      Reverts `QuorumOutOfRange` if removing `v` would leave the
  ///      set at or below quorum — this preserves the strict
  ///      `quorum < length` invariant that prevents a coalition from
  ///      shrinking the set down to its own membership in a single
  ///      step.
  ///
  ///      The validator's nonce floor is saturated to
  ///      `type(uint256).max`. Combined with `QuorumSigLib`'s separate
  ///      rejection of `nonce == type(uint256).max` and the bitmap's
  ///      "consumed nonces stay consumed" property, every signature
  ///      the address ever produced becomes unusable permanently —
  ///      `setValidatorNonceFloor` cannot lower the floor back down
  ///      (strict-increase), so re-admitting the same address resumes
  ///      onto a saturated floor. Operators wanting to re-admit a
  ///      previously-removed party must use a new address.
  function _removeValidator(StorageLayout storage $, address v) private returns (bool) {
    if (!$.validators.remove(v)) return false;
    if ($.validators.length() <= $.quorum) revert WhitelistErrors.QuorumOutOfRange();
    $.validatorNonceFloor[v] = type(uint256).max;
    emit WhitelistEvents.ValidatorRemoved(v);
    emit WhitelistEvents.ValidatorNonceSet(v, type(uint256).max);
    return true;
  }

  /// @dev Shared set-quorum logic. Enforces the invariant
  ///      `1 <= quorum < validators.length`. The strict inequality
  ///      guarantees at least one non-coalition validator is needed to
  ///      block any quorum op, so a `k`-of-`n` coalition cannot in a
  ///      single step capture the registry by removing every dissenter
  ///      down to its own membership: each removal still has to pass
  ///      the `length > quorum` check.
  ///
  ///      Note this is *one-step* anti-capture, not absolute: a
  ///      coalition that controls quorum can first lower `quorum` and
  ///      then iteratively `_removeValidator` non-coalition members
  ///      until only the coalition remains. The mitigation against
  ///      that is governance-level (validator-set membership review),
  ///      not contract-level. The strict inequality buys time and
  ///      observability — every shrink is on-chain and emits
  ///      `ValidatorRemoved` — not a hard invariant against
  ///      coordinated capture.
  ///
  ///      Reverts `QuorumUnchanged` on a same-value write so no-op calls
  ///      don't burn validator nonces or emit misleading events.
  function _setQuorum(StorageLayout storage $, uint16 q) private {
    if (q == 0 || q >= $.validators.length()) revert WhitelistErrors.QuorumOutOfRange();
    if (q == $.quorum) revert WhitelistErrors.QuorumUnchanged();
    $.quorum = q;
    emit WhitelistEvents.QuorumSet(q);
  }

  /// @dev Shared compliance-officer mutator. Rejects the zero address so a
  ///      bad call can't accidentally grant the role to no-one.
  function _setComplianceOfficer(StorageLayout storage $, address a, bool on) private {
    if (a == address(0)) revert WhitelistErrors.ZeroAddress();
    $.isComplianceOfficer[a] = on;
    emit WhitelistEvents.ComplianceOfficerSet(a, on);
  }
}
