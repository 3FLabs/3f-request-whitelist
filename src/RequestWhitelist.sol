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
/// @notice On-chain attestation registry. A quorum of signing validators
///         attests that an address is authored by this registry's operator;
///         consumers call `isWhitelisted(address)` (see `IWhitelist`) as the
///         single source of truth. A compliance role can freeze the
///         registry for a bounded window; while frozen, `isWhitelisted`
///         returns `false` for every address and every state-changing call
///         reverts with `ContractPaused` — with the sole exceptions of
///         `pauseFor` (extend the freeze) and `unpause` (cancel it), both
///         of which remain callable by compliance officers.
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
  struct Layout {
    uint16 quorum; // minimum number of distinct validator sigs required
    uint48 pausedUntil; // unix seconds; 0 == not paused
    EnumerableSetLib.AddressSet validators;
    mapping(address => uint256) validatorNonce;
    mapping(address => bool) isComplianceOfficer;
    mapping(address => bool) _isWhitelisted;
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

  /// @dev While the owner slot is non-zero, only the owner may proceed.
  ///      Once `renounceOwnership()` has set it to `address(0)` the gate
  ///      lifts and any caller may submit (the signature quorum is still
  ///      enforced downstream).
  modifier ownerGatedWhenOwned() {
    address o = owner();
    if (o != address(0) && msg.sender != o) revert WhitelistErrors.NotOwnerWhileOwned();
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
  ///                             Must be in `[1, validators_.length]`.
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

    Layout storage $ = _getStorage();
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

  /// @notice Current on-chain nonce for `v`. Signatures with any other
  ///         nonce are rejected.
  /// @param  v The validator address.
  function validatorNonce(address v) external view returns (uint256) {
    return _getStorage().validatorNonce[v];
  }

  /// @notice True iff `a` can currently pause or unpause the registry.
  /// @param  a The address to check.
  function isComplianceOfficer(address a) external view returns (bool) {
    return _getStorage().isComplianceOfficer[a];
  }

  /// @inheritdoc IWhitelist
  /// @dev    While `block.timestamp < pausedUntil` the function returns
  ///         `false` even for previously-whitelisted targets; this is the
  ///         circuit-breaker guarantee the operator relies on.
  function isWhitelisted(address a) external view returns (bool) {
    Layout storage $ = _getStorage();
    if (block.timestamp < $.pausedUntil) return false;
    return $._isWhitelisted[a];
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

  /// @notice Flips `targets` to the whitelisted state.
  /// @dev    Validator quorum signatures are always required; while an
  ///         owner is set, only the owner may submit the call.
  /// @param  targets  Addresses to whitelist. Can include already-whitelisted
  ///                  entries; those are silently skipped.
  /// @param  deadline Unix timestamp beyond which the sigs stop being valid.
  /// @param  sigs     Validator sigs covering the batch. `sigs.length >= quorum`.
  function whitelist(address[] calldata targets, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    external
    whenNotPaused
    ownerGatedWhenOwned
  {
    _verifyBatchQuorum(_WHITELIST_TYPEHASH, targets, deadline, sigs);
    Layout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if (!$._isWhitelisted[targets[i]]) {
        $._isWhitelisted[targets[i]] = true;
        emit WhitelistEvents.Whitelisted(targets[i]);
      }
    }
  }

  /// @notice Flips `targets` to the non-whitelisted state.
  /// @dev    Validator quorum signatures are required; never owner-gated,
  ///         so any caller with valid sigs may submit. Addresses that
  ///         weren't whitelisted are silently skipped.
  /// @param  targets  Addresses to remove from the whitelist.
  /// @param  deadline Unix timestamp beyond which the sigs stop being valid.
  /// @param  sigs     Validator sigs covering the batch. `sigs.length >= quorum`.
  function unwhitelist(address[] calldata targets, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    external
    whenNotPaused
  {
    _verifyBatchQuorum(_UNWHITELIST_TYPEHASH, targets, deadline, sigs);
    Layout storage $ = _getStorage();
    for (uint256 i; i < targets.length; ++i) {
      if ($._isWhitelisted[targets[i]]) {
        $._isWhitelisted[targets[i]] = false;
        emit WhitelistEvents.Unwhitelisted(targets[i]);
      }
    }
  }

  /// @notice Extends the pause by at least `secondsDuration` seconds.
  /// @dev    Extend-only: a smaller duration than the remaining pause is a
  ///         no-op. Cannot shorten a pause (use `unpause` instead).
  ///         `block.timestamp + secondsDuration` saturates at `uint48.max`.
  /// @param  secondsDuration Seconds to add on top of `block.timestamp`.
  function pauseFor(uint256 secondsDuration) external onlyCompliance {
    Layout storage $ = _getStorage();
    uint256 newUntil;
    unchecked {
      newUntil = secondsDuration > type(uint48).max - block.timestamp
        ? type(uint48).max
        : block.timestamp + secondsDuration;
    }
    if (newUntil > $.pausedUntil) {
      $.pausedUntil = uint48(newUntil);
      emit WhitelistEvents.Paused(uint48(newUntil));
    }
  }

  /// @notice Cancels the current pause immediately. Complements the
  ///         extend-only `pauseFor` — the only way to shorten a pause.
  ///         No-op when the registry is not currently paused.
  function unpause() external onlyCompliance {
    Layout storage $ = _getStorage();
    if ($.pausedUntil != 0) {
      $.pausedUntil = 0;
      emit WhitelistEvents.Unpaused();
    }
  }

  /// @notice A validator jumps their own nonce forward to invalidate every
  ///         outstanding signature they previously produced. The per-sig
  ///         nonce-consume in `QuorumSigLib.assertSigValid` already
  ///         advances the nonce by one on each use; this call is the
  ///         mass-invalidate lever when a key is suspected compromised or
  ///         the validator wants to cancel a queue of pre-signed sigs in
  ///         bulk.
  /// @dev    The new value must be strictly greater than the current one so
  ///         accidental rewrites can't weaken the invariant. The caller
  ///         must currently be a validator.
  /// @param  newNonce The replacement nonce value.
  function setValidatorNonce(uint256 newNonce) external whenNotPaused {
    Layout storage $ = _getStorage();
    if (!$.validators.contains(msg.sender)) revert QuorumSigLib.NotValidator();
    if (newNonce <= $.validatorNonce[msg.sender]) revert WhitelistErrors.NewNonceNotIncreasing();
    $.validatorNonce[msg.sender] = newNonce;
    emit WhitelistEvents.ValidatorNonceSet(msg.sender, newNonce);
  }

  // ----- Admin: owner path --------------------------------------------------

  /// @notice Adds `v` to the validator set. Owner-only.
  /// @param  v The address to grant validator status to.
  function addValidator(address v) external onlyOwner whenNotPaused {
    _addValidator(_getStorage(), v);
  }

  /// @notice Removes `v` from the validator set. Owner-only.
  /// @dev    Their nonce is left as-is; while removed their sigs fail the
  ///         membership check anyway. If the validator is ever re-added,
  ///         the admin should ensure the nonce is bumped first if old sigs
  ///         could still be within their deadline.
  /// @param  v The validator to revoke.
  function removeValidator(address v) external onlyOwner whenNotPaused {
    _removeValidator(_getStorage(), v);
  }

  /// @notice Sets a new quorum. Owner-only. The new value must be in
  ///         `[1, validators.length]`.
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

  // ----- Admin: quorum-sig path (available only after renouncement) --------

  /// @notice `addValidator` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @param  v        The validator to add.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function addValidatorBySig(address v, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external whenNotPaused {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_ADD_VALIDATOR, abi.encode(v), deadline, sigs);
    _addValidator(_getStorage(), v);
  }

  /// @notice `removeValidator` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @param  v        The validator to remove.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function removeValidatorBySig(address v, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external whenNotPaused {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_REMOVE_VALIDATOR, abi.encode(v), deadline, sigs);
    _removeValidator(_getStorage(), v);
  }

  /// @notice `setQuorum` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @param  q        The new quorum.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function setQuorumBySig(uint16 q, uint256 deadline, QuorumSigLib.Sig[] calldata sigs) external whenNotPaused {
    _requireRenounced();
    _verifyAdminQuorum(ACTION_SET_QUORUM, abi.encode(q), deadline, sigs);
    _setQuorum(_getStorage(), q);
  }

  /// @notice `setComplianceOfficer` via a quorum of validator signatures.
  ///         Available only after the owner has been renounced.
  /// @param  a        The address whose compliance flag to flip.
  /// @param  on       The new flag value.
  /// @param  deadline Deadline signed into the sigs.
  /// @param  sigs     Validator signatures covering the request.
  function setComplianceOfficerBySig(address a, bool on, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    external
    whenNotPaused
  {
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
  function _getStorage() private pure returns (Layout storage $) {
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
    Layout storage $ = _getStorage();
    QuorumSigLib.assertDeadlineAndQuorum(deadline, sigs.length, $.quorum);

    bytes32 targetsHash = _hashAddressArray(targets);
    uint256 seen;
    for (uint256 i; i < sigs.length; ++i) {
      QuorumSigLib.Sig calldata s = sigs[i];
      bytes32 structHash = keccak256(abi.encode(typehash, targetsHash, deadline, s.validator, s.nonce));
      seen = QuorumSigLib.assertSigValid($.validators, $.validatorNonce, _hashTypedData(structHash), s, seen);
    }
  }

  /// @dev Verifier for the post-renouncement admin path. The struct hash
  ///      format differs from the batch path because `AdminRequest` has a
  ///      different member layout (`actionId` + `bytes data` instead of a
  ///      `address[]` targets field).
  function _verifyAdminQuorum(bytes32 actionId, bytes memory data, uint256 deadline, QuorumSigLib.Sig[] calldata sigs)
    private
  {
    Layout storage $ = _getStorage();
    QuorumSigLib.assertDeadlineAndQuorum(deadline, sigs.length, $.quorum);

    bytes32 dataHash = keccak256(data);
    uint256 seen;
    for (uint256 i; i < sigs.length; ++i) {
      QuorumSigLib.Sig calldata s = sigs[i];
      bytes32 structHash = keccak256(abi.encode(_ADMIN_TYPEHASH, actionId, dataHash, deadline, s.validator, s.nonce));
      seen = QuorumSigLib.assertSigValid($.validators, $.validatorNonce, _hashTypedData(structHash), s, seen);
    }
  }

  // ----- Mutators (shared by owner and quorum paths) ------------------------

  /// @dev Shared add-validator logic. Enforces the `MAX_VALIDATORS` cap that
  ///      `QuorumSigLib`'s dedup bitmap depends on, rejects the zero
  ///      address, and rejects duplicates.
  function _addValidator(Layout storage $, address v) private {
    if (v == address(0)) revert WhitelistErrors.ZeroAddress();
    if ($.validators.length() >= MAX_VALIDATORS) revert WhitelistErrors.ValidatorLimitReached();
    if (!$.validators.add(v)) revert WhitelistErrors.DuplicateValidator();
    emit WhitelistEvents.ValidatorAdded(v);
  }

  /// @dev Shared remove-validator logic.
  ///      Reverts if `v` isn't a validator, or if removing it would leave
  ///      the set below quorum (which would silently brick whitelisting).
  ///      The validator's nonce is left untouched — while removed, their
  ///      sigs fail the membership check anyway. If an admin re-adds them
  ///      later and wants to invalidate old sigs, the validator (or the
  ///      admin, before re-adding) should bump the nonce explicitly.
  function _removeValidator(Layout storage $, address v) private {
    if (!$.validators.remove(v)) revert QuorumSigLib.NotValidator();
    if ($.validators.length() < $.quorum) revert WhitelistErrors.QuorumOutOfRange();
    emit WhitelistEvents.ValidatorRemoved(v);
  }

  /// @dev Shared set-quorum logic. Enforces the invariant
  ///      `1 <= quorum <= validators.length`.
  function _setQuorum(Layout storage $, uint16 q) private {
    if (q == 0 || q > $.validators.length()) revert WhitelistErrors.QuorumOutOfRange();
    $.quorum = q;
    emit WhitelistEvents.QuorumSet(q);
  }

  /// @dev Shared compliance-officer mutator. Rejects the zero address so a
  ///      bad call can't accidentally grant the role to no-one.
  function _setComplianceOfficer(Layout storage $, address a, bool on) private {
    if (a == address(0)) revert WhitelistErrors.ZeroAddress();
    $.isComplianceOfficer[a] = on;
    emit WhitelistEvents.ComplianceOfficerSet(a, on);
  }
}
