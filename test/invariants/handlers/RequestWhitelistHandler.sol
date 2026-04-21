// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {RequestWhitelist} from "../../../src/RequestWhitelist.sol";
import {QuorumSigLib} from "../../../src/lib/QuorumSigLib.sol";

/// @title  RequestWhitelistHandler
/// @notice Bounded actor for Foundry invariant runs. Owns the validator
///         keys, knows the contract's EIP-712 domain, and exposes `h_*`
///         selectors that map every mutating entry point of
///         `RequestWhitelist` to a fuzz-friendly surface.
/// @dev    The handler tracks *ghost* state whose sole purpose is to
///         observe properties that cannot be read from the contract
///         directly — nonce-floor monotonicity, bitmap persistence,
///         post-removal floor saturation, and ownership-renouncement
///         irreversibility.
contract RequestWhitelistHandler is Test {
  // ───────────────────────────── System under test ─────────────────────────

  RequestWhitelist public wl;
  ERC1967Factory public factory;
  RequestWhitelist public impl;

  address public proxyAdmin;
  address public ownerAddr;
  address public compliance0;
  address public compliance1;

  // ───────────────────────────── Actor pools ───────────────────────────────

  uint256 internal constant POOL_SIZE = 8;
  uint256 internal constant TARGET_POOL_SIZE = 4;

  // Vm.Wallet is (addr, pubX, pubY, privateKey). Fixed-size arrays hold fine.
  Vm.Wallet[POOL_SIZE] internal _pool;
  address[TARGET_POOL_SIZE] internal _targetPool;

  function poolAddr(uint256 i) external view returns (address) {
    return _pool[i].addr;
  }

  function targetAddr(uint256 i) external view returns (address) {
    return _targetPool[i];
  }

  // ───────────────────────────── Ghost state ───────────────────────────────

  /// @dev Max floor we have ever observed for `v` at the end of a handler
  ///      call. Used by `invariant_B1_nonceFloorMonotonic` — current value
  ///      must always be ≥ this.
  mapping(address => uint256) public ghostFloorMax;

  /// @dev True the first time we observe a validator leaving the set via
  ///      `_removeValidator`. Used by `invariant_B2_removedFloorSaturates`
  ///      — once flagged, floor must equal `type(uint256).max` forever.
  mapping(address => bool) public ghostEverRemoved;

  /// @dev True once `owner()` becomes zero. Used by
  ///      `invariant_E1_ownerMonotonicToZero` — once flagged, owner must
  ///      remain zero.
  bool public ghostEverRenounced;

  /// @dev Per-validator list of nonces we believe have been consumed in a
  ///      successful call. Used by `invariant_B3_consumedStaysConsumed` —
  ///      `wl.isNonceConsumed(v, n)` must remain true forever.
  mapping(address => uint256[]) internal _ghostConsumed;
  mapping(address => mapping(uint256 => bool)) internal _ghostConsumedFlag;

  /// @dev Snapshot of `pausedUntil` at the end of the previous call.
  ///      Used by the inline per-call `_assertPauseTransitionLegal`
  ///      check so we can encode C1 ("pauseFor only moves forward;
  ///      only `unpause` drops to 0") without needing to reconstruct
  ///      history from the invariant function.
  uint48 public lastPausedUntil;

  // ───────────────────────────── Local nonce cursor ─────────────────────────

  /// @dev The handler's per-validator cursor. `_nextNonce` returns the
  ///      max of this and the on-chain floor. Advances monotonically so
  ///      we never accidentally re-use a nonce.
  mapping(address => uint256) internal _nextNonceCursor;

  // ───────────────────────────── Stats (observability) ──────────────────────

  uint256 public callCount;
  mapping(bytes32 => uint256) public callsByTag;

  function _tag(bytes32 t, bool ok) internal {
    unchecked {
      ++callCount;
      ++callsByTag[ok ? bytes32(uint256(t) | 1) : t];
    }
  }

  // ───────────────────────────── EIP-712 constants ──────────────────────────

  bytes32 internal constant _WHITELIST_TH =
    keccak256("WhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant _UNWHITELIST_TH =
    keccak256("UnwhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant _ADMIN_TH =
    keccak256("AdminRequest(bytes32 actionId,bytes data,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant _DOMAIN_TH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  // ───────────────────────────── Constructor ────────────────────────────────

  constructor() {
    ownerAddr = makeAddr("h-owner");
    compliance0 = makeAddr("h-compliance0");
    compliance1 = makeAddr("h-compliance1");
    proxyAdmin = makeAddr("h-proxy-admin");

    for (uint256 i; i < POOL_SIZE; ++i) {
      _pool[i] = vm.createWallet(string(abi.encodePacked("h-validator-", vm.toString(i))));
    }
    for (uint256 i; i < TARGET_POOL_SIZE; ++i) {
      _targetPool[i] = makeAddr(string(abi.encodePacked("h-target-", vm.toString(i))));
    }

    impl = new RequestWhitelist();
    factory = new ERC1967Factory();

    address[] memory initVs = new address[](4);
    initVs[0] = _pool[0].addr;
    initVs[1] = _pool[1].addr;
    initVs[2] = _pool[2].addr;
    initVs[3] = _pool[3].addr;
    address[] memory initCs = new address[](2);
    initCs[0] = compliance0;
    initCs[1] = compliance1;

    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, initVs, uint16(2), initCs));
    wl = RequestWhitelist(factory.deployAndCall(address(impl), proxyAdmin, initData));

    lastPausedUntil = 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Handler actions — each maps onto an entry point of `RequestWhitelist`.
  // All actions finish with `_postUpdate()` so ghost state stays live even
  // when the underlying call reverted.
  // ═══════════════════════════════════════════════════════════════════════════

  function h_warp(uint32 skipSeconds) external {
    // Keep the skip bounded so we don't blow past uint48.max and desync
    // the pausedUntil monotonicity check.
    uint256 skip = bound(uint256(skipSeconds), 1, 365 days);
    vm.warp(block.timestamp + skip);
    _postUpdate();
    _tag("warp", true);
  }

  function h_whitelist(uint8 targetMask, uint8 sigMask, uint32 deadlineOffset) external {
    address[] memory targets = _pickTargets(targetMask);
    uint256 deadline = _deadlineFrom(deadlineOffset);
    QuorumSigLib.Sig[] memory sigs = _buildSigs(_WHITELIST_TH, _hashAddrArray(targets), deadline, sigMask);

    bool paused = wl.isPaused();
    address submitter = wl.owner() == address(0) ? makeAddr("h-anyone") : ownerAddr;

    vm.prank(submitter);
    try wl.whitelist(targets, deadline, sigs) {
      _recordConsumedSigs(sigs);
      _tag("whitelist", true);
      // Sanity: if the tx succeeded, the registry was not paused.
      require(!paused, "WL-1: whitelist succeeded while paused");
    } catch {
      _tag("whitelist", false);
    }
    _postUpdate();
  }

  function h_unwhitelist(uint8 targetMask, uint8 sigMask, uint32 deadlineOffset) external {
    address[] memory targets = _pickTargets(targetMask);
    uint256 deadline = _deadlineFrom(deadlineOffset);
    QuorumSigLib.Sig[] memory sigs = _buildSigs(_UNWHITELIST_TH, _hashAddrArray(targets), deadline, sigMask);

    bool paused = wl.isPaused();

    try wl.unwhitelist(targets, deadline, sigs) {
      _recordConsumedSigs(sigs);
      _tag("unwhitelist", true);
      require(!paused, "WL-2: unwhitelist succeeded while paused");
    } catch {
      _tag("unwhitelist", false);
    }
    _postUpdate();
  }

  function h_setValidatorNonce(uint8 vIdx, uint32 bump) external {
    address v = _pool[vIdx % POOL_SIZE].addr;
    uint256 cur = wl.validatorNonceFloor(v);
    if (cur == type(uint256).max) {
      _tag("setFloorSkipSat", true);
      _postUpdate();
      return;
    }
    uint256 step = bound(uint256(bump), 1, 1024);
    uint256 newFloor = cur + step;
    if (newFloor < cur) newFloor = type(uint256).max; // overflow guard

    vm.prank(v);
    try wl.setValidatorNonce(newFloor) {
      _tag("setFloor", true);
    } catch {
      _tag("setFloor", false);
    }
    _postUpdate();
  }

  function h_pauseFor(uint32 duration) external {
    uint256 d = bound(uint256(duration), 1, 30 days);
    vm.prank(compliance0);
    try wl.pauseFor(d) {
      _tag("pauseFor", true);
    } catch {
      _tag("pauseFor", false);
    }
    _postUpdate();
  }

  function h_unpause() external {
    vm.prank(compliance0);
    try wl.unpause() {
      _tag("unpause", true);
    } catch {
      _tag("unpause", false);
    }
    _postUpdate();
  }

  function h_addValidator(uint8 vIdx) external {
    address v = _pool[vIdx % POOL_SIZE].addr;
    if (wl.owner() == address(0)) {
      uint256 deadline = _deadlineFrom(uint32(1 hours));
      QuorumSigLib.Sig[] memory sigs = _buildAdminSigs(wl.ACTION_ADD_VALIDATOR(), abi.encode(v), deadline);
      try wl.addValidatorBySig(v, deadline, sigs) {
        _recordConsumedSigs(sigs);
        _tag("addValBySig", true);
      } catch {
        _tag("addValBySig", false);
      }
    } else {
      vm.prank(ownerAddr);
      try wl.addValidator(v) {
        _tag("addVal", true);
      } catch {
        _tag("addVal", false);
      }
    }
    _postUpdate();
  }

  function h_removeValidator(uint8 vIdx) external {
    address v = _pool[vIdx % POOL_SIZE].addr;
    bool wasValidator = wl.isValidator(v);
    if (wl.owner() == address(0)) {
      uint256 deadline = _deadlineFrom(uint32(1 hours));
      QuorumSigLib.Sig[] memory sigs = _buildAdminSigs(wl.ACTION_REMOVE_VALIDATOR(), abi.encode(v), deadline);
      try wl.removeValidatorBySig(v, deadline, sigs) {
        _recordConsumedSigs(sigs);
        if (wasValidator) ghostEverRemoved[v] = true;
        _tag("rmValBySig", true);
      } catch {
        _tag("rmValBySig", false);
      }
    } else {
      vm.prank(ownerAddr);
      try wl.removeValidator(v) {
        if (wasValidator) ghostEverRemoved[v] = true;
        _tag("rmVal", true);
      } catch {
        _tag("rmVal", false);
      }
    }
    _postUpdate();
  }

  function h_setQuorum(uint8 q) external {
    // Bound to the contract's actual validator count so we exercise the
    // success path more often than the revert path.
    uint256 len = wl.validatorsLength();
    uint16 newQ = uint16(bound(uint256(q), 1, len == 0 ? 1 : len));
    if (wl.owner() == address(0)) {
      uint256 deadline = _deadlineFrom(uint32(1 hours));
      QuorumSigLib.Sig[] memory sigs = _buildAdminSigs(wl.ACTION_SET_QUORUM(), abi.encode(newQ), deadline);
      try wl.setQuorumBySig(newQ, deadline, sigs) {
        _recordConsumedSigs(sigs);
        _tag("setQBySig", true);
      } catch {
        _tag("setQBySig", false);
      }
    } else {
      vm.prank(ownerAddr);
      try wl.setQuorum(newQ) {
        _tag("setQ", true);
      } catch {
        _tag("setQ", false);
      }
    }
    _postUpdate();
  }

  function h_setCompliance(bool flag) external {
    address a = (flag ? compliance0 : compliance1);
    if (wl.owner() == address(0)) {
      uint256 deadline = _deadlineFrom(uint32(1 hours));
      QuorumSigLib.Sig[] memory sigs = _buildAdminSigs(wl.ACTION_SET_COMPLIANCE(), abi.encode(a, flag), deadline);
      try wl.setComplianceOfficerBySig(a, flag, deadline, sigs) {
        _recordConsumedSigs(sigs);
        _tag("setCoBySig", true);
      } catch {
        _tag("setCoBySig", false);
      }
    } else {
      vm.prank(ownerAddr);
      try wl.setComplianceOfficer(a, flag) {
        _tag("setCo", true);
      } catch {
        _tag("setCo", false);
      }
    }
    _postUpdate();
  }

  function h_revokeAllRoles(uint8 vIdx) external {
    if (wl.owner() == address(0)) {
      _tag("revokeAllSkipRenounced", true);
      _postUpdate();
      return;
    }
    address a = _pool[vIdx % POOL_SIZE].addr;
    bool wasValidator = wl.isValidator(a);
    vm.prank(ownerAddr);
    try wl.revokeAllRoles(a) {
      if (wasValidator && !wl.isValidator(a)) ghostEverRemoved[a] = true;
      _tag("revokeAll", true);
    } catch {
      _tag("revokeAll", false);
    }
    _postUpdate();
  }

  function h_renounceOwnership() external {
    if (wl.owner() == address(0)) {
      _tag("renounceSkip", true);
      _postUpdate();
      return;
    }
    vm.prank(ownerAddr);
    try wl.renounceOwnership() {
      _tag("renounce", true);
    } catch {
      _tag("renounce", false);
    }
    _postUpdate();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Ghost-state maintenance (runs after every handler call, pass or fail)
  // ═══════════════════════════════════════════════════════════════════════════

  function _postUpdate() internal {
    _assertPauseTransitionLegal();
    lastPausedUntil = wl.pausedUntil();

    if (wl.owner() == address(0)) ghostEverRenounced = true;

    for (uint256 i; i < POOL_SIZE; ++i) {
      address v = _pool[i].addr;
      uint256 cur = wl.validatorNonceFloor(v);
      if (cur > ghostFloorMax[v]) ghostFloorMax[v] = cur;
    }
  }

  /// @dev Encodes invariant C1 as a per-call inline assertion. Legal
  ///      transitions: (a) `pausedUntil` stays, (b) strictly increases
  ///      (pauseFor), (c) drops to 0 (unpause). Anything else — e.g. a
  ///      shrink to a non-zero value — means the extend-only guarantee
  ///      was broken.
  function _assertPauseTransitionLegal() internal view {
    uint48 cur = wl.pausedUntil();
    if (cur >= lastPausedUntil) return;
    require(cur == 0, "C1: pausedUntil shrank to a non-zero value");
  }

  function _recordConsumedSigs(QuorumSigLib.Sig[] memory sigs) internal {
    for (uint256 i; i < sigs.length; ++i) {
      address v = sigs[i].validator;
      uint256 n = sigs[i].nonce;
      if (!_ghostConsumedFlag[v][n]) {
        _ghostConsumedFlag[v][n] = true;
        _ghostConsumed[v].push(n);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Ghost-state accessors (for the invariant contract)
  // ═══════════════════════════════════════════════════════════════════════════

  function ghostConsumedLen(address v) external view returns (uint256) {
    return _ghostConsumed[v].length;
  }

  function ghostConsumedAt(address v, uint256 i) external view returns (uint256) {
    return _ghostConsumed[v][i];
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Input shaping
  // ═══════════════════════════════════════════════════════════════════════════

  function _pickTargets(uint8 mask) internal view returns (address[] memory out) {
    uint256 count;
    for (uint256 i; i < TARGET_POOL_SIZE; ++i) {
      if (mask & (1 << i) != 0) ++count;
    }
    if (count == 0) count = 1; // avoid zero-length targets, which is pointless
    out = new address[](count);
    uint256 j;
    for (uint256 i; i < TARGET_POOL_SIZE; ++i) {
      if (mask & (1 << i) != 0) {
        out[j++] = _targetPool[i];
      }
    }
    if (j == 0) out[0] = _targetPool[0];
  }

  function _buildSigs(bytes32 typehash, bytes32 targetsHash, uint256 deadline, uint8 sigMask)
    internal
    returns (QuorumSigLib.Sig[] memory)
  {
    uint16 q = wl.quorum();
    // Collect candidate validators: (a) currently in the set, (b) the
    // mask-selected indices come first, (c) pad from the beginning of
    // the pool so we can reach quorum even when the mask misses the
    // current set.
    address[] memory picked = new address[](POOL_SIZE);
    uint256[] memory idxPicked = new uint256[](POOL_SIZE);
    uint256 n;
    for (uint256 i; i < POOL_SIZE; ++i) {
      if (sigMask & (1 << i) != 0 && wl.isValidator(_pool[i].addr)) {
        picked[n] = _pool[i].addr;
        idxPicked[n] = i;
        ++n;
      }
    }
    for (uint256 i; i < POOL_SIZE && n < q; ++i) {
      if (sigMask & (1 << i) == 0 && wl.isValidator(_pool[i].addr)) {
        picked[n] = _pool[i].addr;
        idxPicked[n] = i;
        ++n;
      }
    }

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](n);
    for (uint256 i; i < n; ++i) {
      uint256 nonce = _nextNonce(picked[i]);
      bytes32 structHash = keccak256(abi.encode(typehash, targetsHash, deadline, picked[i], nonce));
      bytes32 digest = _toTypedDataHash(structHash);
      (uint8 vv, bytes32 r, bytes32 s) = vm.sign(_pool[idxPicked[i]], digest);
      sigs[i] = QuorumSigLib.Sig({validator: picked[i], nonce: nonce, signature: abi.encodePacked(r, s, vv)});
    }
    return sigs;
  }

  function _buildAdminSigs(bytes32 actionId, bytes memory data, uint256 deadline)
    internal
    returns (QuorumSigLib.Sig[] memory)
  {
    uint16 q = wl.quorum();
    address[] memory picked = new address[](POOL_SIZE);
    uint256[] memory idxPicked = new uint256[](POOL_SIZE);
    uint256 n;
    for (uint256 i; i < POOL_SIZE && n < q; ++i) {
      if (wl.isValidator(_pool[i].addr)) {
        picked[n] = _pool[i].addr;
        idxPicked[n] = i;
        ++n;
      }
    }

    bytes32 dataHash = keccak256(data);
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](n);
    for (uint256 i; i < n; ++i) {
      uint256 nonce = _nextNonce(picked[i]);
      bytes32 structHash = keccak256(abi.encode(_ADMIN_TH, actionId, dataHash, deadline, picked[i], nonce));
      bytes32 digest = _toTypedDataHash(structHash);
      (uint8 vv, bytes32 r, bytes32 s) = vm.sign(_pool[idxPicked[i]], digest);
      sigs[i] = QuorumSigLib.Sig({validator: picked[i], nonce: nonce, signature: abi.encodePacked(r, s, vv)});
    }
    return sigs;
  }

  function _nextNonce(address v) internal returns (uint256) {
    uint256 floor = wl.validatorNonceFloor(v);
    uint256 cursor = _nextNonceCursor[v];
    uint256 n = cursor < floor ? floor : cursor;
    if (n == type(uint256).max) return n; // signer is retired; sig will bounce
    unchecked {
      _nextNonceCursor[v] = n + 1;
    }
    return n;
  }

  function _deadlineFrom(uint32 deadlineOffset) internal view returns (uint256) {
    return block.timestamp + bound(uint256(deadlineOffset), 1, 7 days);
  }

  function _hashAddrArray(address[] memory xs) internal pure returns (bytes32) {
    bytes32[] memory padded = new bytes32[](xs.length);
    for (uint256 i; i < xs.length; ++i) {
      padded[i] = bytes32(uint256(uint160(xs[i])));
    }
    return keccak256(abi.encodePacked(padded));
  }

  function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
    (, string memory name, string memory version, uint256 chainId, address verifying,,) = wl.eip712Domain();
    bytes32 domainSeparator =
      keccak256(abi.encode(_DOMAIN_TH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying));
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }
}
