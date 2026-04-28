// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RequestWhitelist} from "../../src/RequestWhitelist.sol";
import {IWhitelist} from "../../src/IWhitelist.sol";
import {RequestWhitelistHandler} from "./handlers/RequestWhitelistHandler.sol";

/// @title  RequestWhitelistInvariants
/// @notice State-level invariants for `RequestWhitelist` + `QuorumSigLib`.
///         The single handler (`RequestWhitelistHandler`) is the only
///         target — it owns the validator keys and produces real EIP-712
///         signatures so we exercise the quorum paths, not just the
///         guard-clause surface.
///
///         The labelling (A/B/C/D/E) mirrors the groups in the README:
///           A. Validator-set & quorum structure
///           B. Nonce discipline
///           C. Pause state machine
///           D. `isWhitelisted` semantics
///           E. Ownership irreversibility
contract RequestWhitelistInvariants is Test {
  RequestWhitelistHandler internal handler;
  RequestWhitelist internal wl;

  function setUp() public {
    handler = new RequestWhitelistHandler();
    wl = handler.wl();

    // Restrict the fuzzer to the handler's h_* selectors. Without this
    // the fuzzer will also try calling view methods, constructor-like
    // setters, and the private getters — harmless for state but wasteful.
    bytes4[] memory selectors = new bytes4[](12);
    selectors[0] = RequestWhitelistHandler.h_warp.selector;
    selectors[1] = RequestWhitelistHandler.h_whitelist.selector;
    selectors[2] = RequestWhitelistHandler.h_unwhitelist.selector;
    selectors[3] = RequestWhitelistHandler.h_setValidatorNonceFloor.selector;
    selectors[4] = RequestWhitelistHandler.h_pauseFor.selector;
    selectors[5] = RequestWhitelistHandler.h_unpause.selector;
    selectors[6] = RequestWhitelistHandler.h_addValidator.selector;
    selectors[7] = RequestWhitelistHandler.h_removeValidator.selector;
    selectors[8] = RequestWhitelistHandler.h_setQuorum.selector;
    selectors[9] = RequestWhitelistHandler.h_setCompliance.selector;
    selectors[10] = RequestWhitelistHandler.h_renounceOwnership.selector;
    selectors[11] = RequestWhitelistHandler.h_revokeAllRoles.selector;
    targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    targetContract(address(handler));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // A. Validator set & quorum structure
  // ═══════════════════════════════════════════════════════════════════════════

  /// @dev A1. After initialisation, the quorum is strictly less than the
  ///      validator count and both are in the declared bounds. The strict
  ///      inequality is the whole reason `_removeValidator` and
  ///      `_setQuorum` revert `QuorumOutOfRange` at the boundary — losing
  ///      it would let a k-of-n coalition shrink the set down to its own
  ///      membership.
  function invariant_A1_quorumBounds() external view {
    uint256 len = wl.validatorsLength();
    uint256 q = wl.quorum();
    assertGe(q, 1, "A1: quorum floor");
    assertLt(q, len, "A1: quorum must be strictly less than validators");
    assertLe(len, wl.MAX_VALIDATORS(), "A1: validator cap");
  }

  /// @dev A2. `validators()` contains no duplicates and no zero address.
  function invariant_A2_validatorSetUnique() external view {
    address[] memory vs = wl.validators();
    for (uint256 i; i < vs.length; ++i) {
      assertTrue(vs[i] != address(0), "A2: zero in validator set");
      for (uint256 j = i + 1; j < vs.length; ++j) {
        assertTrue(vs[i] != vs[j], "A2: duplicate validator");
      }
    }
  }

  /// @dev A3. `isValidator(v)` agrees with `validators()` and with
  ///      `validatorAt(i)` for every `i < validatorsLength`. Exercises
  ///      the three public views that a downstream integrator might
  ///      pick between.
  function invariant_A3_validatorViewsConsistent() external view {
    address[] memory vs = wl.validators();
    uint256 len = wl.validatorsLength();
    assertEq(vs.length, len, "A3: length mismatch");
    for (uint256 i; i < len; ++i) {
      address at = wl.validatorAt(i);
      assertEq(at, vs[i], "A3: validatorAt/values disagree");
      assertTrue(wl.isValidator(at), "A3: isValidator false for set member");
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // B. Nonce discipline
  // ═══════════════════════════════════════════════════════════════════════════

  /// @dev B1. `validatorNonceFloor[v]` is monotonically non-decreasing
  ///      across every state transition. The floor has only three
  ///      writers — `setValidatorNonceFloor` (strict-increase), `_removeValidator`
  ///      (saturate to max), and `revokeAllRoles` (same as removal) —
  ///      none of which lower it.
  function invariant_B1_nonceFloorMonotonic() external view {
    for (uint256 i; i < 8; ++i) {
      address v = handler.poolAddr(i);
      uint256 cur = wl.validatorNonceFloor(v);
      uint256 hi = handler.ghostFloorMax(v);
      assertGe(cur, hi, "B1: nonce floor decreased");
    }
  }

  /// @dev B2. After removal, the floor is `type(uint256).max` forever.
  ///      Re-adding the same address does not lower it, which closes
  ///      the re-add replay window the README calls out.
  function invariant_B2_removedFloorSaturates() external view {
    for (uint256 i; i < 8; ++i) {
      address v = handler.poolAddr(i);
      if (handler.ghostEverRemoved(v)) {
        assertEq(wl.validatorNonceFloor(v), type(uint256).max, "B2: removed validator floor not saturated");
      }
    }
  }

  /// @dev B3. A nonce that the handler has witnessed being consumed in
  ///      a successful call stays consumed for the rest of the run.
  ///      Ensures `QuorumSigLib.assertSigValid` never clears bits and
  ///      that `isNonceConsumed`'s read path is in sync with the write.
  function invariant_B3_consumedStaysConsumed() external view {
    for (uint256 i; i < 8; ++i) {
      address v = handler.poolAddr(i);
      uint256 len = handler.ghostConsumedLen(v);
      for (uint256 j; j < len; ++j) {
        uint256 n = handler.ghostConsumedAt(v, j);
        assertTrue(wl.isNonceConsumed(v, n), "B3: consumed nonce lost its bit");
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // C. Pause state machine (C1 encoded inline in the handler via
  //    `_assertPauseTransitionLegal`; these two are statewise checks.)
  // ═══════════════════════════════════════════════════════════════════════════

  /// @dev C2. The `isPaused` view is a pure function of `pausedUntil`
  ///      and `block.timestamp`. Checking the identity protects against
  ///      divergence if a future refactor caches pause state.
  function invariant_C2_isPausedMatchesTimestamp() external view {
    bool onChain = wl.isPaused();
    bool expected = block.timestamp < wl.pausedUntil();
    assertEq(onChain, expected, "C2: isPaused/pausedUntil mismatch");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // D. `isWhitelisted` return-type semantics
  // ═══════════════════════════════════════════════════════════════════════════

  /// @dev D1/D2. While paused the enum is one of the `Paused*` variants;
  ///      while live it's one of the non-paused variants. This is the
  ///      circuit-breaker guarantee downstream integrators rely on. We
  ///      sample the target pool + zero address — enough to catch a
  ///      regression where the branch goes the wrong way.
  function invariant_D_isWhitelistedStatusMatchesPhase() external view {
    bool paused = wl.isPaused();
    address[] memory probe = new address[](5);
    probe[0] = address(0);
    for (uint256 i; i < 4; ++i) {
      probe[i + 1] = handler.targetAddr(i);
    }
    for (uint256 i; i < probe.length; ++i) {
      IWhitelist.WhitelistStatus status = wl.isWhitelisted(probe[i]);
      if (paused) {
        assertTrue(
          status == IWhitelist.WhitelistStatus.PausedWhitelisted
            || status == IWhitelist.WhitelistStatus.PausedNotWhitelisted,
          "D1: live variant returned while paused"
        );
      } else {
        assertTrue(
          status == IWhitelist.WhitelistStatus.Whitelisted || status == IWhitelist.WhitelistStatus.NotWhitelisted,
          "D2: paused variant returned while live"
        );
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Sanity: make sure the handler actually produces successful quorum calls,
  // otherwise B3 would pass trivially (empty consumed-nonces list) and the
  // run would silently be checking nothing interesting.
  //
  // Run with `forge test --match-test testHandlerExercisesQuorum` to bypass
  // the invariant harness.
  // ═══════════════════════════════════════════════════════════════════════════

  function testHandlerExercisesQuorum() public {
    handler.h_whitelist(0x01, 0xff, uint32(1 hours));
    handler.h_whitelist(0x02, 0xff, uint32(1 hours));
    // After two successful whitelists with two signers each, at least one
    // validator should have a consumed-nonces list populated. If not, the
    // sig-building path is broken and every other invariant is vacuous.
    uint256 total;
    for (uint256 i; i < 4; ++i) {
      total += handler.ghostConsumedLen(handler.poolAddr(i));
    }
    assertGt(total, 0, "handler never produced a successful quorum call");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // E. Ownership irreversibility
  // ═══════════════════════════════════════════════════════════════════════════

  /// @dev E1. Once the handler has observed `owner() == 0`, it must stay
  ///      zero. `renounceOwnership` is documented as irreversible and a
  ///      regression here would re-open the Phase-1 admin surface after
  ///      handover to the quorum.
  function invariant_E1_ownerMonotonicToZero() external view {
    if (handler.ghostEverRenounced()) {
      assertEq(wl.owner(), address(0), "E1: owner resurrected after renounce");
    }
  }
}
