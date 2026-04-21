// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {RequestWhitelist} from "../src/RequestWhitelist.sol";
import {IWhitelist} from "../src/IWhitelist.sol";
import {QuorumSigLib} from "../src/lib/QuorumSigLib.sol";
import {WhitelistErrors} from "../src/lib/WhitelistErrors.sol";
import {MockERC1271} from "./mocks/MockERC1271.sol";

contract RequestWhitelistTest is Test {
  RequestWhitelist internal impl;
  RequestWhitelist internal wl;
  ERC1967Factory internal factory;

  address internal proxyAdmin = makeAddr("proxyAdmin");
  address internal ownerAddr = makeAddr("ownerAddr");
  address internal compliance = makeAddr("compliance");

  // Three validator EOAs.
  Vm.Wallet internal v0;
  Vm.Wallet internal v1;
  Vm.Wallet internal v2;

  address internal t0 = makeAddr("target0");
  address internal t1 = makeAddr("target1");

  /// @dev Local per-validator nonce cursor for the test suite. Validators
  ///      pick any nonce at or above their on-chain floor that has not
  ///      yet been consumed; the suite picks sequentially starting from
  ///      the floor so tests don't have to hand-roll nonce allocations.
  mapping(address => uint256) internal _nextNonce;

  // ---------- setup ----------------------------------------------------------

  function setUp() public {
    v0 = vm.createWallet("validator0");
    v1 = vm.createWallet("validator1");
    v2 = vm.createWallet("validator2");

    impl = new RequestWhitelist();
    factory = new ERC1967Factory();

    address[] memory vs = new address[](3);
    vs[0] = v0.addr;
    vs[1] = v1.addr;
    vs[2] = v2.addr;

    address[] memory cos = new address[](1);
    cos[0] = compliance;

    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, vs, 2, cos));
    wl = RequestWhitelist(factory.deployAndCall(address(impl), proxyAdmin, initData));
  }

  // ---------- storage slot ---------------------------------------------------

  function testStorageSlotMatches() public pure {
    bytes32 expected =
      keccak256(abi.encode(uint256(keccak256("3f.storage.RequestWhitelist")) - 1)) & ~bytes32(uint256(0xff));
    // The literal in the contract must equal this.
    assertEq(expected, 0x9e193f57867c54cb61bb3037d351387081a88b862376ceddfd961cec2c798100, "ERC-7201 slot drift");
  }

  // ---------- initialize guards ---------------------------------------------

  function testImplementationCannotBeInitialized() public {
    address[] memory vs = new address[](1);
    vs[0] = v0.addr;
    address[] memory cos = new address[](0);
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    impl.initialize(ownerAddr, vs, 1, cos);
  }

  function testCannotInitializeTwice() public {
    address[] memory vs = new address[](1);
    vs[0] = v0.addr;
    address[] memory cos = new address[](0);
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    wl.initialize(ownerAddr, vs, 1, cos);
  }

  function testInitRejectsZeroOwner() public {
    RequestWhitelist fresh = new RequestWhitelist();
    address[] memory vs = new address[](1);
    vs[0] = v0.addr;
    address[] memory cos = new address[](0);
    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (address(0), vs, 1, cos));
    vm.expectRevert(WhitelistErrors.OwnerIsZero.selector);
    factory.deployAndCall(address(fresh), proxyAdmin, initData);
  }

  function testInitRejectsEmptyValidators() public {
    RequestWhitelist fresh = new RequestWhitelist();
    address[] memory vs = new address[](0);
    address[] memory cos = new address[](0);
    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, vs, 1, cos));
    vm.expectRevert(WhitelistErrors.EmptyValidators.selector);
    factory.deployAndCall(address(fresh), proxyAdmin, initData);
  }

  function testInitRejectsQuorumZero() public {
    RequestWhitelist fresh = new RequestWhitelist();
    address[] memory vs = new address[](1);
    vs[0] = v0.addr;
    address[] memory cos = new address[](0);
    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, vs, 0, cos));
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    factory.deployAndCall(address(fresh), proxyAdmin, initData);
  }

  function testInitRejectsQuorumAboveCount() public {
    RequestWhitelist fresh = new RequestWhitelist();
    address[] memory vs = new address[](2);
    vs[0] = v0.addr;
    vs[1] = v1.addr;
    address[] memory cos = new address[](0);
    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, vs, 3, cos));
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    factory.deployAndCall(address(fresh), proxyAdmin, initData);
  }

  function testInitRejectsDuplicateValidators() public {
    RequestWhitelist fresh = new RequestWhitelist();
    address[] memory vs = new address[](2);
    vs[0] = v0.addr;
    vs[1] = v0.addr;
    address[] memory cos = new address[](0);
    bytes memory initData = abi.encodeCall(RequestWhitelist.initialize, (ownerAddr, vs, 1, cos));
    vm.expectRevert(WhitelistErrors.DuplicateValidator.selector);
    factory.deployAndCall(address(fresh), proxyAdmin, initData);
  }

  function testInitialStateReadable() public view {
    assertEq(wl.owner(), ownerAddr);
    assertEq(wl.quorum(), 2);
    assertTrue(wl.isValidator(v0.addr));
    assertTrue(wl.isValidator(v1.addr));
    assertTrue(wl.isValidator(v2.addr));
    assertEq(wl.validatorsLength(), 3);
    assertTrue(wl.isComplianceOfficer(compliance));
    assertFalse(wl.isPaused());
  }

  // ---------- whitelist happy paths -----------------------------------------

  function testWhitelistWithEOAs() public {
    address[] memory targets = new address[](2);
    targets[0] = t0;
    targets[1] = t1;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigs);

    assertTrue(_listed(t0));
    assertTrue(_listed(t1));
  }

  function testWhitelistWithERC1271Signer() public {
    // Replace v2 with a mock 1271 contract that signs via the same key.
    // Add first, then remove — with the strict `quorum < length` invariant,
    // removing v2 directly from the initial set (3 → 2 with quorum 2) would
    // revert `QuorumOutOfRange`, so we bounce through length = 4.
    MockERC1271 contractSigner = new MockERC1271(v2.addr);
    vm.prank(ownerAddr);
    wl.addValidator(address(contractSigner));
    vm.prank(ownerAddr);
    wl.removeValidator(v2.addr);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    // Craft a 1271 sig: the contract recovers ecdsa(hash) and matches signer.
    bytes32 digest = _whitelistDigest(targets, deadline, address(contractSigner), 0);
    (uint8 vv, bytes32 r, bytes32 s) = vm.sign(v2, digest);
    sigs[1] = QuorumSigLib.Sig({validator: address(contractSigner), nonce: 0, signature: abi.encodePacked(r, s, vv)});

    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigs);
    assertTrue(_listed(t0));
  }

  // ---------- whitelist rejections ------------------------------------------

  function testWhitelistRevertsWhenOwnerAndSubmitterMismatches() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.expectRevert(WhitelistErrors.NotOwnerWhileOwned.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsExpired() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.warp(deadline + 1);
    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.SignatureExpired.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsUnderQuorum() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](1);
    sigs[0] = _signWhitelist(v0, targets, deadline);

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.QuorumNotMet.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsDuplicateSigner() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v0, targets, deadline);

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.DuplicateSignature.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsNonValidator() public {
    Vm.Wallet memory stranger = vm.createWallet("stranger");
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(stranger, targets, deadline);

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NotValidator.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsBadSignature() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    // v1 signs for a different target list, but submitter claims this batch
    address[] memory other = new address[](1);
    other[0] = t1;
    QuorumSigLib.Sig memory bad = _signWhitelist(v1, other, deadline);
    bad.validator = v1.addr;
    sigs[1] = bad;

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.SignatureInvalid.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsNonceBelowFloor() public {
    // Raise v1's floor to 10; any sig they produced at a lower nonce
    // must be rejected `NonceBelowFloor`.
    vm.prank(v1.addr);
    wl.setValidatorNonce(10);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelistWithNonce(v1, targets, deadline, 3); // below floor

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceBelowFloor.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testWhitelistRevertsNonceConsumed() public {
    // First batch consumes v1's nonce 0; a second batch with the same
    // sig must be rejected `NonceConsumed`.
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig memory v0Sig0 = _signWhitelistWithNonce(v0, targets, deadline, 0);
    QuorumSigLib.Sig memory v1Sig0 = _signWhitelistWithNonce(v1, targets, deadline, 0);
    QuorumSigLib.Sig[] memory first = new QuorumSigLib.Sig[](2);
    first[0] = v0Sig0;
    first[1] = v1Sig0;
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, first);

    QuorumSigLib.Sig[] memory replay = new QuorumSigLib.Sig[](2);
    replay[0] = v0Sig0;
    replay[1] = v1Sig0;
    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceConsumed.selector);
    wl.whitelist(targets, deadline, replay);
  }

  function testWhitelistRevertsWhenPaused() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  // ---------- validator nonce -----------------------------------------------

  function testSetValidatorNonceInvalidatesOldSigs() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.prank(v1.addr);
    wl.setValidatorNonce(42);

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceBelowFloor.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testSetValidatorNonceRejectsNonIncreasing() public {
    vm.prank(v0.addr);
    wl.setValidatorNonce(5);
    vm.prank(v0.addr);
    vm.expectRevert(WhitelistErrors.NewNonceNotIncreasing.selector);
    wl.setValidatorNonce(5);
  }

  function testSetValidatorNonceOnlyValidator() public {
    address stranger = makeAddr("stranger");
    vm.prank(stranger);
    vm.expectRevert(QuorumSigLib.NotValidator.selector);
    wl.setValidatorNonce(1);
  }

  /// @dev The nonce floor is a monotonically-raised lever; the bitmap
  ///      nonce model removes the need to cap below `type(uint256).max`
  ///      (no per-sig arithmetic bump, so no overflow surface). A
  ///      validator can therefore legitimately saturate their own
  ///      floor to `type(uint256).max` to permanently burn their sig
  ///      space — equivalent to the operator saying "retire this key
  ///      entirely". Re-admission of the same address is blocked
  ///      because `setValidatorNonce` is strict-increase.
  function testSetValidatorNonceAllowsMax() public {
    vm.prank(v0.addr);
    wl.setValidatorNonce(type(uint256).max);
    assertEq(wl.validatorNonceFloor(v0.addr), type(uint256).max);

    // Further setValidatorNonce calls are locked out — nothing is
    // strictly greater than max.
    vm.prank(v0.addr);
    vm.expectRevert(WhitelistErrors.NewNonceNotIncreasing.selector);
    wl.setValidatorNonce(type(uint256).max);
  }

  // ---------- L-5: isWhitelisted enum surface -------------------------------

  function testIsWhitelistedEnumNotWhitelisted() public {
    address never = makeAddr("never");
    assertTrue(wl.isWhitelisted(never) == IWhitelist.WhitelistStatus.NotWhitelisted);
  }

  function testIsWhitelistedEnumWhitelisted() public {
    _whitelistAsOwner(t0);
    assertTrue(wl.isWhitelisted(t0) == IWhitelist.WhitelistStatus.Whitelisted);
  }

  function testIsWhitelistedEnumPausedNotWhitelisted() public {
    address never = makeAddr("never");
    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertTrue(wl.isWhitelisted(never) == IWhitelist.WhitelistStatus.PausedNotWhitelisted);
  }

  function testIsWhitelistedEnumPausedWhitelisted() public {
    _whitelistAsOwner(t0);
    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertTrue(wl.isWhitelisted(t0) == IWhitelist.WhitelistStatus.PausedWhitelisted);
  }

  // ---------- M-1: strict quorum < length -----------------------------------

  function testSetQuorumRejectsQuorumEqualToLength() public {
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    wl.setQuorum(3); // length = 3, so 3 >= 3 reverts
  }

  function testSetQuorumRejectsUnchanged() public {
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.QuorumUnchanged.selector);
    wl.setQuorum(2); // already quorum
  }

  // ---------- M-5: combined-role revoke -------------------------------------

  function testRevokeAllRolesRemovesBothRoles() public {
    // Make compliance a validator too (common attack-surface shape).
    vm.prank(ownerAddr);
    wl.addValidator(compliance);
    assertTrue(wl.isValidator(compliance));
    assertTrue(wl.isComplianceOfficer(compliance));

    vm.prank(ownerAddr);
    wl.revokeAllRoles(compliance);

    assertFalse(wl.isValidator(compliance));
    assertFalse(wl.isComplianceOfficer(compliance));
  }

  function testRevokeAllRolesSilentOnMissingRoles() public {
    address bystander = makeAddr("bystander");
    vm.prank(ownerAddr);
    wl.revokeAllRoles(bystander); // no-op; must not revert
    assertFalse(wl.isValidator(bystander));
    assertFalse(wl.isComplianceOfficer(bystander));
  }

  function testRevokeAllRolesOnlyOwner() public {
    vm.expectRevert(Ownable.Unauthorized.selector);
    wl.revokeAllRoles(v0.addr);
  }

  function testRevokeAllRolesRespectsQuorumFloor() public {
    // With length = 3 and quorum = 2, revoking any validator role
    // would drop length to 2 and violate `quorum < length`.
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    wl.revokeAllRoles(v2.addr);
  }

  // ---------- unwhitelist ---------------------------------------------------

  function testUnwhitelistNotOwnerGated() public {
    _whitelistAsOwner(t0);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signUnwhitelist(v0, targets, deadline);
    sigs[1] = _signUnwhitelist(v1, targets, deadline);

    address stranger = makeAddr("stranger");
    vm.prank(stranger);
    wl.unwhitelist(targets, deadline, sigs);

    assertFalse(_listed(t0));
  }

  function testUnwhitelistRevertsWhenPaused() public {
    _whitelistAsOwner(t0);
    vm.prank(compliance);
    wl.pauseFor(1 days);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signUnwhitelist(v0, targets, deadline);
    sigs[1] = _signUnwhitelist(v1, targets, deadline);

    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.unwhitelist(targets, deadline, sigs);
  }

  // ---------- pause semantics -----------------------------------------------

  function testPauseMasksReads() public {
    _whitelistAsOwner(t0);
    assertTrue(_listed(t0));

    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertFalse(_listed(t0));
    assertTrue(wl.isPaused());

    vm.warp(block.timestamp + 1 days + 1);
    assertTrue(_listed(t0));
    assertFalse(wl.isPaused());
  }

  function testPauseShorterDurationReverts() public {
    vm.startPrank(compliance);
    wl.pauseFor(10 days);
    uint48 longUntil = wl.pausedUntil();
    vm.expectRevert(WhitelistErrors.PauseNotExtended.selector);
    wl.pauseFor(1 days); // smaller — now reverts instead of silent no-op
    vm.stopPrank();
    assertEq(wl.pausedUntil(), longUntil);
  }

  function testPauseForZeroReverts() public {
    vm.prank(compliance);
    vm.expectRevert(WhitelistErrors.PauseNotExtended.selector);
    wl.pauseFor(0);
  }

  function testUnpauseClearsTimer() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertTrue(wl.isPaused());
    vm.prank(compliance);
    wl.unpause();
    assertFalse(wl.isPaused());
    assertEq(wl.pausedUntil(), 0);
  }

  function testOnlyComplianceCanPause() public {
    vm.expectRevert(WhitelistErrors.NotCompliance.selector);
    wl.pauseFor(1 days);
  }

  // ---------- renouncement dual path ----------------------------------------

  function testOwnerPathRevertsAfterRenounce() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();

    vm.expectRevert(Ownable.Unauthorized.selector);
    wl.addValidator(makeAddr("new"));
  }

  function testAdminBySigRevertsWhileOwned() public {
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_ADD_VALIDATOR(), abi.encode(makeAddr("new")), deadline);

    vm.expectRevert(WhitelistErrors.OwnerStillSet.selector);
    wl.addValidatorBySig(makeAddr("new"), deadline, sigs);
  }

  function testAdminBySigWorksAfterRenounce() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();

    address fresh = makeAddr("freshValidator");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_ADD_VALIDATOR(), abi.encode(fresh), deadline);

    wl.addValidatorBySig(fresh, deadline, sigs);
    assertTrue(wl.isValidator(fresh));
  }

  function testWhitelistOpenAfterRenounce() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    address stranger = makeAddr("stranger");
    vm.prank(stranger);
    wl.whitelist(targets, deadline, sigs);
    assertTrue(_listed(t0));
  }

  // ---------- admin mutations under invariants ------------------------------

  function testRemoveValidatorAtQuorumReverts() public {
    // Under the strict `quorum < length` invariant, removing v2 from the
    // initial 3-validator / quorum-2 set would leave length = quorum,
    // violating the invariant. Must revert — the operator has to lower
    // quorum first (or add another validator) before pruning.
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    wl.removeValidator(v2.addr);
  }

  /// @dev H-3 fix via the bitmap nonce model: removing a validator
  ///      saturates their floor to `type(uint256).max` so any
  ///      pre-signed sig at any reasonable nonce becomes
  ///      `NonceBelowFloor` thereafter. Combined with
  ///      `setValidatorNonce`'s strict-increase rule, re-admitting the
  ///      same address yields a permanently unusable key — operators
  ///      wanting to rotate must use a new address.
  function testRemoveValidatorBurnsNonceFloor() public {
    vm.prank(v2.addr);
    wl.setValidatorNonce(7);

    // Pad the set so removing v2 doesn't violate the strict
    // `quorum < length` invariant.
    vm.prank(ownerAddr);
    wl.addValidator(makeAddr("padding"));
    vm.prank(ownerAddr);
    wl.removeValidator(v2.addr);

    assertEq(wl.validatorNonceFloor(v2.addr), type(uint256).max);
  }

  function testReAddingRemovedValidatorCannotReplayOldSigs() public {
    // v2 signs an unwhitelist at a low nonce, holds it in the mempool.
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig memory leaked = _signUnwhitelistWithNonce(v2, targets, deadline, 0);

    // Pad and remove v2.
    vm.prank(ownerAddr);
    wl.addValidator(makeAddr("padding"));
    vm.prank(ownerAddr);
    wl.removeValidator(v2.addr);

    // Operator re-admits v2 at the same address (an anti-pattern we
    // explicitly do not want to make safe — this test codifies that
    // the leaked sig is *not* replayable).
    vm.prank(ownerAddr);
    wl.addValidator(v2.addr);

    // Even though v2 is a validator again, the floor is still
    // saturated, so every leaked sig below `type(uint256).max` is
    // rejected.
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signUnwhitelist(v0, targets, deadline);
    sigs[1] = leaked;
    vm.expectRevert(QuorumSigLib.NonceBelowFloor.selector);
    wl.unwhitelist(targets, deadline, sigs);
  }

  function testAddValidatorDuplicateReverts() public {
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.DuplicateValidator.selector);
    wl.addValidator(v0.addr);
  }

  // ---------- proxy domain separator ----------------------------------------

  function testProxyDomainSeparatorIsUsed() public view {
    (,, string memory version, uint256 chainId, address verifying,,) = wl.eip712Domain();
    assertEq(version, "1");
    assertEq(chainId, block.chainid);
    assertEq(verifying, address(wl));
  }

  // ---------- NM-002: whitelist/unwhitelist sig replay is rejected ----------

  function testWhitelistSigCannotBeReplayed() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelistWithNonce(v0, targets, deadline, 0);
    sigs[1] = _signWhitelistWithNonce(v1, targets, deadline, 0);

    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigs);

    assertTrue(wl.isNonceConsumed(v0.addr, 0), "v0 nonce consumed");
    assertTrue(wl.isNonceConsumed(v1.addr, 0), "v1 nonce consumed");

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceConsumed.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  function testUnwhitelistSigCannotBeReplayedToUndoRewhitelist() public {
    _whitelistAsOwner(t0);

    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory unsigs = new QuorumSigLib.Sig[](2);
    unsigs[0] = _signUnwhitelist(v0, targets, deadline);
    unsigs[1] = _signUnwhitelist(v1, targets, deadline);

    address stranger = makeAddr("stranger");
    vm.prank(stranger);
    wl.unwhitelist(targets, deadline, unsigs);
    assertFalse(_listed(t0));

    QuorumSigLib.Sig[] memory reWhitelist = new QuorumSigLib.Sig[](2);
    reWhitelist[0] = _signWhitelist(v0, targets, deadline);
    reWhitelist[1] = _signWhitelist(v1, targets, deadline);
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, reWhitelist);
    assertTrue(_listed(t0));

    vm.prank(stranger);
    vm.expectRevert(QuorumSigLib.NonceConsumed.selector);
    wl.unwhitelist(targets, deadline, unsigs);

    assertTrue(_listed(t0));
  }

  /// @dev M-4 fix: with the bitmap nonce model, sigs can be submitted
  ///      in any order. A batch at nonce 5 can be consumed before a
  ///      batch at nonce 3; each remains single-use.
  function testSigsConsumableInAnyOrder() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    // Three independent batches, each signed at a distinct nonce.
    QuorumSigLib.Sig[] memory batchAt5 = new QuorumSigLib.Sig[](2);
    batchAt5[0] = _signWhitelistWithNonce(v0, targets, deadline, 5);
    batchAt5[1] = _signWhitelistWithNonce(v1, targets, deadline, 5);

    QuorumSigLib.Sig[] memory batchAt3 = new QuorumSigLib.Sig[](2);
    batchAt3[0] = _signWhitelistWithNonce(v0, targets, deadline, 3);
    batchAt3[1] = _signWhitelistWithNonce(v1, targets, deadline, 3);

    QuorumSigLib.Sig[] memory batchAt7 = new QuorumSigLib.Sig[](2);
    batchAt7[0] = _signWhitelistWithNonce(v0, targets, deadline, 7);
    batchAt7[1] = _signWhitelistWithNonce(v1, targets, deadline, 7);

    // Submit 5 first — passes.
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, batchAt5);
    assertTrue(wl.isNonceConsumed(v0.addr, 5));

    // Then 3 — also passes (would have been NonceMismatch in the old model).
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, batchAt3);
    assertTrue(wl.isNonceConsumed(v0.addr, 3));

    // Finally 7 — passes. Gaps at 0, 1, 2, 4, 6 remain available for
    // other in-flight sigs, demonstrating that any nonce allocation
    // pattern (sequential, sparse, time-based) is valid.
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, batchAt7);
    assertTrue(wl.isNonceConsumed(v0.addr, 7));
    assertFalse(wl.isNonceConsumed(v0.addr, 4));
  }

  /// @dev Within a single call the same sig cannot be credited twice;
  ///      the call-local dedup fires on the second occurrence.
  function testSameNonceTwiceInOneCallReverts() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig memory v0Sig = _signWhitelistWithNonce(v0, targets, deadline, 0);
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = v0Sig;
    sigs[1] = v0Sig; // same validator, same nonce

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.DuplicateSignature.selector);
    wl.whitelist(targets, deadline, sigs);
  }

  // ---------- NM-003: admin *BySig sig replay is rejected -------------------

  function testAddValidatorBySigCannotBeReplayed() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();

    address fresh = makeAddr("freshValidator");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory addSigs = _signAdmin(ACTION_ADD_VALIDATOR(), abi.encode(fresh), deadline);
    wl.addValidatorBySig(fresh, deadline, addSigs);
    assertTrue(wl.isValidator(fresh));

    QuorumSigLib.Sig[] memory removeSigs = _signAdmin(ACTION_REMOVE_VALIDATOR(), abi.encode(fresh), deadline);
    wl.removeValidatorBySig(fresh, deadline, removeSigs);
    assertFalse(wl.isValidator(fresh));

    vm.expectRevert(QuorumSigLib.NonceConsumed.selector);
    wl.addValidatorBySig(fresh, deadline, addSigs);
  }

  function testSetComplianceOfficerBySigCannotBeReplayed() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();

    address attacker = makeAddr("attacker");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory addSigs = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(attacker, true), deadline);
    wl.setComplianceOfficerBySig(attacker, true, deadline, addSigs);
    assertTrue(wl.isComplianceOfficer(attacker));

    QuorumSigLib.Sig[] memory revokeSigs = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(attacker, false), deadline);
    wl.setComplianceOfficerBySig(attacker, false, deadline, revokeSigs);
    assertFalse(wl.isComplianceOfficer(attacker));

    vm.expectRevert(QuorumSigLib.NonceConsumed.selector);
    wl.setComplianceOfficerBySig(attacker, true, deadline, addSigs);
  }

  // ---------- NM-001: pause gates every admin path --------------------------

  function testPausedBlocksAddValidator() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.addValidator(makeAddr("new"));
  }

  function testPausedBlocksRemoveValidator() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.removeValidator(v2.addr);
  }

  function testPausedBlocksSetQuorum() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setQuorum(3);
  }

  function testPausedBlocksSetComplianceOfficer() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(ownerAddr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setComplianceOfficer(makeAddr("co2"), true);
  }

  /// @dev H-1 fix: `setValidatorNonce` must remain callable while paused,
  ///      because the most credible reason to pause is suspected key
  ///      compromise — exactly the scenario that needs mass-invalidation.
  function testSetValidatorNonceWorksWhilePaused() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(v0.addr);
    wl.setValidatorNonce(42);
    assertEq(wl.validatorNonceFloor(v0.addr), 42);
  }

  /// @dev H-2 fix: quorum-signed admin rotation must remain reachable
  ///      while paused. Pause freezes *whitelisting*, not *administration*.
  function testAddValidatorBySigWorksWhilePaused() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    address fresh = makeAddr("freshValidator");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_ADD_VALIDATOR(), abi.encode(fresh), deadline);
    wl.addValidatorBySig(fresh, deadline, sigs);
    assertTrue(wl.isValidator(fresh));
  }

  function testRemoveValidatorBySigWorksWhilePaused() public {
    // Add a fresh validator first so the set is big enough to prune v2
    // under the strict `quorum < length` invariant.
    vm.prank(ownerAddr);
    wl.addValidator(makeAddr("padding"));

    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_REMOVE_VALIDATOR(), abi.encode(v2.addr), deadline);
    wl.removeValidatorBySig(v2.addr, deadline, sigs);
    assertFalse(wl.isValidator(v2.addr));
  }

  function testSetQuorumBySigWorksWhilePaused() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_SET_QUORUM(), abi.encode(uint16(1)), deadline);
    wl.setQuorumBySig(1, deadline, sigs);
    assertEq(wl.quorum(), 1);
  }

  /// @dev H-2 fix: the quorum must be able to rotate out a rogue
  ///      compliance officer via `*BySig` even while the officer has the
  ///      registry paused. Without this, a rogue officer calling
  ///      `pauseFor(max)` would permanently lock the registry because
  ///      `setComplianceOfficerBySig` would itself be `whenNotPaused`.
  function testComplianceOfficerRotationWorksWhilePaused() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(10 days);
    assertTrue(wl.isPaused());

    address newOfficer = makeAddr("newOfficer");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory swapIn = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(newOfficer, true), deadline);
    wl.setComplianceOfficerBySig(newOfficer, true, deadline, swapIn);

    QuorumSigLib.Sig[] memory swapOut = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(compliance, false), deadline);
    wl.setComplianceOfficerBySig(compliance, false, deadline, swapOut);

    assertFalse(wl.isComplianceOfficer(compliance));
    assertTrue(wl.isComplianceOfficer(newOfficer));

    // Fresh officer unpauses to fully recover the registry.
    vm.prank(newOfficer);
    wl.unpause();
    assertFalse(wl.isPaused());
  }

  function testPauseForExtendableDuringPause() public {
    vm.startPrank(compliance);
    wl.pauseFor(1 days);
    uint48 u1 = wl.pausedUntil();
    wl.pauseFor(5 days);
    vm.stopPrank();
    assertGt(wl.pausedUntil(), u1);
  }

  function testUnpauseCallableDuringPause() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertTrue(wl.isPaused());
    vm.prank(compliance);
    wl.unpause();
    assertFalse(wl.isPaused());
  }

  // ---------- NM-006: pauseFor saturates on extreme durations ---------------

  function testPauseForSaturatesOnHugeDuration() public {
    vm.prank(compliance);
    wl.pauseFor(type(uint256).max);
    assertEq(wl.pausedUntil(), type(uint48).max);
  }

  function testPauseForSaturatesJustAboveUint48() public {
    vm.prank(compliance);
    wl.pauseFor(uint256(type(uint48).max) + 1);
    assertEq(wl.pausedUntil(), type(uint48).max);
  }

  // ---------- helpers -------------------------------------------------------

  /// @dev Returns true iff `a` is in the trusted `Whitelisted` state —
  ///      i.e. attested AND the registry is not paused. Wraps the enum
  ///      return type of `IWhitelist.isWhitelisted` so the existing
  ///      assertions read the same as before the L-5 fix.
  function _listed(address a) internal view returns (bool) {
    return wl.isWhitelisted(a) == IWhitelist.WhitelistStatus.Whitelisted;
  }

  function _whitelistAsOwner(address target) internal {
    address[] memory targets = new address[](1);
    targets[0] = target;
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigs);
  }

  /// @dev Picks the next nonce for validator `v`: max of the on-chain
  ///      floor and the suite's local cursor, then advances the cursor.
  ///      Tests that raise the floor via `setValidatorNonce` automatically
  ///      get sigs at or above the new floor on the next helper call.
  function _pickNonce(address v) internal returns (uint256) {
    uint256 floor = wl.validatorNonceFloor(v);
    uint256 n = _nextNonce[v];
    if (n < floor) n = floor;
    _nextNonce[v] = n + 1;
    return n;
  }

  function _signWhitelist(Vm.Wallet memory w, address[] memory targets, uint256 deadline)
    internal
    returns (QuorumSigLib.Sig memory)
  {
    return _signWhitelistWithNonce(w, targets, deadline, _pickNonce(w.addr));
  }

  function _signWhitelistWithNonce(Vm.Wallet memory w, address[] memory targets, uint256 deadline, uint256 nonce)
    internal
    view
    returns (QuorumSigLib.Sig memory)
  {
    bytes32 digest = _whitelistDigest(targets, deadline, w.addr, nonce);
    (uint8 vv, bytes32 r, bytes32 s) = vm.sign(w, digest);
    return QuorumSigLib.Sig({validator: w.addr, nonce: nonce, signature: abi.encodePacked(r, s, vv)});
  }

  function _signUnwhitelist(Vm.Wallet memory w, address[] memory targets, uint256 deadline)
    internal
    returns (QuorumSigLib.Sig memory)
  {
    return _signUnwhitelistWithNonce(w, targets, deadline, _pickNonce(w.addr));
  }

  function _signUnwhitelistWithNonce(Vm.Wallet memory w, address[] memory targets, uint256 deadline, uint256 nonce)
    internal
    view
    returns (QuorumSigLib.Sig memory)
  {
    bytes32 structHash =
      keccak256(abi.encode(UNWHITELIST_TYPEHASH, _hashAddressArray(targets), deadline, w.addr, nonce));
    bytes32 digest = _toTypedDataHash(structHash);
    (uint8 vv, bytes32 r, bytes32 s) = vm.sign(w, digest);
    return QuorumSigLib.Sig({validator: w.addr, nonce: nonce, signature: abi.encodePacked(r, s, vv)});
  }

  function _signAdmin(bytes32 actionId, bytes memory data, uint256 deadline)
    internal
    returns (QuorumSigLib.Sig[] memory out)
  {
    out = new QuorumSigLib.Sig[](2);
    out[0] = _signAdminFor(v0, actionId, data, deadline);
    out[1] = _signAdminFor(v1, actionId, data, deadline);
  }

  function _signAdminFor(Vm.Wallet memory w, bytes32 actionId, bytes memory data, uint256 deadline)
    internal
    returns (QuorumSigLib.Sig memory)
  {
    uint256 nonce = _pickNonce(w.addr);
    bytes32 structHash = keccak256(abi.encode(ADMIN_TYPEHASH, actionId, keccak256(data), deadline, w.addr, nonce));
    bytes32 digest = _toTypedDataHash(structHash);
    (uint8 vv, bytes32 r, bytes32 s) = vm.sign(w, digest);
    return QuorumSigLib.Sig({validator: w.addr, nonce: nonce, signature: abi.encodePacked(r, s, vv)});
  }

  // Locally-computed digests — the contract no longer exposes hash helpers.

  bytes32 internal constant WHITELIST_TYPEHASH =
    keccak256("WhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant UNWHITELIST_TYPEHASH =
    keccak256("UnwhitelistRequest(address[] targets,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant ADMIN_TYPEHASH =
    keccak256("AdminRequest(bytes32 actionId,bytes data,uint256 deadline,address validator,uint256 nonce)");
  bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  function _whitelistDigest(address[] memory targets, uint256 deadline, address validator_, uint256 nonce)
    internal
    view
    returns (bytes32)
  {
    bytes32 structHash =
      keccak256(abi.encode(WHITELIST_TYPEHASH, _hashAddressArray(targets), deadline, validator_, nonce));
    return _toTypedDataHash(structHash);
  }

  function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
    (, string memory name, string memory version, uint256 chainId, address verifying,,) = wl.eip712Domain();
    bytes32 domainSeparator = keccak256(
      abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying)
    );
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }

  function _hashAddressArray(address[] memory targets) internal pure returns (bytes32) {
    bytes32[] memory padded = new bytes32[](targets.length);
    for (uint256 i; i < targets.length; ++i) {
      padded[i] = bytes32(uint256(uint160(targets[i])));
    }
    return keccak256(abi.encodePacked(padded));
  }

  function ACTION_ADD_VALIDATOR() internal pure returns (bytes32) {
    return keccak256("ADD_VALIDATOR");
  }

  function ACTION_REMOVE_VALIDATOR() internal pure returns (bytes32) {
    return keccak256("REMOVE_VALIDATOR");
  }

  function ACTION_SET_QUORUM() internal pure returns (bytes32) {
    return keccak256("SET_QUORUM");
  }

  function ACTION_SET_COMPLIANCE() internal pure returns (bytes32) {
    return keccak256("SET_COMPLIANCE_OFFICER");
  }
}
