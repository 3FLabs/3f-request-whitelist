// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {RequestWhitelist} from "../src/RequestWhitelist.sol";
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

    assertTrue(wl.isWhitelisted(t0));
    assertTrue(wl.isWhitelisted(t1));
  }

  function testWhitelistWithERC1271Signer() public {
    // Replace v2 with a mock 1271 contract that signs via the same key.
    vm.prank(ownerAddr);
    wl.removeValidator(v2.addr);
    MockERC1271 contractSigner = new MockERC1271(v2.addr);
    vm.prank(ownerAddr);
    wl.addValidator(address(contractSigner));

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
    assertTrue(wl.isWhitelisted(t0));
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

  function testWhitelistRevertsNonceMismatch() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    QuorumSigLib.Sig[] memory sigs = new QuorumSigLib.Sig[](2);
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelistWithNonce(v1, targets, deadline, 5); // wrong nonce

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
    wl.whitelist(targets, deadline, sigs);
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
    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
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

    assertFalse(wl.isWhitelisted(t0));
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
    assertTrue(wl.isWhitelisted(t0));

    vm.prank(compliance);
    wl.pauseFor(1 days);
    assertFalse(wl.isWhitelisted(t0));
    assertTrue(wl.isPaused());

    vm.warp(block.timestamp + 1 days + 1);
    assertTrue(wl.isWhitelisted(t0));
    assertFalse(wl.isPaused());
  }

  function testPauseIsExtendOnly() public {
    vm.startPrank(compliance);
    wl.pauseFor(10 days);
    uint48 longUntil = wl.pausedUntil();
    wl.pauseFor(1 days); // smaller — no-op
    assertEq(wl.pausedUntil(), longUntil);
    vm.stopPrank();
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
    assertTrue(wl.isWhitelisted(t0));
  }

  // ---------- admin mutations under invariants ------------------------------

  function testRemoveValidatorBelowQuorumReverts() public {
    vm.startPrank(ownerAddr);
    wl.removeValidator(v2.addr);
    vm.expectRevert(WhitelistErrors.QuorumOutOfRange.selector);
    wl.removeValidator(v1.addr); // would leave 1 < quorum 2
    vm.stopPrank();
  }

  function testRemoveValidatorLeavesNonceUntouched() public {
    vm.prank(v2.addr);
    wl.setValidatorNonce(7);

    vm.prank(ownerAddr);
    wl.removeValidator(v2.addr);

    assertEq(wl.validatorNonce(v2.addr), 7);
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
    sigs[0] = _signWhitelist(v0, targets, deadline);
    sigs[1] = _signWhitelist(v1, targets, deadline);

    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigs);

    assertEq(wl.validatorNonce(v0.addr), 1, "v0 nonce consumed");
    assertEq(wl.validatorNonce(v1.addr), 1, "v1 nonce consumed");

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
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
    assertFalse(wl.isWhitelisted(t0));

    QuorumSigLib.Sig[] memory reWhitelist = new QuorumSigLib.Sig[](2);
    reWhitelist[0] = _signWhitelist(v0, targets, deadline);
    reWhitelist[1] = _signWhitelist(v1, targets, deadline);
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, reWhitelist);
    assertTrue(wl.isWhitelisted(t0));

    vm.prank(stranger);
    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
    wl.unwhitelist(targets, deadline, unsigs);

    assertTrue(wl.isWhitelisted(t0));
  }

  function testSequentialSigsMustBeConsumedInOrder() public {
    address[] memory targets = new address[](1);
    targets[0] = t0;
    uint256 deadline = block.timestamp + 1 hours;

    // Pre-signed at nonce 1 while on-chain nonces are 0 — out-of-order.
    QuorumSigLib.Sig[] memory sigsN1 = new QuorumSigLib.Sig[](2);
    sigsN1[0] = _signWhitelistWithNonce(v0, targets, deadline, 1);
    sigsN1[1] = _signWhitelistWithNonce(v1, targets, deadline, 1);

    vm.prank(ownerAddr);
    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
    wl.whitelist(targets, deadline, sigsN1);

    // Consuming nonce 0 first unblocks the nonce-1 batch.
    QuorumSigLib.Sig[] memory sigsN0 = new QuorumSigLib.Sig[](2);
    sigsN0[0] = _signWhitelistWithNonce(v0, targets, deadline, 0);
    sigsN0[1] = _signWhitelistWithNonce(v1, targets, deadline, 0);
    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigsN0);

    vm.prank(ownerAddr);
    wl.whitelist(targets, deadline, sigsN1);

    assertEq(wl.validatorNonce(v0.addr), 2);
    assertEq(wl.validatorNonce(v1.addr), 2);
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

    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
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

    vm.expectRevert(QuorumSigLib.NonceMismatch.selector);
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

  function testPausedBlocksSetValidatorNonce() public {
    vm.prank(compliance);
    wl.pauseFor(1 days);
    vm.prank(v0.addr);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setValidatorNonce(42);
  }

  function testPausedBlocksAddValidatorBySig() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    address fresh = makeAddr("freshValidator");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_ADD_VALIDATOR(), abi.encode(fresh), deadline);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.addValidatorBySig(fresh, deadline, sigs);
  }

  function testPausedBlocksRemoveValidatorBySig() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_REMOVE_VALIDATOR(), abi.encode(v2.addr), deadline);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.removeValidatorBySig(v2.addr, deadline, sigs);
  }

  function testPausedBlocksSetQuorumBySig() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(1 days);

    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory sigs = _signAdmin(ACTION_SET_QUORUM(), abi.encode(uint16(3)), deadline);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setQuorumBySig(3, deadline, sigs);
  }

  /// @dev The NM-001 headline defeat path: compliance-officer swap via
  ///      `*BySig` while paused is what allowed unpausing the circuit
  ///      breaker. It must now revert before touching any state.
  function testPausedBlocksComplianceOfficerSwapDefeat() public {
    vm.prank(ownerAddr);
    wl.renounceOwnership();
    vm.prank(compliance);
    wl.pauseFor(10 days);
    assertTrue(wl.isPaused());

    address attacker = makeAddr("attacker");
    uint256 deadline = block.timestamp + 1 hours;
    QuorumSigLib.Sig[] memory swapIn = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(attacker, true), deadline);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setComplianceOfficerBySig(attacker, true, deadline, swapIn);

    QuorumSigLib.Sig[] memory swapOut = _signAdmin(ACTION_SET_COMPLIANCE(), abi.encode(compliance, false), deadline);
    vm.expectRevert(WhitelistErrors.ContractPaused.selector);
    wl.setComplianceOfficerBySig(compliance, false, deadline, swapOut);

    // Original compliance officer keeps the keys to the cell.
    assertTrue(wl.isComplianceOfficer(compliance));
    assertFalse(wl.isComplianceOfficer(attacker));
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

  function _signWhitelist(Vm.Wallet memory w, address[] memory targets, uint256 deadline)
    internal
    view
    returns (QuorumSigLib.Sig memory)
  {
    return _signWhitelistWithNonce(w, targets, deadline, wl.validatorNonce(w.addr));
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
    view
    returns (QuorumSigLib.Sig memory)
  {
    uint256 nonce = wl.validatorNonce(w.addr);
    bytes32 structHash =
      keccak256(abi.encode(UNWHITELIST_TYPEHASH, _hashAddressArray(targets), deadline, w.addr, nonce));
    bytes32 digest = _toTypedDataHash(structHash);
    (uint8 vv, bytes32 r, bytes32 s) = vm.sign(w, digest);
    return QuorumSigLib.Sig({validator: w.addr, nonce: nonce, signature: abi.encodePacked(r, s, vv)});
  }

  function _signAdmin(bytes32 actionId, bytes memory data, uint256 deadline)
    internal
    view
    returns (QuorumSigLib.Sig[] memory out)
  {
    out = new QuorumSigLib.Sig[](2);
    out[0] = _signAdminFor(v0, actionId, data, deadline);
    out[1] = _signAdminFor(v1, actionId, data, deadline);
  }

  function _signAdminFor(Vm.Wallet memory w, bytes32 actionId, bytes memory data, uint256 deadline)
    internal
    view
    returns (QuorumSigLib.Sig memory)
  {
    uint256 nonce = wl.validatorNonce(w.addr);
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
