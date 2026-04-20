// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-1271 signer used in tests. The contract delegates
///         validity to an inner EOA whose private key lives in the test.
contract MockERC1271 {
  address public immutable signer;

  constructor(address signer_) {
    signer = signer_;
  }

  function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
    if (sig.length != 65) return 0xffffffff;
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := calldataload(sig.offset)
      s := calldataload(add(sig.offset, 0x20))
      v := byte(0, calldataload(add(sig.offset, 0x40)))
    }
    if (ecrecover(hash, v, r, s) == signer) return 0x1626ba7e;
    return 0xffffffff;
  }
}
