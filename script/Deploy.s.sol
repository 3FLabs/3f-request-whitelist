// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {ERC1967FactoryConstants} from "solady/utils/ERC1967FactoryConstants.sol";

import {RequestWhitelist} from "../src/RequestWhitelist.sol";

/// @dev 0age's canonical `ImmutableCreate2Factory`, used to bootstrap the
///      solady `ERC1967Factory` at its canonical cross-chain address and
///      to CREATE2-deploy the `RequestWhitelist` implementation if the
///      target chain is cold.
interface IImmutableCreate2Factory {
  function safeCreate2(bytes32 salt, bytes calldata initializationCode) external payable returns (address);
}

/// @title  DeployRequestWhitelist
/// @notice Deterministic proxy deployment of `RequestWhitelist`.
///
///         Every deployed artefact lives at a cross-chain-deterministic
///         address:
///           1. `ERC1967Factory` — always the canonical solady address
///              (`ERC1967FactoryConstants.ADDRESS`); bootstrapped via
///              `ImmutableCreate2Factory` if cold.
///           2. `RequestWhitelist` implementation — CREATE2'd via
///              `ImmutableCreate2Factory` at `IMPLEMENTATION_SALT`
///              (default `bytes32(uint256(0x3f))`). The address is a
///              function of `(create2-factory, salt, creationCode)` and
///              is identical on every chain that runs this script.
///           3. Proxy — CREATE2'd via the `ERC1967Factory` at the
///              user-provided `SALT`, initialised atomically in the
///              same tx (closing the `initialize` front-run window).
///
///         The script is idempotent at the artefact level: if an
///         artefact already has code at its predicted address, the
///         deploy step for that artefact is skipped.
///
/// @dev    Required env:
///           - `SALT`                 bytes32  CREATE2 salt for the proxy.
///           - `PROXY_ADMIN`          address  ERC-1967 admin (upgrades).
///           - `OWNER`                address  Phase-1 application owner.
///           - `VALIDATORS`           address[],comma-delimited
///           - `QUORUM`               uint     1 <= QUORUM < validators.length
///
///         Optional env:
///           - `IMPLEMENTATION`       address  Explicit impl override.
///                                             Skips CREATE2 deployment
///                                             entirely.
///           - `IMPLEMENTATION_SALT`  bytes32  CREATE2 salt for the impl.
///                                             Default `bytes32(uint256(0x3f))`.
///                                             Ignored if `IMPLEMENTATION`
///                                             is set.
///           - `COMPLIANCE_OFFICERS`  address[],comma-delimited; empty if unset.
contract DeployRequestWhitelist is Script {
  /// @dev Canonical address of 0age's `ImmutableCreate2Factory` on every
  ///      EVM chain where it has been deployed.
  address internal constant IMMUTABLE_CREATE2_FACTORY = 0x0000000000FFe8B47B3e2130213B802212439497;

  /// @dev Default CREATE2 salt for the implementation. The top 20 bytes
  ///      are zero, so the salt satisfies
  ///      `ImmutableCreate2Factory`'s "zero-prefix or caller-prefix"
  ///      guard from any deployer.
  bytes32 internal constant DEFAULT_IMPLEMENTATION_SALT = bytes32(uint256(0x3f));

  function run() external returns (ERC1967Factory factory, address implementation, address proxy) {
    bytes32 salt = vm.envBytes32("SALT");
    address proxyAdmin = vm.envAddress("PROXY_ADMIN");
    address owner = vm.envAddress("OWNER");
    uint16 quorumValue = uint16(vm.envUint("QUORUM"));
    address[] memory validatorSet = vm.envAddress("VALIDATORS", ",");

    address[] memory complianceOfficers;
    if (vm.envExists("COMPLIANCE_OFFICERS")) {
      complianceOfficers = vm.envAddress("COMPLIANCE_OFFICERS", ",");
    } else {
      complianceOfficers = new address[](0);
    }

    address implEnv = vm.envOr("IMPLEMENTATION", address(0));
    bytes32 implSalt = vm.envOr("IMPLEMENTATION_SALT", DEFAULT_IMPLEMENTATION_SALT);

    bytes memory initData =
      abi.encodeCall(RequestWhitelist.initialize, (owner, validatorSet, quorumValue, complianceOfficers));

    vm.startBroadcast();

    factory = _canonicalFactory();
    implementation = implEnv != address(0) ? implEnv : _deterministicImplementation(implSalt);

    address predicted = factory.predictDeterministicAddress(salt);
    proxy = factory.deployDeterministicAndCall(implementation, proxyAdmin, salt, initData);

    vm.stopBroadcast();

    require(proxy == predicted, "deterministic address mismatch");

    console2.log("ERC1967Factory:", address(factory));
    console2.log("Implementation:", implementation);
    console2.log("Proxy:         ", proxy);
  }

  /// @dev Returns the canonical `ERC1967Factory`, deploying it via
  ///      `ImmutableCreate2Factory` if the target chain hasn't seen it
  ///      yet. Reverts with a clear message if even the underlying
  ///      create2 factory is missing — a fully cold chain needs one
  ///      bootstrap step the script cannot do for you.
  function _canonicalFactory() internal returns (ERC1967Factory) {
    address canonical = ERC1967FactoryConstants.ADDRESS;
    if (canonical.code.length != 0) return ERC1967Factory(canonical);

    _requireCreate2Factory();
    address deployed = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY)
      .safeCreate2(ERC1967FactoryConstants.SALT, ERC1967FactoryConstants.INITCODE);
    require(deployed == canonical, "canonical factory address mismatch");
    return ERC1967Factory(canonical);
  }

  /// @dev Returns the CREATE2-deployed `RequestWhitelist` implementation
  ///      at `salt`, deploying it via `ImmutableCreate2Factory` if the
  ///      target chain hasn't seen this salt before. Idempotent: a
  ///      previously-deployed impl at the predicted address is reused.
  function _deterministicImplementation(bytes32 salt) internal returns (address impl) {
    bytes memory initcode = type(RequestWhitelist).creationCode;
    address predicted = vm.computeCreate2Address(salt, keccak256(initcode), IMMUTABLE_CREATE2_FACTORY);
    if (predicted.code.length != 0) return predicted;

    _requireCreate2Factory();
    impl = IImmutableCreate2Factory(IMMUTABLE_CREATE2_FACTORY).safeCreate2(salt, initcode);
    require(impl == predicted, "implementation address mismatch");
  }

  function _requireCreate2Factory() internal view {
    require(
      IMMUTABLE_CREATE2_FACTORY.code.length != 0,
      "ImmutableCreate2Factory not deployed; bootstrap it first (see 0age/ImmutableCreate2Factory)"
    );
  }
}
