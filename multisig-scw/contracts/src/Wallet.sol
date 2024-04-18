//SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

contract Wallet is BaseAccount, Initializable, UUPSUpgradeable, TokenCallbackHandler {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    uint256 constant SIG_VALIDATION_FAILED = 0x0001;

    address public immutable walletFactory;
    IEntryPoint private immutable _entryPoint;
    address[] public owners;

    event WalletInitialized(IEntryPoint indexed entryPoint, address[] owners);

    modifier _requireFromEntryPointOrFactory() {
        require(
            msg.sender == address(_entryPoint) || msg.sender == walletFactory,
            "only entry point or wallet factory can call"
        );
        _;
    }

    constructor(IEntryPoint entryPoint, address _walletFactory) {
        _entryPoint = entryPoint;
        walletFactory = _walletFactory;
    }

    function initialize(address[] memory initialOwners) public initializer {
        _initialize(initialOwners);
    }

    function _initialize(address[] memory initialOwners) internal {
        require(initialOwners.length > 0, "empty list of owners");
        owners = initialOwners;
        emit WalletInitialized(_entryPoint, initialOwners);
    }

    function _authorizeUpgrade(address) internal view override _requireFromEntryPointOrFactory {}

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     *
     * @param dest - destination address
     * @param value - value of ether senede with call
     * @param func - function calldata
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external _requireFromEntryPointOrFactory {
        _call(dest, value, func);
    }

    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external _requireFromEntryPointOrFactory {
        require(dests.length == funcs.length && funcs.length == values.length "Array lengths are not equal");
        for (uint256 i = 0; i < dests.length; i++) {
            _call(dests[i], values[i], funcs[i]);
        }
    }

    /**
     *
     * @param userOp - UserOperation data structure passed as input
     * @param userOpHash - hash of the UserOperation without the signatures
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256) {
        // Convert the UserOpHash to an Ethereum Signed MessageHash
        bytes32 hash = userOpHash.toEthSignedMessageHash();

        // Decode the signatures from the userOp and store them in a bytes arra in memory
        bytes32[] memory signatures = abi.encode(userOp.signature, (bytes[]));

        // Loop through all the owners of the wallet
        for (uint256 i = 0; i < owners.length; i++) {
            // Recover the signers address from each signature
            // If recovered address doesn't match the owner's address, return SIG_VALIDATION_FAILED
            if (owners[i] != hash.recover(hash, signatures[i])) {
                return SIG_VALIDATION_FAILED;
            }
        }
        // If all signatures are valid(i.e. they all belong to the owners), return 0
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                // The assembly code here skips the first 32 bytes of the result, which contains the length of the of data.
                // It then loads the actual error message using mload and calls revert with this error message.
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * This function encodes the signatures into a bytes array, which can be used to pass as data when making calls to the contract.
     * @param signatures - signatures for encoding
     */
    function encodeSignatures( bytes[] memory signatures) public pure returns (bytes memory) {
        return abi.encode(signatures);
    }

    /**
     * This function checks the balance of the wallet with EntryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * This function adds a deposit for the wallet in EntryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    // This function allows the contract to accept the ETH
    receive() external payable {}
}
