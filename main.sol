// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./node_modules/@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./node_modules/@openzeppelin/contracts/utils/Pausable.sol";
import "./node_modules/@openzeppelin/contracts/access/Ownable.sol";
import "./Mixer.sol";
import "./MerkleTreeWithHistory.sol";

interface IVerifier {
    function verifyProof(bytes memory _proof, uint256[6] memory _input)
        external
        returns (bool);
}

abstract contract ENS {
    function resolver(bytes32 node) public view virtual returns (Resolver);
}

abstract contract Resolver {
    function addr(bytes32 node) public view virtual returns (address);
}

struct zkID {
    bytes32 balance; // secret(balance)
    bytes32 node; // ENS domain
}

/* Map hashes to ENS domain names */
contract zkENS is Mixer, Pausable, Ownable {
    mapping(bytes32 => zkID) public identity; // bytes32 = hash(secret)
    ENS public ens = ENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    string public messageString = "zkENS Public Test"; // Used to derive pk
    IVerifier public immutable verifier;

    constructor(
        IVerifier _verifier,
        IVerifier _depositVerifier,
        IHasher _hasher,
        uint32 _merkleTreeHeight
    ) Mixer(_verifier, _depositVerifier, _hasher, _merkleTreeHeight) {}

    function _processDeposit() internal override whenNotPaused {
        // What happens once deposit is good
    }

    function _processRedeem(
        bytes32 _zkid,
        address payable _relayer,
        uint256 _fee,
        bytes32 _encryptedBalance
    ) internal override whenNotPaused {
        //require(msg.value == _refund, "Incorrect refund amount received by the contract");
        identity(_zkID).balance = _encryptedBalance;
        if (_fee > 0) _relayer.call{value: _fee}(""); // Double check this and how _refund works
    }
}
