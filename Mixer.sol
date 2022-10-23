// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IVerifier {
    function verifyProof(bytes memory _proof, uint256[7] memory _input)
        external
        returns (bool);
}
interface IDVerifier {
    function verifyProof(bytes memory _proof, uint256[1] memory _input)
        external
        returns (bool);
}

abstract contract Mixer is MerkleTreeWithHistory, ReentrancyGuard {
    IVerifier public immutable verifier;
    IDVerifier public immutable depositVerifier;
    mapping(address => bytes[]) public mappedDeposits; // Encrypted deposits by address
    bytes32[] public allCommitments;

    mapping(bytes32 => bool) public nullifierHashes;
    // we store all commitments just to prevent accidental deposits with the same commitment
    mapping(bytes32 => bool) public commitments;

    event Deposit(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 timestamp
    );
    event Redeem(
        address to,
        bytes32 nullifierHash,
        address indexed relayer,
        uint256 fee
    );

    /**
    @dev The constructor
    @param _verifier the address of SNARK verifier for this contract
    @param _hasher the address of MiMC hash contract
    @param _merkleTreeHeight the height of deposits' Merkle Tree
  */
    constructor(
        IVerifier _verifier,
        IDVerifier _depositVerifier,
        IHasher _hasher,
        uint32 _merkleTreeHeight
    ) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) {
        verifier = _verifier;
        depositVerifier = _depositVerifier;
    }

    /**
    @dev Return the entire commitment array
   */
    function commitmentList() public view returns (bytes32[] memory) {
        return allCommitments;
    }

    /**
    @dev Deposit funds into the contract. The caller must send (for ETH) or approve (for ERC20) value equal to or `denomination` of this instance.
    @param _commitment the note commitment, which is PedersenHash(nullifier + secret + msg.value)
    @param _encryptedNote encrypted preimage
  */
    function deposit(bytes32 _commitment, bytes calldata _encryptedNote)
        external
        payable
        nonReentrant
    {
        require(!commitments[_commitment], "already submitted");
        require(
            depositVerifier.verifyProof(_proof, [msg.value]), // This proof is only here to ensure the user doesn't lie about the amount deposited
            "Invalid deposit proof"
        );
        uint32 insertedIndex = _insert(_commitment);
        allCommitments.push(_commitment);
        commitments[_commitment] = true;
        mappedDeposits[msg.sender] = _encryptedNote;
        _processDeposit();

        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    /** @dev this function is defined in a child contract */
    function _processDeposit() internal virtual;

    /**
    @dev Redeem a deposit from the contract. `proof` is a zkSNARK proof data, and input is an array of circuit public inputs
    `input` array consists of:
      - merkle root of all deposits in the contract
      - hash of unique deposit nullifier to prevent double spends
      - the recipient of funds
      - optional fee that goes to the transaction sender (usually a relay)
  */
    function redeem(
        bytes calldata _proof,
        bytes32 _zkid,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _relayer,
        uint256 _fee,
        bytes32 _encryptedBalanceNew
    ) external payable nonReentrant {
        bytes32 _encryptedBalanceOld = identity(_zkid).balance;
        // If we're just initializing the zkID's balance, check balance equality in contract
        if (uint256(_encryptedBalanceOld) == 0) _encryptedBalanceOld = _encryptedBalanceNew; 
        require(
            !nullifierHashes[_nullifierHash],
            "The note has been already spent"
        );
        require(isKnownRoot(_root), "Cannot find your merkle root"); // Make sure to use a recent one
        /*
          Summary of verification circuit:
          - Check the commitment is valid in the tree
          - Decrypt balanceOld and balanceNew using secret key
          - Check that decrypted balanceOld minus fees plus amount is equal to decrypted balanceNew
        */
        require(
            verifier.verifyProof(
                _proof,
                [
                    uint256(_root),
                    uint256(_nullifierHash),
                    uint256(_zkid), // h(secret)
                    uint256(_relayer),
                    _fee, // Make sure user can afford the fee (in-circuit)
                    uint256(_encryptedBalanceOld), // Old encrypted balance
                    uint256(_encryptedBalanceNew) // New encrypted balance
                ]
            ),
            "Invalid withdraw proof"
        );
        nullifierHashes[_nullifierHash] = true;
        _processRedeem(_zkid, _relayer, _fee, _encryptedBalanceNew);
        emit Redeem(_zkid, _nullifierHash, _relayer, _fee);
    }

    /** @dev this function is defined in a child contract */
    function _processRedeem(
        address payable _recipient,
        address payable _relayer,
        uint256 _fee,
        uint256 _refund
    ) internal virtual;

    /** @dev whether a note is already spent */
    function isSpent(bytes32 _nullifierHash) public view returns (bool) {
        return nullifierHashes[_nullifierHash];
    }

    /** @dev whether an array of notes is already spent */
    function isSpentArray(bytes32[] calldata _nullifierHashes)
        external
        view
        returns (bool[] memory spent)
    {
        spent = new bool[](_nullifierHashes.length);
        for (uint256 i = 0; i < _nullifierHashes.length; i++) {
            if (isSpent(_nullifierHashes[i])) {
                spent[i] = true;
            }
        }
    }
}
