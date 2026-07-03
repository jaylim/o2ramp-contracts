// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// OpenZeppelin Contracts (last updated v5.1.0) (utils/StorageSlot.sol)
// Trimmed to the Uint256Slot variant used by ReentrancyGuard.
library StorageSlot {
    struct Uint256Slot {
        uint256 value;
    }

    function getUint256Slot(
        bytes32 slot
    ) internal pure returns (Uint256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }
}

// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)
abstract contract ReentrancyGuard {
    using StorageSlot for bytes32;

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_GUARD_STORAGE =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    error ReentrancyGuardReentrantCall();

    constructor() {
        _reentrancyGuardStorageSlot().getUint256Slot().value = NOT_ENTERED;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        if (_reentrancyGuardEntered()) {
            revert ReentrancyGuardReentrantCall();
        }
        _reentrancyGuardStorageSlot().getUint256Slot().value = ENTERED;
    }

    function _nonReentrantAfter() private {
        _reentrancyGuardStorageSlot().getUint256Slot().value = NOT_ENTERED;
    }

    function _reentrancyGuardEntered() internal view returns (bool) {
        return _reentrancyGuardStorageSlot().getUint256Slot().value == ENTERED;
    }

    function _reentrancyGuardStorageSlot()
        internal
        pure
        virtual
        returns (bytes32)
    {
        return REENTRANCY_GUARD_STORAGE;
    }
}

// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/IERC20.sol)
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address to, uint256 value) external returns (bool);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function approve(address spender, uint256 value) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);
}

// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/utils/SafeERC20.sol)
// Trimmed to safeTransfer / safeTransferFrom. The assembly path reverts when the
// token address holds no code (phantom-deposit protection) and on a `false`/non-1
// return, so every token movement in this file is guarded at once.
library SafeERC20 {
    error SafeERC20FailedOperation(address token);

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeCall(token.transferFrom, (from, to, value))
        );
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            let success := call(
                gas(),
                token,
                0,
                add(data, 0x20),
                mload(data),
                0,
                0x20
            )
            if iszero(success) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
            returnSize := returndatasize()
            returnValue := mload(0)
        }

        if (
            returnSize == 0
                ? address(token).code.length == 0
                : returnValue != 1
        ) {
            revert SafeERC20FailedOperation(address(token));
        }
    }
}

// OpenZeppelin Contracts (last updated v5.1.0) (utils/cryptography/MessageHashUtils.sol)
// Trimmed to the EIP-712 typed-data digest used by EIP712._hashTypedDataV4.
library MessageHashUtils {
    function toTypedDataHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"1901")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}

// OpenZeppelin Contracts (last updated v5.1.0) (utils/cryptography/ECDSA.sol).
// Trimmed to the recovery path: rejects upper-range (malleable) s values per
// EIP-2 and reverts on the zero address.
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    error ECDSAInvalidSignature();
    error ECDSAInvalidSignatureLength(uint256 length);
    error ECDSAInvalidSignatureS(bytes32 s);

    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return;
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }

    function tryRecover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address, RecoverError, bytes32) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (
                address(0),
                RecoverError.InvalidSignatureLength,
                bytes32(signature.length)
            );
        }
    }

    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError, bytes32) {
        // EIP-2: reject upper-range (malleable) s values.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    function recover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(
            hash,
            signature
        );
        _throwError(error, errorArg);
        return recovered;
    }
}

// OpenZeppelin Contracts (last updated v5.1.0) (utils/cryptography/EIP712.sol).
// Trimmed to the digest path (no ERC-5267 introspection, no ShortString cache).
// The domain separator binds chainid + this contract address; the struct hash
// (built by the caller) binds every signed field.
abstract contract EIP712 {
    bytes32 private constant TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedThis;

    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;

    constructor(string memory name, string memory version) {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        _hashedName = hashedName;
        _hashedVersion = hashedVersion;
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator(
            hashedName,
            hashedVersion
        );
        _cachedThis = address(this);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        } else {
            return _buildDomainSeparator(_hashedName, _hashedVersion);
        }
    }

    function _buildDomainSeparator(
        bytes32 hashedName,
        bytes32 hashedVersion
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TYPE_HASH,
                    hashedName,
                    hashedVersion,
                    block.chainid,
                    address(this)
                )
            );
    }

    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view returns (bytes32) {
        return
            MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}

// Custom errors (cheaper reverts + smaller bytecode than string reasons).
error NotOwner();
error NoAccessPermission();
error ZeroAddress();
error DepositPaused();
error TokenNotAllowed();
error InvalidAmount();
error DepositExpired();
error NonceUsed();
error InvalidSignature();
error FundAlreadyDistributed();
error SplitAlreadyProcessed();
error EmptyBatch();
error BatchTooLarge();
error LengthMismatch();
error InvalidReceiver();
error InvalidMaxBatch();
error NotAContract();

contract StandardModule {
    using SafeERC20 for IERC20;

    address public owner;

    mapping(address => bool) public access_permission;

    event TransferOwner(address indexed old_owner, address indexed new_owner);
    event UpdateAccessPermission(address indexed _address, bool status);
    event EmergencyCollectToken(address indexed token, uint amount);

    modifier onlyOwner() {
        if (owner != msg.sender) revert NotOwner();
        _;
    }

    modifier hasAccessPermission() {
        if (!access_permission[msg.sender]) revert NoAccessPermission();
        _;
    }

    constructor() {
        owner = msg.sender;
        access_permission[owner] = true;
    }

    /// @notice Transfer ownership; revokes the old owner's operator rights and
    ///         grants them to `new_owner`.
    function transferOwner(address new_owner) external onlyOwner {
        if (new_owner == address(0)) revert ZeroAddress();
        // Clean handover: revoke the outgoing owner's operator rights and grant
        // them to the incoming owner so a former owner keeps no privileged access.
        address old_owner = owner;
        _setAccessPermission(old_owner, false);
        _setAccessPermission(new_owner, true);
        owner = new_owner;
        emit TransferOwner(old_owner, new_owner);
    }

    /// @notice Grant or revoke operator (access permission) rights for an address.
    function updateAccessPermission(
        address _address,
        bool status
    ) external onlyOwner {
        _setAccessPermission(_address, status);
    }

    function _setAccessPermission(address _address, bool status) internal {
        access_permission[_address] = status;
        emit UpdateAccessPermission(_address, status);
    }

    /// @notice Sweep an ERC-20 balance to the owner.
    /// @dev The owner is the full custodian of pooled funds — this can move the
    ///      entire contract balance of `_token`. Deliberate trust assumption, not
    ///      a cap-enforced limit.
    function emergencyCollectToken(
        address _token,
        uint _amount
    ) external onlyOwner {
        IERC20(_token).safeTransfer(owner, _amount);
        emit EmergencyCollectToken(_token, _amount);
    }
}

/// @title DepositCashierV2
/// @notice Custodies ERC-20 deposits authorized by an off-chain EIP-712 signer,
///         and lets operators distribute or split the pooled balance.
/// @dev Operator (access_permission) power over the pooled funds is a deliberate
///      trust assumption, not a cap-enforced limit. See updateAccessPermission.
contract DepositCashierV2 is StandardModule, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct LogInfo {
        uint user_id;
        address buyer;
        address token;
        uint amount;
        uint block_number;
        uint timestamp;
    }

    struct DepositParams {
        uint user_id;
        address token;
        uint amount;
        uint nonce;
        uint exp;
    }

    // Shared by fundDistribute and processSplit (identical shape).
    struct BatchParams {
        uint id;
        address token;
        address[] receiver_addresses;
        uint[] receiver_amounts;
    }

    // EIP-712 struct typehash for a deposit authorization. Field order/names must
    // match the off-chain signer's signTypedData payload exactly.
    bytes32 private constant DEPOSIT_TYPEHASH =
        keccak256(
            "Deposit(address buyer,uint256 user_id,address token,uint256 amount,uint256 nonce,uint256 exp)"
        );

    // id => processed status
    mapping(uint => bool) public is_fund_distributed;

    // id => processed status
    mapping(uint => bool) public is_process_split;

    // log_id => log info
    mapping(uint => LogInfo) private logs;

    // nonce => used (single-use deposit authorizations, replay protection)
    mapping(uint => bool) public used_nonce;

    // token => allowed for deposit (vetted no-fee / non-rebasing tokens only)
    mapping(address => bool) public allowed_token;

    uint public log_id;
    address public signer;
    bool public is_paused;
    // Hard ceiling for max_batch. Keeps a full batch of ERC-20 transfers within
    // the block gas limit even if the owner misconfigures max_batch.
    uint public constant MAX_BATCH_LIMIT = 256;
    uint public max_batch = 10;

    event Deposit(
        uint indexed log_id,
        uint indexed user_id,
        address indexed token,
        address buyer,
        uint amount,
        uint nonce
    );
    event FundDistribute(
        uint indexed id,
        uint indexed block_number,
        uint block_timestamp
    );
    event ProcessSplit(
        uint indexed id,
        uint indexed block_number,
        uint block_timestamp
    );
    event UpdateSigner(address indexed old_signer, address indexed new_signer);
    event UpdateIsPaused(bool status);
    event UpdateMaxBatch(uint max_batch);
    event UpdateAllowedToken(address indexed token, bool status);

    constructor(address _signer) EIP712("DepositCashierV2", "1") {
        if (_signer == address(0)) revert ZeroAddress();
        signer = _signer;
    }

    /// @notice Deposit `params.amount` of an allowlisted token, authorized by an
    ///         off-chain EIP-712 signature from `signer`.
    /// @param params Deposit authorization (user id, token, amount, nonce, expiry).
    /// @param signature EIP-712 signature over the Deposit struct by `signer`.
    function deposit(
        DepositParams calldata params,
        bytes calldata signature
    ) external nonReentrant {
        if (is_paused) revert DepositPaused();
        if (!allowed_token[params.token]) revert TokenNotAllowed();
        if (params.amount == 0) revert InvalidAmount();
        if (params.exp < block.timestamp) revert DepositExpired();
        if (used_nonce[params.nonce]) revert NonceUsed();

        bytes32 structHash = keccak256(
            abi.encode(
                DEPOSIT_TYPEHASH,
                msg.sender,
                params.user_id,
                params.token,
                params.amount,
                params.nonce,
                params.exp
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        if (ECDSA.recover(digest, signature) != signer) {
            revert InvalidSignature();
        }

        // Effects before interaction (CEI): burn the nonce, record the log and
        // bump the counter before pulling tokens, so state stays consistent even
        // if the reentrancy guard is ever removed in a future refactor.
        used_nonce[params.nonce] = true;
        uint id = log_id;
        logs[id] = LogInfo(
            params.user_id,
            msg.sender,
            params.token,
            params.amount,
            block.number,
            block.timestamp
        );
        ++log_id;

        IERC20(params.token).safeTransferFrom(
            msg.sender,
            address(this),
            params.amount
        );

        emit Deposit(
            id,
            params.user_id,
            params.token,
            msg.sender,
            params.amount,
            params.nonce
        );
    }

    /// @notice Distribute the pooled balance to a batch of receivers, once per id.
    /// @param params Batch id, token, and equal-length receiver/amount arrays.
    function fundDistribute(
        BatchParams calldata params
    ) external hasAccessPermission nonReentrant {
        if (is_fund_distributed[params.id]) revert FundAlreadyDistributed();
        is_fund_distributed[params.id] = true;
        _batchTransfer(params);
        emit FundDistribute(params.id, block.number, block.timestamp);
    }

    /// @notice Split the pooled balance to a batch of receivers, once per id.
    /// @param params Batch id, token, and equal-length receiver/amount arrays.
    function processSplit(
        BatchParams calldata params
    ) external hasAccessPermission nonReentrant {
        if (is_process_split[params.id]) revert SplitAlreadyProcessed();
        is_process_split[params.id] = true;
        _batchTransfer(params);
        emit ProcessSplit(params.id, block.number, block.timestamp);
    }

    /// @dev Shared transfer loop for fundDistribute and processSplit. Validates a
    ///      bounded, non-empty, equal-length batch then pays each receiver. The
    ///      processed flag is set by the caller before this runs; any revert here
    ///      rolls it back, so an invalid batch can never consume an id.
    function _batchTransfer(BatchParams calldata params) private {
        uint len = params.receiver_addresses.length;
        if (len == 0) revert EmptyBatch();
        if (len > max_batch) revert BatchTooLarge();
        if (len != params.receiver_amounts.length) revert LengthMismatch();

        for (uint i = 0; i < len; ) {
            if (params.receiver_addresses[i] == address(0)) {
                revert InvalidReceiver();
            }
            if (params.receiver_amounts[i] == 0) revert InvalidAmount();

            IERC20(params.token).safeTransfer(
                params.receiver_addresses[i],
                params.receiver_amounts[i]
            );
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Return the recorded deposit log for `id`.
    function getLogInfo(uint id) external view returns (LogInfo memory) {
        return logs[id];
    }

    /// @notice Set the off-chain authorization signer. Owner only.
    function updateSigner(address _address) external onlyOwner {
        if (_address == address(0)) revert ZeroAddress();
        emit UpdateSigner(signer, _address);
        signer = _address;
    }

    /// @notice Pause or unpause deposits. Operator only.
    function updateIsPaused(bool status) external hasAccessPermission {
        is_paused = status;
        emit UpdateIsPaused(status);
    }

    /// @notice Set the max receivers per distribution/split batch. Owner only.
    function updateMaxBatch(uint _max_batch) external onlyOwner {
        if (_max_batch == 0 || _max_batch > MAX_BATCH_LIMIT) {
            revert InvalidMaxBatch();
        }
        max_batch = _max_batch;
        emit UpdateMaxBatch(_max_batch);
    }

    /// @notice Allow or disallow a token for deposit. Owner only.
    /// @dev Restricting to vetted no-fee / non-rebasing tokens keeps the recorded
    ///      amount equal to the amount actually received.
    function updateAllowedToken(
        address token,
        bool status
    ) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (token.code.length == 0) revert NotAContract();
        allowed_token[token] = status;
        emit UpdateAllowedToken(token, status);
    }
}
