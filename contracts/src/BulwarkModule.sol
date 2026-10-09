// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {MerkleLib} from "./libraries/MerkleLib.sol";
import {RateLimitLib} from "./libraries/RateLimitLib.sol";

/// @title BulwarkModule
/// @notice Safe module that is the ONLY path an AI agent's session key has to the treasury.
///         The agent is treated as hostile: it can only ask for (a) an ERC-20 transfer to an
///         allowlisted recipient or (b) an exact ERC-20 approval to an allowed spender,
///         both inside a token-bucket spend limit. The module builds the calldata itself,
///         so there is no agent-supplied calldata to decode or smuggle through.
///
/// Authority model (asymmetric):
///   - TIGHTENING (lower limits, remove access, pause) is immediate.
///   - LOOSENING (raise limits, add recipients/spenders/session keys) is queued and only
///     takes effect after `loosenDelay`, giving the guardian time to cancel.
///   - Guardian can ONLY pause, cancel queued loosening, and revoke session keys.
///
/// Security assumptions are documented in docs/threat-model.md. Non-goals: compromise of the
/// Safe owners, bugs in Safe itself.
contract BulwarkModule {
    using RateLimitLib for RateLimitLib.Bucket;

    // ───────────────────────────── types ─────────────────────────────
    enum Kind {
        TRANSFER,
        APPROVE
    }

    /// @dev Loosening operations (each goes through queue -> delay -> applyPending).
    enum Op {
        SET_TOKEN_LIMIT, // (address token, uint128 capacity, uint128 refillPerSecond, bool enabled)
        SET_ALLOWLIST_ROOT, // (bytes32 root)
        SET_SPENDER, // (address spender, bool allowed)
        ADD_SESSION, // (address key, uint64 expiresAt, uint32 minInterval)
        SET_MAX_APPROVE // (address token, uint256 max)
    }

    struct Session {
        uint64 expiresAt;
        uint64 lastExec;
        uint32 minInterval;
        bool active;
    }

    // ─────────────────────────── immutables ───────────────────────────
    ISafe public immutable safe;
    uint64 public immutable loosenDelay;

    uint64 public constant MAX_SESSION_DURATION = 7 days;
    uint64 public constant MAX_DEADLINE_WINDOW = 1 hours;
    uint64 public constant QUEUE_GRACE = 30 days; // queued op becomes stale after eta + grace

    // ───────────────────────────── state ─────────────────────────────
    address public guardian;
    bool public paused;
    bool public killed;
    bytes32 public allowlistRoot;

    mapping(address token => RateLimitLib.Bucket) internal _buckets;
    mapping(address spender => bool) public allowedSpender;
    mapping(address token => uint256) public maxApprove;
    mapping(address key => Session) public sessions;
    mapping(bytes32 id => uint64 eta) public pendingAt;
    mapping(bytes32 intentHash => bool) public usedIntent;

    uint256 private _lock = 1;

    // ───────────────────────────── events ─────────────────────────────
    event Executed(
        bytes32 indexed intentHash,
        address indexed sessionKey,
        Kind kind,
        address indexed token,
        address counterparty,
        uint256 amount,
        uint256 bucketAfter
    );
    event LooseningQueued(bytes32 indexed id, Op op, uint64 eta);
    event LooseningApplied(bytes32 indexed id, Op op);
    event LooseningCancelled(bytes32 indexed id, address indexed by);
    event TokenTightened(address indexed token, uint128 capacity, uint128 refillPerSecond, bool enabled);
    event AllowlistCleared();
    event SpenderRemoved(address indexed spender);
    event MaxApproveLowered(address indexed token, uint256 max);
    event SessionRevoked(address indexed key, address indexed by);
    event GuardianSet(address indexed guardian);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event Killed(address indexed by);

    // ───────────────────────────── errors ─────────────────────────────
    error NotSafe();
    error NotGuardianOrSafe();
    error NotSessionKey();
    error SessionExpired();
    error ModulePaused();
    error ModuleKilled();
    error DeadlinePassed();
    error DeadlineTooFar();
    error CooldownActive();
    error IntentReplayed();
    error ZeroAmount();
    error BadCounterparty();
    error TokenDisabledOrBucketExceeded(uint256 requested, uint256 available);
    error RecipientNotAllowed();
    error SpenderNotAllowed();
    error ApproveTooLarge();
    error AllowanceNotZero();
    error CallFailed();
    error CallReturnedFalse();
    error PostConditionFailed();
    error Reentrancy();
    error AlreadyQueued();
    error NotQueued();
    error DelayNotElapsed();
    error QueuedOpStale();
    error NotATightening();
    error BadParams();

    // ─────────────────────────── modifiers ───────────────────────────
    modifier onlySafe() {
        if (msg.sender != address(safe)) revert NotSafe();
        _;
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(address safe_, address guardian_, uint64 loosenDelay_) {
        if (safe_ == address(0)) revert BadParams();
        safe = ISafe(safe_);
        guardian = guardian_;
        loosenDelay = loosenDelay_;
        emit GuardianSet(guardian_);
    }

    // ═════════════════════════════ EXECUTION ═════════════════════════════

    /// @notice Called by an agent session key (via the signer service) to move value.
    /// @param kind          TRANSFER or APPROVE
    /// @param token         ERC-20 held by the Safe
    /// @param to            recipient (TRANSFER, must be allowlisted) or spender (APPROVE, must be allowed)
    /// @param amount        base units; charged against the token's bucket in both cases
    /// @param proof         Merkle proof for `to` (TRANSFER only)
    /// @param deadline      unix seconds; must be within MAX_DEADLINE_WINDOW of now
    /// @param intentHash    unique id binding this tx to an off-chain intent (replay protection)
    function execute(
        Kind kind,
        address token,
        address to,
        uint256 amount,
        bytes32[] calldata proof,
        uint64 deadline,
        bytes32 intentHash
    ) external nonReentrant {
        if (killed) revert ModuleKilled();
        if (paused) revert ModulePaused();
        if (amount == 0) revert ZeroAmount();
        if (to == address(0) || to == address(safe) || to == address(this)) revert BadCounterparty();

        // ── effects (before any external call) ──
        _checkAndTouchSession(deadline, intentHash);
        uint256 availBefore = _charge(token, amount);

        // ── build calldata on-chain from validated fields ──
        bytes memory data = _buildCall(kind, token, to, amount, proof);

        // ── interaction ──
        uint256 balBefore = IERC20(token).balanceOf(address(safe));
        _callThroughSafe(token, data);

        // ── post-conditions: what actually happened must match what was charged ──
        _postCheck(kind, token, to, amount, balBefore);

        emit Executed(intentHash, msg.sender, kind, token, to, amount, availBefore - amount);
    }

    function _checkAndTouchSession(uint64 deadline, bytes32 intentHash) private {
        Session storage s = sessions[msg.sender];
        if (!s.active) revert NotSessionKey();
        if (block.timestamp >= s.expiresAt) revert SessionExpired();
        if (block.timestamp > deadline) revert DeadlinePassed();
        if (deadline > block.timestamp + MAX_DEADLINE_WINDOW) revert DeadlineTooFar();
        if (block.timestamp < uint256(s.lastExec) + uint256(s.minInterval)) revert CooldownActive();
        if (intentHash == bytes32(0) || usedIntent[intentHash]) revert IntentReplayed();
        usedIntent[intentHash] = true;
        s.lastExec = uint64(block.timestamp);
    }

    function _charge(address token, uint256 amount) private returns (uint256 availBefore) {
        bool ok;
        (ok, availBefore) = _buckets[token].tryConsume(amount);
        if (!ok) revert TokenDisabledOrBucketExceeded(amount, availBefore);
    }

    function _buildCall(Kind kind, address token, address to, uint256 amount, bytes32[] calldata proof)
        private
        view
        returns (bytes memory)
    {
        if (kind == Kind.TRANSFER) {
            if (!MerkleLib.verify(proof, allowlistRoot, MerkleLib.leaf(to))) revert RecipientNotAllowed();
            return abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
        }
        if (!allowedSpender[to]) revert SpenderNotAllowed();
        if (amount > maxApprove[token]) revert ApproveTooLarge();
        // forbid stacking / approve-race: allowance must be zero before a new nonzero approval
        if (IERC20(token).allowance(address(safe), to) != 0) revert AllowanceNotZero();
        return abi.encodeWithSelector(IERC20.approve.selector, to, amount);
    }

    function _callThroughSafe(address token, bytes memory data) private {
        // operation 0 = CALL. DELEGATECALL (1) is never used: it would let a target rewrite Safe storage.
        (bool success, bytes memory ret) = safe.execTransactionFromModuleReturnData(token, 0, data, 0);
        if (!success) revert CallFailed();
        if (ret.length != 0) {
            // accept both "no return value" tokens and standard `true`; reject `false` / garbage
            if (ret.length != 32 || abi.decode(ret, (uint256)) != 1) revert CallReturnedFalse();
        }
    }

    function _postCheck(Kind kind, address token, address to, uint256 amount, uint256 balBefore) private view {
        uint256 balAfter = IERC20(token).balanceOf(address(safe));
        if (kind == Kind.TRANSFER) {
            if (balAfter > balBefore || balBefore - balAfter > amount) revert PostConditionFailed();
        } else {
            if (balAfter < balBefore) revert PostConditionFailed(); // an approve must not move funds
            if (IERC20(token).allowance(address(safe), to) != amount) revert PostConditionFailed();
        }
    }

    // ═════════════════════════ LOOSENING (queued) ═════════════════════════

    /// @param data abi.encode(Op op, bytes args) - see the Op enum for each args layout
    function queue(bytes calldata data) external onlySafe returns (bytes32 id) {
        (Op op,) = abi.decode(data, (Op, bytes)); // reverts on an invalid enum value
        id = keccak256(data);
        if (pendingAt[id] != 0) revert AlreadyQueued();
        uint64 eta = uint64(block.timestamp) + loosenDelay;
        pendingAt[id] = eta;
        emit LooseningQueued(id, op, eta);
    }

    /// @notice Anyone may finalize a queued change once the delay has passed.
    function applyPending(bytes calldata data) external {
        bytes32 id = keccak256(data);
        uint64 eta = pendingAt[id];
        if (eta == 0) revert NotQueued();
        if (block.timestamp < eta) revert DelayNotElapsed();
        if (block.timestamp > uint256(eta) + QUEUE_GRACE) revert QueuedOpStale();
        delete pendingAt[id];

        (Op op, bytes memory args) = abi.decode(data, (Op, bytes));
        if (op == Op.SET_TOKEN_LIMIT) {
            (address token, uint128 cap, uint128 refill, bool enabled) =
                abi.decode(args, (address, uint128, uint128, bool));
            if (token == address(0)) revert BadParams();
            _buckets[token].configure(cap, refill, enabled);
        } else if (op == Op.SET_ALLOWLIST_ROOT) {
            allowlistRoot = abi.decode(args, (bytes32));
        } else if (op == Op.SET_SPENDER) {
            (address spender, bool allowed) = abi.decode(args, (address, bool));
            if (spender == address(0)) revert BadParams();
            allowedSpender[spender] = allowed;
        } else if (op == Op.ADD_SESSION) {
            (address key, uint64 expiresAt, uint32 minInterval) = abi.decode(args, (address, uint64, uint32));
            if (key == address(0) || expiresAt <= block.timestamp) revert BadParams();
            if (expiresAt > block.timestamp + MAX_SESSION_DURATION) revert BadParams();
            sessions[key] = Session({expiresAt: expiresAt, lastExec: 0, minInterval: minInterval, active: true});
        } else {
            // Op.SET_MAX_APPROVE
            (address token, uint256 max) = abi.decode(args, (address, uint256));
            if (token == address(0)) revert BadParams();
            maxApprove[token] = max;
        }
        emit LooseningApplied(id, op);
    }

    function cancelPending(bytes32 id) external {
        if (msg.sender != address(safe) && !_isGuardian(msg.sender)) revert NotGuardianOrSafe();
        if (pendingAt[id] == 0) revert NotQueued();
        delete pendingAt[id];
        emit LooseningCancelled(id, msg.sender);
    }

    // ═════════════════════════ TIGHTENING (immediate) ═════════════════════════

    /// @notice Lower a token's limits and/or disable it. Cannot raise anything or enable.
    function tightenToken(address token, uint128 capacity, uint128 refillPerSecond, bool enabled) external onlySafe {
        RateLimitLib.Bucket storage b = _buckets[token];
        if (capacity > b.capacity || refillPerSecond > b.refillPerSecond) revert NotATightening();
        if (enabled && !b.enabled) revert NotATightening();
        b.configure(capacity, refillPerSecond, enabled);
        emit TokenTightened(token, capacity, refillPerSecond, enabled);
    }

    function clearAllowlist() external onlySafe {
        allowlistRoot = bytes32(0);
        emit AllowlistCleared();
    }

    function removeSpender(address spender) external onlySafe {
        allowedSpender[spender] = false;
        emit SpenderRemoved(spender);
    }

    function lowerMaxApprove(address token, uint256 max) external onlySafe {
        if (max > maxApprove[token]) revert NotATightening();
        maxApprove[token] = max;
        emit MaxApproveLowered(token, max);
    }

    function revokeSession(address key) external {
        if (msg.sender != address(safe) && !_isGuardian(msg.sender)) revert NotGuardianOrSafe();
        sessions[key].active = false;
        emit SessionRevoked(key, msg.sender);
    }

    // ═════════════════════════ EMERGENCY / ADMIN ═════════════════════════

    function pause() external {
        if (msg.sender != address(safe) && !_isGuardian(msg.sender)) revert NotGuardianOrSafe();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlySafe {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Irreversible. Redeploy a new module to resume.
    function kill() external onlySafe {
        killed = true;
        emit Killed(msg.sender);
    }

    /// @dev Safe to change immediately: the guardian can only make things stricter.
    function setGuardian(address newGuardian) external onlySafe {
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
    }

    // ═════════════════════════════ VIEWS ═════════════════════════════

    function bucketOf(address token)
        external
        view
        returns (uint128 capacity, uint128 refillPerSecond, uint256 availableNow, bool enabled)
    {
        RateLimitLib.Bucket storage b = _buckets[token];
        return (b.capacity, b.refillPerSecond, b.current(), b.enabled);
    }

    function _isGuardian(address who) private view returns (bool) {
        return guardian != address(0) && who == guardian;
    }
}
