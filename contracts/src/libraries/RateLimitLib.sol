// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Token bucket. Capacity C refills continuously at `refillPerSecond`.
///   Guarantee (invariant I1): total consumed over any span T never exceeds C + refill*T,
///   and a single burst never exceeds C. Unlike a fixed window there is no 2x boundary burst.
library RateLimitLib {
    struct Bucket {
        uint128 capacity;
        uint128 refillPerSecond;
        uint128 available; // value at `lastUpdated`
        uint64 lastUpdated;
        bool enabled;
    }

    /// @dev Spendable amount right now. Disabled buckets have nothing.
    function current(Bucket storage b) internal view returns (uint256) {
        if (!b.enabled) return 0;
        // lastUpdated <= block.timestamp always; elapsed < 2^64 and refill < 2^128 so no overflow
        uint256 elapsed = block.timestamp - uint256(b.lastUpdated);
        uint256 v = uint256(b.available) + elapsed * uint256(b.refillPerSecond);
        return v > b.capacity ? b.capacity : v;
    }

    /// @return ok false if disabled or amount exceeds what is available (state untouched)
    function tryConsume(Bucket storage b, uint256 amount) internal returns (bool ok, uint256 availableNow) {
        availableNow = current(b);
        if (!b.enabled || amount > availableNow) return (false, availableNow);
        // amount <= availableNow <= capacity <= uint128.max, so the cast is safe
        b.available = uint128(availableNow - amount);
        b.lastUpdated = uint64(block.timestamp);
        return (true, availableNow);
    }

    /// @dev Reconfigure. Existing balance is synced under the OLD config first, then clamped
    ///      to the new capacity. A bucket that is newly enabled starts full.
    function configure(Bucket storage b, uint128 capacity, uint128 refillPerSecond, bool enabled) internal {
        bool wasEnabled = b.enabled;
        uint256 cur = wasEnabled ? current(b) : 0;
        b.capacity = capacity;
        b.refillPerSecond = refillPerSecond;
        b.enabled = enabled;
        uint256 next = (!wasEnabled && enabled) ? capacity : (cur > capacity ? capacity : cur);
        b.available = uint128(next);
        b.lastUpdated = uint64(block.timestamp);
    }
}
