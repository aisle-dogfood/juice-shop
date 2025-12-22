// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


interface Token {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract BeeFaucet {
    Token public token = Token(0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13);
    uint8 public balance = 200;
    
    // Per-address accounting to prevent abuse
    mapping(address => uint256) public lastWithdrawTime;
    
    // Withdrawal limits
    uint8 public constant MAX_WITHDRAWAL_PER_REQUEST = 10;
    uint256 public constant COOLDOWN_PERIOD = 1 days;
    
    // Events for transparency
    event Withdrawal(address indexed user, uint8 amount, uint8 remainingBalance);

    function withdraw(uint8 amount) public {
        // Validate amount is non-zero
        require(amount > 0, "Withdrawal amount must be greater than zero");
        
        // Enforce per-request withdrawal limit
        require(amount <= MAX_WITHDRAWAL_PER_REQUEST, "Exceeds maximum withdrawal limit per request");
        
        // Check global balance BEFORE subtracting
        require(amount <= balance, "Insufficient faucet balance");
        
        // Enforce cooldown period
        require(
            block.timestamp >= lastWithdrawTime[msg.sender] + COOLDOWN_PERIOD,
            "Cooldown period has not elapsed. Please wait before withdrawing again"
        );
        
        // Update state before external call (checks-effects-interactions pattern)
        balance -= amount;
        lastWithdrawTime[msg.sender] = block.timestamp;
        
        // Emit event
        emit Withdrawal(msg.sender, amount, balance);
        
        // External call last
        token.transfer(msg.sender, uint256(amount) * 1000000000000000000);
    }

    function getBalance() public view returns (uint8) {
        return balance;
    }
    
    function getLastWithdrawTime(address user) public view returns (uint256) {
        return lastWithdrawTime[user];
    }
    
    function getTimeUntilNextWithdrawal(address user) public view returns (uint256) {
        uint256 nextAllowedTime = lastWithdrawTime[user] + COOLDOWN_PERIOD;
        if (block.timestamp >= nextAllowedTime) {
            return 0;
        }
        return nextAllowedTime - block.timestamp;
    }
}
