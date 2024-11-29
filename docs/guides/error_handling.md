# **Error Handling**

This document explains how to handle errors effectively in fhEVM smart contracts. Since transactions involving encrypted data do not automatically revert when conditions are not met, developers need alternative mechanisms to communicate errors to users.

## **Challenges in Error Handling**

In the context of encrypted data:

1. **No Automatic Reversion**: Transactions do not revert if a condition fails, making it challenging to notify users of issues like insufficient funds or invalid inputs.
2. **Limited Feedback**: Encrypted computations lack direct mechanisms for exposing failure reasons while maintaining confidentiality.

---

## **Recommended Approach: Error Logging with a Handler**

To address these challenges, implement an **error handler** that records the most recent error for each user. This allows dApps or frontends to query error states and provide appropriate feedback to users.

### **Example Implementation**

For a complete implementation of error handling, see our reference contracts:

- [EncryptedErrors.sol](https://github.com/zama-ai/fhevm-contracts/blob/main/contracts/utils/EncryptedErrors.sol) - Base error handling contract
- [EncryptedERC20WithErrors.sol](https://github.com/zama-ai/fhevm-contracts/blob/main/contracts/token/ERC20/extensions/EncryptedERC20WithErrors.sol) - Example usage in an ERC20 token

The following contract demonstrates how to implement and use an error handler:

```solidity
struct LastError {
  euint8 error;      // Encrypted error code
  uint timestamp;    // Timestamp of the error
}

// Define error codes
euint8 internal NO_ERROR;
euint8 internal NOT_ENOUGH_FUNDS;

constructor() {
  NO_ERROR = TFHE.asEuint8(0);           // Code 0: No error
  NOT_ENOUGH_FUNDS = TFHE.asEuint8(1);   // Code 1: Insufficient funds
}

// Store the last error for each address
mapping(address => LastError) private _lastErrors;

// Event to notify about an error state change
event ErrorChanged(address indexed user);

/**
 * @dev Set the last error for a specific address.
 * @param error Encrypted error code.
 * @param addr Address of the user.
 */
function setLastError(euint8 error, address addr) private {
  _lastErrors[addr] = LastError(error, block.timestamp);
  emit ErrorChanged(addr);
}

/**
 * @dev Internal transfer function with error handling.
 * @param from Sender's address.
 * @param to Recipient's address.
 * @param amount Encrypted transfer amount.
 */
function _transfer(address from, address to, euint32 amount) internal {
  // Check if the sender has enough balance to transfer
  ebool canTransfer = TFHE.le(amount, balances[from]);

  // Log the error state: NO_ERROR or NOT_ENOUGH_FUNDS
  setLastError(TFHE.select(canTransfer, NO_ERROR, NOT_ENOUGH_FUNDS), msg.sender);

  // Perform the transfer operation conditionally
  balances[to] = TFHE.add(balances[to], TFHE.select(canTransfer, amount, TFHE.asEuint32(0)));
  TFHE.allowThis(balances[to]);
  TFHE.allow(balances[to], to);

  balances[from] = TFHE.sub(balances[from], TFHE.select(canTransfer, amount, TFHE.asEuint32(0)));
  TFHE.allowThis(balances[from]);
  TFHE.allow(balances[from], from);
}
```

---

## **How It Works**

1. **Define Error Codes**:

   - `NO_ERROR`: Indicates a successful operation.
   - `NOT_ENOUGH_FUNDS`: Indicates insufficient balance for a transfer.

2. **Record Errors**:

   - Use the `setLastError` function to log the latest error for a specific address along with the current timestamp.
   - Emit the `ErrorChanged` event to notify external systems (e.g., dApps) about the error state change.

3. **Conditional Updates**:

   - Use the `TFHE.select` function to update balances and log errors based on the transfer condition (`canTransfer`).

4. **Frontend Integration**:
   - The dApp can query `_lastErrors` for a user’s most recent error and display appropriate feedback, such as "Insufficient funds" or "Transaction successful."

---

## **Example Error Query**

The frontend or another contract can query the `_lastErrors` mapping to retrieve error details:

```solidity
/**
 * @dev Get the last error for a specific address.
 * @param user Address of the user.
 * @return error Encrypted error code.
 * @return timestamp Timestamp of the error.
 */
function getLastError(address user) public view returns (euint8 error, uint timestamp) {
  LastError memory lastError = _lastErrors[user];
  return (lastError.error, lastError.timestamp);
}
```

---

## **Benefits of This Approach**

1. **User Feedback**:
   - Provides actionable error messages without compromising the confidentiality of encrypted computations.
2. **Scalable Error Tracking**:
   - Logs errors per user, making it easy to identify and debug specific issues.
3. **Event-Driven Notifications**:
   - Enables frontends to react to errors in real time via the `ErrorChanged` event.

---

By implementing error handlers as demonstrated, developers can ensure a seamless user experience while maintaining the privacy and integrity of encrypted data operations.