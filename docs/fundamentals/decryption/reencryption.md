# Re-encryption

This document explains how to perform re-encryption. Re-encryption is required when you want a user to access their private data without it being exposed to the blockchain.

Re-encryption in fhEVM enables the secure sharing or reuse of encrypted data under a new public key without exposing the plaintext. This feature is essential for scenarios where encrypted data must be transferred between contracts, dApps, or users while maintaining its confidentiality.

{% hint style="info" %}
Before implementing re-encryption, ensure you are familiar with the foundational concepts of encryption, re-encryption and computation. Refer to [Encryption, Decryption, Re-encryption, and Computation](../d_re_ecrypt_compute.md).
{% endhint %}

## When to use re-encryption

Re-encryption is particularly useful for **allowing individual users to securely access and decrypt their private data**, such as balances or counters, while maintaining data confidentiality.

## Overview

The re-encryption process involves retrieving ciphertext from the blockchain and performing re-encryption on the client-side. In other words we take the data that has been encrypted by the KMS, decrypt it and encrypt it with the users private key, so only he can access the information.

This ensures that the data remains encrypted under the blockchain’s FHE key but can be securely shared with a user by re-encrypting it under the user’s NaCl public key.

Re-encryption is facilitated by the **Gateway** and the **Key Management System (KMS)**. The workflow consists of the following:

1. Retrieving the ciphertext from the blockchain using a contract’s view function.
2. Re-encrypting the ciphertext client-side with the user’s public key, ensuring only the user can decrypt it.

## Step 1: retrieve the ciphertext

To retrieve the ciphertext that needs to be re-encrypted, you can implement a view function in your smart contract. Below is an example implementation:

```solidity
import "fhevm/lib/TFHE.sol";

contract ConfidentialERC20 {
  ...
  function balanceOf(account address) public view returns (bytes euint64) {
    return balances[msg.sender];
  }
  ...
}
```

Here, `balanceOf` allows retrieval of the user’s encrypted balance stored on the blockchain.

## Step 2: re-encrypt the ciphertext

Re-encryption is performed client-side using the `fhevmjs` library. [Refer to the guide](../../guides/frontend/webapp.md) to learn how to include `fhevmjs` in your project.
Below is an example of how to implement reencryption in a dApp:

```ts
import { createInstances } from "../instance";
import { getSigners, initSigners } from "../signers";
import abi from "./abi.json";
import { Contract, BrowserProvider } from "ethers";
import { createInstance } from "fhevmjs/bundle";

const CONTRACT_ADDRESS = "";

const provider = new BrowserProvider(window.ethereum);
const accounts = await provider.send("eth_requestAccounts", []);
const USER_ADDRESS = accounts[0];

await initSigners(); // Initialize signers
const signers = await getSigners();

const instance = await createInstances(this.signers);
// Generate the private and public key, used for the reencryption
const { publicKey, privateKey } = instance.generateKeypair();

// Create an EIP712 object for the user to sign.
const eip712 = instance.createEIP712(publicKey, CONTRACT_ADDRESS);

// Request the user's signature on the public key
const params = [USER_ADDRESS, JSON.stringify(eip712)];
const signature = await window.ethereum.request({ method: "eth_signTypedData_v4", params });

// Get the ciphertext to reencrypt
const ConfidentialERC20 = new Contract(CONTRACT_ADDRESS, abi, signer).connect(provider);
const encryptedBalance = ConfidentialERC20.balanceOf(userAddress);

// This function will call the gateway and decrypt the received value with the provided private key
const userBalance = instance.reencrypt(
  encryptedBalance, // the encrypted balance
  privateKey, // the private key generated by the dApp
  publicKey, // the public key generated by the dApp
  signature, // the user's signature of the public key
  CONTRACT_ADDRESS, // The contract address where the ciphertext is
  USER_ADDRESS, // The user address where the ciphertext is
);

console.log(userBalance);
```

This code retrieves the user’s encrypted balance, re-encrypts it with their public key, and decrypts it on the client-side using their private key.

### Key additions to the code

- **`instance.generateKeypair()`**: Generates a public-private keypair for the user.
- **`instance.createEIP712(publicKey, CONTRACT_ADDRESS)`**: Creates an EIP712 object for signing the user’s public key.
- **`instance.reencrypt()`**: Facilitates the re-encryption process by contacting the Gateway and decrypting the data locally with the private key.

## Applying re-encryption to the counter example

Here’s an enhanced **Encrypted Counter** example where each user maintains their own encrypted counter. Re-encryption is used to securely share counter values with individual users.

### Encrypted counter with re-encryption

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import { SepoliaZamaFHEVMConfig } from "fhevm/config/ZamaFHEVMConfig.sol";

/// @title EncryptedCounter4
/// @notice A contract that maintains encrypted counters for each user and is meant for demonstrating how re-encryption works
/// @dev Uses TFHE library for fully homomorphic encryption operations
/// @custom:security Each user can only access and modify their own counter
/// @custom:experimental This contract is experimental and uses FHE technology
contract EncryptedCounter4 is SepoliaZamaFHEVMConfig {
  // Mapping from user address to their encrypted counter value
  mapping(address => euint8) private counters;

  function incrementBy(einput amount, bytes calldata inputProof) public {
    // Initialize counter if it doesn't exist
    if (!TFHE.isInitialized(counters[msg.sender])) {
      counters[msg.sender] = TFHE.asEuint8(0);
    }

    // Convert input to euint8 and add to sender's counter
    euint8 incrementAmount = TFHE.asEuint8(amount, inputProof);
    counters[msg.sender] = TFHE.add(counters[msg.sender], incrementAmount);
    TFHE.allowThis(counters[msg.sender]);
    TFHE.allow(counters[msg.sender], msg.sender);
  }

  function getCounter() public view returns (euint8) {
    // Return the encrypted counter value for the sender
    return counters[msg.sender];
  }
}
```

### Frontend code of re-encryption / tests for EncryptedCounter4

Here’s a sample test to verify re-encryption functionality:

```ts
import { createInstance } from "../instance";
import { reencryptEuint8 } from "../reencrypt";
import { getSigners, initSigners } from "../signers";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("EncryptedCounter4", function () {
  before(async function () {
    await initSigners(); // Initialize signers
    this.signers = await getSigners();
  });

  beforeEach(async function () {
    const CounterFactory = await ethers.getContractFactory("EncryptedCounter4");
    this.counterContract = await CounterFactory.connect(this.signers.alice).deploy();
    await this.counterContract.waitForDeployment();
    this.contractAddress = await this.counterContract.getAddress();
    this.instances = await createInstance();
  });

  it("should allow reencryption and decryption of counter value", async function () {
    const input = this.instances.createEncryptedInput(this.contractAddress, this.signers.alice.address);
    input.add8(1); // Increment by 1 as an example
    const encryptedAmount = await input.encrypt();

    // Call incrementBy with encrypted amount
    const tx = await this.counterContract.incrementBy(encryptedAmount.handles[0], encryptedAmount.inputProof);
    await tx.wait();

    // Get the encrypted counter value
    const encryptedCounter = await this.counterContract.getCounter();

    const decryptedValue = await reencryptEuint8(
      this.signers,
      this.instances,
      "alice",
      encryptedCounter,
      this.contractAddress,
    );

    // Verify the decrypted value is 1 (since we incremented once)
    expect(decryptedValue).to.equal(1);
  });

  it("should allow reencryption of counter value", async function () {
    const input = this.instances.createEncryptedInput(this.contractAddress, this.signers.bob.address);
    input.add8(1); // Increment by 1 as an example
    const encryptedAmount = await input.encrypt();

    // Call incrementBy with encrypted amount
    const tx = await this.counterContract
      .connect(this.signers.bob)
      .incrementBy(encryptedAmount.handles[0], encryptedAmount.inputProof);
    await tx.wait();

    // Get the encrypted counter value
    const encryptedCounter = await this.counterContract.connect(this.signers.bob).getCounter();

    const decryptedValue = await reencryptEuint8(
      this.signers,
      this.instances,
      "bob",
      encryptedCounter,
      this.contractAddress,
    );

    // Verify the decrypted value is 1 (since we incremented once)
    expect(decryptedValue).to.equal(1);
  });
});
```

#### Key additions in testing

- **`setupReencryption():`** Prepares the re-encryption process by generating keys and a signature for the user.
- **`instance.reencrypt():`** Facilitates re-encryption and local decryption of the data for testing purposes.
- **Validation:** Confirms that the decrypted counter matches the expected value.
