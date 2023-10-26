// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.13 <0.8.20;

import "./Common.sol";
import "./Precompiles.sol";
import "./FheOps.sol";

library Impl {
    // 32 bytes for the 'byte' type header + 48 bytes for the NaCl anonymous
    // box overhead + 4 bytes for the plaintext value.
    uint256 constant reencryptedSize = 32 + 48 + 4;

    // 32 bytes for the 'byte' header + 16553 bytes of key data.
    uint256 constant fhePubKeySize = 32 + 16553;

    function skipFirst32Bytes(bytes memory data) public pure returns (bytes memory) {
        require(data.length >= 32, "Input data is too short");

        // Create a new bytes variable starting from the 32nd byte
        bytes memory actualData = new bytes(data.length - 32);

        for (uint256 i = 0; i < data.length - 32; i++) {
            actualData[i] = data[i + 32];
        }

        return actualData;
    }

    function getValue(bytes memory a) internal pure returns (uint256 value) {
        assembly {
            value := mload(add(a, 0x20))
        }
    }

    function add(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);
        uint32 inputLen = uint32(input.length);

        bytes memory output;
        // Call the add precompile.

        output = FheOps(Precompiles.Fheos).add(input, inputLen);
        result = getValue(output);
    }

    function sub(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);
        uint32 inputLen = uint32(input.length);

        bytes memory output;
        // Call the sub precompile.

        output = FheOps(Precompiles.Fheos).sub(input, inputLen);
        result = getValue(output);
    }

    function mul(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);
        uint32 inputLen = uint32(input.length);

        bytes memory output;
        // Call the mul precompile.
        output = FheOps(Precompiles.Fheos).mul(input, inputLen);
        result = getValue(output);
    }

    function le(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);
        uint32 inputLen = uint32(input.length);

        bytes memory output;
        // Call the le precompile.
        output = FheOps(Precompiles.Fheos).lte(input, inputLen);
        result = getValue(output);
    }

    function lt(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);
        uint32 inputLen = uint32(input.length);

        bytes memory output;
        // Call the lt precompile.
        output = FheOps(Precompiles.Fheos).lt(input, inputLen);
        result = getValue(output);
    }

    function optReq(uint256 ciphertext) internal view {
        bytes memory input = bytes.concat(bytes32(ciphertext));
        uint32 inputLen = 32;

        // Call the optimistic require precompile.
        FheOps(Precompiles.Fheos).optReq(input, inputLen);
    }

    function bytes32ArrayToBytes(bytes32[2] memory input) public pure returns (bytes memory) {
        bytes memory output = new bytes(64); // 32 bytes per element, 2 elements
        uint256 dest = 0;

        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = 0; j < 32; j++) {
                output[dest] = input[i][j];
                dest++;
            }
        }

        return output;
    }

    function reencrypt(uint256 ciphertext, bytes32 publicKey) internal view returns (bytes memory reencrypted) {
        bytes32[2] memory input;
        input[0] = bytes32(ciphertext);
        input[1] = publicKey;
        uint32 inputLen = 64;

        // Call the reencrypt precompile.
        reencrypted = FheOps(Precompiles.Fheos).reencrypt(bytes32ArrayToBytes(input), inputLen);

        return reencrypted;
    }

    function verify(bytes memory _ciphertextBytes, uint8 _toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(_ciphertextBytes, bytes1(_toType));
        uint32 inputLen = uint32(input.length);

        bytes memory output;

        // Call the verify precompile.
        output = FheOps(Precompiles.Fheos).verify(input, inputLen);
        result = getValue(output);
    }

    function cast(uint256 ciphertext, uint8 toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(bytes32(ciphertext), bytes1(toType));
        uint32 inputLen = uint32(input.length);

        bytes memory output;

        // Call the cast precompile.
        output = FheOps(Precompiles.Fheos).cast(input, inputLen);
        result = getValue(output);
    }

    function trivialEncrypt(uint256 value, uint8 toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(bytes32(value), bytes1(toType));

        bytes memory output;

        // Call the trivialEncrypt precompile.
        output = FheOps(Precompiles.Fheos).trivialEncrypt(input);

        result = getValue(output);
    }

    // ============= Based on prev precompiles
    function decrypt(uint256 ciphertext) internal view returns (uint256 result) {
        bytes32[1] memory input;
        input[0] = bytes32(ciphertext);
        uint256 inputLen = 32;

        bytes32[1] memory output;
        uint256 outputLen = 32;

        // Call the decrypt precompile.
        uint256 precompile = Precompiles.Decrypt;
        assembly {
            if iszero(staticcall(gas(), precompile, input, inputLen, output, outputLen)) {
                revert(0, 0)
            }
        }
        // The output is a 32-byte buffer of a 256-bit big-endian unsigned integer.
        result = uint256(output[0]);
    }

    function fhePubKey() internal view returns (bytes memory key) {
        // Set a byte value of 1 to signal the call comes from the library.
        bytes1[1] memory input;
        input[0] = 0x01;
        uint256 inputLen = 1;

        key = new bytes(fhePubKeySize);

        // Call the fhePubKey precompile.
        uint256 precompile = Precompiles.FhePubKey;
        assembly {
            if iszero(staticcall(gas(), precompile, input, inputLen, key, fhePubKeySize)) {
                revert(0, 0)
            }
        }
    }

    // =============== Not yet implemented in nitro
    function and(uint256, uint256) internal view returns (uint256) {
        return 0;
    }

    function or(uint256, uint256) internal view returns (uint256) {
        return 0;
    }

    function xor(uint256, uint256) internal view returns (uint256) {
        return 0;
    }

    function div(uint256, uint256) internal view returns (uint256) {
        return 0;
    }

    function shl(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function shr(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function eq(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function ne(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function ge(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function gt(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function min(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function max(uint256, uint256, bool) internal view returns (uint256) {
        return 0;
    }

    function neg(uint256) internal view returns (uint256) {
        return 0;
    }

    function not(uint256) internal view returns (uint256) {
        return 0;
    }

    function rand(uint8) internal view returns (uint256) {
        return 0;
    }

    function cmux(uint256, uint256, uint256) internal view returns (uint256) {
        return 0;
    }
}
