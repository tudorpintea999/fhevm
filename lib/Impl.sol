// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.13 <0.8.20;

import "./Common.sol";
import "./Precompiles.sol";
import "./FheOps.sol";

library Impl {
    // 32 bytes for the 'byte' header + 16553 bytes of key data.
    uint256 constant fhePubKeySize = 32 + 16553;

    /* A generic logic of calling a precompile is based on the following:
     * 1. Convert all input params to bytes and concatenate them together.
     *  The idea behind this is to be able to be as generic as possible,
     * in the future we can make a single function the will route to the needed logic
     * 2. Call a precompiled contract that implements the interface defined
     * in "FheOps.sol" in a specific address (Precompiles.Fheos)
     * 3. Parse the response and skip the first 32 bytes of header.
     */

    function getValue(bytes memory a) internal pure returns (uint256 value) {
        assembly {
            value := mload(add(a, 0x20))
        }
    }

    function mathHelper(
        uint256 lhs,
        uint256 rhs,
        bool scalar,
        function(bytes memory) external view returns (bytes memory) impl
    ) internal view returns (uint256 result) {
        bytes1 scalarByte;
        if (scalar) {
            scalarByte = 0x01;
        } else {
            scalarByte = 0x00;
        }
        bytes memory input = bytes.concat(bytes32(lhs), bytes32(rhs), scalarByte);

        bytes memory output;
        // Call the add precompile.

        output = impl(input);
        result = getValue(output);
    }

    function add(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        result = mathHelper(lhs, rhs, scalar, FheOps(Precompiles.Fheos).add);
    }

    function sub(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        result = mathHelper(lhs, rhs, scalar, FheOps(Precompiles.Fheos).sub);
    }

    function mul(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        result = mathHelper(lhs, rhs, scalar, FheOps(Precompiles.Fheos).mul);
    }

    function le(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        result = mathHelper(lhs, rhs, scalar, FheOps(Precompiles.Fheos).lte);
    }

    function lt(uint256 lhs, uint256 rhs, bool scalar) internal view returns (uint256 result) {
        result = mathHelper(lhs, rhs, scalar, FheOps(Precompiles.Fheos).lt);
    }

    function req(uint256 ciphertext) internal view {
        bytes memory input = bytes.concat(bytes32(ciphertext));
        uint32 inputLen = 32;

        // Call the optimistic require precompile.
        FheOps(Precompiles.Fheos).req(input);
    }

    function reencrypt(uint256 ciphertext, bytes32 publicKey) internal view returns (bytes memory reencrypted) {
        bytes32[2] memory input;
        input[0] = bytes32(ciphertext);
        input[1] = publicKey;
        uint32 inputLen = 64;

        // Call the reencrypt precompile.
        reencrypted = FheOps(Precompiles.Fheos).reencrypt(bytes.concat(input[0], input[1]));

        return reencrypted;
    }

    function verify(bytes memory _ciphertextBytes, uint8 _toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(_ciphertextBytes, bytes1(_toType));
        uint32 inputLen = uint32(input.length);

        bytes memory output;

        // Call the verify precompile.
        output = FheOps(Precompiles.Fheos).verify(input);
        result = getValue(output);
    }

    function cast(uint256 ciphertext, uint8 toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(bytes32(ciphertext), bytes1(toType));
        uint32 inputLen = uint32(input.length);

        bytes memory output;

        // Call the cast precompile.
        output = FheOps(Precompiles.Fheos).cast(input);
        result = getValue(output);
    }

    function trivialEncrypt(uint256 value, uint8 toType) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(bytes32(value), bytes1(toType));

        bytes memory output;

        // Call the trivialEncrypt precompile.
        output = FheOps(Precompiles.Fheos).trivialEncrypt(input);

        result = getValue(output);
    }

    function cmux(uint256 control, uint256 ifTrue, uint256 ifFalse) internal view returns (uint256 result) {
        bytes memory input = bytes.concat(bytes32(control), bytes32(ifTrue), bytes32(ifFalse));
        uint32 inputLen = uint32(input.length);

        bytes memory output;

        // Call the trivialEncrypt precompile.
        output = FheOps(Precompiles.Fheos).cmux(input);

        result = getValue(output);
    }

    // ============= Based on prev precompiles
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
}
