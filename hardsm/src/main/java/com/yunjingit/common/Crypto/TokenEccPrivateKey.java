package com.yunjingit.common.Crypto;

import com.yunjingit.common.Sm;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class TokenEccPrivateKey implements ECPrivateKey {
    static final int SMMA_ECC_FP_256_PUBLIC_KEY_LEN = 32 * 2;
    static final int SMMA_ECC_FP_256_PRIVATE_KEY_LEN = 32;

    @Override
    public BigInteger getS() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    @Override
    public ECParameterSpec getParams() {
        return null;
    }

    TokenEccPrivateKey(Sm.KeyPair keyPair){

    }
}
