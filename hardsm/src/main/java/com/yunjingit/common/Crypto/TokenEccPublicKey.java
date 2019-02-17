package com.yunjingit.common.Crypto;

import com.yunjingit.common.Sm;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.util.encoders.Hex;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class TokenEccPublicKey implements ECPublicKey {
    private org.bouncycastle.math.ec.ECPoint q;
    private SM2P256V1Curve c = new SM2P256V1Curve();
    private X9ECPoint G = new X9ECPoint(c, Hex.decode("04"
            + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
            + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));

    private ECParameterSpec         ecSpec;// = new ECParameterSpec( )//("sm2p256v1");

    @Override
    public ECPoint getW() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }


    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    @Override
    public ECParameterSpec getParams() {
        return null;
    }

    public TokenEccPublicKey(Sm.KeyPair keyPair){
        String key =keyPair.getPublicKey();


    }
}
