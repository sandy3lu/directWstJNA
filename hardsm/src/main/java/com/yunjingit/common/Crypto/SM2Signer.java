package com.yunjingit.common.Crypto;

import com.yunjingit.common.CSMApi;
import com.yunjingit.common.ResponseUtils;
import com.yunjingit.common.SMException;
import com.yunjingit.common.Sm;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;

public class SM2Signer {

    private final SM3Digest digest = new SM3Digest();
    /*Z = SM3(ENTL || ID || a || b || xG || yG || xa || ya)*/
    private byte[] z;
    private byte[] buf = new byte[1024];
    private String ecKey;

    public void init(boolean forSigning, String privKey, String pubkey){
        byte[] userID;
        userID = Hex.decode("31323334353637383132333435363738"); // the default value
        z = getZ(userID, pubkey);

        if (forSigning)
        {
            // private key
            ecKey = privKey;
        }else {
            //public key
            ecKey = pubkey;
        }

        digest.update(z,0,z.length);
    }


    private byte[] getZ(byte[] userID, String pubkey)
    {
        digest.reset();
        byte[] zdata = new byte[1024];
        int len = userID.length * 8;
        zdata[0] = (byte)(len >> 8 & 0xFF);
        zdata[1] = (byte)(len & 0xFF);
        System.arraycopy(userID,0,zdata,2,userID.length);
        int startOff = 2+userID.length;

        X9ECParameters ecParams = CustomNamedCurves.getByName("sm2p256v1");

        startOff = addFieldElement(zdata,startOff,ecParams.getCurve().getA());
        startOff = addFieldElement(zdata,startOff,ecParams.getCurve().getB());
        startOff = addFieldElement(zdata,startOff,ecParams.getG().getAffineXCoord());
        startOff = addFieldElement(zdata,startOff,ecParams.getG().getAffineYCoord());


        digest.update(zdata,0,startOff);
        byte[] result = new byte[digest.getDigestSize()];

        digest.doFinal(zdata, 0);

        return result;
    }

    private int addFieldElement(byte[] buf, int startoff, ECFieldElement v)
    {
        byte[] p = v.getEncoded();
        System.arraycopy(p,0,buf,startoff,p.length);
        return startoff+p.length;
    }




    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }


    public byte[] generateSignature(){

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        String hexHash = ByteUtils.toHexString(result);

        int l = CSMApi.INSTANCE.api_sign(0,0,ecKey.getBytes(),hexHash.getBytes(),buf);
        Sm.Response response = null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            String signature = response.getStrValue().getValue();
            return ByteUtils.fromHexString(signature);
        } catch (SMException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verifySignature(String hexSignature){
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        String hexHash = ByteUtils.toHexString(result);

        int l = CSMApi.INSTANCE.api_verify(0,0,hexSignature.getBytes(),ecKey.getBytes(),hexHash.getBytes(),buf);
        Sm.Response response = null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            int verify  = response.getIntValue().getValue();
            if(verify == 0){
                return true;
            }
        } catch (SMException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean verifySignature(byte[] signature)
    {
        try
        {
            BigInteger[] rs = derDecode(signature);
            if (rs != null)
            {
                return verifySignature(rs[0], rs[1]);
            }
        }
        catch (IOException e)
        {
        }

        return false;
    }

    private boolean verifySignature(BigInteger r, BigInteger s){
        //TODO:
        return false;

    }

    protected BigInteger[] derDecode(byte[] encoding)
            throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2)
        {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] expectedEncoding = derEncode(r, s);
        if (!Arrays.constantTimeAreEqual(expectedEncoding, encoding))
        {
            return null;
        }

        return new BigInteger[]{ r, s };
    }


    protected byte[] derEncode(BigInteger r, BigInteger s)
            throws IOException
    {

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

}
