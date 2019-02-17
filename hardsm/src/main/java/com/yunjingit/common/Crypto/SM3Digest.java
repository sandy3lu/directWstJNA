package com.yunjingit.common.Crypto;

import com.yunjingit.common.CSMApi;
import com.yunjingit.common.ResponseUtils;
import com.yunjingit.common.SMException;
import com.yunjingit.common.Sm;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.util.Arrays;

public class SM3Digest {

    private static final int DIGEST_LENGTH = 32;   // bytes
    private static final int BLOCK_SIZE = 64;
    private TokenContext tokenContext;
    private byte[] buf = new byte[1024];
    private byte[] content = new byte[BLOCK_SIZE];
    private int vaildContent = 0;

    private boolean mock = false;

    /**
     * Standard constructor
     */
    public SM3Digest()
    {

        tokenContext = new TokenContext(0,0);
        reset();

    }

    public SM3Digest(TokenContext tokenContext)
    {

        this.tokenContext = tokenContext;
        reset();

    }

    public SM3Digest(boolean mock)
    {

        tokenContext = new TokenContext(0,0);
        this.mock = mock;
        reset();

    }

    public void setMock(boolean mock){
        this.mock = mock;
    }

    public void reset(){
        if(mock){
            return;
        }

        int l = CSMApi.INSTANCE.api_digest_init(tokenContext.getDeviceIndex(),tokenContext.getPipeIndex(),buf);
        try {
            ResponseUtils.processResponse(buf,l);
        } catch (SMException e) {
            e.printStackTrace();
        }
    }

    public String getAlgorithmName()
    {
        return "SM3";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }


    public void update(
            byte[]  in,
            int     inOff,
            int     len){

        if(len + vaildContent > content.length) {
            int totallen = len + vaildContent;
            int blocks = totallen % BLOCK_SIZE;
            byte[] tmp = new byte[blocks * BLOCK_SIZE];
            int left = totallen - blocks*BLOCK_SIZE;

            System.arraycopy(content,0,tmp,0,vaildContent);
            System.arraycopy(in,inOff,tmp,vaildContent,tmp.length - vaildContent);
            System.arraycopy(in,inOff + tmp.length - vaildContent,content,0,left);
            vaildContent = left;

            if(mock){
                return;
            }

            int l = CSMApi.INSTANCE.api_digest_update(tokenContext.getDeviceIndex(), tokenContext.getPipeIndex(), tmp, tmp.length, buf);
            try {
                ResponseUtils.processResponse(buf, l);
            } catch (SMException e) {
                e.printStackTrace();
            }

        }else{
            // only fill the content
            System.arraycopy(in,inOff,content,vaildContent,len);
            vaildContent = vaildContent + len;
        }
    }

    public int doFinal(byte[] out,
                       int outOff)
    {
        if(mock){
            System.arraycopy(tokenContext, 0, out, outOff,DIGEST_LENGTH);
            return vaildContent;
        }

        int l = CSMApi.INSTANCE.api_digest_final(tokenContext.getDeviceIndex(),tokenContext.getPipeIndex(),content,vaildContent,buf);
        Sm.Response response= null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            String result = response.getStrValue().getValue();
            byte[] data =ByteUtils.fromHexString(result);
            System.arraycopy(data, 0, out, outOff,data.length);
            reset();
        } catch (SMException e) {
            e.printStackTrace();
        }


        return DIGEST_LENGTH;
    }

}
