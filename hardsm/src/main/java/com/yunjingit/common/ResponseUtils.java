package com.yunjingit.common;

import com.google.protobuf.InvalidProtocolBufferException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.util.Arrays;

public class ResponseUtils {

    public static Sm.Response processResponse(byte[] buf, int length) throws SMException{
        byte[] bs = Arrays.copyOfRange(buf, 0, length);
        Sm.Response response = null;
        try {
            response = Sm.Response.parseFrom(bs);
            parseResponse(response);
            System.out.println( ByteUtils.toHexString(bs) );
            return response;
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void parseResponse(Sm.Response response) throws SMException {
        if (response.getCode() != 0) {
            throw new SMException(response.getCode(), response.getMsg());
        }

    }


}
