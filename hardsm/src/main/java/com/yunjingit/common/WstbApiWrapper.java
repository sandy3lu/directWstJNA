package com.yunjingit.common;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public interface WstbApiWrapper extends Library{

    WstbApiWrapper INSTANCE = (WstbApiWrapper) Native.loadLibrary("yjsmwst", com.yunjingit.common.WstbApiWrapper.class);


    /**
     * K12. SM_GenerateKeyPair<br>
     * Original signature : <code>SM_RV SM_GenerateKeyPair(SM_PIPE_HANDLE, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE)</code><br>
     * @param hPipe in<br>
     * @param phPublicKey out<br>
     * @param phPrivateKey out<br>
     * <i>native declaration : sm_api.h:1588</i>
     */
    int generate_keypair_wrapper(Pointer hPipe,  PointerByReference phPublicKey,
                           PointerByReference phPrivateKey);
}
