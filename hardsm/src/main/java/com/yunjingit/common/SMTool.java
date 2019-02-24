package com.yunjingit.common;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;


public class SMTool {

    public static void main( String[] args ) {

		Native.setProtected(true);
		System.out.println("Native.isProtected = " +Native.isProtected());

        //最大可用内存，对应-Xmx
        System.out.printf("maxMemory = %x , freeMemory = %x, totalMemory = %x\n",Runtime.getRuntime().maxMemory(),
                Runtime.getRuntime().freeMemory(),Runtime.getRuntime().totalMemory()) ;

        if(!WstbManager.init()){
            return;
        }
        String password = "11111111";
        if(!WstbManager.login(0,password,0)){
            return;
        }
        for(int i=0;i<1;i++) {
            System.out.printf("---- getRandom  %d  times -----\n", i);
            byte[] data = WstbManager.getRandom(0, 8);
        }

        byte[] plaindata = new byte[]{'a','b','c'};
        String expect = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

        byte[] digest = null;
        for(int i=0;i<1;i++) {
            System.out.printf("---- getSM3Digest %d  times -----\n", i);
            digest = WstbManager.getSM3Digest(0, plaindata);
            if (!expect.equals(ByteUtils.toHexString(digest))) {
                System.out.println("Digest FAILED " + expect);
            }
        }
        byte[] key= null;
        for(int i=0;i<1;i++) {
            System.out.printf("---- generateSM4Key %d  times -----\n", i);
            key = WstbManager.generateSM4Key(0);
        }

        String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
        for(int i=0;i<1;i++) {
            System.out.printf("---- sm4Enc %d  times -----\n", i);
            byte[] data = WstbManager.sm4Enc(true, 0, key, origin_data.getBytes());
            byte[] tmp = WstbManager.sm4Enc(false, 0, key, data);
            if (!Arrays.equals(origin_data.getBytes(), tmp)) {
                System.out.println("SM4 FAILED ");
            }
        }

        byte[] keys = WstbManager.generateSM2Key(0);
        byte[] privkey = Arrays.copyOfRange(keys,0,WstbApi.SMMA_ECC_FP_256_PRIVATE_KEY_LEN);
        byte[] pubkey = Arrays.copyOfRange(keys,WstbApi.SMMA_ECC_FP_256_PRIVATE_KEY_LEN,keys.length);

        byte[] sig = WstbManager.sm2Sign(0,privkey,digest);
        if(WstbManager.sm2Verify(0,pubkey,digest,sig)){
            System.out.println("SM2 sign and verify OK!");
        }else{
            System.out.println("SM2 sign and verify Failed!");
        }

        byte[] cipher = WstbManager.sm2Enc(true,0,pubkey,digest);
        System.out.printf("cipher %s\n",ByteUtils.toHexString(cipher));
        byte[] plain = WstbManager.sm2Enc(false,0,privkey,cipher);
        if(Arrays.equals(plain,digest)){
            System.out.println("SM2 end and dec OK!");
        }else {
            System.out.println("SM2 end and dec Failed!");
            System.out.printf("plain  %s\n", ByteUtils.toHexString(plain));
            System.out.printf("expect %s\n", ByteUtils.toHexString(digest));
        }

        for(int i=0;i<15;i++) {
            System.out.printf("---- %d  times -----\n", i);
            testSM2Perform(digest);
        }

        boolean ret = WstbManager.release();
        System.out.println("release " + ret);

        System.out.println("-------finish ----------");
    }


    private static void testSM2Perform(byte[] digest){
        byte[] keys = WstbManager.generateSM2Key(0);
        byte[] privkey = Arrays.copyOfRange(keys,0,WstbApi.SMMA_ECC_FP_256_PRIVATE_KEY_LEN);
        byte[] pubkey = Arrays.copyOfRange(keys,WstbApi.SMMA_ECC_FP_256_PRIVATE_KEY_LEN,keys.length);

        byte[] sig=new byte[]{0};
        int count = 2000;
        long startTime = System.currentTimeMillis();
        for(int i=0; i<count;i++) {
            sig = WstbManager.sm2Sign(0, privkey, digest);
        }
        long endTime = System.currentTimeMillis();
        System.out.printf("SM2 only sign : %d ms ( %d )\n", endTime - startTime, count);

        startTime = System.currentTimeMillis();
        for(int i=0; i<count;i++) {
            if (!WstbManager.sm2Verify(0, pubkey, digest, sig)) {
                System.out.println("SM2 verify Failed!");
            }
        }
        endTime = System.currentTimeMillis();
        System.out.printf("SM2 only verify : %d ms ( %d )\n", endTime - startTime, count);
    }

    private static void testSM4(PointerByReference pipeHandle, PointerByReference hKey, WstbApi.SM_ALGORITHM.ByReference algo) {
        int result;
        String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
        ByteBuffer in_bb = ByteBuffer.wrap(origin_data.getBytes());
        byte[] outdata = new byte[origin_data.length()];
        ByteBuffer out_data = ByteBuffer.wrap(outdata);
        IntBuffer outLen = IntBuffer.allocate(1);

        WstbApi.SM_BLOB_KEY.ByReference keyblob = new WstbApi.SM_BLOB_KEY.ByReference();
        keyblob.uiDataLen = 8;
        keyblob.pbyData = hKey.getPointer();
        System.out.printf("SM4 keyHandle = %x\n" ,Pointer.nativeValue(hKey.getValue()));
        result = WstbApi.INSTANCE.SM_Encrypt(pipeHandle.getValue(),keyblob,algo,0,in_bb,origin_data.length(),out_data,outLen);
        if (result == WstbApi.SM_ERR_FREE) {
            int outlen = outLen.get();
            System.out.printf("SM_Encrypt  %s  , length =%d\n" , ByteUtils.toHexString(outdata), outlen);
            result = WstbApi.INSTANCE.SM_Decrypt(pipeHandle.getValue(),keyblob,algo,0,out_data,outlen ,in_bb,outLen);
            if (result == WstbApi.SM_ERR_FREE) {
                byte[] tmp = in_bb.array();
                System.out.printf("SM_Decrypt  %s, length = %d \n" , new String(tmp), tmp.length);

            }else{
                System.out.printf("SM_Decrypt error %d\n", result);
            }
        }else{
            System.out.printf("SM_Encrypt error %d\n", result);
        }
    }


    static WstbApi.SM_ALGORITHM g_mac_algorithm;
    static byte[] g_byiv = new byte[WstbApi.SMMA_ALG34_IV_LEN];

        static void init_mac_algorithm() {

            g_mac_algorithm.AlgoType = WstbApi.SMM_ALG35_MAC;
            //g_mac_algorithm.pParameter = new Pointer(g_byiv);
            g_mac_algorithm.uiParameterLen = WstbApi.SMMA_ALG34_IV_LEN;
        }


//    private static boolean loginDevice(byte[] normal_buf) {
//        int i;
//        System.out.println("---api_init");
//        Sm.Response response = null;
//        i = CSMApi.INSTANCE.api_init(normal_buf);
//        try {
//            ResponseUtils.processResponse(normal_buf,i);
//        } catch (SMException e) {
//
//            return true;
//        }
//
//        System.out.println("---api_ctx_info");
//        i = CSMApi.INSTANCE.api_ctx_info(normal_buf);
//        try {
//            response = ResponseUtils.processResponse(normal_buf,i);
//            Sm.CtxInfo ctxInfo = response.getCtxInfo();
//            printCtxInfo(ctxInfo);
//            int deviceCount = ctxInfo.getDeviceCount();
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//
//        System.out.println("---api_login_device");
//        i=CSMApi.INSTANCE.api_login_device(0,"11111111",normal_buf);
//        try {
//            ResponseUtils.processResponse(normal_buf,i);
//        } catch (SMException e) {
//            e.printStackTrace();
//            exitToken(normal_buf);
//            return true;
//        }
//        return false;
//    }
//
//    private static void getStatus(byte[] normal_buf) {
//        int i;
//        Sm.Response response;
//        System.out.println("---api_device_status");
//        i= CSMApi.INSTANCE.api_device_status(0,normal_buf);
//        try {
//            response = ResponseUtils.processResponse(normal_buf,i);
//            Sm.DevStatus deviceStatus =response.getDeviceStatus();
//            printDevStatus(deviceStatus);
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private static void exitToken(byte[] buf){
//        System.out.println("---api_logout_device---");
//        int i=CSMApi.INSTANCE.api_logout_device(0,buf);
//        try {
//            ResponseUtils.processResponse(buf,i);
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//        System.out.println("---api_final---");
//        i= CSMApi.INSTANCE.api_final(buf);
//        try {
//            ResponseUtils.processResponse(buf,i);
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//    }
//
//    static void printDevStatus(Sm.DevStatus deviceStatus) {
//        System.out.printf("index: %d\n", deviceStatus.getIndex());
//        System.out.printf("opened: %b\n", deviceStatus.getOpened());
//        System.out.printf("logged_in: %b\n", deviceStatus.getLoggedIn());
//        System.out.printf("pipes_count: %d\n", deviceStatus.getPipesCount());
//        System.out.printf("free_pipes_count: %d\n", deviceStatus.getFreePipesCount());
//        System.out.printf("secret_key_count: %d\n", deviceStatus.getSecretKeyCount());
//        System.out.printf("public_key_count: %d\n", deviceStatus.getPublicKeyCount());
//        System.out.printf("private_key_count: %d\n", deviceStatus.getPrivateKeyCount());
//    }
//
//    static void printCtxInfo(Sm.CtxInfo ctxInfo) {
//        System.out.printf("protect_key: %b \n", ctxInfo.getProtectKey());
//        System.out.printf(" device_count: %d\n", ctxInfo.getDeviceCount());
//        System.out.printf(" api_version: %s\n", ctxInfo.getApiVersion());
//    }
//
//    static void printKeypair(Sm.KeyPair keypair) {
//        System.out.printf("public_key: %s\n", keypair.getPublicKey());
//        System.out.printf("private_key: %s\n", keypair.getPrivateKey());
//    }
//
//    static void printBytes(Sm.BytesValue bytes) {
//        com.google.protobuf.ByteString value = bytes.getValue();
//        byte[] data1 = value.toByteArray();
//        String v = org.bouncycastle.pqc.math.linearalgebra.ByteUtils.toHexString(data1);
//        System.out.printf("data_len: %ld\n", value.size());
//        System.out.printf("encrypted data: %s\n", v);
//    }
//
//    static void testCrypto(){
//        System.out.println("---testCrypto");
//        byte[] buf= new byte[LARGE_BUF_SIZE];
//
//        testDigest(buf);
//
//        //testDigestSection(buf);
//        testSm3Digest();
//        testRandom(buf);
//
//        //testEncrypt(buf,null, null);
//
//        //testDecrypt(buf, null, null);
//
//        testGenerateKey(buf);
//
//        testGenerateKeypair(buf);
//    }
//
//    private static Sm.BytesValue testDecrypt(byte[] buf, String key, String enctext) {
//        System.out.println("---testDecrypt");
//
//        String encrypt_result = "eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a292eefb0602800038b355744473abe2a2921bda5859da7534a80121a1e79b859431";
//        String hex_secret = "9353b0995d93c0b7f470deec26112172";
//        if(key!=null){
//            hex_secret = key;
//            if(enctext ==null){
//                System.out.println("need parameter [enctext]");
//                return null;
//            }
//            encrypt_result = enctext;
//        }
//        byte[] data = ByteUtils.fromHexString(encrypt_result);
//        int l = CSMApi.INSTANCE.api_decrypt(0,0,hex_secret.getBytes(),null,data,data.length,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            Sm.BytesValue  bytes= response.getBytesValue();
//            System.out.printf("decrypt result: %s\n", new String(bytes.getValue().toByteArray()));
//            return bytes;
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//        return null;
//
//    }
//
//    private static Sm.BytesValue testEncrypt(byte[] buf, String key, String plaintxt) {
//        System.out.println("---testEncrypt");
//
//        String hex_secret = "9353b0995d93c0b7f470deec26112172";
//        String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
//        if(key!=null) {
//            hex_secret = key;
//            if(plaintxt ==null){
//                System.out.println("need parameter [plaintxt]");
//                return null;
//            }
//            origin_data = plaintxt;
//        }
//
//        int l=CSMApi.INSTANCE.api_encrypt(0,0,hex_secret.getBytes(),null,origin_data.getBytes(),origin_data.getBytes().length,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            Sm.BytesValue  bytesValue= response.getBytesValue();
//            printBytes(bytesValue);
//            return bytesValue;
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//        return null;
//
//    }
//
//    private static void testGenerateKeypair(byte[] buf) {
//        System.out.println("---testGenerateKeypair");
//
//        int l = CSMApi.INSTANCE.api_generate_keypair(0,0,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            Sm.KeyPair kp = response.getKeyPair();
//            String  private_key="bd900427cf189b954ee2fa388a22b7398600921d38c7e3b16eb6f9159bb47c2e";
//            String public_key = "c2922e404876182400623e0e254e1ea08f5d15245abb9032d85396ec70de9067abc3cbf58e9fa379753ba5ce8f00c75e93997be7fac501da35d025f87261b534";
//            printKeypair(kp);
//
//            String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
//            SM3Digest digest = new SM3Digest();
//            digest.reset();
//            digest.update(origin_data.getBytes(),0,origin_data.getBytes().length);
//            byte[] hash= new byte[digest.getDigestSize()];
//            digest.doFinal(hash,0);
//            String hexHash = ByteUtils.toHexString(hash);
//
//            l = CSMApi.INSTANCE.api_sign(0,0,kp.getPrivateKey().getBytes(),hexHash.getBytes(),buf);
//            response = ResponseUtils.processResponse(buf,l);
//            String signature = response.getStrValue().getValue();
//            System.out.printf("signature = %s ", signature);
//
//            l=CSMApi.INSTANCE.api_verify(0,0,kp.getPublicKey().getBytes(),hexHash.getBytes(),signature.getBytes(),buf);
//            response = ResponseUtils.processResponse(buf,l);
//            int result  = response.getIntValue().getValue();
//            System.out.printf("verify = %d ", result);
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//
//    }
//
//    private static void testGenerateKey(byte[] buf) {
//        System.out.println("---testGenerateKey");
//
//        int l = CSMApi.INSTANCE.api_generate_key(0,0,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            String str = response.getStrValue().getValue();
//            System.out.printf("secret key %s\n", str);
//
//            String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
//            Sm.BytesValue encValue= testEncrypt(buf, str,origin_data);
//            if(encValue ==null){
//                return;
//            }
//            byte[] data = encValue.getValue().toByteArray();
//
//            Sm.BytesValue plainValue= testDecrypt(buf,str,new String(data));
//            if(plainValue ==null){
//                return;
//            }
//            byte[] plain = plainValue.getValue().toByteArray();
//            String s = ByteUtils.toHexString(plain);
//            System.out.printf("orires = %s \n result = %s \n", origin_data, s);
//
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//
//    }
//
//    private static void testRandom(byte[] buf) {
//        System.out.println("---testRandom");
//
//        int l = CSMApi.INSTANCE.api_random(0,0,16,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            String str = response.getStrValue().getValue();
//            System.out.printf("random %s\n", str);
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//    }

//    static void testDigest(byte[] buf){
//        System.out.println("---testDigest");
//
//        byte[] data = new byte[]{'a','b','c'};
//        String expect = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
//        int l = CSMApi.INSTANCE.api_digest(0,0,data,data.length,buf);
//        Sm.Response response = null;
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            String str = response.getStrValue().getValue();
//            System.out.printf("digest %s\n", str);
//            System.out.printf("expect %s\n", expect);
//            if(str.equals(expect)){
//                System.out.println("digest function OK!");
//            }else{
//                System.out.println("digest function WRONG!");
//            }
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//    }

//    static void testSm3Digest(){
//        System.out.println("---testSm3Digest");
//        byte[] data = new byte[]{'a','b','c','d'};
//        com.yunjingit.common.Crypto.SM3Digest digest = new com.yunjingit.common.Crypto.SM3Digest();
//
//
//        for(int i=0;i<16;i++) {
//            digest.update(data,0,data.length);
//        }
//        byte[] result = new byte[digest.getDigestSize()];
//        digest.doFinal(result,0);
//        String expect = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
//        String str = ByteUtils.toHexString(result);
//        System.out.printf("digest %s\n", str);
//        System.out.printf("expect %s\n", expect);
//        if(str.equals(expect)){
//            System.out.println("digest section function OK!");
//        }else{
//            System.out.println("digest section function WRONG!");
//        }
//    }

//    static void testDigestSection(byte[] buf){
//        System.out.println("---testDigestSection");
//
//        String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
//        byte[] data = origin_data.getBytes();
//        String expect = "2667d7de2aed63166446e92065d29ddc93d41a08a04264a822daa40723e53fda";
//
//        Sm.Response response=null;
//
//        int l = CSMApi.INSTANCE.api_digest_init(0,0,buf);
//        try {
//            ResponseUtils.processResponse(buf,l);
//        } catch (SMException e) {
//            e.printStackTrace();
//            return;
//        }
//        for(int i=0;i<2;i++) {
//            l = CSMApi.INSTANCE.api_digest_update(0, 0, data, data.length, buf);
//            try {
//                ResponseUtils.processResponse(buf, l);
//            } catch (SMException e) {
//                e.printStackTrace();
//                return;
//            }
//        }
//        l=CSMApi.INSTANCE.api_digest_final(0,0,data,data.length,buf);
//        try {
//            response = ResponseUtils.processResponse(buf,l);
//            String str = response.getStrValue().getValue();
//            System.out.printf("digest %s\n", str);
//            System.out.printf("expect %s\n", expect);
//            if(str.equals(expect)){
//                System.out.println("digest section function OK!");
//            }else{
//                System.out.println("digest section function WRONG!");
//            }
//        } catch (SMException e) {
//            e.printStackTrace();
//        }
//
//    }



}
