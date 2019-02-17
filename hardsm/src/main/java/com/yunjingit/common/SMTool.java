package com.yunjingit.common;


import com.sun.jna.Memory;

import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;



public class SMTool {

    private static final int NORMAL_BUF_SIZE = 256;
    private static final int LARGE_BUF_SIZE = 1024 * 32;


    public static void main( String[] args ) {

//        String  private_key="bd900427cf189b954ee2fa388a22b7398600921d38c7e3b16eb6f9159bb47c2e";
//        String public_key = "c2922e404876182400623e0e254e1ea08f5d15245abb9032d85396ec70de9067abc3cbf58e9fa379753ba5ce8f00c75e93997be7fac501da35d025f87261b534";
//        System.out.println(private_key.length() + "  "  + public_key.length());//64  128


        IntByReference deviceNum = new IntByReference();
        int result = WstbApi.INSTANCE.SM_GetDeviceNum(deviceNum);
        System.out.printf("SM_GetDeviceNum result = %d, num= %d\n",result, deviceNum.getValue());
        if(deviceNum.getValue()<1){
            System.out.println("not found the device");
            return;
        }

        String apiversion= WstbApi.INSTANCE.SM_GetAPIVersion();
        System.out.println("api version : " + apiversion);

        IntByReference deviceType = new IntByReference();
        result = WstbApi.INSTANCE.SM_GetDeviceType(deviceType);
        if(result == WstbApi.SM_ERR_FREE) {
            System.out.printf("SM_GetDeviceType deviceType = %d\n", deviceType.getValue());
        }else{
            System.out.println("SM_GetDeviceType is failed " + result );
            return;
        }

        PointerByReference deviceHandle = new PointerByReference();
        result = WstbApi.INSTANCE.SM_OpenDevice(0,0,deviceHandle);
        if(result == WstbApi.SM_ERR_FREE) {
            System.out.printf("SM_OpenDevice deviceHandle = %s \n", deviceHandle.getValue().toString());

            IntByReference list = new IntByReference();

            result = WstbApi.INSTANCE.SM_TestDevice(deviceHandle.getValue(),list);
            if(result== WstbApi.SM_ERR_FREE){
                System.out.println("SM_TestDevice is success " );
            }else{
                result = WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
                System.out.println("SM_TestDevice is failed " + result );
            }

            ShortByReference wMechanismNum = new ShortByReference();

            result = WstbApi.INSTANCE.SM_GetMechanismList(deviceHandle.getValue(),list,wMechanismNum);
            if(result == WstbApi.SM_ERR_FREE){
                // puiMechanismList = 1537, wMechanismNum = 12
                System.out.printf("SM_GetMechanismList puiMechanismList = %d, wMechanismNum = %d \n", list.getValue(), wMechanismNum.getValue());
                WstbApi.SM_MECHANISM_INFO.ByReference stMech = new WstbApi.SM_MECHANISM_INFO.ByReference();
                result = WstbApi.INSTANCE.SM_GetMechanismInfo(deviceHandle.getValue(),list.getValue(),stMech);
                if(result == WstbApi.SM_ERR_FREE){
                    System.out.printf("SM_GetMechanismInfo uiMinBlockSize = %d  uiMaxBlockSize = %d uiMinKeySize = %d uiMaxKeySize = %d uiFlags =%d \n",
                            stMech.uiMinBlockSize, stMech.uiMaxBlockSize, stMech.uiMinKeySize, stMech.uiMaxKeySize,  stMech.uiFlags);
                }else{
                    System.out.println("SM_GetMechanismInfo is failed " + result );
                }

            }else{
                System.out.println("SM_GetMechanismList is failed " + result );
            }

            /*
            WstbApi.SM_DEVICE_INFO.ByReference info = new WstbApi.SM_DEVICE_INFO.ByReference();
            result = WstbApi.INSTANCE.SM_GetDeviceInfo(deviceHandle.getValue(),info);
            if(result == WstbApi.SM_ERR_FREE){
                System.out.printf("SM_GetDeviceInfo uiFlags = %d, uiStatus = %d\n", info.uiFlags,info.uiStatus);
                System.out.println("---- stDevResourceInfo -------");
                System.out.printf(" stADMem.uiMaxAuthDevMem1Size = %d \n",info.stDevResourceInfo.stADMem.uiMaxAuthDevMem1Size);
                System.out.printf(" stADMem.uiMaxAuthDevMem2Size = %d \n",info.stDevResourceInfo.stADMem.uiMaxAuthDevMem2Size);
                System.out.printf(" stNVMem.uiMaxNVMemSize = %d \n",info.stDevResourceInfo.stNVMem.uiMaxNVMemSize);
                System.out.printf(" stNVMem.uiNVMemSectorSize = %d \n",info.stDevResourceInfo.stNVMem.uiNVMemSectorSize);
                System.out.printf(" uiHPIBufSize = %d \n",info.stDevResourceInfo.uiHPIBufSize);
                System.out.printf(" wFirmwareVersion = %d \n",info.stDevResourceInfo.wFirmwareVersion);
                System.out.printf(" wHardwareVersion = %d \n",info.stDevResourceInfo.wHardwareVersion);

                System.out.printf(" wFreePipeCount = %d \n",info.stDevResourceInfo.wFreePipeCount);
                System.out.printf(" wMaxPipeCount = %d \n",info.stDevResourceInfo.wMaxPipeCount);
                System.out.printf(" wFreePrivateKeyCount = %d \n",info.stDevResourceInfo.wFreePrivateKeyCount);
                System.out.printf(" wMaxPrivateKeyCount = %d \n",info.stDevResourceInfo.wMaxPrivateKeyCount);
                System.out.printf(" wFreePrivateKeyTokenCount = %d \n",info.stDevResourceInfo.wFreePrivateKeyTokenCount);
                System.out.printf(" wMaxPrivateKeyTokenCount = %d \n",info.stDevResourceInfo.wMaxPrivateKeyTokenCount);

                System.out.printf(" wFreePublicKeyCount = %d \n",info.stDevResourceInfo.wFreePublicKeyCount);
                System.out.printf(" wFreePublicKeyTokenCount = %d \n",info.stDevResourceInfo.wFreePublicKeyTokenCount);
                System.out.printf(" wFreeSecretKeyCount = %d \n",info.stDevResourceInfo.wFreeSecretKeyCount);
                System.out.printf(" wFreeSecretKeyTokenCount = %d \n",info.stDevResourceInfo.wFreeSecretKeyTokenCount);
                System.out.printf(" wMaxPublicKeyCount = %d \n",info.stDevResourceInfo.wMaxPublicKeyCount);
                System.out.printf(" wMaxPublicKeyTokenCount = %d \n",info.stDevResourceInfo.wMaxPublicKeyTokenCount);
                System.out.printf(" wMaxSecretKeyCount = %d \n",info.stDevResourceInfo.wMaxSecretKeyCount);
                System.out.printf(" wMaxSecretKeyTokenCount = %d \n",info.stDevResourceInfo.wMaxSecretKeyTokenCount);

                System.out.printf(" wMaxPinLen = %d \n",info.stDevResourceInfo.wMaxPinLen);
                System.out.printf(" wMinPinLen = %d \n",info.stDevResourceInfo.wMinPinLen);
                System.out.printf(" wMaxSOPinLen = %d \n",info.stDevResourceInfo.wMaxSOPinLen);
                System.out.printf(" wMinSOPinLen = %d \n",info.stDevResourceInfo.wMinSOPinLen);
                System.out.println("---- stManufactureInfo -------");
                System.out.printf(" byBatch = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byBatch));
                System.out.printf(" byDateTime = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byDateTime));
                System.out.printf(" byManufactureDate = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byManufactureDate));
                System.out.printf(" byManufacturerID = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byManufacturerID));
                System.out.printf(" byModel = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byModel));
                System.out.printf(" bySerial = %s \n",ByteUtils.toHexString(info.stManufactureInfo.bySerial));

            }else{
                result = WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
                System.out.println("SM_GetDeviceInfo is failed " + result );
                return;
            }
            */


            /**********************************************/
            PointerByReference pipeHandle = new PointerByReference();
            result = WstbApi.INSTANCE.SM_OpenSecPipe(deviceHandle.getValue(),pipeHandle);

            if(result == WstbApi.SM_ERR_FREE)
            {
                System.out.printf("SM_OpenSecPipe is success\n");

                /********RANDOM*******/
                int uiRandomLen = 16;

                ByteByReference random_data = new ByteByReference();
                Memory mymem = new Memory(uiRandomLen*2);
                random_data.setPointer(mymem);
                result = WstbApi.INSTANCE.SM_GenRandom(pipeHandle.getValue(),(short)0, random_data, uiRandomLen);
                if(result == WstbApi.SM_ERR_FREE)
                {
                    byte[] pbyRandom = random_data.getPointer().getByteArray(0,uiRandomLen);
                    System.out.printf(" random = %s \n",ByteUtils.toHexString(pbyRandom));
                }
                else
                {
                    System.out.printf("SM_GenRandom error is =0x%x\n",result);

                }

                /********LogIn*******/
                String password = "11111111";
                ShortByReference pwTryNum = new ShortByReference();
                result = WstbApi.INSTANCE.SM_Login(pipeHandle.getValue(),password.getBytes(),password.length(),pwTryNum);
                if(result == WstbApi.SM_ERR_FREE)
                {
                    System.out.printf("SM_Login  sucess! \n");

                    /********SM4*******/
                    PointerByReference hKey = new PointerByReference();
                    WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr = new WstbApi.SM_KEY_ATTRIBUTE.ByReference();
                    init_key_attr_sm4(keyAttr);
                    result = WstbApi.INSTANCE.SM_GenerateKey(pipeHandle.getValue(), keyAttr, hKey);
                    if (result == WstbApi.SM_ERR_FREE)
                    {
                        System.out.printf("SM_GenerateKey  sucess! \n");

                        WstbApi.SM_BLOB_KEY.ByReference keyblob = new WstbApi.SM_BLOB_KEY.ByReference();
                        keyblob.uiDataLen = 8;
                        keyblob.pbyData = hKey;
                        WstbApi.SM_ALGORITHM.ByReference algo = new WstbApi.SM_ALGORITHM.ByReference();
                        boolean b = make_crypt_algorithm(algo,null);
                        if(!b){
                            System.out.printf("make_crypt_algorithm failed! \n");
                        }else{
                            String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
                            ByteByReference out_data = new ByteByReference();
                             mymem = new Memory(origin_data.getBytes().length);
                            out_data.setPointer(mymem);
                            IntByReference outLen = new IntByReference();
                            result = WstbApi.INSTANCE.SM_Encrypt(pipeHandle.getValue(),keyblob,algo,0,origin_data.getBytes(),origin_data.length(),out_data,outLen);
                            if (result == WstbApi.SM_ERR_FREE) {
                                byte[] outbytes = out_data.getPointer().getByteArray(0, outLen.getValue());
                                System.out.printf("SM_Encrypt  %s \n" , ByteUtils.toHexString(outbytes));
                                result = WstbApi.INSTANCE.SM_Decrypt(pipeHandle.getValue(),keyblob,algo,0,outbytes,outbytes.length,out_data,outLen);
                                if (result == WstbApi.SM_ERR_FREE) {
                                    byte[] outbytes_dec = out_data.getPointer().getByteArray(0, outLen.getValue());
                                    System.out.printf("SM_Decrypt  %s \n" , new String(outbytes_dec));

                                }else{
                                    System.out.printf("SM_Decrypt error %d\n", result);
                                }
                            }else{
                                System.out.printf("SM_Encrypt error %d\n", result);
                            }
                        }





                        byte[] export_key = new byte[WstbApi.SMMA_ALG35_BLOCK_LEN];
                        ShortByReference key_len = new ShortByReference();
                        result = WstbApi.INSTANCE.SM_ExportKey(pipeHandle.getValue(),hKey.getValue(),null,null,export_key,key_len);
                        if(result!=WstbApi.SM_ERR_FREE){
                            String errMsg = WstbApi.INSTANCE.SM_GetErrorString(result, 0);
                            System.out.printf("SM_ExportKey error %s\n", errMsg);

                        }else {
                            System.out.printf("SM_ExportKey is OK! key = %s\n", ByteUtils.toHexString(export_key));

                            PointerByReference improt_hKey = new PointerByReference();
                            result = WstbApi.INSTANCE.SM_ImportKey(pipeHandle.getValue(),export_key,(short)export_key.length,null,null,keyAttr,improt_hKey);
                            if (result == WstbApi.SM_ERR_FREE){
                                System.out.printf("SM_ImportKey success\n" );

                                //TODO: Test enc again

                                result = WstbApi.INSTANCE.SM_DestroyKey(pipeHandle.getValue(), improt_hKey.getValue());
                                System.out.printf("SM_DestroyKey is %d\n", result);
                            }else{
                                System.out.printf("SM_ImportKey is %d\n", result);
                            }
                        }

                       result = WstbApi.INSTANCE.SM_DestroyKey(pipeHandle.getValue(), hKey.getValue());
                       if(result!=WstbApi.SM_ERR_FREE){
                           String errMsg = WstbApi.INSTANCE.SM_GetErrorString(result, 0);
                           System.out.printf("SM_GetErrorString is %s\n", errMsg);
                       }else {
                           System.out.printf("SM_DestroyKey is %d\n", result);
                       }
                    }
                    else
                    {
                       System.out.printf("SM_GenerateKey is %d\n",result);
                    }

                    /********SM3*******/
                    byte[] plaindata = new byte[]{'a','b','c'};
                    String expect = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
                    ByteByReference digest_out_data = new ByteByReference();
                    mymem = new Memory(WstbApi.SMMA_SCH_256_LEN);
                    digest_out_data.setPointer(mymem);
                    IntByReference digest_len = new IntByReference();
                    WstbApi.SM_ALGORITHM.ByReference alg_hash = new WstbApi.SM_ALGORITHM.ByReference();
                    init_hash_algorithm(alg_hash);
                    int error_code = WstbApi.INSTANCE.SM_Digest(pipeHandle.getValue(), null, alg_hash, plaindata, plaindata.length, digest_out_data, digest_len);
                    if (error_code == WstbApi.SM_ERR_FREE) {
                        byte[] outbytes = digest_out_data.getPointer().getByteArray(0, digest_len.getValue());
                        System.out.printf("SM_Digest  %s \n" , ByteUtils.toHexString(outbytes));
                        System.out.printf("expect     %s \n" , expect);
                    }else{
                        System.out.printf("SM_Encrypt error %d\n", error_code);
                    }


                    /********SM2*******/
                    





                    result = WstbApi.INSTANCE.SM_Logout(pipeHandle.getValue());
                    System.out.printf("SM_Logout  result = %d \n",  result);
                }
                else
                {
                    System.out.printf("SM_Login is =0x%x\n",result);

                }

                result = WstbApi.INSTANCE.SM_CloseSecPipe(pipeHandle.getValue());
                System.out.printf("SM_CloseDevice  result = %d \n",  result);
            }
            else
            {
                System.out.printf("SM_OpenSecPipe =0x%x\n",result);

            }




            result = WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            System.out.printf("SM_CloseDevice  result = %d \n",  result);

        }else{
            System.out.printf("SM_OpenDevice failed = %d \n", result);
        }





        System.out.println("-------finish ----------");
    }


    static boolean make_crypt_algorithm(WstbApi.SM_ALGORITHM.ByReference algorithm, byte[] iv) {
        if (null != iv) {
            if ((iv.length) != WstbApi.SMMA_ALG35_BLOCK_LEN * 2) return false;
        }


        if (null != iv) {

            algorithm.AlgoType = WstbApi.SMM_ALG35_CBC;

            algorithm.pParameter = null; //TODO:iv;
            algorithm.uiParameterLen = WstbApi.SMMA_ALG35_IV_LEN;
        } else {
            algorithm.AlgoType = WstbApi.SMM_ALG35_ECB;
            algorithm.pParameter = null;
            algorithm.uiParameterLen = 0;
        }

        return true;
    }


    static WstbApi.SM_KEY_ATTRIBUTE g_key_attr_sm2public = new WstbApi.SM_KEY_ATTRIBUTE();
    static WstbApi.SM_KEY_ATTRIBUTE g_key_attr_sm2private= new WstbApi.SM_KEY_ATTRIBUTE();
    static WstbApi.SM_ECC_PARAMETER g_ecc_param= new WstbApi.SM_ECC_PARAMETER();
    static WstbApi.SM_ALGORITHM g_export_algorithm;


    static void init_key_attr_sm4(WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr) {

        keyAttr.uiObjectClass = WstbApi.SMO_SECRET_KEY;
        keyAttr.KeyType = WstbApi.SM_KEY_ALG35;
        keyAttr.pParameter = null;
        keyAttr.uiParameterLen = 0;
        keyAttr.uiFlags = WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_ENCRYPT | WstbApi.SMKA_DECRYPT;
    }

    static void init_ecc_param() {

        g_ecc_param.uiModulusBits = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;
    }

    static void init_key_attr_sm2public() {

        g_key_attr_sm2public.uiObjectClass = WstbApi.SMO_PUBLIC_KEY;
        g_key_attr_sm2public.KeyType = WstbApi.SM_KEY_ECC_PUBLIC;
        g_key_attr_sm2public.pParameter = g_ecc_param.getPointer();
        g_key_attr_sm2public.uiParameterLen = 4+4 +4;
        g_key_attr_sm2public.uiFlags = WstbApi.SMKA_VERIFY | WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_WRAP | WstbApi.SMKA_UNWRAP;
    }

    static void init_key_attr_sm2private() {

        g_key_attr_sm2private.uiObjectClass = WstbApi.SMO_PRIVATE_KEY;
        g_key_attr_sm2private.KeyType = WstbApi.SM_KEY_ECC_PRIVATE;
        g_key_attr_sm2private.pParameter = g_ecc_param.getPointer();
        g_key_attr_sm2private.uiParameterLen = 4+4 +4;
        g_key_attr_sm2private.uiFlags = WstbApi.SMKA_SIGN | WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_WRAP | WstbApi.SMKA_UNWRAP;
    }

    /* Crypto card can exports all keys (except public key) in ciphertext form. You can choose encrypt exported keys
     * with sm4 (ECB or CBC) or sm3 or sm2.
     * Here we choose sm4 ECB to encrypt it, the simplest way, so pParameter is NULL. */
    static void init_export_algorithm() {

        /* For unknown reason, it's only support ALG34. If use ALG35 then raise KEY TYPE ERROR!
         * But I prefer ALG35.
         * Why use ECB mode? First, keys are short, no need to use CBC or other mode; Second, no iv needed; Third, simple */
        g_export_algorithm.AlgoType = WstbApi.SMM_ALG34_ECB;
        g_export_algorithm.pParameter = null;
        g_export_algorithm.uiParameterLen = 0;
    }



    static WstbApi.SM_ALGORITHM g_hash_algorithm;
    static WstbApi.SM_ALGORITHM g_mac_algorithm;
    static WstbApi.SM_ALGORITHM g_sign_algorithm;
    static WstbApi.SM_ALGORITHM g_verify_algorithm;
    static byte[] g_byiv = new byte[WstbApi.SMMA_ALG34_IV_LEN];
    //static ByteByReference g_byiv = new ByteByReference(WstbApi.SMMA_ALG34_IV_LEN);


        static void init_hash_algorithm(WstbApi.SM_ALGORITHM.ByReference alg_hash) {

            alg_hash.AlgoType = WstbApi.SMM_SCH_256;
            alg_hash.pParameter = null;
            alg_hash.uiParameterLen = WstbApi.SMMA_SCH_256_LEN;
        }

        static void init_mac_algorithm() {

            g_mac_algorithm.AlgoType = WstbApi.SMM_ALG35_MAC;
            //g_mac_algorithm.pParameter = new Pointer(g_byiv);
            g_mac_algorithm.uiParameterLen = WstbApi.SMMA_ALG34_IV_LEN;
        }

        static void init_sign_algorithm() {

            g_sign_algorithm.AlgoType = WstbApi.SMM_ECC_FP_SIGN;
            g_sign_algorithm.pParameter = null;
            g_sign_algorithm.uiParameterLen = 0;
            g_sign_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;
        }

        static void init_verify_algorithm() {

            g_verify_algorithm.AlgoType = WstbApi.SMM_ECC_FP_VERIFY;
            g_verify_algorithm.pParameter = null;
            g_verify_algorithm.uiParameterLen = 0;
            g_verify_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;
        }










    private static boolean loginDevice(byte[] normal_buf) {
        int i;
        System.out.println("---api_init");
        Sm.Response response = null;
        i = CSMApi.INSTANCE.api_init(normal_buf);
        try {
            ResponseUtils.processResponse(normal_buf,i);
        } catch (SMException e) {

            return true;
        }

        System.out.println("---api_ctx_info");
        i = CSMApi.INSTANCE.api_ctx_info(normal_buf);
        try {
            response = ResponseUtils.processResponse(normal_buf,i);
            Sm.CtxInfo ctxInfo = response.getCtxInfo();
            printCtxInfo(ctxInfo);
            int deviceCount = ctxInfo.getDeviceCount();
        } catch (SMException e) {
            e.printStackTrace();
        }


        System.out.println("---api_login_device");
        i=CSMApi.INSTANCE.api_login_device(0,"11111111",normal_buf);
        try {
            ResponseUtils.processResponse(normal_buf,i);
        } catch (SMException e) {
            e.printStackTrace();
            exitToken(normal_buf);
            return true;
        }
        return false;
    }

    private static void getStatus(byte[] normal_buf) {
        int i;
        Sm.Response response;
        System.out.println("---api_device_status");
        i= CSMApi.INSTANCE.api_device_status(0,normal_buf);
        try {
            response = ResponseUtils.processResponse(normal_buf,i);
            Sm.DevStatus deviceStatus =response.getDeviceStatus();
            printDevStatus(deviceStatus);
        } catch (SMException e) {
            e.printStackTrace();
        }
    }




    private static void exitToken(byte[] buf){
        System.out.println("---api_logout_device---");
        int i=CSMApi.INSTANCE.api_logout_device(0,buf);
        try {
            ResponseUtils.processResponse(buf,i);
        } catch (SMException e) {
            e.printStackTrace();
        }

        System.out.println("---api_final---");
        i= CSMApi.INSTANCE.api_final(buf);
        try {
            ResponseUtils.processResponse(buf,i);
        } catch (SMException e) {
            e.printStackTrace();
        }
    }

    static void printDevStatus(Sm.DevStatus deviceStatus) {
        System.out.printf("index: %d\n", deviceStatus.getIndex());
        System.out.printf("opened: %b\n", deviceStatus.getOpened());
        System.out.printf("logged_in: %b\n", deviceStatus.getLoggedIn());
        System.out.printf("pipes_count: %d\n", deviceStatus.getPipesCount());
        System.out.printf("free_pipes_count: %d\n", deviceStatus.getFreePipesCount());
        System.out.printf("secret_key_count: %d\n", deviceStatus.getSecretKeyCount());
        System.out.printf("public_key_count: %d\n", deviceStatus.getPublicKeyCount());
        System.out.printf("private_key_count: %d\n", deviceStatus.getPrivateKeyCount());
    }

    static void printCtxInfo(Sm.CtxInfo ctxInfo) {
        System.out.printf("protect_key: %b \n", ctxInfo.getProtectKey());
        System.out.printf(" device_count: %d\n", ctxInfo.getDeviceCount());
        System.out.printf(" api_version: %s\n", ctxInfo.getApiVersion());
    }

    static void printKeypair(Sm.KeyPair keypair) {
        System.out.printf("public_key: %s\n", keypair.getPublicKey());
        System.out.printf("private_key: %s\n", keypair.getPrivateKey());
    }

//    static void printBytes(Sm.BytesValue bytes) {
//        com.google.protobuf.ByteString value = bytes.getValue();
//        byte[] data1 = value.toByteArray();
//        String v = org.bouncycastle.pqc.math.linearalgebra.ByteUtils.toHexString(data1);
//        System.out.printf("data_len: %ld\n", value.size());
//        System.out.printf("encrypted data: %s\n", v);
//    }

    static void testCrypto(){
        System.out.println("---testCrypto");
        byte[] buf= new byte[LARGE_BUF_SIZE];

        testDigest(buf);

        testDigestSection(buf);
        testSm3Digest();
        testRandom(buf);

        //testEncrypt(buf,null, null);

        //testDecrypt(buf, null, null);

        //testGenerateKey(buf);

        testGenerateKeypair(buf);
    }

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
//
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

    private static void testGenerateKeypair(byte[] buf) {
        System.out.println("---testGenerateKeypair");

        int l = CSMApi.INSTANCE.api_generate_keypair(0,0,buf);
        Sm.Response response = null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            Sm.KeyPair kp = response.getKeyPair();
            String  private_key="bd900427cf189b954ee2fa388a22b7398600921d38c7e3b16eb6f9159bb47c2e";
            String public_key = "c2922e404876182400623e0e254e1ea08f5d15245abb9032d85396ec70de9067abc3cbf58e9fa379753ba5ce8f00c75e93997be7fac501da35d025f87261b534";
            printKeypair(kp);

            String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
            SM3Digest digest = new SM3Digest();
            digest.reset();
            digest.update(origin_data.getBytes(),0,origin_data.getBytes().length);
            byte[] hash= new byte[digest.getDigestSize()];
            digest.doFinal(hash,0);
            String hexHash = ByteUtils.toHexString(hash);

            l = CSMApi.INSTANCE.api_sign(0,0,kp.getPrivateKey().getBytes(),hexHash.getBytes(),buf);
            response = ResponseUtils.processResponse(buf,l);
            String signature = response.getStrValue().getValue();
            System.out.printf("signature = %s ", signature);

            l=CSMApi.INSTANCE.api_verify(0,0,kp.getPublicKey().getBytes(),hexHash.getBytes(),signature.getBytes(),buf);
            response = ResponseUtils.processResponse(buf,l);
            int result  = response.getIntValue().getValue();
            System.out.printf("verify = %d ", result);
        } catch (SMException e) {
            e.printStackTrace();
        }


    }

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

    private static void testRandom(byte[] buf) {
        System.out.println("---testRandom");

        int l = CSMApi.INSTANCE.api_random(0,0,16,buf);
        Sm.Response response = null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            String str = response.getStrValue().getValue();
            System.out.printf("random %s\n", str);
        } catch (SMException e) {
            e.printStackTrace();
        }

    }

    static void testDigest(byte[] buf){
        System.out.println("---testDigest");

        byte[] data = new byte[]{'a','b','c'};
        String expect = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        int l = CSMApi.INSTANCE.api_digest(0,0,data,data.length,buf);
        Sm.Response response = null;
        try {
            response = ResponseUtils.processResponse(buf,l);
            String str = response.getStrValue().getValue();
            System.out.printf("digest %s\n", str);
            System.out.printf("expect %s\n", expect);
            if(str.equals(expect)){
                System.out.println("digest function OK!");
            }else{
                System.out.println("digest function WRONG!");
            }
        } catch (SMException e) {
            e.printStackTrace();
        }

    }

    static void testSm3Digest(){
        System.out.println("---testSm3Digest");
        byte[] data = new byte[]{'a','b','c','d'};
        com.yunjingit.common.Crypto.SM3Digest digest = new com.yunjingit.common.Crypto.SM3Digest();


        for(int i=0;i<16;i++) {
            digest.update(data,0,data.length);
        }
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result,0);
        String expect = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
        String str = ByteUtils.toHexString(result);
        System.out.printf("digest %s\n", str);
        System.out.printf("expect %s\n", expect);
        if(str.equals(expect)){
            System.out.println("digest section function OK!");
        }else{
            System.out.println("digest section function WRONG!");
        }
    }

    static void testDigestSection(byte[] buf){
        System.out.println("---testDigestSection");

        String origin_data = "0123456701234567012345670123456701234567012345670123456701234567";
        byte[] data = origin_data.getBytes();
        String expect = "2667d7de2aed63166446e92065d29ddc93d41a08a04264a822daa40723e53fda";

        Sm.Response response=null;

        int l = CSMApi.INSTANCE.api_digest_init(0,0,buf);
        try {
            ResponseUtils.processResponse(buf,l);
        } catch (SMException e) {
            e.printStackTrace();
            return;
        }
        for(int i=0;i<2;i++) {
            l = CSMApi.INSTANCE.api_digest_update(0, 0, data, data.length, buf);
            try {
                ResponseUtils.processResponse(buf, l);
            } catch (SMException e) {
                e.printStackTrace();
                return;
            }
        }


        l=CSMApi.INSTANCE.api_digest_final(0,0,data,data.length,buf);
        try {
            response = ResponseUtils.processResponse(buf,l);
            String str = response.getStrValue().getValue();
            System.out.printf("digest %s\n", str);
            System.out.printf("expect %s\n", expect);
            if(str.equals(expect)){
                System.out.println("digest section function OK!");
            }else{
                System.out.println("digest section function WRONG!");
            }
        } catch (SMException e) {
            e.printStackTrace();
        }

    }



}
