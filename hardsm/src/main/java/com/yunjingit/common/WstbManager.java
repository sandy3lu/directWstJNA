package com.yunjingit.common;

import com.sun.jna.Memory;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.ShortBuffer;
import java.util.Arrays;


public class WstbManager {

    static WstbContext wstbContext = new WstbContext();

    static WstbApi.SM_ALGORITHM.ByReference alg_hash;
    static WstbApi.SM_ALGORITHM.ByReference export_algorithm ;

    static WstbApi.SM_ALGORITHM g_sign_algorithm;
    static WstbApi.SM_ALGORITHM g_verify_algorithm;
    static WstbApi.SM_ALGORITHM g_ecc_enc_algorithm;
    static WstbApi.SM_ALGORITHM g_ecc_dec_algorithm;

    static WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr;
    static WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr_pub;
    static WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr_priv;
    static WstbApi.SM_ECC_PARAMETER.ByReference g_ecc_param;

    static WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr_priv_dec;


    static byte[] digest = new byte[32];
    static ByteBuffer digest_out_data = ByteBuffer.wrap(digest);
    static ByteBuffer sign_outdata = ByteBuffer.allocate(64);

    static WstbApi.SM_BLOB_KEY.ByReference keyblob_verify = new WstbApi.SM_BLOB_KEY.ByReference();


    public static boolean init(){

        IntByReference deviceNum = new IntByReference();
        int result = WstbApi.INSTANCE.SM_GetDeviceNum(deviceNum);
        int count = deviceNum.getValue();
        if(count<1){
            System.out.println("not found the device");
            return false;
        }else{
            //System.out.printf("SM_GetDeviceNum result = %d, num= %d\n",result, count);
            wstbContext.setDevice_count(count);
        }

        IntByReference deviceType = new IntByReference();
        result = WstbApi.INSTANCE.SM_GetDeviceType(deviceType);
        if(result == WstbApi.SM_ERR_FREE) {
            //System.out.printf("SM_GetDeviceType deviceType = %d\n", deviceType.getValue());
            wstbContext.setDevice_type(deviceType.getValue());
            initKeyContext();
            initCryptoContext();
            return true;
        }else{
            System.out.println("SM_GetDeviceType is failed " + result );
            return false;
        }

    }

    public static int getDeviceNume(){
        return wstbContext.getDevice_count();
    }


    private static void initKeyContext(){
        keyAttr = new WstbApi.SM_KEY_ATTRIBUTE.ByReference();
      init_key_attr_sm4(keyAttr);

      g_ecc_param= new WstbApi.SM_ECC_PARAMETER.ByReference();
      g_ecc_param.uiModulusBits = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;
      g_ecc_param.pParameter = null;
      g_ecc_param.uiParameterLen = 0;

        keyAttr_pub = new WstbApi.SM_KEY_ATTRIBUTE.ByReference();
      init_key_attr_sm2public(keyAttr_pub);

      /**SM2 private key sign*/
        keyAttr_priv = new WstbApi.SM_KEY_ATTRIBUTE.ByReference();
        keyAttr_priv.uiObjectClass = WstbApi.SMO_PRIVATE_KEY;
        keyAttr_priv.KeyType = WstbApi.SM_KEY_ECC_PRIVATE;
        keyAttr_priv.pParameter = g_ecc_param;
        keyAttr_priv.uiParameterLen = g_ecc_param.size();
        keyAttr_priv.uiFlags = WstbApi.SMKA_SIGN | WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_WRAP | WstbApi.SMKA_UNWRAP;

        /** SM2 private key dec */
        keyAttr_priv_dec = new WstbApi.SM_KEY_ATTRIBUTE.ByReference();
        keyAttr_priv_dec.uiObjectClass = WstbApi.SMO_PRIVATE_KEY;
        keyAttr_priv_dec.KeyType = WstbApi.SM_KEY_ECC_PRIVATE;
        keyAttr_priv_dec.uiKeyLabel = 1;
        keyAttr_priv_dec.pParameter = g_ecc_param;
        keyAttr_priv_dec.uiParameterLen = g_ecc_param.size();
        keyAttr_priv_dec.uiFlags = WstbApi.SMKA_DECRYPT | WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_WRAP | WstbApi.SMKA_UNWRAP;

        /** key blob*/
        keyblob_sign.uiDataLen = Native.POINTER_SIZE;
        keyblob_verify.uiDataLen = Native.POINTER_SIZE;
    }

    private static void initCryptoContext(){
        alg_hash = new WstbApi.SM_ALGORITHM.ByReference();
        alg_hash.AlgoType = WstbApi.SMM_SCH_256;
        alg_hash.pParameter = null;
        alg_hash.uiParameterLen = WstbApi.SMMA_SCH_256_LEN;

        /**
         * Crypto card can exports all keys (except public key) in ciphertext form. You can choose encrypt exported keys
         * with sm4 (ECB or CBC) or sm3 or sm2. For unknown reason, it's only support ALG34. If use ALG35 then raise KEY TYPE ERROR!
         * Here we choose sm4 ECB to encrypt it, the simplest way, so pParameter is NULL. */
        export_algorithm = new WstbApi.SM_ALGORITHM.ByReference();
        export_algorithm.AlgoType = WstbApi.SMM_ALG34_ECB;
        export_algorithm.pParameter = null;
        export_algorithm.uiParameterLen = 0;

        g_sign_algorithm = new WstbApi.SM_ALGORITHM.ByReference();
        g_sign_algorithm.AlgoType = WstbApi.SMM_ECC_FP_SIGN;
        g_sign_algorithm.pParameter = null;
        g_sign_algorithm.uiParameterLen = 0;
        g_sign_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;

        g_verify_algorithm = new WstbApi.SM_ALGORITHM.ByReference();
        g_verify_algorithm.AlgoType = WstbApi.SMM_ECC_FP_VERIFY;
        g_verify_algorithm.pParameter = null;
        g_verify_algorithm.uiParameterLen = 0;
        g_verify_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;

        g_ecc_enc_algorithm = new WstbApi.SM_ALGORITHM();
        g_ecc_enc_algorithm.AlgoType = WstbApi.SMM_ECC_FP_ENC;
        g_ecc_enc_algorithm.uiParameterLen = 0;
        g_ecc_enc_algorithm.pParameter = null;
        g_ecc_enc_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;

        g_ecc_dec_algorithm = new WstbApi.SM_ALGORITHM();
        g_ecc_dec_algorithm.AlgoType = WstbApi.SMM_ECC_FP_DEC;
        g_ecc_enc_algorithm.uiParameterLen = 0;
        g_ecc_enc_algorithm.pParameter = null;
        g_ecc_enc_algorithm.uiReserve = WstbApi.SMMA_ECC_FP_256_MODULUS_BITS;
    }


    public static boolean login(int deviceIndex, String password, int bExclusive){
        PointerByReference deviceHandle = new PointerByReference();
        int result = WstbApi.INSTANCE.SM_OpenDevice(deviceIndex,bExclusive,deviceHandle);
        if(result!=WstbApi.SM_ERR_FREE){
            System.out.printf("SM_OpenDevice failed = %d \n", result);
            return false;
        }

        IntByReference testResult = new IntByReference();
        result = WstbApi.INSTANCE.SM_TestDevice(deviceHandle.getValue(),testResult);
        if(result!= WstbApi.SM_ERR_FREE){
            WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            System.out.println("SM_TestDevice failed " + result + " , so we close it!");
            return false;
        }
        if(testResult.getValue()!=0){
            System.out.printf("SM_TestDevice find Device error %x! so we close it! \n",testResult.getValue() );
            WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            return false;
        }

        ShortBuffer wMechanismNum = ShortBuffer.allocate(1);
        IntBuffer list = IntBuffer.allocate(32);
        result = WstbApi.INSTANCE.SM_GetMechanismList(deviceHandle.getValue(),list,wMechanismNum);
        if(result!= WstbApi.SM_ERR_FREE){
            WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            System.out.println("SM_GetMechanismInfo failed " + result + " , so we close it!");
            return false;
        }
        int num = wMechanismNum.get();

        int[] listdata = list.array();
        for(int i=0;i<num;i++){
            System.out.printf("puiMechanismList[%d] = %x \n", i, listdata[i]);
            WstbApi.SM_MECHANISM_INFO.ByReference stMech = new WstbApi.SM_MECHANISM_INFO.ByReference();
            result = WstbApi.INSTANCE.SM_GetMechanismInfo(deviceHandle.getValue(),listdata[i],stMech);
            if(result == WstbApi.SM_ERR_FREE){
                System.out.printf("SM_GetMechanismInfo uiMinBlockSize = %d  uiMaxBlockSize = %d uiMinKeySize = %d uiMaxKeySize = %d uiFlags =%d \n",
                        stMech.uiMinBlockSize, stMech.uiMaxBlockSize, stMech.uiMinKeySize, stMech.uiMaxKeySize,  stMech.uiFlags);
            }else{
                System.out.println("SM_GetMechanismInfo is failed " + result );
            }
        }


        PointerByReference pipeHandle = new PointerByReference();
        result = WstbApi.INSTANCE.SM_OpenSecPipe(deviceHandle.getValue(),pipeHandle);
        if(result != WstbApi.SM_ERR_FREE){
            WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            System.out.println("SM_OpenSecPipe failed " + result + " , so we close it!");
            return false;
        }

        ByteBuffer bb = ByteBuffer.wrap(password.getBytes());
        ShortBuffer sb = ShortBuffer.allocate(1);
        result = WstbApi.INSTANCE.SM_Login(pipeHandle.getValue(),bb,password.length(),sb);
        if(result != WstbApi.SM_ERR_FREE){
            System.out.println("SM_Login failed " + result + " , so we close it!");
            result = WstbApi.INSTANCE.SM_CloseSecPipe(pipeHandle.getValue());
            System.out.printf("SM_CloseSecPipe  result = %d \n",  result);
            WstbApi.INSTANCE.SM_CloseDevice(deviceHandle.getValue());
            return false;
        }

        WstbApi.SM_BLOB_KEY sb_key = new WstbApi.SM_BLOB_KEY();
        PointerByReference cfgKey = new PointerByReference();
        // uiDataLen = sizeof（SM_UINT）
        sb_key.uiDataLen = 4;
        Memory memory = new Memory(sb_key.uiDataLen);
        memory.setInt(0,WstbApi.SMCK_SYMM);
        sb_key.pbyData =memory;
        result = WstbApi.INSTANCE.SM_GetCfgKeyHandle(pipeHandle.getValue(),sb_key,cfgKey);
        if(result == WstbApi.SM_ERR_FREE) {
            wstbContext.setDeviceContext(deviceIndex, deviceHandle.getValue(), pipeHandle.getValue(),cfgKey.getValue());
        }else{
            System.out.println("SM_GetCfgKeyHandle failed " + result );
        }
        return true;
    }

    private void getDeviceInfo(Pointer hdevice){
        WstbApi.SM_DEVICE_INFO.ByReference info = new WstbApi.SM_DEVICE_INFO.ByReference();
        int result = WstbApi.INSTANCE.SM_GetDeviceInfo(hdevice,info);
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
            System.out.printf(" byBatch = %s \n", ByteUtils.toHexString(info.stManufactureInfo.byBatch));
            System.out.printf(" byDateTime = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byDateTime));
            System.out.printf(" byManufactureDate = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byManufactureDate));
            System.out.printf(" byManufacturerID = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byManufacturerID));
            System.out.printf(" byModel = %s \n",ByteUtils.toHexString(info.stManufactureInfo.byModel));
            System.out.printf(" bySerial = %s \n",ByteUtils.toHexString(info.stManufactureInfo.bySerial));

        }else{
            result = WstbApi.INSTANCE.SM_CloseDevice(hdevice);
            System.out.println("SM_GetDeviceInfo is failed " + result );
            return;
        }

    }


    public static boolean release(){

        boolean result = true;
        for(int i=0;i<wstbContext.getDevice_count();i++){
            if(!wstbContext.logout(i)){
                result = false;
                System.out.println("device " + i + " release FAIL !");
            }else {
                System.out.println("device " + i + " release OK !");
            }
        }
        return result;
    }



    public static byte[] getRandom(int deviceIndex, int length){

        int uiRandomLen = length;
        byte[] random = new byte[uiRandomLen];
        ByteBuffer bb = ByteBuffer.wrap(random);
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        int result = WstbApi.INSTANCE.SM_GenRandom(p,(short)0, bb, uiRandomLen);
        if(result == WstbApi.SM_ERR_FREE)
        {
            return random;
        }
        else
        {
            System.out.printf("SM_GenRandom error is =0x%x\n",result);
            return null;
        }
    }

    public synchronized static byte[] getSM3Digest(int deviceIndex, byte[] plaindata){
        ByteBuffer input_bb = ByteBuffer.wrap(plaindata);
        IntBuffer digest_length = IntBuffer.allocate(1);
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        int error_code = WstbApi.INSTANCE.SM_Digest(p, null, alg_hash, input_bb, plaindata.length, digest_out_data, digest_length);
        if (error_code == WstbApi.SM_ERR_FREE) {
            return Arrays.copyOf(digest,digest.length);
        }else{
            System.out.printf("SM_Digest error %d\n", error_code);
            return null;
        }

    }

    private static boolean destroyKey(Pointer p, PointerByReference hKey){
        int result =  WstbApi.INSTANCE.SM_DestroyKey(p, hKey.getValue());
        if(result!=WstbApi.SM_ERR_FREE){
            System.out.println("SM_DestroyKey error " + result);
            return false;
        }
        return true;
    }
    private static boolean destroyPubKey(Pointer p, PointerByReference hKey){
        int result =  WstbApi.INSTANCE.SM_DestroyPublicKey(p, hKey.getValue());
        if(result!=WstbApi.SM_ERR_FREE){
            System.out.println("SM_DestroyPublicKey error " + result);
            return false;
        }
        return true;
    }
    private static boolean destroyPrivKey(Pointer p, PointerByReference hKey){
        int result =  WstbApi.INSTANCE.SM_DestroyPrivateKey(p, hKey.getValue());
        if(result!=WstbApi.SM_ERR_FREE){
            System.out.println("SM_DestroyPrivateKey error " + result);
            return false;
        }
        return true;
    }

    public static byte[] generateSM4Key(int deviceIndex){
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        PointerByReference hKey = new PointerByReference();
        int result = WstbApi.INSTANCE.SM_GenerateKey(p, keyAttr, hKey);
        if(result!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_GenerateKey error " + result);
        }
        byte[] export_key = new byte[WstbApi.SMMA_ALG35_BLOCK_LEN];
        ByteBuffer export_bb = ByteBuffer.wrap(export_key);
        ShortBuffer key_len = ShortBuffer.allocate(1);
        result = WstbApi.INSTANCE.SM_ExportKey(p,hKey.getValue(),null,null,export_bb,key_len);
        if(result!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ExportKey error " + result);
        }
        destroyKey(p,  hKey);
       return export_key;
    }

    public static byte[] sm4Enc(boolean isEnc, int deviceIndex, byte[] key, byte[] input){
        // check length
        if((input.length % WstbApi.SMMA_ALG35_BLOCK_LEN)!=0){
            throw new WstbException("input data length error");
        }

        WstbApi.SM_ALGORITHM.ByReference algo = new WstbApi.SM_ALGORITHM.ByReference();
        boolean b = make_crypt_algorithm(algo,null);
        if(!b){
            throw new WstbException("make_crypt_algorithm error");
        }

        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        //import key
        PointerByReference import_hKey = new PointerByReference();
        ByteBuffer key_bb = ByteBuffer.wrap(key);
        int result = WstbApi.INSTANCE.SM_ImportKey(p,key_bb,(short)key.length,null,null,keyAttr,import_hKey);
        if (result != WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ImportKey error" + result);
        }

        ByteBuffer in_bb = ByteBuffer.wrap(input);
        byte[] outdata = new byte[input.length];
        ByteBuffer out_data = ByteBuffer.wrap(outdata);
        IntBuffer outLen = IntBuffer.allocate(1);
        WstbApi.SM_BLOB_KEY.ByReference keyblob = new WstbApi.SM_BLOB_KEY.ByReference();
        keyblob.uiDataLen = Native.POINTER_SIZE;
        keyblob.pbyData = import_hKey.getPointer();

        if(isEnc) {
            result = WstbApi.INSTANCE.SM_Encrypt(p, keyblob, algo, 0, in_bb, input.length, out_data, outLen);
        }else{
            result = WstbApi.INSTANCE.SM_Decrypt(p, keyblob, algo,0, in_bb, input.length ,out_data,outLen);
        }
        destroyKey(p,  import_hKey);

        if (result == WstbApi.SM_ERR_FREE) {
            return outdata;
        }else{
            throw new WstbException("SM_Encrypt error " + result);
        }

    }


    public static byte[] generateSM2Key(int deviceIndex){

        Pointer p = wstbContext.getDevicePipe(deviceIndex);

        PointerByReference hKey_priv = new PointerByReference();
        PointerByReference hKey_pub = new PointerByReference();

        int result = WstbApi.INSTANCE.SM_GenerateKeyPair(p, keyAttr_pub,hKey_pub,keyAttr_priv,hKey_priv);
        if(result!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_GenerateKeyPair error " + result);
        }

        byte[] pub_key = new byte[WstbApi.SMMA_ECC_FP_256_PUBLIC_KEY_LEN];
        byte[] pri_key = new byte[WstbApi.SMMA_ECC_FP_256_PRIVATE_KEY_LEN];
        ByteBuffer pub_bb = ByteBuffer.wrap(pub_key);
        ByteBuffer pri_bb = ByteBuffer.wrap(pri_key);
        ShortBuffer keylen = ShortBuffer.allocate(1);
        result = WstbApi.INSTANCE.SM_ExportPublicKey(p,hKey_pub.getValue(),pub_bb,keylen);
        if(result!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ExportPublicKey error " + result);
        }
        short pubkeylen = keylen.get();

        Pointer authKey = wstbContext.getDeviceAuthKey(deviceIndex);
        ShortBuffer keylen1 = ShortBuffer.allocate(1);
        result = WstbApi.INSTANCE.SM_ExportPrivateKey(p,hKey_priv.getValue(),authKey,export_algorithm,pri_bb,keylen1);
        if(result!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ExportPrivateKey error " + result);
        }
        short privkeylen = keylen1.get();

        destroyPrivKey(p,hKey_priv);
        destroyPubKey(p,hKey_pub);
        byte[] keys = new byte[pri_key.length + pub_key.length];
        System.arraycopy(pri_key,0,keys,0,pri_key.length);
        System.arraycopy(pub_key,0,keys,pri_key.length,pub_key.length);
        return keys;
    }

    static WstbApi.SM_BLOB_KEY.ByReference keyblob_sign = new WstbApi.SM_BLOB_KEY.ByReference();

    synchronized static byte[] sm2Sign(int deviceIndex, byte[] privkey, byte[]digest){
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        Pointer authKey = wstbContext.getDeviceAuthKey(deviceIndex);
        ByteBuffer priv = ByteBuffer.wrap(privkey);
        PointerByReference hKey_priv = new PointerByReference();
        int ret = WstbApi.INSTANCE.SM_ImportPrivateKey(p,priv,(short)privkey.length,authKey,export_algorithm,keyAttr_priv,hKey_priv);
        if(ret!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ImportPrivateKey error " + ret);
        }

        keyblob_sign.pbyData = hKey_priv.getPointer();
        ByteBuffer indata = ByteBuffer.wrap(digest);

        IntBuffer len = IntBuffer.allocate(1);
        ret =WstbApi.INSTANCE.SM_ECCSignature(p,keyblob_sign,g_sign_algorithm,indata,digest.length,sign_outdata,len);
        if(ret!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ECCSignature error " + ret);
        }
        destroyPrivKey(p,hKey_priv);
        byte[] tmp = sign_outdata.array();
        return Arrays.copyOf(tmp,tmp.length);
    }


    synchronized static boolean sm2Verify(int deviceIndex, byte[] pubkey,byte[]digest , byte[]sig){
        boolean result = false;
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        ByteBuffer pub = ByteBuffer.wrap(pubkey);
        PointerByReference hKey_pub = new PointerByReference();
        int ret = WstbApi.INSTANCE.SM_ImportPublicKey(p,pub,(short)pubkey.length,keyAttr_pub,hKey_pub);
        if(ret!=WstbApi.SM_ERR_FREE){
            throw new WstbException("SM_ImportPublicKey error " + ret);
        }

        keyblob_verify.pbyData = hKey_pub.getPointer();
        ByteBuffer indata = ByteBuffer.wrap(digest);
        ByteBuffer sigData = ByteBuffer.wrap(sig);
        ret = WstbApi.INSTANCE.SM_ECCVerify(p,keyblob_verify,g_verify_algorithm,indata,digest.length,sigData,sig.length);
        if(ret == WstbApi.SM_ERR_FREE){
            result = true;
        }

        destroyPubKey(p,hKey_pub);
        return result;
    }

    static byte[] sm2Enc(boolean isEnc, int deviceIndex, byte[] key, byte[] input){
        if(key.length >1024){
            throw new WstbException("sm2Enc max input length is 1024" );
        }
        Pointer p = wstbContext.getDevicePipe(deviceIndex);
        ByteBuffer keybb = ByteBuffer.wrap(key);
        PointerByReference hKey = new PointerByReference();

        ByteBuffer indata = ByteBuffer.wrap(input);
        if(isEnc){
            // public key enc
            int ret = WstbApi.INSTANCE.SM_ImportPublicKey(p,keybb,(short)key.length,keyAttr_pub,hKey);
            if(ret!=WstbApi.SM_ERR_FREE){
                throw new WstbException("SM_ImportPublicKey error " + ret);
            }
            WstbApi.SM_BLOB_KEY.ByReference keyblob = new WstbApi.SM_BLOB_KEY.ByReference();
            keyblob.uiDataLen = Native.POINTER_SIZE;
            keyblob.pbyData = hKey.getPointer();

            WstbApi.SM_BLOB_ECCCIPHER sm_blob_ecccipher = new WstbApi.SM_BLOB_ECCCIPHER();
            ret = WstbApi.INSTANCE.SM_ECCEncrypt(p,keyblob,g_ecc_enc_algorithm,indata,input.length,sm_blob_ecccipher);
            if(ret!=WstbApi.SM_ERR_FREE){
                throw new WstbException("SM_ECCEncrypt error " + ret);
            }
            System.out.println(sm_blob_ecccipher.toString());
            int uiCipherLen = sm_blob_ecccipher.uiCheckDataLen+sm_blob_ecccipher.uiCipherDataLen+sm_blob_ecccipher.uiSessionKeyLen;

            Memory outmem = new Memory(uiCipherLen);
            sm_blob_ecccipher.pbyData = outmem;
            ret = WstbApi.INSTANCE.SM_ECCEncrypt(p,keyblob,g_ecc_enc_algorithm,indata,input.length,sm_blob_ecccipher);
            if(ret!=WstbApi.SM_ERR_FREE){
                destroyPubKey(p,hKey);
                throw new WstbException("SM_ECCEncrypt error " + ret);
            }

            destroyPubKey(p,hKey);
            byte[] data = new byte[uiCipherLen];
            for(int i = 0; i<data.length;i++){
                data[i] = outmem.getByte(i);
            }

            return data;
        }else{
            // private key dec
            Pointer authKey = wstbContext.getDeviceAuthKey(deviceIndex);
            int ret = WstbApi.INSTANCE.SM_ImportPrivateKey(p,keybb,(short)key.length,authKey,export_algorithm,keyAttr_priv_dec,hKey);
            if(ret!=WstbApi.SM_ERR_FREE){
                throw new WstbException("SM_ImportPublicKey error " + ret);
            }
            WstbApi.SM_BLOB_KEY.ByReference keyblob = new WstbApi.SM_BLOB_KEY.ByReference();
            keyblob.uiDataLen = Native.POINTER_SIZE;
            keyblob.pbyData = hKey.getPointer();

            WstbApi.SM_BLOB_ECCCIPHER sm_blob_ecccipher = new WstbApi.SM_BLOB_ECCCIPHER();
            Memory inmem = new Memory(input.length);
            for(int i = 0; i<input.length;i++){
                inmem.setByte(i, input[i]);
            }
            sm_blob_ecccipher.pbyData = inmem;
            sm_blob_ecccipher.uiCheckDataLen = WstbApi.SMMA_SCH_256_LEN;
            sm_blob_ecccipher.uiSessionKeyLen = WstbApi.SMMA_ECC_FP_256_PUBLIC_KEY_LEN;
            sm_blob_ecccipher.uiCipherDataLen = input.length - WstbApi.SMMA_SCH_256_LEN - WstbApi.SMMA_ECC_FP_256_PUBLIC_KEY_LEN;
            IntBuffer len = IntBuffer.allocate(1);
            ret = WstbApi.INSTANCE.SM_ECCDecrypt(p,keyblob,g_ecc_dec_algorithm,sm_blob_ecccipher,null,len);
            if(ret!=WstbApi.SM_ERR_FREE){
                throw new WstbException("SM_ECCDecrypt error " + ret);
            }
            int outlen = len.get();
            ByteBuffer out = ByteBuffer.allocate(outlen);
            ret = WstbApi.INSTANCE.SM_ECCDecrypt(p,keyblob,g_ecc_dec_algorithm,sm_blob_ecccipher,out,len);
            if(ret!=WstbApi.SM_ERR_FREE){
                destroyPrivKey(p,hKey);
                throw new WstbException("SM_ECCEncrypt error " + ret);
            }
            destroyPrivKey(p,hKey);
            return out.array();
        }

    }


    static boolean make_crypt_algorithm(WstbApi.SM_ALGORITHM.ByReference algorithm, byte[] iv) {
        if (null != iv) {
            if ((iv.length) != WstbApi.SMMA_ALG35_BLOCK_LEN ) {
                return false;
            }
        }

        if (null != iv) {

            algorithm.AlgoType = WstbApi.SMM_ALG35_CBC;
            Memory memory = new Memory(iv.length);
            for(int i=0;i<iv.length;i++) {
                memory.setByte(i,iv[i]);
            }

            Pointer p =  memory;
            algorithm.pParameter = p;
            algorithm.uiParameterLen = WstbApi.SMMA_ALG35_IV_LEN;
        } else {
            algorithm.AlgoType = WstbApi.SMM_ALG35_ECB;
            algorithm.pParameter = null;
            algorithm.uiParameterLen = 0;
        }
        return true;
    }

    static void init_key_attr_sm4(WstbApi.SM_KEY_ATTRIBUTE.ByReference keyAttr) {

        keyAttr.uiObjectClass = WstbApi.SMO_SECRET_KEY;
        keyAttr.KeyType = WstbApi.SM_KEY_ALG35;
        keyAttr.pParameter = null;
        keyAttr.uiParameterLen = 0;
        keyAttr.uiFlags = WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_ENCRYPT | WstbApi.SMKA_DECRYPT;
    }


    static void init_key_attr_sm2public(WstbApi.SM_KEY_ATTRIBUTE.ByReference g_key_attr_sm2public) {

        g_key_attr_sm2public.uiObjectClass = WstbApi.SMO_PUBLIC_KEY;
        g_key_attr_sm2public.KeyType = WstbApi.SM_KEY_ECC_PUBLIC;
        g_key_attr_sm2public.pParameter =g_ecc_param;
        g_key_attr_sm2public.uiParameterLen = g_ecc_param.size();
        g_key_attr_sm2public.uiFlags = WstbApi.SMKA_VERIFY | WstbApi.SMKA_EXTRACTABLE | WstbApi.SMKA_WRAP | WstbApi.SMKA_UNWRAP;
        //System.out.printf("g_key_attr_sm2public = %s \n", g_key_attr_sm2public.toString());
    }







}
