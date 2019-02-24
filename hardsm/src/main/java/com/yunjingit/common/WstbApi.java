package com.yunjingit.common;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.ShortBuffer;
import java.util.Arrays;
import java.util.List;


public interface WstbApi extends Library {
    WstbApi INSTANCE = (WstbApi) Native.loadLibrary("smwstb",WstbApi.class);

    int SM_ERR_FREE   =    0;

    /* ///////////////////////////////////////////////////////////////////////// */
    /* define Object class type */
    /* ///////////////////////////////////////////////////////////////////////// */
int SMO_PUBLIC_KEY       =        0x00000002;
    int SMO_PRIVATE_KEY    =         0x00000003;
    int SMO_SECRET_KEY       =       0x00000004;

            /* ///////////////////////////////////////////////////////////////////////// */
            /* define Key attribute flags mask */
            /* ///////////////////////////////////////////////////////////////////////// */
            int     SMKA_TOKEN      =         0x00000001;
    int SMKA_EXTRACTABLE   =         0x00000002;
    int  SMKA_MODIFIABLE     =        0x00000004;
    int  SMKA_ENCRYPT    =            0x00000008;
    int  SMKA_DECRYPT    =            0x00000010;
    int  SMKA_SIGN     =              0x00000020;
    int  SMKA_VERIFY     =            0x00000040;
    int  SMKA_WRAP    =               0x00000080;
    int  SMKA_UNWRAP     =            0x00000100;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define MechanismInfo flags mask
             * used by SM_GetMechanismInfo
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMMF_ENCRYPT   =             0x00000001;
    int  SMMF_DECRYPT  =              0x00000002;
    int  SMMF_DIGEST   =              0x00000004;
    int  SMMF_SIGN     =              0x00000008;
    int  SMMF_VERIFY   =              0x00000010;
    int SMMF_WRAP     =              0x00000020;
    int  SMMF_UNWRAP   =              0x00000040;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define Hardware type
             * used by SM_GetDeviceType
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int SMH_TYPE_PCI       =         0  ; /*< Secure module type is PCI    */
    int  SMH_TYPE_PCMCIA    =         1  ; /*< Secure module type is PCMCIA */
    int  SMH_TYPE_USB      =          2  ; /*< Secure module type is USB    */
    int  SMH_TYPE_RS232     =         3  ; /*< Secure module type is RS232  */
    int  SMH_TYPE_USBKEY    =         4  ; /*< Secure module type is USBKEY */

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define Random Number
             * used by SM_GenRandom
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMH_DEV_RND_NUM0   =          0;
    int SMH_DEV_RND_NUM1   =          1;
    int SMH_DEV_RND_NUM2    =         2;
    int SMH_DEV_RND_NUM3   =          3;
    int  SMH_DEV_RND_ALL    =          0xFFFF;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define destroy resource identification
             * used by SM_ClearResource
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMH_RESOURCE_LEVEL0    =         0;
    int  SMH_RESOURCE_LEVEL1    =         1;
    int  SMH_RESOURCE_LEVEL2    =         2;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define update key pair flag
             * used by SM_UpdateKeyPair
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMKF_UPDATE_KEY_PAIR_SIGN   =          0;
    int  SMKF_UPDATE_KEY_PAIR_WRAP    =         1;
    int  SMKF_UPDATE_KEY_PAIR_SYMM    =         2;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define config key identifiers
             * used by SM_GetCfgKeyHandle
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMCK_ECC_ENC_PUBLIC        =    0x105;
    int  SMCK_ECC_DEC_PRIVATE      =     0x106;
    int  SMCK_ECC_VERIFY_PUBLIC    =     0x205;
    int  SMCK_ECC_SIGN_PRIVATE     =     0x206;
    int  SMCK_SYMM              =        0x1;

            /* ///////////////////////////////////////////////////////////////////////// */
            /*
             * define current Hash process mode is normal or CP
             * used by Hash related API
             */
            /* ///////////////////////////////////////////////////////////////////////// */
            int  SMH_DEV_MODE_SD     =                 0;
    int  SMH_DEV_MODE_CP     =                 1;




    /* SM1 */
int SMM_ALG34_ECB  =     0x00000601;
            int SMM_ALG34_CBC  =                 0x00000602;
    int SMM_ALG34_MAC      =             0x00000604;

            /* SM2 */
            int SMM_ECC_FP_ENC   =               0x00000111;
    int SMM_ECC_FP_DEC   =               0x00000112;
    int SMM_ECC_FP_SIGN    =             0x00000113;
    int SMM_ECC_FP_VERIFY    =           0x00000114;
    int SMM_ECC_FP_EXCHANGE_KEY  =       0x00000115;

            /* SM3 */
            int SMM_SCH_256    =                 0x0000016C;

            /* SM4 */
            int SMM_ALG35_ECB   =                0x00003a01;
    int SMM_ALG35_CBC     =              0x00003a02;
    int SMM_ALG35_MAC     =              0x00003a04;

            /* ///////////////////////////////////////////////////////////////////////// */
            /* define Key type */
            /* ///////////////////////////////////////////////////////////////////////// */
            int SM_KEY_ALG34_H     =     0x00000028   ;   /* Key length 32bytes */
    int SM_KEY_ALG34_M  =        0x00000029  ;    /* Key length 24bytes */
    int SM_KEY_ALG34_L   =       0x0000002a  ;    /* Key length 16bytes */
    int SM_KEY_ALG35    =        0x00000109   ;   /* Key length 16bytes */

    int SM_KEY_ECC_PUBLIC   =    0x00000005;
    int SM_KEY_ECC_PRIVATE  =    0x00000006;

            /* ///////////////////////////////////////////////////////////////////////// */
            /* Algorithm character */
            /* ///////////////////////////////////////////////////////////////////////// */
            /* SM1 */
            int SMMA_ALG34_BLOCK_LEN     =       16;
            int SMMA_ALG34_KEY_L_LEN    =        SMMA_ALG34_BLOCK_LEN;
int SMMA_ALG34_IV_LEN     =          SMMA_ALG34_BLOCK_LEN;
int SMMA_ALG34_MAC_VALUE_LEN     =   16;

    /* SM3 */
    int SMMA_SCH_256_LEN      =          32;
    int SMMA_SCH_CBLOCK   =              64;

            /* SM2 */
            int SMMA_ECC_FP_256_MODULUS_BITS =   256;
            int SMMA_ECC_FP_256_BLOCK_LEN  =     ((SMMA_ECC_FP_256_MODULUS_BITS + 7) / 8);
            int SMMA_ECC_FP_256_ENC_MIN_LEN  =   1;
            int SMMA_ECC_FP_256_ENC_MAX_LEN  =   128;
            int SMMA_ECC_FP_256_SIG_MIN_LEN  =   SMMA_SCH_256_LEN;
int SMMA_ECC_FP_256_SIG_MAX_LEN   =  SMMA_SCH_256_LEN;
int SMMA_ECC_FP_256_SIG_VALLEN   =   (SMMA_ECC_FP_256_BLOCK_LEN * 2);
int SMMA_ECC_FP_256_VER_VALLEN    =  (SMMA_ECC_FP_256_BLOCK_LEN * 2);
int SMMA_ECC_FP_256_PUBLIC_KEY_LEN = (SMMA_ECC_FP_256_BLOCK_LEN * 2);
int SMMA_ECC_FP_256_PRIVATE_KEY_LEN =SMMA_ECC_FP_256_BLOCK_LEN;
int SMMA_ECC_FP_256_EXCHANGE_OUTLEN  =  4000;



            /* SM4 */
            int SMMA_ALG35_BLOCK_LEN   =         16;
            int SMMA_ALG35_KEY_LEN   =           SMMA_ALG35_BLOCK_LEN;
int SMMA_ALG35_IV_LEN        =       SMMA_ALG35_BLOCK_LEN;
int SMMA_ALG35_MAC_VALUE_LEN    =    16;

    int SM_GetDeviceNum(IntByReference puiDevNum);
	int SM_GetDeviceNum(IntBuffer puiDevNum);

	/**If the native method returns char* and actually allocates memory, a return type of Pointer should be used to avoid leaking the memory*/
	Pointer SM_GetErrorString(int uiErrCode, int bChinese);    
	Pointer SM_GetAPIVersion();
	
	
    int SM_GetDeviceType(IntByReference puiDeviceType);
	int SM_GetDeviceType(IntBuffer puiDeviceType);
	
	
    int  SM_OpenDevice(int uiDevID, int bExclusive, PointerByReference phDevice);

    int SM_CloseDevice(Pointer hDevice);

    //int SM_GetMechanismList(Pointer hDevice, IntByReference puiMechanismList, ShortByReference pwMechanismNum);
	int SM_GetMechanismList(Pointer hDevice, IntBuffer puiMechanismList, ShortBuffer pwMechanismNum);

    int SM_GetMechanismInfo(Pointer hDevice, int uiMechanism, SM_MECHANISM_INFO.ByReference pstMech);

    int SM_TestDevice(Pointer hDevice, IntByReference puiResult);
	int SM_TestDevice(Pointer hDevice, IntBuffer puiResult);
	
    int SM_GetDeviceInfo(Pointer hDevice, SM_DEVICE_INFO.ByReference pstDeviceInfo);

    int SM_GetDeviceIndex(Pointer hDevice, int[] puiDeviceIndex);
	int SM_GetDeviceIndex(Pointer hDevice, IntBuffer puiDeviceIndex);

	/**
	 * D10. SM_ChangeUserPin<br>
	 * Original signature : <code>SM_RV SM_ChangeUserPin(SM_DEVICE_HANDLE, PSM_BYTE, SM_UINT, PSM_BYTE, SM_UINT, PSM_WORD)</code><br>
	 * @param hDevice in<br>
	 * @param pbyOldPin in<br>
	 * @param uiOldPinLen in<br>
	 * @param pbyNewPin in<br>
	 * @param uiNewPinLen in<br>
	 * @param pwTryNum out<br>
	 * <i>native declaration : sm_api.h:860</i>
	 */
	int SM_ChangeUserPin(Pointer hDevice, ByteBuffer pbyOldPin, int uiOldPinLen, ByteBuffer pbyNewPin, int uiNewPinLen, ShortBuffer pwTryNum);
	
	
    int SM_DestroySensitiveInfo(Pointer hDevice, int uiType);

	
	/**
	 * A function, lock the memory.
<br>
	 *  \param hDevice              [in]  the handle of the device.
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_LockMem(SM_DEVICE_HANDLE)</code><br>
	 * @param hDevice in<br>
	 * <i>native declaration : sm_api.h:881</i>
	 */
	int SM_LockMem(Pointer hDevice);
	/**
	 * A function, unlock the memory.
<br>
	 *  \param hDevice              [in]  the handle of the device.
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_UnlockMem(SM_DEVICE_HANDLE)</code><br>
	 * @param hDevice in<br>
	 * <i>native declaration : sm_api.h:892</i>
	 */
	int SM_UnlockMem(Pointer hDevice);
	
	/**
	 * A function, read nonvolatile data.
<br>
	 *  \param hDevice              [in]  the handle of the device.
<br>
	 *  \param uiLocation           [in] the address of the read data.
<br>
	 *  \param uiDataOutLen         [in] the length of the data to be read.
<br>
	 *  \param pbyDataOut           [out] the address of the data to be read.
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_ReadNonVolatile(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataOutLen in<br>
	 * @param pbyDataOut out<br>
	 * <i>native declaration : sm_api.h:905</i>
	 */
	int SM_ReadNonVolatile(Pointer hDevice, int uiLocation, int uiDataOutLen, ByteBuffer pbyDataOut);
	
	/**
	 * A function, write nonvolatile data.
<br>
	 *  \param hDevice            [in]  the handle of the device.
<br>
	 *  \param uiLocation         [in]  the address of the write data.
<br>
	 *  \param uiDataInLen        [in] the length of the data to be write.
<br>
	 *  \param pbyDataIn          [in] the address of the data to be write.
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_WriteNonVolatile(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataInLen in<br>
	 * @param pbyDataIn in<br>
	 * <i>native declaration : sm_api.h:923</i>
	 */
	int SM_WriteNonVolatile(Pointer hDevice, int uiLocation, int uiDataInLen, ByteBuffer pbyDataIn);
	
    int SM_CommTest(Pointer hDevice);

	
	/**
	 * A function, write nonvolatile data.
<br>
	 *  \param hDevice            [in]  the handle of the device.
<br>
	 *  \param pbyPin             [in]  the address of the init Pin data.
<br>
	 *  \param uiPinLen           [in]  the length of the Pin data.
<br>
	 *  \param wKeyNum            [in]  the number of the key pairs, must be 1 or 2.
<br>
	 *  \param pbyVerifyPublicKey       [out]  the data of the verify public key
<br>
	 *  \param pwVerifyPubKeyLen        [out]  the length of the verify public key
<br>
	 *  \param pbyWrapPublicKey         [out]  the data of the wrap public key
<br>
	 *  \param pwWrapPublicLen          [out]  the length of the wrap public key
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_BuildAuthDev(SM_DEVICE_HANDLE, PSM_BYTE, SM_UINT, SM_WORD, PSM_BYTE, PSM_WORD, PSM_BYTE, PSM_WORD)</code><br>
	 * @param hDevice in<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * @param wKeyNum in<br>
	 * @param pbyVerifyPublicKey out<br>
	 * @param pwVerifyPubKeyLen out<br>
	 * @param pbyWrapPublicKey out<br>
	 * @param pwWrapPublicLen out<br>
	 * <i>native declaration : sm_api.h:949</i>
	 */
	int SM_BuildAuthDev(Pointer hDevice, ByteBuffer pbyPin, int uiPinLen, short wKeyNum, ByteBuffer pbyVerifyPublicKey, ShortBuffer pwVerifyPubKeyLen, ByteBuffer pbyWrapPublicKey, ShortBuffer pwWrapPublicLen);
	
	/**
	 * D22. SM_ReadAuthDevMem<br>
	 * Original signature : <code>SM_RV SM_ReadAuthDevMem(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataOutLen in<br>
	 * @param pbyDataOut out<br>
	 * <i>native declaration : sm_api.h:961</i>
	 */
	int SM_ReadAuthDevMem(Pointer hDevice, int uiLocation, int uiDataOutLen, ByteBuffer pbyDataOut);
	
	/**
	 * D23. SM_WriteAuthDevMem<br>
	 * Original signature : <code>SM_RV SM_WriteAuthDevMem(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataInLen in<br>
	 * @param pbyDataIn in<br>
	 * <i>native declaration : sm_api.h:969</i>
	 */
	int SM_WriteAuthDevMem(Pointer hDevice, int uiLocation, int uiDataInLen, ByteBuffer pbyDataIn);
	
	/**
	 * D24. SM_ReadAuthDevMem_PIN<br>
	 * Original signature : <code>SM_RV SM_ReadAuthDevMem_PIN(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE, PSM_BYTE, SM_UINT)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataOutLen in<br>
	 * @param pbyDataOut out<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * <i>native declaration : sm_api.h:977</i>
	 */
	int SM_ReadAuthDevMem_PIN(Pointer hDevice, int uiLocation, int uiDataOutLen, ByteBuffer pbyDataOut, ByteBuffer pbyPin, int uiPinLen);
	
	/**
	 * D25. SM_WriteAuthDevMem_PIN<br>
	 * Original signature : <code>SM_RV SM_WriteAuthDevMem_PIN(SM_DEVICE_HANDLE, SM_UINT, SM_UINT, PSM_BYTE, PSM_BYTE, SM_UINT)</code><br>
	 * @param hDevice in<br>
	 * @param uiLocation in<br>
	 * @param uiDataInLen in<br>
	 * @param pbyDataIn in<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * <i>native declaration : sm_api.h:987</i>
	 */
	int SM_WriteAuthDevMem_PIN(Pointer hDevice, int uiLocation, int uiDataInLen, ByteBuffer pbyDataIn, ByteBuffer pbyPin, int uiPinLen);
	
	
    int SM_OpenSecPipe(Pointer hDevice, PointerByReference phPipe);

    int  SM_CloseSecPipe(Pointer hPipe);

    int SM_CloseAllSecPipe(Pointer hDevice);


//    int SM_Login(
//            Pointer hPipe,          /* in  */
//            byte[] pbyPin,         /* in  */
//            int uiPinLen,       /* in  */
//            ShortByReference pwTryNum        /* out */
//    );
	int SM_Login(Pointer hPipe, ByteBuffer pbyPin, int uiPinLen, ShortBuffer pwTryNum);

    int SM_Logout(
            Pointer hPipe          /* in  */
    );


/**
	 * A function, encrypt init.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pstKey               [in]  the pointer of the struct SM_BLOB_KEY
<br>
	 *  \param pstAlgo              [in]  the pointer of the struct SM_ALGORITHM
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_EncryptInit(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_ALGORITHM)</code><br>
	 * <i>native declaration : sm_api.h:1072</i>
	 */
	int SM_EncryptInit(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo);
/**
	 * A function, encrypt update.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pbyDataIn            [in]  the pointer of the plain data
<br>
	 *  \param uiDataInLen          [in]  the length of the plain data
<br>
	 *  \param pbyDataOut           [out] the pointer of the cipher data 
<br>
	 *  \param puiDataOutLen        [out] the pointer of the cipher length 
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_EncryptUpdate(SM_PIPE_HANDLE, PSM_BYTE, SM_UINT, PSM_BYTE, PSM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1090</i>
	 */
	int SM_EncryptUpdate(Pointer hPipe, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);
/**
	 * A function, encrypt final.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param bPad                 [in]  the mode of pad, include
<br>
	 *  \n TRUE, PAD
<br>
	 *  \n FALSE, NO PAD
<br>
	 *  \param pbyDataIn            [in]  the pointer of the plain data
<br>
	 *  \param uiDataInLen          [in]  the length of the plain data
<br>
	 *  \param pbyDataOut           [out] the pointer of the cipher data 
<br>
	 *  \param puiDataOutLen        [out] the pointer of the cipher length 
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_EncryptFinal(SM_PIPE_HANDLE, SM_BOOL, PSM_BYTE, SM_UINT, PSM_BYTE, PSM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1113</i>
	 */
	int SM_EncryptFinal(Pointer hPipe, int bPad, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);
	
	/**
	 * A function, decrypt init.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pstKey               [in]  the pointer of the struct SM_BLOB_KEY
<br>
	 *  \param pstAlgo              [in]  the pointer of the struct SM_ALGORITHM
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DecryptInit(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_ALGORITHM)</code><br>
	 * <i>native declaration : sm_api.h:1132</i>
	 */
	int SM_DecryptInit(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo);
	
/**
	 * A function, decrypt update.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pbyDataIn            [in]  the pointer of the cipher data
<br>
	 *  \param uiDataInLen          [in]  the length of the cipher data
<br>
	 *  \param pbyDataOut           [out] the pointer of the plain data 
<br>
	 *  \param puiDataOutLen        [out] the pointer of the plain length 
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DecryptUpdate(SM_PIPE_HANDLE, PSM_BYTE, SM_UINT, PSM_BYTE, PSM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1150</i>
	 */
	int SM_DecryptUpdate(Pointer hPipe, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);	
	/**
	 * A function, decrypt final.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param bPad                 [in]  the mode of pad, include
<br>
	 *  \n TRUE, PAD
<br>
	 *  \n FALSE, NO PAD
<br>
	 *  \param pbyDataIn            [in]  the pointer of the cipher data
<br>
	 *  \param uiDataInLen          [in]  the length of the cipher data
<br>
	 *  \param pbyDataOut           [out] the pointer of the plain data 
<br>
	 *  \param puiDataOutLen        [out] the pointer of the plain length 
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DecryptFinal(SM_PIPE_HANDLE, SM_BOOL, PSM_BYTE, SM_UINT, PSM_BYTE, PSM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1173</i>
	 */
	int SM_DecryptFinal(Pointer hPipe, int bPad, ByteBuffer pDataIn, int uiDataInLen, ByteBuffer pDataOut, IntBuffer puiDataOutLen);
	
	
	
//    int SM_Encrypt(
//            Pointer hPipe,
//            SM_BLOB_KEY.ByReference pstKey,
//            SM_ALGORITHM.ByReference pstAlgo,
//            int bPad,
//            byte[] pbyDataIn,
//            int uiDataInLen,
//            ByteByReference pbyDataOut,
//            IntByReference puiDataOutLen
//    );
int SM_Encrypt(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo, int bPad, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);

//    int SM_Decrypt(
//            Pointer hPipe,
//            SM_BLOB_KEY.ByReference pstKey,
//            SM_ALGORITHM.ByReference pstAlgo,
//            int bPad,
//            byte[] pbyDataIn,
//            int uiDataInLen,
//            ByteByReference pbyDataOut,
//            IntByReference puiDataOutLen
//    );
int SM_Decrypt(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo, int bPad, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);

/**
	 * A function, digest init.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pstKey               [in]  the pointer of the struct SM_BLOB_KEY
<br>
	 *  \param pstAlgo              [in]  the pointer of the struct SM_ALGORITHM
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DigestInit(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_ALGORITHM)</code><br>
	 * <i>native declaration : sm_api.h:1248</i>
	 */
	int SM_DigestInit(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo);
/**
	 * A function, digest update.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pbyDataIn            [in]  the pointer of the digest data
<br>
	 *  \param uiDataInLen          [in]  the length of the digest data
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DigestUpdate(SM_PIPE_HANDLE, PSM_BYTE, SM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1264</i>
	 */
	int SM_DigestUpdate(Pointer hPipe, ByteBuffer pbyDataIn, int uiDataInLen);	
	
/**
	 * A function, digest final.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pbyDataIn            [in]  the pointer of the digest data
<br>
	 *  \param uiDataInLen          [in]  the length of the digest data
<br>
	 *  \param pbyDigestValue       [out] the pointer of the digest value 
<br>
	 *  \param puiDigestValLen      [out] the pointer of the digest value length 
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DigestFinal(SM_PIPE_HANDLE, PSM_BYTE, SM_UINT, PSM_BYTE, PSM_UINT)</code><br>
	 * <i>native declaration : sm_api.h:1282</i>
	 */
	int SM_DigestFinal(Pointer hPipe, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDigestValue, IntBuffer puiDigestValLen);	
	
	
//    int SM_Digest(
//            Pointer hPipe,
//            SM_BLOB_KEY.ByReference pstKey,
//            SM_ALGORITHM.ByReference pstAlgo,
//            byte[] pbyDataIn,
//            int uiDataInLen,
//            ByteByReference pbyDigestValue,
//            IntByReference puiDigestValLen
//    );

int SM_Digest(Pointer hPipe, SM_BLOB_KEY pstKey, SM_ALGORITHM pstAlgo, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDigestValue, IntBuffer puiDigestValLen);

    int SM_ECCEncrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPubKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            SM_BLOB_ECCCIPHER.ByReference pstEccCipher
    );
	int SM_ECCEncrypt(Pointer hPipe, SM_BLOB_KEY pstPubKey, SM_ALGORITHM pstAlgo, ByteBuffer pbyDataIn, int uiDataInLen, SM_BLOB_ECCCIPHER pstEccCipher);

    int SM_ECCDecrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPriKey,
            SM_ALGORITHM.ByReference pstAlgo,
            SM_BLOB_ECCCIPHER.ByReference pstEccCipher,
            byte[] pbyDataOut,
            int[] puiDataOutLen
    );
int SM_ECCDecrypt(Pointer hPipe, SM_BLOB_KEY pstPriKey, SM_ALGORITHM pstAlgo, SM_BLOB_ECCCIPHER pstEccCipher, ByteBuffer pbyDataOut, IntBuffer puiDataOutLen);


    int SM_ECCSignature(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPriKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            byte[] pbyDataSign,
            int[] puiDataSignLen
    );
int SM_ECCSignature(Pointer hPipe, SM_BLOB_KEY pstPriKey, SM_ALGORITHM pstAlgo, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataSign, IntBuffer puiDataSignLen);


    int SM_ECCVerify(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPubKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            byte[] pbyDataSign,
            int uiDataSignLen
    );
int SM_ECCVerify(Pointer hPipe, SM_BLOB_KEY pstPubKey, SM_ALGORITHM pstAlgo, ByteBuffer pbyDataIn, int uiDataInLen, ByteBuffer pbyDataSign, int uiDataSignLen);

int SM_ECCExchangeKey(Pointer hPipe, short wFlag, ByteBuffer pSelfHashValue, int uiSelfHashValueLen, Pointer hSelfPriKey, Pointer hSelfTempPriKey, ByteBuffer pOpposedHashValue, int uiOpposedHashValueLen, ByteBuffer pOpposedPubKey, int uiOpposedPubKeyLen, ByteBuffer pOpposedTempPubKey, int uiOpposedTempPubKeyLen, ByteBuffer pbySymKey, IntBuffer puiSymKeyLen);



//    int SM_GenRandom(
//            Pointer hPipe,
//            short wRandNo,
//            ByteByReference pbyRandom,
//            int uiRandomLen
//    );
int SM_GenRandom(Pointer hPipe, short wRandNo, ByteBuffer pbyRandom, int uiRandomLen);

	/**
	 * A function, backupauthdev.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pbyPin               [in]  the pointer of the pin
<br>
	 *  \param uiPinLen              [in]  the length of the pin
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_BackupAuthDev(SM_PIPE_HANDLE, PSM_BYTE, SM_UINT)</code><br>
	 * @param hPipe in<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * <i>native declaration : sm_api.h:1450</i>
	 */
	int SM_BackupAuthDev(Pointer hPipe, ByteBuffer pbyPin, int uiPinLen);
	
/**
	 * A function, update asymkey pair to device.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pstPublicKey         [in]  the pointer of the pin
<br>
	 *  \param pstPrivateKey        [in]  the length of the pin
<br>
	 *  \param wKeyFlag				[in]  0 - sign&verify key pair
<br>
	 * 1 - enc&dec key pair
<br>
	 *  \param pbyPin				[in]  the pointer of the pin
<br>
	 *  \param uiPinLen			    [in]  the length of the pin
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_UpdateKeyPair(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_BLOB_KEY, SM_WORD, PSM_BYTE, SM_UINT)</code><br>
	 * @param hPipe in<br>
	 * @param pstPublicKey in<br>
	 * @param pstPrivateKey in<br>
	 * @param wKeyFlag in<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * <i>native declaration : sm_api.h:1469</i>
	 */
	int SM_UpdateKeyPair(Pointer hPipe, SM_BLOB_KEY pstPublicKey, SM_BLOB_KEY pstPrivateKey, short wKeyFlag, ByteBuffer pbyPin, int uiPinLen);


/**
	 * A function, update config symmkey to device.
<br>
	 *  \param hPipe                [in]  the handle of the pipe
<br>
	 *  \param pstKey         [in]  the pointer of the pin
<br>
	 *  \param pbyPin				[in]  the pointer of the pin
<br>
	 *  \param uiPinLen			    [in]  the length of the pin
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_UpdateKey(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_BYTE, SM_UINT)</code><br>
	 * @param hPipe in<br>
	 * @param pstKey in<br>
	 * @param pbyPin in<br>
	 * @param uiPinLen in<br>
	 * <i>native declaration : sm_api.h:1487</i>
	 */
	int SM_UpdateKey(Pointer hPipe, SM_BLOB_KEY pstKey, ByteBuffer pbyPin, int uiPinLen);
	
		/**
	 * K1. SM_GetCfgKeyHandle<br>
	 * Original signature : <code>SM_RV SM_GetCfgKeyHandle(SM_PIPE_HANDLE, PSM_BLOB_KEY, PSM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param pstKey in<br>
	 * @param phKey out<br>
	 * <i>native declaration : sm_api.h:1494</i>
	 */
	int SM_GetCfgKeyHandle(Pointer hPipe, SM_BLOB_KEY pstKey, PointerByReference phKey);
	
	/**
	 * K2. SM_GetKeyHdlID<br>
	 * Original signature : <code>SM_RV SM_GetKeyHdlID(SM_PIPE_HANDLE, SM_KEY_HANDLE, PSM_WORD)</code><br>
	 * @param hPipe in<br>
	 * @param hKey in<br>
	 * @param pwKeyHandleID out<br>
	 * <i>native declaration : sm_api.h:1501</i>
	 */
	int SM_GetKeyHdlID(Pointer hPipe, Pointer hKey, ShortBuffer pwKeyHandleID);
	
	/**
	 * K3. SM_GetKeyAttribute<br>
	 * Original signature : <code>SM_RV SM_GetKeyAttribute(SM_PIPE_HANDLE, SM_KEY_HANDLE, PSM_KEY_ATTRIBUTE)</code><br>
	 * @param hPipe in<br>
	 * @param hKey in<br>
	 * @param pstKeyAttr out<br>
	 * <i>native declaration : sm_api.h:1508</i>
	 */
	int SM_GetKeyAttribute(Pointer hPipe, Pointer hKey, SM_KEY_ATTRIBUTE pstKeyAttr);
	
	/**
	 * K6. SM_CloseTokKeyHdl<br>
	 * Original signature : <code>SM_RV SM_CloseTokKeyHdl(SM_PIPE_HANDLE, SM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param hKey in<br>
	 * <i>native declaration : sm_api.h:1515</i>
	 */
	int SM_CloseTokKeyHdl(Pointer hPipe, Pointer hKey);
	
	
    int SM_GenerateKey(
            Pointer hPipe,          /* in  */
            SM_KEY_ATTRIBUTE.ByReference pstKeyAttr,     /* in  */
            PointerByReference phKey           /* out */
    );
//    int SM_ExportKey(
//            Pointer      hPipe,          /* in  */
//            Pointer       hKey,           /* in  */
//            Pointer       hKEK,           /* in  */
//            SM_ALGORITHM.ByReference       pstKEKAlgo,     /* in  */
//            byte[]            pbyKey,         /* in/out */
//            ShortByReference            pwKeyLen        /* out */
//    );
	int SM_ExportKey(Pointer hPipe, Pointer hKey, Pointer hKEK, SM_ALGORITHM pstKEKAlgo, ByteBuffer pbyKey, ShortBuffer pwKeyLen);

//    int SM_ImportKey(
//            Pointer      hPipe,          /* in  */
//            byte[]            pbyKey,         /* in  */
//            short             wKeyLen,        /* in  */
//            Pointer       hKEK,           /* in  */
//            SM_ALGORITHM.ByReference       pstKEKAlgo,     /* in  */
//            SM_KEY_ATTRIBUTE.ByReference   pstKeyAttr,     /* in  */
//            PointerByReference      phKey           /* out */
//    );
int SM_ImportKey(Pointer hPipe, ByteBuffer pbyKey, short wKeyLen, Pointer hKEK, SM_ALGORITHM pstKEKAlgo, SM_KEY_ATTRIBUTE pstKeyAttr, PointerByReference phKey);

    int SM_DestroyKey(
            Pointer      hPipe,          /* in  */
            Pointer      hKey            /* in  */
    );

	
	/**
	 * K12. SM_GenerateKeyPair<br>
	 * Original signature : <code>SM_RV SM_GenerateKeyPair(SM_PIPE_HANDLE, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param pstPubKeyAttr in<br>
	 * @param phPublicKey out<br>
	 * @param pstPriKeyAttr in<br>
	 * @param phPrivateKey out<br>
	 * <i>native declaration : sm_api.h:1588</i>
	 */
	int SM_GenerateKeyPair(Pointer hPipe, SM_KEY_ATTRIBUTE.ByReference pstPubKeyAttr, PointerByReference phPublicKey,
						                  SM_KEY_ATTRIBUTE.ByReference pstPriKeyAttr, PointerByReference phPrivateKey);
	
	/**
	 * K13 SM_GenerateKeyPair_CP<br>
	 * Original signature : <code>SM_RV SM_GenerateKeyPair_CP(SM_PIPE_HANDLE, PSM_KEY_ATTRIBUTE, PSM_BYTE, PSM_WORD, PSM_KEY_ATTRIBUTE, PSM_BYTE, PSM_WORD)</code><br>
	 * @param hPipe in<br>
	 * @param pstPubKeyAttr in<br>
	 * @param pbyPublicKey out<br>
	 * @param pwPubKeyLen out<br>
	 * @param pstPriKeyAttr in<br>
	 * @param pbyPrivateKey out<br>
	 * @param pwPriKeyLen out<br>
	 * <i>native declaration : sm_api.h:1597</i>
	 */
	int SM_GenerateKeyPair_CP(Pointer hPipe, SM_KEY_ATTRIBUTE pstPubKeyAttr, ByteBuffer pbyPublicKey, ShortBuffer pwPubKeyLen, SM_KEY_ATTRIBUTE pstPriKeyAttr, ByteBuffer pbyPrivateKey, ShortBuffer pwPriKeyLen);
	
	/**
	 * A function, import public key.
<br>
	 *  \param hPipe              [in]  the handle of the pipe
<br>
	 *  \param pbyPublicKey       [in]  the data of the public key
<br>
	 *  \param wPubKeyLen         [in]  the length of the public key
<br>
	 *  \param pstPubKeyAttr      [in]  the pointer of the public key struct
<br>
	 *  \param phPublicKey        [out]  the handle of the public key
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_ImportPublicKey(SM_PIPE_HANDLE, PSM_BYTE, SM_WORD, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param pbyPublicKey in<br>
	 * @param wPubKeyLen in<br>
	 * @param pstPubKeyAttr in<br>
	 * @param phPublicKey out<br>
	 * <i>native declaration : sm_api.h:1618</i>
	 */
	int SM_ImportPublicKey(Pointer hPipe, ByteBuffer pbyPublicKey, short wPubKeyLen, SM_KEY_ATTRIBUTE pstPubKeyAttr, PointerByReference phPublicKey);
	
	
	/**
	 * A function, import private key.
<br>
	 *  \param hPipe              [in]  the handle of the pipe
<br>
	 *  \param pbyPrivateKey      [in]  the data of the private key
<br>
	 *  \param wPriKeyLen         [in]  the length of the private key
<br>
	 *  \param hKEK               [in]  the KEK key
<br>
	 *  \param pstKEKAlgo         [in]  the KEK algorithm
<br>
	 *  \param pstPubKeyAttr      [in]  the pointer of the private key struct
<br>
	 *  \param phPublicKey        [out]  the handle of the private key
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_ImportPrivateKey(SM_PIPE_HANDLE, PSM_BYTE, SM_WORD, SM_KEY_HANDLE, PSM_ALGORITHM, PSM_KEY_ATTRIBUTE, PSM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param pbyPrivateKey in<br>
	 * @param wPriKeyLen in<br>
	 * @param hKEK in<br>
	 * @param pstKEKAlgo in<br>
	 * @param pstPriKeyAttr in<br>
	 * @param phPrivateKey out<br>
	 * <i>native declaration : sm_api.h:1640</i>
	 */
	int SM_ImportPrivateKey(Pointer hPipe, ByteBuffer pbyPrivateKey, short wPriKeyLen, Pointer hKEK, SM_ALGORITHM pstKEKAlgo, SM_KEY_ATTRIBUTE pstPriKeyAttr, PointerByReference phPrivateKey);
	
	
	/**
	 * K16. SM_ExportPublicKey<br>
	 * Original signature : <code>SM_RV SM_ExportPublicKey(SM_PIPE_HANDLE, SM_KEY_HANDLE, PSM_BYTE, PSM_WORD)</code><br>
	 * @param hPipe in<br>
	 * @param hPublicKey in<br>
	 * @param pbyPubKey out<br>
	 * @param pwPubKeyLen out<br>
	 * <i>native declaration : sm_api.h:1652</i>
	 */
	int SM_ExportPublicKey(Pointer hPipe, Pointer hPublicKey, ByteBuffer pbyPubKey, ShortBuffer pwPubKeyLen);
	/**
	 * K17. SM_ExportPrivateKey<br>
	 * Original signature : <code>SM_RV SM_ExportPrivateKey(SM_PIPE_HANDLE, SM_KEY_HANDLE, SM_KEY_HANDLE, PSM_ALGORITHM, PSM_BYTE, PSM_WORD)</code><br>
	 * @param hPipe in<br>
	 * @param hPrivateKey in<br>
	 * @param hKEK in<br>
	 * @param pstKEKAlgo in<br>
	 * @param pbyPriKey out<br>
	 * @param pwPriKeyLen out<br>
	 * <i>native declaration : sm_api.h:1660</i>
	 */
	int SM_ExportPrivateKey(Pointer hPipe, Pointer hPrivateKey, Pointer hKEK, SM_ALGORITHM pstKEKAlgo, ByteBuffer pbyPriKey, ShortBuffer pwPriKeyLen);
	
	/**
	 * A function, destroy public key.
<br>
	 *  \param hPipe              [in]  the handle of the pipe
<br>
	 *  \param hPublicKey         [in]  the handle of the public key
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DestroyPublicKey(SM_PIPE_HANDLE, SM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param hPublicKey in<br>
	 * <i>native declaration : sm_api.h:1677</i>
	 */
	int SM_DestroyPublicKey(Pointer hPipe, Pointer hPublicKey);
	/**
	 * A function, destroy private key.
<br>
	 *  \param hPipe              [in]  the handle of the pipe
<br>
	 *  \param hPrivateKey        [in]  the handle of the private key
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DestroyPrivateKey(SM_PIPE_HANDLE, SM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param hPrivateKey in<br>
	 * <i>native declaration : sm_api.h:1691</i>
	 */
	int SM_DestroyPrivateKey(Pointer hPipe, Pointer hPrivateKey);
	
	/**
	 * A function, destroy private key.
<br>
	 *  \param hPipe              [in]  the handle of the pipe
<br>
	 *  \param uIKeyID			 [in]  the key ID got from SM_GetKeyHdlID
<br>
	 *  \param wObjectClass	     [in]  the object class of the key
<br>
	 *  \param phKey	             [out] the duplicated key handle
<br>
	 *  \return 0-ok, !0-fail.
<br>
	 *  \warning none.<br>
	 * Original signature : <code>SM_RV SM_DuplicateKeyHandle(SM_PIPE_HANDLE, SM_WORD, SM_WORD, PSM_KEY_HANDLE)</code><br>
	 * @param hPipe in<br>
	 * @param uIKeyID in<br>
	 * @param wObjectClass in<br>
	 * @param phKey out<br>
	 * <i>native declaration : sm_api.h:1707</i>
	 */
	int SM_DuplicateKeyHandle(Pointer hPipe, short uIKeyID, short wObjectClass, PointerByReference phKey);
	
	
	
    public static class SM_MECHANISM_INFO extends Structure {

        public int uiMinBlockSize;
        public int uiMaxBlockSize;
        public int uiMinKeySize;
        public int uiMaxKeySize;
        /**
         * A member variable.
         * The function of algorithm, include
         * 0x00000001, algorithm using for encrypt
         * 0x00000002, algorithm using for decrypt
         * 0x00000004, algorithm using for digest
         * 0x00000008, algorithm using for sign(mac)
         * 0x00000010, algorithm using for verify(mac)
         * 0x00000020, algorithm using for wrap
         * 0x00000040, algorithm using for unwrap
         */
        public int uiFlags;

		public SM_MECHANISM_INFO() {
			super();
		}
	
        public static class ByReference extends SM_MECHANISM_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_MECHANISM_INFO implements Structure.ByValue{		};


        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMinBlockSize", "uiMaxBlockSize", "uiMinKeySize","uiMaxKeySize","uiFlags");
        }
		
		/**
		 * @param uiMinBlockSize C type : SM_UINT<br>
		 * @param uiMaxBlockSize C type : SM_UINT<br>
		 * @param uiMinKeySize C type : SM_UINT<br>
		 * @param uiMaxKeySize C type : SM_UINT<br>
		 * @param uiFlags C type : SM_UINT
		 */
		public SM_MECHANISM_INFO(int uiMinBlockSize, int uiMaxBlockSize, int uiMinKeySize, int uiMaxKeySize, int uiFlags) {
			super();
			this.uiMinBlockSize = uiMinBlockSize;
			this.uiMaxBlockSize = uiMaxBlockSize;
			this.uiMinKeySize = uiMinKeySize;
			this.uiMaxKeySize = uiMaxKeySize;
			this.uiFlags = uiFlags;
		}
		public SM_MECHANISM_INFO(Pointer peer) {
			super(peer);
		}


    }

    public static class SM_DEVICE_INFO extends Structure {

        /**
         * 
         * the struct resource info of device.
         */
        public SM_RESOURCE_INFO    stDevResourceInfo;
        /**
         * 
         * the struct mechanism info of device.
         */
        public SM_MANUFCT_INFO     stManufactureInfo;
        /**
         * 
         * the flags of the device, include
         * \n F_EXCLUSIVE                    0x00000001
         * \n F_DEV_LEVEL                    0x00000002
         * \n F_RNG                          0x00000004
         * \n F_CLOCK                        0x00000008
         * \n F_AUTHDEV_REQUIRED             0x00000010
         * \n F_LOGIN_REQUIRED               0x00000020
         * \n F_USER_PIN_INITIALIZED         0x00000040
         * \n F_RESTORE_KEY_NOT_NEEDED       0x00000080
         * \n F_RESOURCE_INITIALIZED         0x00000100
         * \n F_USER_PIN_COUNT_LOW           0x00000200
         * \n F_USER_PIN_LOCKED              0x00000400
         * \n F_SO_PIN_COUNT_LOW             0x00000800
         * \n F_SO_PIN_LOCKED                0x00001000
         * \n --    Bit[31:13]
         */
        public int             uiFlags;
        /**
         * A member variable.
         * the status of the device, include
         * \n F_PY_CHUCHANG               0x00000000
         * \n F_PY_GONGZUO                0x00000001
         * \n F_PY_RUKU                   0x00000002
         */
        public int             uiStatus;
		public SM_DEVICE_INFO() {
				super();
			}
	
        public static class ByReference extends SM_DEVICE_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_DEVICE_INFO implements Structure.ByValue{		};

		/**
		 * @param stDevResourceInfo C type : SM_RESOURCE_INFO<br>
		 * @param stManufactureInfo C type : SM_MANUFCT_INFO<br>
		 * @param uiFlags C type : SM_UINT<br>
		 * @param uiStatus C type : SM_UINT
		 */
		public SM_DEVICE_INFO(SM_RESOURCE_INFO stDevResourceInfo, SM_MANUFCT_INFO stManufactureInfo, int uiFlags, int uiStatus) {
			super();
			this.stDevResourceInfo = stDevResourceInfo;
			this.stManufactureInfo = stManufactureInfo;
			this.uiFlags = uiFlags;
			this.uiStatus = uiStatus;
		}
		public SM_DEVICE_INFO(Pointer peer) {
			super(peer);
		}
	
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("stDevResourceInfo", "stManufactureInfo", "uiFlags","uiStatus");
        }

    }


    public static class SM_RESOURCE_INFO extends Structure
    {
        /**
         * the buffer size of the transfer.
         */
        public int         uiHPIBufSize;

        /**
         * the maximal number of pipe.
         */
        public short         wMaxPipeCount;
        /**
         * the left number of pipe.
         */
        public short         wFreePipeCount;
        /**
         * the maximal number of secret key object.
         * include token object and session object.
         */
        public short         wMaxSecretKeyCount;
        /**
         * the left number of secret key object.
         * include token object and session object.
         */
        public short         wFreeSecretKeyCount;
        /**
         * the maximal number of public key object.
         * include token object and session object.
         */
        public short         wMaxPublicKeyCount;
        /**
         * the left number of public key object.
         * \n include token object and session object.
         */
        public short         wFreePublicKeyCount;
        /**
         * the maximal number of private key object.
         * \n include token object and session object.
         */
        public short         wMaxPrivateKeyCount;
        /**
         * the left number of private key object.
         * \n include token object and session object.
         */
        public short         wFreePrivateKeyCount;

        /**
         * A member variable.
         * the maximal number of secret key token object.
         */
        public short         wMaxSecretKeyTokenCount;
        /**
         * A member variable.
         * the left number of secret key token object.
         */
        public short         wFreeSecretKeyTokenCount;
        /**
         * A member variable.
         * the maximal number of public key token object.
         */
        public short         wMaxPublicKeyTokenCount;
        /**
         * A member variable.
         * the left number of public key token object.
         */
        public short         wFreePublicKeyTokenCount;
        /**
         * A member variable.
         * the maximal number of private key token object.
         */
        public short         wMaxPrivateKeyTokenCount;
        /**
         * A member variable.
         * the left number of private key token object.
         */
        public short         wFreePrivateKeyTokenCount;

        /**
         * A member variable.
         * the device NVMem info.
         */
        public SM_NVMEM_INFO.ByValue   stNVMem;

        /**
         * A member variable.
         * the device ADMem info.
         */
        public SM_ADMEM_INFO.ByValue   stADMem;

        /**
         * A member variable.
         * the maximal length of user pin.
         */
        public short         wMaxPinLen;
        /**
         * A member variable.
         * the minimum length of user pin.
         */
        public short         wMinPinLen;
        /**
         * A member variable.
         * the maximal length of SO pin.
         */
        public short         wMaxSOPinLen;
        /**
         * A member variable.
         * the minimum length of SO pin.
         */
        public short         wMinSOPinLen;
        /**
         * A member variable.
         * the version of the device hardware.
         * \n the high 8bits is major version,
         * \n the low  8bits is minor version.
         * \n Example: 0102, the major is 1, the minor is 2.
         */
        public short         wHardwareVersion;
        /**
         * A member variable.
         * the version of the device firmware.
         * \n the high 8bits is major version,
         * \n the low  8bits is minor version.
         * \n Example: 0102, the major is 1, the minor is 2.
         */
        public short         wFirmwareVersion;

		public SM_RESOURCE_INFO() {
			super();
		}
	
		public SM_RESOURCE_INFO(Pointer peer) {
			super(peer);
		}
	
        public static class ByReference extends SM_RESOURCE_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_RESOURCE_INFO implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiHPIBufSize", "wMaxPipeCount", "wFreePipeCount", "wMaxSecretKeyCount", "wFreeSecretKeyCount", "wMaxPublicKeyCount", "wFreePublicKeyCount", "wMaxPrivateKeyCount", "wFreePrivateKeyCount", "wMaxSecretKeyTokenCount", "wFreeSecretKeyTokenCount", "wMaxPublicKeyTokenCount", "wFreePublicKeyTokenCount", "wMaxPrivateKeyTokenCount", "wFreePrivateKeyTokenCount", "stNVMem", "stADMem", "wMaxPinLen", "wMinPinLen", "wMaxSOPinLen", "wMinSOPinLen", "wHardwareVersion", "wFirmwareVersion");
        }
    }

    public static class SM_NVMEM_INFO extends Structure
    {
        /**
         * the maximal size of the NVMem.
         */
        public int         uiMaxNVMemSize;
        /**
         * the sector size of the NVMem.
         */
        public int         uiNVMemSectorSize;

		public SM_NVMEM_INFO() {
			super();
		}
	
        public static class ByReference extends SM_NVMEM_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_NVMEM_INFO implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMaxNVMemSize","uiNVMemSectorSize");
        }
		
		/**
		 * @param uiMaxNVMemSize C type : SM_UINT<br>
		 * @param uiNVMemSectorSize C type : SM_UINT
		 */
		public SM_NVMEM_INFO(int uiMaxNVMemSize, int uiNVMemSectorSize) {
			super();
			this.uiMaxNVMemSize = uiMaxNVMemSize;
			this.uiNVMemSectorSize = uiNVMemSectorSize;
		}
		public SM_NVMEM_INFO(Pointer peer) {
			super(peer);
		}
    }

    public static class SM_ADMEM_INFO extends Structure
    {
        /**
         *
         * the maximal size of the AuthDevMem1.
         */
        public int         uiMaxAuthDevMem1Size;
        /**
         *
         * the maximal size of the AuthDevMem2.
         */
        public int         uiMaxAuthDevMem2Size;

		public SM_ADMEM_INFO() {
			super();
		}
	
        public static class ByReference extends SM_ADMEM_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_ADMEM_INFO implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMaxAuthDevMem1Size","uiMaxAuthDevMem2Size");
        }
		
		/**
		 * @param uiMaxAuthDevMem1Size C type : SM_UINT<br>
		 * @param uiMaxAuthDevMem2Size C type : SM_UINT
		 */
		public SM_ADMEM_INFO(int uiMaxAuthDevMem1Size, int uiMaxAuthDevMem2Size) {
			super();
			this.uiMaxAuthDevMem1Size = uiMaxAuthDevMem1Size;
			this.uiMaxAuthDevMem2Size = uiMaxAuthDevMem2Size;
		}
		public SM_ADMEM_INFO(Pointer peer) {
			super(peer);
		}
    }


    public static class SM_MANUFCT_INFO extends Structure
    {
        /**
         *
         * the model name of the device.
         */
        public byte[]         byModel=new byte[16];
        /**
         *
         * the product name of the device.
         */
        public byte[]         byManufacturerID=new byte[32];
        /**
         *
         * the product date of the device.
         */
        public byte[]          byManufactureDate=new byte[4];
        /**
         *
         * the batch of the device.
         */
        public byte[]          byBatch=new byte[4];
        /**
         *
         * the HUID of the device.
         */
        public byte[]          bySerial=new byte[16];
        /**
         *
         * the data time of the hardware.
         */
        public byte[]          byDateTime=new byte[8];

        public static class ByReference extends SM_MANUFCT_INFO implements Structure.ByReference{					};
        public static class ByValue extends SM_MANUFCT_INFO implements Structure.ByValue{		};

		public SM_MANUFCT_INFO() {
			super();
		}
	
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("byModel","byManufacturerID","byManufactureDate","byBatch","bySerial","byDateTime");
        }
		
		/**
		 * @param byModel C type : SM_BYTE[16]<br>
		 * @param byManufacturerID C type : SM_BYTE[32]<br>
		 * @param byManufactureDate C type : SM_BYTE[4]<br>
		 * @param byBatch C type : SM_BYTE[4]<br>
		 * @param bySerial C type : SM_BYTE[16]<br>
		 * @param byDateTime C type : SM_BYTE[8]
		 */
		public SM_MANUFCT_INFO(byte byModel[], byte byManufacturerID[], byte byManufactureDate[], byte byBatch[], byte bySerial[], byte byDateTime[]) {
			super();
			if ((byModel.length != this.byModel.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byModel = byModel;
			if ((byManufacturerID.length != this.byManufacturerID.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byManufacturerID = byManufacturerID;
			if ((byManufactureDate.length != this.byManufactureDate.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byManufactureDate = byManufactureDate;
			if ((byBatch.length != this.byBatch.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byBatch = byBatch;
			if ((bySerial.length != this.bySerial.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.bySerial = bySerial;
			if ((byDateTime.length != this.byDateTime.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byDateTime = byDateTime;
		}
		public SM_MANUFCT_INFO(Pointer peer) {
			super(peer);
		}
	}


    public static class SM_BLOB_KEY extends Structure
    {
        /**
         *
         * The length of data
         */
        public int         uiDataLen;
        /**
         *
         * The pointer of data  C type : PSM_BYTE 
         */
        public Pointer        pbyData;

		public SM_BLOB_KEY() {
			super();
		}
	
        public static class ByReference extends SM_BLOB_KEY implements Structure.ByReference{					};
        public static class ByValue extends SM_BLOB_KEY implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiDataLen","pbyData");
        }
		
		/**
		 * @param uiDataLen C type : SM_UINT<br>
		 * @param pbyData C type : PSM_BYTE
		 */
		public SM_BLOB_KEY(int uiDataLen, Pointer pbyData) {
			super();
			this.uiDataLen = uiDataLen;
			this.pbyData = pbyData;
		}
		public SM_BLOB_KEY(Pointer peer) {
			super(peer);
		}
    }


    public static class SM_BLOB_ECCCIPHER extends Structure
    {
        /**
         *
         * The length of session key
         */
        public int         uiSessionKeyLen;
        /**
         *
         * The length of cipher data
         */
        public int         uiCipherDataLen;
        /**
         *
         * The length of check data
         */
        public int         uiCheckDataLen;
        /**
         * C type : PSM_BYTE 
         * The pointer of data
         */
        public Pointer        pbyData;

		public SM_BLOB_ECCCIPHER() {
			super();
		}

        public static class ByReference extends SM_BLOB_ECCCIPHER implements Structure.ByReference{					};
        public static class ByValue extends SM_BLOB_ECCCIPHER implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiSessionKeyLen", "uiCipherDataLen", "uiCheckDataLen", "pbyData");
        }
		
		/**
		 * @param uiSessionKeyLen C type : SM_UINT<br>
		 * @param uiCipherDataLen C type : SM_UINT<br>
		 * @param uiCheckDataLen C type : SM_UINT<br>
		 * @param pbyData C type : PSM_BYTE
		 */
		public SM_BLOB_ECCCIPHER(int uiSessionKeyLen, int uiCipherDataLen, int uiCheckDataLen, Pointer pbyData) {
			super();
			this.uiSessionKeyLen = uiSessionKeyLen;
			this.uiCipherDataLen = uiCipherDataLen;
			this.uiCheckDataLen = uiCheckDataLen;
			this.pbyData = pbyData;
		}
		public SM_BLOB_ECCCIPHER(Pointer peer) {
			super(peer);
		}
    }

    public static class SM_KEY_ATTRIBUTE extends Structure{
        /**
         * The type of object
         */
        public int         uiObjectClass;
        /**
         * The type of key
         */
        public int     KeyType;
        /**
         * The label of key
         */
        public int         uiKeyLabel;
        /**
         * The start data of key
         */
        public byte[]         byStartDate=new byte[4];
        /**
         * The end data of key
         */
        public byte[]         byEndDate=new byte[4];
        /**
         * The attribute flag of key
         */
        public int         uiFlags;
        /**
         * The parameter of key
         */
        public WstbApi.SM_ECC_PARAMETER.ByReference        pParameter; // Pointer
        /**
         * The parameter length of key
         */
        public int         uiParameterLen;

		public SM_KEY_ATTRIBUTE() {
			super();
		}

        public static class ByReference extends SM_KEY_ATTRIBUTE implements Structure.ByReference{					};
        public static class ByValue extends SM_KEY_ATTRIBUTE implements Structure.ByValue{		};
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiObjectClass","KeyType","uiKeyLabel","byStartDate","byEndDate","uiFlags","pParameter","uiParameterLen");
        }
		
		/**
		 * @param uiObjectClass C type : SM_UINT<br>
		 * @param KeyType C type : SM_KEY_TYPE<br>
		 * @param uiKeyLabel C type : SM_UINT<br>
		 * @param byStartDate C type : SM_BYTE[4]<br>
		 * @param byEndDate C type : SM_BYTE[4]<br>
		 * @param uiFlags C type : SM_UINT<br>
		 * @param pParameter C type : PSM_VOID<br>
		 * @param uiParameterLen C type : SM_UINT
		 */
		public SM_KEY_ATTRIBUTE(int uiObjectClass, int KeyType, int uiKeyLabel, byte byStartDate[], byte byEndDate[], int uiFlags,
								WstbApi.SM_ECC_PARAMETER.ByReference pParameter, int uiParameterLen) {
			super();
			this.uiObjectClass = uiObjectClass;
			this.KeyType = KeyType;
			this.uiKeyLabel = uiKeyLabel;
			if ((byStartDate.length != this.byStartDate.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byStartDate = byStartDate;
			if ((byEndDate.length != this.byEndDate.length)) {
				throw new IllegalArgumentException("Wrong array size !");
			}
			this.byEndDate = byEndDate;
			this.uiFlags = uiFlags;
			this.pParameter = pParameter;
			this.uiParameterLen = uiParameterLen;
		}
		public SM_KEY_ATTRIBUTE(Pointer peer) {
			super(peer);
		}
    }

    public static class SM_ALGORITHM extends Structure{
        /**
         *
         * The type of algorithm
         */
        public int   AlgoType;
        /**
         *
         * The parameter of algorithm
         */
        public Pointer           pParameter;
        /**
         *
         * The length of parameter
         */
        public int             uiParameterLen;
        /**
         *
         * The reserve data of algorithm
         */
        public int             uiReserve;

		public SM_ALGORITHM() {
			super();
		}
	
        public static class ByReference extends SM_ALGORITHM implements Structure.ByReference{					};
        public static class ByValue extends SM_ALGORITHM implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("AlgoType","pParameter","uiParameterLen","uiReserve");
        }
		/**
		 * @param AlgoType C type : SM_ALGORITHM_TYPE<br>
		 * @param pParameter C type : PSM_VOID<br>
		 * @param uiParameterLen C type : SM_UINT<br>
		 * @param uiReserve C type : SM_UINT
		 */
		public SM_ALGORITHM(int AlgoType, Pointer pParameter, int uiParameterLen, int uiReserve) {
			super();
			this.AlgoType = AlgoType;
			this.pParameter = pParameter;
			this.uiParameterLen = uiParameterLen;
			this.uiReserve = uiReserve;
		}
		public SM_ALGORITHM(Pointer peer) {
			super(peer);
		}
    }


    public static class SM_ECC_PARAMETER extends Structure
    {
        /**
         * The modulus bit of ECC
         */
        public int         uiModulusBits;
        /**
         * The parameter of ECC
         */
        public Pointer        pParameter;
        /**
         * The parameter length of ECC
         */
        public int         uiParameterLen;

		public SM_ECC_PARAMETER() {
			super();
		}
	
        public static class ByReference extends SM_ECC_PARAMETER implements Structure.ByReference{					};
        public static class ByValue extends SM_ECC_PARAMETER implements Structure.ByValue{		};

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiModulusBits","pParameter","uiParameterLen");
        }
		
		/**
		 * @param uiModulusBits C type : SM_UINT<br>
		 * @param pParameter C type : PSM_VOID<br>
		 * @param uiParameterLen C type : SM_UINT
		 */
		public SM_ECC_PARAMETER(int uiModulusBits, Pointer pParameter, int uiParameterLen) {
			super();
			this.uiModulusBits = uiModulusBits;
			this.pParameter = pParameter;
			this.uiParameterLen = uiParameterLen;
		}
		public SM_ECC_PARAMETER(Pointer peer) {
			super(peer);
		}

    }
}


