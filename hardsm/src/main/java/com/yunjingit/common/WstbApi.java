package com.yunjingit.common;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;

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

    String SM_GetErrorString(int uiErrCode, int bChinese);

    String SM_GetAPIVersion();

    int SM_GetDeviceType(IntByReference puiDeviceType);

    int  SM_OpenDevice(int uiDevID, int bExclusive, PointerByReference phDevice);

    int SM_CloseDevice(Pointer hDevice);

    int SM_GetMechanismList(Pointer hDevice, IntByReference puiMechanismList, ShortByReference pwMechanismNum);


    int SM_GetMechanismInfo(Pointer hDevice, int uiMechanism, SM_MECHANISM_INFO.ByReference pstMech);

    int SM_TestDevice(Pointer hDevice, IntByReference puiResult);

    int SM_GetDeviceInfo(Pointer hDevice, SM_DEVICE_INFO.ByReference pstDeviceInfo);

    int SM_GetDeviceIndex(Pointer hDevice, int[] puiDeviceIndex);


    int SM_DestroySensitiveInfo(Pointer hDevice, int uiType);

    int SM_CommTest(Pointer hDevice);

    int SM_OpenSecPipe(Pointer hDevice, PointerByReference phPipe);

    int  SM_CloseSecPipe(Pointer hPipe);

    int SM_CloseAllSecPipe(Pointer hDevice);


    int SM_Login(
            Pointer hPipe,          /* in  */
            byte[] pbyPin,         /* in  */
            int uiPinLen,       /* in  */
            ShortByReference pwTryNum        /* out */
    );


    int SM_Logout(
            Pointer hPipe          /* in  */
    );





    int SM_Encrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstKey,
            SM_ALGORITHM.ByReference pstAlgo,
            int bPad,
            byte[] pbyDataIn,
            int uiDataInLen,
            ByteByReference pbyDataOut,
            IntByReference puiDataOutLen
    );


    int SM_Decrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstKey,
            SM_ALGORITHM.ByReference pstAlgo,
            int bPad,
            byte[] pbyDataIn,
            int uiDataInLen,
            ByteByReference pbyDataOut,
            IntByReference puiDataOutLen
    );



    int SM_Digest(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            ByteByReference pbyDigestValue,
            IntByReference puiDigestValLen
    );



    int SM_ECCEncrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPubKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            SM_BLOB_ECCCIPHER.ByReference pstEccCipher
    );


    int SM_ECCDecrypt(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPriKey,
            SM_ALGORITHM.ByReference pstAlgo,
            SM_BLOB_ECCCIPHER.ByReference pstEccCipher,
            byte[] pbyDataOut,
            int[] puiDataOutLen
    );



    int SM_ECCSignature(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPriKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            byte[] pbyDataSign,
            int[] puiDataSignLen
    );



    int SM_ECCVerify(
            Pointer hPipe,
            SM_BLOB_KEY.ByReference pstPubKey,
            SM_ALGORITHM.ByReference pstAlgo,
            byte[] pbyDataIn,
            int uiDataInLen,
            byte[] pbyDataSign,
            int uiDataSignLen
    );


    int SM_GenRandom(
            Pointer hPipe,
            short wRandNo,
            ByteByReference pbyRandom,
            int uiRandomLen
    );


    int SM_GenerateKey(
            Pointer hPipe,          /* in  */
            SM_KEY_ATTRIBUTE.ByReference pstKeyAttr,     /* in  */
            PointerByReference phKey           /* out */
    );


    int SM_ExportKey(
            Pointer      hPipe,          /* in  */
            Pointer       hKey,           /* in  */
            Pointer       hKEK,           /* in  */
            SM_ALGORITHM.ByReference       pstKEKAlgo,     /* in  */
            byte[]            pbyKey,         /* in/out */
            ShortByReference            pwKeyLen        /* out */
    );


    int SM_ImportKey(
            Pointer      hPipe,          /* in  */
            byte[]            pbyKey,         /* in  */
            short             wKeyLen,        /* in  */
            Pointer       hKEK,           /* in  */
            SM_ALGORITHM.ByReference       pstKEKAlgo,     /* in  */
            SM_KEY_ATTRIBUTE.ByReference   pstKeyAttr,     /* in  */
            PointerByReference      phKey           /* out */
    );


    int SM_DestroyKey(
            Pointer      hPipe,          /* in  */
            Pointer      hKey            /* in  */
    );

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

        public static class ByReference extends SM_MECHANISM_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_MECHANISM_INFO implements Structure.ByValue{		}


        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMinBlockSize", "uiMaxBlockSize", "uiMinKeySize","uiMaxKeySize","uiFlags");
        }


    }

    public static class SM_DEVICE_INFO extends Structure {

        /**
         * A member variable.
         * the struct resource info of device.
         */
        public SM_RESOURCE_INFO.ByValue    stDevResourceInfo;
        /**
         * A member variable.
         * the struct mechanism info of device.
         */
        public SM_MANUFCT_INFO.ByValue     stManufactureInfo;
        /**
         * A member variable.
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

        public static class ByReference extends SM_DEVICE_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_DEVICE_INFO implements Structure.ByValue{		}


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
        /*!
         * A member variable.
         * the left number of public key object.
         * \n include token object and session object.
         */
        public short         wFreePublicKeyCount;
        /*!
         * A member variable.
         * the maximal number of private key object.
         * \n include token object and session object.
         */
        public short         wMaxPrivateKeyCount;
        /*!
         * A member variable.
         * the left number of private key object.
         * \n include token object and session object.
         */
        public short         wFreePrivateKeyCount;

        /*!
         * A member variable.
         * the maximal number of secret key token object.
         */
        public short         wMaxSecretKeyTokenCount;
        /*!
         * A member variable.
         * the left number of secret key token object.
         */
        public short         wFreeSecretKeyTokenCount;
        /*!
         * A member variable.
         * the maximal number of public key token object.
         */
        public short         wMaxPublicKeyTokenCount;
        /*!
         * A member variable.
         * the left number of public key token object.
         */
        public short         wFreePublicKeyTokenCount;
        /*!
         * A member variable.
         * the maximal number of private key token object.
         */
        public short         wMaxPrivateKeyTokenCount;
        /*!
         * A member variable.
         * the left number of private key token object.
         */
        public short         wFreePrivateKeyTokenCount;

        /*!
         * A member variable.
         * the device NVMem info.
         */
        public SM_NVMEM_INFO.ByValue   stNVMem;

        /*!
         * A member variable.
         * the device ADMem info.
         */
        public SM_ADMEM_INFO.ByValue   stADMem;

        /*!
         * A member variable.
         * the maximal length of user pin.
         */
        public short         wMaxPinLen;
        /*!
         * A member variable.
         * the minimum length of user pin.
         */
        public short         wMinPinLen;
        /*!
         * A member variable.
         * the maximal length of SO pin.
         */
        public short         wMaxSOPinLen;
        /*!
         * A member variable.
         * the minimum length of SO pin.
         */
        public short         wMinSOPinLen;
        /*!
         * A member variable.
         * the version of the device hardware.
         * \n the high 8bits is major version,
         * \n the low  8bits is minor version.
         * \n Example: 0102, the major is 1, the minor is 2.
         */
        public short         wHardwareVersion;
        /*!
         * A member variable.
         * the version of the device firmware.
         * \n the high 8bits is major version,
         * \n the low  8bits is minor version.
         * \n Example: 0102, the major is 1, the minor is 2.
         */
        public short         wFirmwareVersion;

        public static class ByReference extends SM_RESOURCE_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_RESOURCE_INFO implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiHPIBufSize", "wMaxPipeCount", "wFreePipeCount","wMaxSecretKeyCount","wFreeSecretKeyCount","wMaxPublicKeyCount",
                    "wFreePublicKeyCount","wMaxPrivateKeyCount","wFreePrivateKeyCount","wMaxSecretKeyTokenCount","wFreeSecretKeyTokenCount",
                    "wMaxPublicKeyTokenCount","wFreePublicKeyTokenCount","wMaxPrivateKeyTokenCount","wFreePrivateKeyTokenCount","stNVMem",
                    "stADMem","wMaxPinLen","wMinPinLen", "wMaxSOPinLen","wMinSOPinLen","wHardwareVersion","wFirmwareVersion");
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

        public static class ByReference extends SM_NVMEM_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_NVMEM_INFO implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMaxNVMemSize","uiNVMemSectorSize");
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

        public static class ByReference extends SM_ADMEM_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_ADMEM_INFO implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiMaxAuthDevMem1Size","uiMaxAuthDevMem2Size");
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

        public static class ByReference extends SM_MANUFCT_INFO implements Structure.ByReference{					}
        public static class ByValue extends SM_MANUFCT_INFO implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("byModel","byManufacturerID","byManufactureDate","byBatch","bySerial","byDateTime");
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
         * The pointer of data
         */
        public PointerByReference        pbyData;

        public static class ByReference extends SM_BLOB_KEY implements Structure.ByReference{					}
        public static class ByValue extends SM_BLOB_KEY implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiDataLen","pbyData");
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
         *
         * The pointer of data
         */
        public byte[]        pbyData;

        public static class ByReference extends SM_BLOB_ECCCIPHER implements Structure.ByReference{					}
        public static class ByValue extends SM_BLOB_ECCCIPHER implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiSessionKeyLen","uiCipherDataLen","uiCheckDataLen");
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
        /*!
         * The end data of key
         */
        public byte[]         byEndDate=new byte[4];
        /*!
         * The attribute flag of key
         */
        public int         uiFlags;
        /*!
         * The parameter of key
         */
        public Pointer        pParameter;
        /*!
         * The parameter length of key
         */
        public int         uiParameterLen;

        public static class ByReference extends SM_KEY_ATTRIBUTE implements Structure.ByReference{					}
        public static class ByValue extends SM_KEY_ATTRIBUTE implements Structure.ByValue{		}
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiObjectClass","KeyType","uiKeyLabel","byStartDate","byEndDate","uiFlags","pParameter","uiParameterLen");
        }
    }

    public static class SM_ALGORITHM extends Structure{
        /*!
         *
         * The type of algorithm
         */
        public int   AlgoType;
        /*!
         *
         * The parameter of algorithm
         */
        public Pointer           pParameter;
        /*!
         *
         * The length of parameter
         */
        public int             uiParameterLen;
        /*!
         *
         * The reserve data of algorithm
         */
        public int             uiReserve;

        public static class ByReference extends SM_ALGORITHM implements Structure.ByReference{					}
        public static class ByValue extends SM_ALGORITHM implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("AlgoType","pParameter","uiParameterLen","uiReserve");
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

        public static class ByReference extends SM_ECC_PARAMETER implements Structure.ByReference{					}
        public static class ByValue extends SM_ECC_PARAMETER implements Structure.ByValue{		}

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("uiModulusBits","pParameter","uiParameterLen");
        }

    }
}


