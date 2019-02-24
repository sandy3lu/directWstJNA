package com.yunjingit.common;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface CSMApi extends Library {

    CSMApi INSTANCE = Native.loadLibrary("yjsmwst", CSMApi.class);

    /* 打印 API 的返回数据结构体，只打印调用的状态信息，成功或是失败，以及错误描述信息 */
    void print_response_status(Sm.Response response);

    int api_init(byte[] out);

    int api_final(byte[] out);



    /* 输出上下文信息至字符串缓冲区
     * int verbose: 0 表示输出简要信息，1 表示输出详细信息 */
    // return: StrValue
    int api_print_context(int verbose, byte[] out);


    /* 获取上下文信息结构体，其中包括检测到的设备数目 */
// return: CtxInfo
    int api_ctx_info(byte[] out);

    /* 登录设备，并申请设备的相关资源。采用独占方式登录，即若一个进程登录设备后，其他进程便无法再登录。
     * int device_index: 设备编号，从 0 开始索引
     * const char *pin_code: 设备密钥口令 */
    // return: None
    int api_login_device(int device_index, String pin_code, byte[] out);

    /* 登出设备，并释放设备的相关资源 */
    // return: None
    int api_logout_device(int device_index, byte[] out);

    /* 获取设备实时状态信息 */
// return: DevStatus
    int api_device_status(int device_index, byte[] out);


    /* 从加密卡导出公钥，一律是不予加密保护的；从加密卡导出私钥，一律是予以保护的，采用 SM1 ECB 算法进行加密。
     * 但从加密卡导出对称密钥，可以选择保护或者不保护。若选择保护对称密钥，则对称密钥导出时加密，导入时被解密。
     * 调用本 API 可以设置全局开关，设定是否对导出或者导入的密钥进行保护。
     * int flag: true 表示进行保护，false 表示不予保护 */
    // return: None
    int api_protect_key(int flag, byte[] out);

    /* SM3 摘要算法，在数据量比较少时调用
     * char *data: 待计算的原文二进制数据
     * int data_len: 指明原文的字节长度 */
// return: StrValue，摘要值的 hex 编码
    int api_digest(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    /* 当数据量比较庞大，比如计算一个文件的摘要值时，推荐采用分步计算方法，分为三个步骤:
     * 1. 初始化，申请计算资源
     * 2. 0 次或者多次迭代更新，不断载入新的原文数据
     * 3. 输出最终的摘要值
     * 倘若要多次分步计算摘要，可以 final 后直接 update，而不用重复 init，节省步骤 */
    // return: None
    int api_digest_init(int device_index, int pipe_index, byte[] out);
    // return: None, data.length = N* 64
    int api_digest_update(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);
    // return: StrValue, 摘要值的 hex 编码
    int api_digest_final(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    /* 生成真随机数
     * int length: 最大为 1024 */
// return: StrValue，随机数的 hex 编码
    int api_random(int device_index, int pipe_index, int length, byte[] out);

    /* 生成 SM4 密钥 */
// return: StrValue，密钥的 hex 编码
    int api_generate_key(int device_index, int pipe_index, byte[] out);

    /* 生成 SM2 密钥对 */
// return: KeyPair，公钥和私钥的 hex 编码
    int api_generate_keypair(int device_index, int pipe_index, byte[] out);


    /* SM4 对称加密，在数据量较少时调用
     * char *hex_key: 密钥的 hex 编码
     * char *hex_iv: 初始向量的 hex 编码，字符长度 32，若 hex_iv == NULL，则采用 ECB 模式，否者采用 CBC 模式
     * char *data: 原文数据，二进制
     * int data_len: 原文数据的字节长度 */
// return: BytesValue，密文数据及长度
    int api_encrypt(int device_index, int pipe_index, byte[] hex_key, byte[] hex_iv, byte[] data, int data_len, byte[] out);

    /* SM4 对称解密，在数据量较少时调用
     * char *hex_key: 密钥的 hex 编码
     * char *hex_iv: 初始向量的 hex 编码，字符长度 32，若 hex_iv == NULL，则采用 ECB 模式，否者采用 CBC 模式
     * char *data: 密文数据，二进制
     * int data_len: 密文数据的字节长度 */
// return: BytesValue，原文数据及长度
    int api_decrypt(int device_index, int pipe_index, byte[] hex_key, byte[] hex_iv, byte[] data, int data_len, byte[] out);


    /* 当数据量较大，比如加密一个文件时，推荐采用分步计算方法，分为三个步骤:
     * 1. 初始化，传入密钥和初始向量，申请计算资源
     * 2. 分步加密，每次加密的数据块必须为 16 字节，并输出当前块的密文
     * 3. 最后一次加密，计算最后一个数据块，并输出密文
     * 倘若要使用同一密钥加密多份数据，可以 final 后直接 update，不用重新 init，节省步骤 */
// return: None
    int api_encrypt_init(int device_index, int pipe_index, byte[] hex_key, byte[] hex_iv, byte[] out);
    // return: BytesValue，密文数据及长度
    int api_encrypt_update(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);
    // return: BytesValue，密文数据及长度
    int api_encrypt_final(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    /* 当数据量较大，比如解密一个文件时，推荐采用分步计算方法，分为三个步骤:
     * 1. 初始化，传入密钥和初始向量，申请计算资源
     * 2. 分步解密，每次解密的数据块必须为 16 字节，并输出当前块的原文
     * 3. 最后一次解密，计算最后一个数据块，并输出原文
     * 倘若要使用同一密钥解密多份数据，可以 final 后直接 update，不用重新 init，节省步骤 */
// return: None
    int api_decrypt_init(int device_index, int pipe_index, byte[] hex_key, byte[] hex_iv, byte[] out);
    // return: BytesValue，原文数据及长度
    int api_decrypt_update(int device_index, int pipe_index, byte[] data, byte data_len, byte[] out);
    // return: BytesValue，原文数据及长度
    int api_decrypt_final(int device_index, int pipe_index, byte[] data, byte data_len, byte[] out);


    /* 数字签名
     * char *hex_key: 私钥 hex 编码
     * char *hex_data: 原文数据 hex 编码 */
// return: StrValue，签名值 hex 编码
    int api_sign(int device_index, int pipe_index, byte[]  hex_key, byte[]  hex_data, byte[] out);

    /* 验签
     * char *hex_key: 公钥 hex 编码
     * char *hex_data: 原文数据 hex 编码
     * char *hex_signature: 签名值 hex 编码 */
// return: IntValue, 0 表示验签成功，否者验签失败，不同数值代表不同原因
    int api_verify(int device_index, int pipe_index, byte[]  hex_key, byte[]  hex_data, byte[]  hex_signature, byte[] out);


}

