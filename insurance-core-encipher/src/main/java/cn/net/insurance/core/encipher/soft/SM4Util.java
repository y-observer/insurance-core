package cn.net.insurance.core.encipher.soft;


import cn.net.insurance.core.base.constant.ConfigConsts;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
@Slf4j
public abstract class SM4Util {

    private static Logger logger = LoggerFactory.getLogger(SM4Util.class);

    private static final String PROVIDER_NAME = "BC";
    public static final String ALGORITHM_NAME = "SM4";
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
    public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";
    public static final String ALGORITHM_NAME_ECB_NOPADDING = "SM4/ECB/NoPadding";
    public static final String ALGORITHM_NAME_CBC_NOPADDING = "SM4/CBC/NoPadding";
    /*public static final String DEFAULT_KEY = "random_seed";*/
    public static final int DEFAULT_KEY_SIZE = 128;
    private static final int ENCRYPT_MODE = 1;
    private static final int DECRYPT_MODE = 2;
    private static final String PARAMETER_SPEC = "1234567890123456";


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * ecb 加密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] encryptEcb(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateEcbCipher(ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }
    /**
     * CBC 加密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] encrypt(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateCbcCipher(ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }

    /**
     * CBC 加密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] encryptNoPadding(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateCbcNoPaddingCipher(ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }

    /**
     * ECB 加密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] encryptEcbNoPadding(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateEcbNoPaddingCipher(ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }


    /***
     * ecb加密
     * @param key
     * @param data
     * @return
     */
    public static synchronized String encryptEcb(String key, String data) {
        try {
            Cipher cipher = generateEcbCipher(ENCRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(data.getBytes(ConfigConsts.ENCODING));
            return ByteUtils.toHexString(a);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }
    /***
     * ecb加密
     * @param key
     * @param data
     * @return
     */
    public static synchronized String encrypt(String key, String data) {
        try {
            Cipher cipher = generateCbcCipher(ENCRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(data.getBytes(ConfigConsts.ENCODING));
            return ByteUtils.toHexString(a);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }
    /***
     * ecb加密
     * @param key
     * @param data
     * @return
     */
    public static synchronized String encryptNoPadding(String key, String data) {
        try {
            Cipher cipher = generateCbcNoPaddingCipher(ENCRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(data.getBytes(ConfigConsts.ENCODING));
            return ByteUtils.toHexString(a);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }

    /***
     * ecb加密
     * @param key
     * @param data
     * @return
     */
    public static synchronized String encryptEcbNoPadding(String key, String data) {
        try {
            Cipher cipher = generateEcbNoPaddingCipher(ENCRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(data.getBytes(ConfigConsts.ENCODING));
            return ByteUtils.toHexString(a);
        } catch (Exception e) {
            log.error("SM4加密失败", e);
        }
        return null;
    }


    /**
     * ecb 解密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] decryptEcb(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateEcbCipher(DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }

    /**
     * CBC 解密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] decrypt(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateCbcCipher(DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }

    /**
     * CBC 解密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] decryptEcbNoPadding(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateEcbNoPaddingCipher(DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }
    /**
     * CBC 解密
     *
     * @param key
     * @param data
     */
    public static synchronized byte[] decryptNoPadding(byte[] key, byte[] data) {
        try {
            Cipher cipher = generateCbcNoPaddingCipher(DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }

    /**
     * ecb 解密
     *
     * @param key
     * @param data
     */
    public static synchronized String decryptEcb(String key, String data) {
        try {
            Cipher cipher = generateEcbCipher(DECRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(ByteUtils.fromHexString(data));
            return new String(a, ConfigConsts.ENCODING);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }

    /**
     * cbc 解密
     *
     * @param key
     * @param data
     */
    public static synchronized String decrypt(String key, String data) {
        try {
            Cipher cipher = generateCbcCipher(DECRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(ByteUtils.fromHexString(data));
            return new String(a, ConfigConsts.ENCODING);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }
    /**
     * cbc 解密
     *
     * @param key
     * @param data
     */
    public static synchronized String decryptEcbNoPadding(String key, String data) {
        try {
            Cipher cipher = generateEcbNoPaddingCipher(DECRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(ByteUtils.fromHexString(data));
            return new String(a, ConfigConsts.ENCODING);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }
    /**
     * cbc 解密
     *
     * @param key
     * @param data
     */
    public static synchronized String decryptNoPadding(String key, String data) {
        try {
            Cipher cipher = generateCbcNoPaddingCipher(DECRYPT_MODE, key.getBytes(ConfigConsts.ENCODING));
            byte[] a = cipher.doFinal(ByteUtils.fromHexString(data));
            return new String(a, ConfigConsts.ENCODING);
        } catch (Exception e) {
            log.error("SM4解密失败", e);
        }
        return null;
    }


    /**
     * ecb cipher
     *
     * @param mode
     * @param key
     * @return
     */
    private static Cipher generateEcbCipher(int mode, byte[] key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_ECB_PADDING, PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }
    /**
     * ecb cipher
     *
     * @param mode
     * @param key
     * @return
     */
    private static Cipher generateEcbNoPaddingCipher(int mode, byte[] key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_ECB_NOPADDING, PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     * cbc cipher
     *
     * @param mode
     * @param key
     * @return
     */
    private static Cipher generateCbcCipher(int mode, byte[] key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_CBC_PADDING, PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key,generateIV());
        return cipher;
    }

    /**
     * cbc cipher
     *
     * @param mode
     * @param key
     * @return
     */
    private static Cipher generateCbcNoPaddingCipher(int mode, byte[] key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_CBC_NOPADDING, PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key,generateIV());
        return cipher;
    }
    //生成iv
    public static AlgorithmParameters generateIV() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidParameterSpecException {
        AlgorithmParameters params = AlgorithmParameters.getInstance(ALGORITHM_NAME);
        params.init(new IvParameterSpec(PARAMETER_SPEC.getBytes(ConfigConsts.ENCODING)));
        return params;
    }

    /**
     * 自动生成密钥
     *
     * @return
     * @explain
     */
    public static byte[] generateKey() throws Exception {
        return generateKey(DEFAULT_KEY_SIZE);
    }


    public static String generateKeyString() throws Exception {
        return ByteUtils.toHexString(generateKey());
    }

    /**
     * @param keySize
     * @return
     * @throws Exception
     * @explain
     */
    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }


    public static int bytes2Int(byte[] b) {
        byte[] a = new byte[4];
        int i = a.length - 1,j = b.length - 1;
        for (; i >= 0 ; i--,j--) {//从b的尾部(即int值的低位)开始copy数据
            if(j >= 0)
                a[i] = b[j];
            else
                a[i] = 0;//如果b.length不足4,则将高位补0
        }
        int v0 = (a[0] & 0xff) << 24;//&0xff将byte值无差异转成int,避免Java自动类型提升后,会保留高位的符号位
        int v1 = (a[1] & 0xff) << 16;
        int v2 = (a[2] & 0xff) << 8;
        int v3 = (a[3] & 0xff) ;
        return v0 + v1 + v2 + v3;
    }
}
