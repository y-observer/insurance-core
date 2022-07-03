package cn.net.insurance.core.encipher.soft;

import cn.net.insurance.core.base.constant.ConfigConsts;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

@Slf4j
public abstract class SM3Util {

    /***
     * 生成sm3哈希值
     * @param content
     * @return
     */

    private static final int DEFAULT_BUFFER_SIZE = 8192;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(String content) {
        try {
            byte[] result = hash(content.getBytes(ConfigConsts.ENCODING));
            return ByteUtils.toHexString(result);
        } catch (Exception e) {
            log.error("SM3哈希运算失败", e);
        }
        return null;
    }

    public static byte[] hash(byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SM3", "BC");
        return instance.digest(data);
    }

    public static String encrypt(String content, String key) {
        try {
            byte[] data = content.getBytes(ConfigConsts.ENCODING);
            KeyParameter keyParameter = new KeyParameter(key.getBytes(ConfigConsts.ENCODING));
            SM3Digest digest = new SM3Digest();
            HMac mac = new HMac(digest);
            mac.init(keyParameter);
            mac.update(data, 0, data.length);
            byte[] result = new byte[mac.getMacSize()];
            mac.doFinal(result, 0);
            return ByteUtils.toHexString(result);
        } catch (Exception e) {
            log.error("SM3哈希运算失败", e);
        }
        return null;
    }

    public static boolean verify(String srcStr, String sm3HexString) {
        boolean flag = false;
        try {
            byte[] srcData = srcStr.getBytes(ConfigConsts.ENCODING);
            byte[] sm3Hash = ByteUtils.fromHexString(sm3HexString);
            byte[] newHash = hash(srcData);
            if (Arrays.equals(newHash, sm3Hash)) {
                flag = true;
            }
        } catch (Exception e) {
            log.error("[SM3Util 异常] verify异常,原始数据:{},加密数据:{}", srcStr, sm3HexString, e);
        }
        return flag;
    }


    /**
     * 对数据流进行哈希
     *
     * @param source will be closed
     * @return 十六进制哈希值字符串
     */
    public static String encrypt(InputStream source) {
        try (InputStream inputStream = source) {
            MessageDigest instance = MessageDigest.getInstance("SM3", "BC");
            final byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
            int read;
            while ((read = inputStream.read(buffer, 0, DEFAULT_BUFFER_SIZE)) > -1) {
                instance.update(buffer, 0, read);
            }
            return ByteUtils.toHexString(instance.digest());
        } catch (Exception e) {
            log.error("SM3哈希运算失败", e);
        }
        return null;
    }

}
