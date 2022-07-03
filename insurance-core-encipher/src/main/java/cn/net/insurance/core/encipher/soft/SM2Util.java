package cn.net.insurance.core.encipher.soft;


import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public abstract class SM2Util {
    static {
        Security.removeProvider("SunEC");
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair createKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(sm2Spec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] content) throws InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException, InvalidCipherTextException {
        CipherParameters pubKeyParameters = new ParametersWithRandom(publicKeyToParams("SM2", publicKey.getEncoded()));
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(true, pubKeyParameters);
        return engine.processBlock(content, 0, content.length);
    }

    public static ECPublicKeyParameters publicKeyToParams(String algorithm, byte[] key) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = generatePublicKey(algorithm, key);
        return (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
    }

    public static PublicKey generatePublicKey(String algorithm, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new X509EncodedKeySpec(key);
        algorithm = "EC";
        return getKeyFactory(algorithm).generatePublic(keySpec);
    }

    private static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        final Provider provider = new BouncyCastleProvider();
        return KeyFactory.getInstance(algorithm, provider);
    }

    /**
     * 根据公钥public base64  返回publicKey对象
     *
     * @param key
     * @return
     */
    public static PublicKey generatePublicKey(byte[] key) throws Exception {
        try {
            KeySpec keySpec = new X509EncodedKeySpec(key);
            String algorithm = "EC";
            return getKeyFactory(algorithm).generatePublic(keySpec);
        } catch (Exception e) {
            throw e;
        }
    }


    public static byte[] encrypt(PublicKey publicKey, String content) throws InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException, InvalidCipherTextException, UnsupportedEncodingException {
        return encrypt(publicKey, content.getBytes(Charset.forName("UTF-8").name()));
    }

    public static String encryptToBase64(PublicKey publicKey, byte[] content) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException {
        byte[] result = encrypt(publicKey, content);
        //return Base64Utils.encodeToString(result);
        return Base64.toBase64String(result);
    }

    public static String encryptToBase64(PublicKey publicKey, String content) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {
        return encryptToBase64(publicKey, content.getBytes(Charset.forName("UTF-8").name()));
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws InvalidKeyException, InvalidCipherTextException {
        CipherParameters privateKeyParameters = ECUtil.generatePrivateKeyParameter(privateKey);
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(false, privateKeyParameters);
        byte[] byteDate = engine.processBlock(data, 0, data.length);
        return byteDate;
    }

    public static String decryptToString(PrivateKey privateKey, String base64String) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException {
        byte[] result = decrypt(privateKey, Base64.decode(base64String));
        return Base64.toBase64String(result);
    }

    public static String decryptToByte(PrivateKey privateKey, String base64String) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException {
        byte[] result = decrypt(privateKey, Base64.decode(base64String));
        return new String(result);
    }

    public static boolean verify(String source, byte[] sign, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        boolean flag = false;
        byte[] sourceSign = encrypt(publicKey, source);

//        byte[] sourceBytes = source.getBytes("UTF-8");
//        Signature signature = Signature.getInstance(SM2SIGN_WITH_SM3, new BouncyCastleProvider());
//        signature.initVerify(publicKey);
//        signature.update(sourceBytes);
//        signature.verify(sign)
        if (Arrays.equals(sourceSign, sign)) {
            flag = true;
        }
        return flag;
    }
}
