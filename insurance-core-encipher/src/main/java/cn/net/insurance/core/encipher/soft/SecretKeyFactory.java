package cn.net.insurance.core.encipher.soft;

import cn.net.insurance.core.base.model.SecretKey;
import cn.net.insurance.core.base.utils.JacksonUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;
import sun.misc.BASE64Decoder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class SecretKeyFactory {

    static final String KEY_STORE = "JKS";

    static final String PRIVATE_ALIAS = "PRIVATE_KEY-6D1826259549";

    private static final String SM2SIGN_WITH_SM3 = "SM3withSM2";

    static {
        Security.removeProvider("SunEC");
        Security.addProvider(new BouncyCastleProvider());
    }

    public static SecretKey create() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, OperatorCreationException {
        SecretKey secretKey = null;
        KeyPair keyPair = SM2Util.createKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        secretKey = new SecretKey(publicKey, privateKey);
        createPKCS10(publicKey, privateKey);
        return secretKey;
    }

    public static PublicKey getPublicKey(String publicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] publicBytes = new BASE64Decoder().decodeBuffer(publicKey);
        X509EncodedKeySpec eks = new X509EncodedKeySpec(publicBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECPublicKey bce2 = (BCECPublicKey) kf.generatePublic(eks);
        return bce2;
    }

    public static PrivateKey getPrivateKey(String privateKey) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] prvBytes22 = new BASE64Decoder().decodeBuffer(privateKey);
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(prvBytes22);
        KeyFactory kf22= KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey pvk= kf22.generatePrivate(eks2);
        BCECPrivateKey bpve = (BCECPrivateKey) pvk;
        return bpve;
    }

    public static PublicKey getPublicKeyFromCert(String certStr) throws UnsupportedEncodingException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream byteInputStream = new ByteArrayInputStream(certStr.getBytes("UTF-8"));
        X509Certificate cert = (X509Certificate) cf.generateCertificate(byteInputStream);
        return cert.getPublicKey();
    }
    public static X509Certificate getCert(String certStr) throws UnsupportedEncodingException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream byteInputStream = new ByteArrayInputStream(Base64.decode(certStr));
        X509Certificate cert = (X509Certificate) cf.generateCertificate(byteInputStream);
        return cert;
    }
    public static String createPKCS10(PublicKey publicKey, PrivateKey privateKey) throws IOException, OperatorCreationException {
        String formatter = "-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n";
        ContentSigner contentSigner = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(new BouncyCastleProvider())
                .build(privateKey);

        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(x500Name(), publicKey);
        PKCS10CertificationRequest pkcs10 = pkcs10CertificationRequestBuilder.build(contentSigner);
        byte[] encoded = pkcs10.getEncoded();
        return String.format(formatter, Base64.toBase64String(encoded));
    }

    private static X500Name x500Name() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        // 公用名
        builder.addRDN(BCStyle.CN, "WEWAY");
        // 国家代码
        builder.addRDN(BCStyle.C, "CN");
        // 组织
        builder.addRDN(BCStyle.O, "WEWAY");
        // 省份
        builder.addRDN(BCStyle.ST, "Guangdong");
        // 地区
        builder.addRDN(BCStyle.L, "Shenzhen");
        return builder.build();
    }

    public static boolean isExits(File keyFile) {
        return keyFile.exists();
    }

    public static SecretKey getSecretKey(String password, File keyFile) throws Exception {
        return new SecretKey(loadPublicKey(keyFile, password), loadPrivateKey(keyFile, password));
    }

    public static void save(File keyFile, String password, SecretKey secretKey) throws Exception {
        char[] ksPass = password.toCharArray();
        FileOutputStream stream = null;
        try {
            KeyStore ks = KeyStore.getInstance(KEY_STORE);
            ks.load(null, ksPass);
            //存储私钥
            ks.setKeyEntry(PRIVATE_ALIAS, secretKey.getPrivateKey(), ksPass, new java.security.cert.Certificate[]{
                    generate(secretKey.getPrivateKey(), secretKey.getPublicKey())});
            stream = new FileOutputStream(keyFile);
            ks.store(stream, ksPass);
        } catch (Exception e) {
            throw e;
        } finally {
            if (stream != null) {
                stream.close();
            }
        }
    }

    public static PrivateKey loadPrivateKey(File keyFile, String password) throws Exception {
        FileInputStream fis = null;
        try {
            KeyStore ks = KeyStore.getInstance(KEY_STORE);
            fis = new FileInputStream(keyFile);
            ks.load(fis, password.toCharArray());
            return (PrivateKey) ks.getKey(PRIVATE_ALIAS, password.toCharArray());
        } catch (Exception e) {
            throw e;
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    public static PublicKey loadPublicKey(File keyFile, String password) throws Exception {
        FileInputStream fis = null;
        try {
            KeyStore ks = KeyStore.getInstance(KEY_STORE);
            fis = new FileInputStream(keyFile);
            ks.load(fis, password.toCharArray());
            return ks.getCertificate(PRIVATE_ALIAS).getPublicKey();
        } catch (Exception e) {
            throw e;
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    static Certificate generate(PrivateKey privateKey, PublicKey publicKey) throws CertificateException, OperatorCreationException {
        Provider provider = new BouncyCastleProvider();
        X500Name x500Name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.C, "").build();
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                // 颁发者信息
                x500Name
                // 证书序列号
                , new BigInteger(128, new SecureRandom())
                // 证书生效日期
                , new Date(System.currentTimeMillis() - 50 * 1000)
                // 证书失效日期
                , new Date(System.currentTimeMillis() + 50 * 1000)
                // 使用者信息（PS：由于是自签证书，所以颁发者和使用者DN都相同）
                , x500Name
                // 证书公钥
                , publicKey);
        ContentSigner sigGen = new JcaContentSignerBuilder(SM2SIGN_WITH_SM3)
                .setProvider(provider)
                .build(privateKey);
        return new JcaX509CertificateConverter()
                .setProvider(provider)
                .getCertificate(certGen.build(sigGen));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, InvalidKeyException, InvalidCipherTextException, NoSuchProviderException, SignatureException {
        SecretKey secretKey = create();
        System.out.println("sm2公钥----->" + Base64.toBase64String(secretKey.getPublicKey().getEncoded()));
        System.out.println("sm2私钥----->" + Base64.toBase64String(secretKey.getPrivateKey().getEncoded()));
        PublicKey publicKey = SecretKeyFactory.getPublicKey(Base64.toBase64String(secretKey.getPublicKey().getEncoded()));
        PrivateKey privateKey = SecretKeyFactory.getPrivateKey(Base64.toBase64String(secretKey.getPrivateKey().getEncoded()));

        byte[] sign = SignUtil.sign("12345678ppp", privateKey);
        boolean verify = SignUtil.verify("12345678ppp", sign, publicKey);
        System.out.println("SM2-Sm3签名结果：" + verify);


        byte[] encrypt = SM2Util.encrypt(publicKey, "12345678ppp");
        System.out.println("SM2加密后数据" + Base64.toBase64String(encrypt));
        byte[] decrypt = SM2Util.decrypt(privateKey,  Base64.decode(Base64.toBase64String(encrypt)));
        System.out.println("SM2解密后数据:" + new String(decrypt));

    }


}
