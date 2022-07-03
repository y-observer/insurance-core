package cn.net.insurance.core.encipher.soft;


import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public abstract class SignUtil {

    private static Signature signature;

    private static final String SM2SIGN_WITH_SM3 = "SM3withSM2";

    static {
        try {
            signature = Signature.getInstance(
                    SM2SIGN_WITH_SM3,
                    new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static synchronized byte[] sign(String src, PrivateKey privateKey) throws InvalidKeyException, SignatureException, UnsupportedEncodingException {
        signature.initSign(privateKey);
        byte[] plainText = src.getBytes("UTF-8");
        signature.update(plainText);
        return signature.sign();
    }

    public static synchronized boolean verify(String plainText, byte[] signText, PublicKey publicKey) throws InvalidKeyException, SignatureException {
        signature.initVerify(publicKey);
        signature.update(plainText.getBytes());
        return signature.verify(signText);
    }


}
