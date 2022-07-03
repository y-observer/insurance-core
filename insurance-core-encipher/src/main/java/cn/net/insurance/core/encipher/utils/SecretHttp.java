package cn.net.insurance.core.encipher.utils;

import cn.hutool.http.HttpRequest;

import cn.net.insurance.core.base.model.ExtraCodeEnum;
import cn.net.insurance.core.base.model.RespResult;
import cn.net.insurance.core.base.utils.CommonUtils;
import cn.net.insurance.core.base.utils.JacksonUtils;
import cn.net.insurance.core.encipher.soft.SM2Util;
import cn.net.insurance.core.encipher.soft.SM3Util;
import cn.net.insurance.core.encipher.soft.SM4Util;
import cn.net.insurance.core.encipher.soft.SignUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class SecretHttp {

    /***
     * 加密加签数字信封发送报文
     * @param url  请求url地址
     * @param subsystemno 子系统编号
     * @param paramMap  请求参数
     * @param num   加密机密钥组
     * @param publicKey  公钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidCipherTextException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     */
    public static RespResult doPost(String url, String subsystemno, Map<String, Object> paramMap, int num, PublicKey publicKey,PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        long ts = System.currentTimeMillis();
        //k作为sm4的加密key
        String k = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        //k通过SM2加密得到sid
        String sid = ByteUtils.toHexString(SM2Util.encrypt(publicKey, k));
        String params = JacksonUtils.toJson(paramMap);
        String str = params + "|" + ts;
        log.info("签名值原文{},sid:{}", str, sid);
        String sign = SM3Util.encrypt(str);
        //todo
        String sig = ByteUtils.toHexString(SignUtil.sign(sign,privateKey));
        String encodeStr = SM4Util.encrypt(k, params + "|" + sig);
        Map<String, String> map = new HashMap();
        map.put("ts", ts + "");
        map.put("sign", sign);
        map.put("sid", sid);
        map.put("params", encodeStr);
        Object req = HttpRequest.post(url)
                .header("Content-type", "application/json")
                .header("subsystemno", subsystemno)
                .body(JacksonUtils.toJson(map))
                .execute()
                .body();
        RespResult result ;
        if (req instanceof RespResult) {
            result = (RespResult) req;
        } else {
            result = JacksonUtils.toObj(req.toString(), RespResult.class);
        }
        if (result.result() && !CommonUtils.isEmpty(result.getData())) {
            String respStr = SM4Util.decrypt(k, result.getData().toString());
            if (CommonUtils.isEmpty(respStr)) {
                return RespResult.fail(ExtraCodeEnum.AUTH_ENCYPT_DECYPT);
            }
            int index = respStr.lastIndexOf("|");
            if (index <= 0) {
                return RespResult.fail(ExtraCodeEnum.INVALID_RESPONSE);
            }
            String respSig = respStr.substring(index + 1);
            String jsonStr = respStr.substring(0, index);
            if (CommonUtils.isEmpty(respSig) || CommonUtils.isEmpty(jsonStr)) {
                return RespResult.fail(ExtraCodeEnum.INVALID_RESPONSE);
            }
            String hash = SM3Util.encrypt(jsonStr);
            boolean isSuccess = SignUtil.verify(hash, ByteUtils.fromHexString(respSig), publicKey);
            if (!isSuccess) {
                return RespResult.fail(ExtraCodeEnum.AUTH_SIGN_IVALID);
            }
            result.setData(jsonStr);
        }
        return result;
    }
}
