package com.yaxi.simulation;

import com.yaxi.simulation.entity.SM2Result;
import com.yaxi.sm.SM2;
import com.yaxi.sm.SM2Utils;
import com.yaxi.sm.SM4Utils;
import com.yaxi.sm.Util;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public class EncryptHelper {


    /**
     * sm4对原始数据进行加密
     * @param sm4Key sm4加密的秘钥
     * @param sourceData 待加密的原始数据
     * @param iv sm4 cbc模式的初始化向量值
     * @return sm4加密后的数据
     */
    public static String SM4EncryptForCBC(String sm4Key, String sourceData,String iv) {
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = sm4Key;
        sm4.hexString = true;
        sm4.iv = iv;
        String cipherText = sm4.encryptData_CBC(sourceData);
        return cipherText;
    }

    /**
     * sm4对密文数据进行解密
     * @param sm4Key sm4加密的秘钥
     * @param cipherData 待解密的密文数据
     * @param iv sm4 cbc模式的初始化向量值
     * @return sm4解密后的数据
     */
    public static String SM4DecryptForCBC(String sm4Key, String cipherData,String iv){
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = sm4Key;
        sm4.hexString = true;
        sm4.iv = iv;
        String plainText = sm4.decryptData_CBC(cipherData);
        return plainText;
    }


    public static String SM2Sign(String sm2Key, String sourceData,String userID) throws Exception {
        byte[] sm2KeyByte = Util.hexStringToBytes(sm2Key);
        byte[] sourceDataByte = sourceData.getBytes();

        BigInteger userD = new BigInteger(sm2KeyByte);

        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_point_g.multiply(userD);
//        System.out.println("椭圆曲线点X: " + userKey.getXCoord().toBigInteger().toString(16));
//        System.out.println("椭圆曲线点Y: " + userKey.getYCoord().toBigInteger().toString(16));

        byte[] sm2GetZ = sm2.sm2GetZ(userID.getBytes(), userKey);

        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(sm2GetZ, 0, sm2GetZ.length);
        sm3Digest.update(sourceDataByte, 0, sourceDataByte.length);
        byte[] md = new byte[32];
        sm3Digest.doFinal(md, 0);

        SM2Result sm2Result = new SM2Result();
        sm2.sm2Sign(md, userD, userKey, sm2Result);
//        System.out.println("r: " + sm2Result.r.toString(16));
//        System.out.println("s: " + sm2Result.s.toString(16));


        ASN1Integer d_r = new ASN1Integer(sm2Result.r);
        ASN1Integer d_s = new ASN1Integer(sm2Result.s);
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(d_r);
        v2.add(d_s);
        DERSequence sign = new DERSequence(v2);
        String result = Util.byteToHex(sign.getEncoded());
        return result;
    }

    public static String SM2Encrypt(String key, String sourceData) throws IOException {
        return SM2Utils.encrypt(Util.hexToByte(key), sourceData.getBytes());
    }

    public static String SM2Decrypt(String key,String cipherData) throws IOException {
        return new String(SM2Utils.decrypt(Util.hexToByte(key),Util.hexToByte(cipherData)));
    }


    /**
     * 验证签名
     *
     * @param publicKey  公钥信息
     * @param sourceData 密文信息
     * @param signData   签名信息
     * @return 验签的对象 包含了相关参数和验签结果
     */
    @SuppressWarnings("unchecked")
    public static boolean SM2VerifySign(byte[] publicKey, byte[] sourceData, byte[] signData,String userID) throws IOException {
        byte[] formatedPubKey;
        if (publicKey.length == 64) {
            // 添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
        } else {
            formatedPubKey = publicKey;
        }
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);
        byte[] z = sm2.sm2GetZ(userID.getBytes(), userKey);

        SM3Digest sm3Digest = new SM3Digest();
        //System.out.println("SM3摘要Z: " + Util.getHexString(z));
        sm3Digest.update(z, 0, z.length);
        sm3Digest.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3Digest.doFinal(md, 0);
        //System.out.println("SM3摘要值: " + Util.getHexString(md));
        ByteArrayInputStream bis = new ByteArrayInputStream(signData);
        ASN1InputStream dis = new ASN1InputStream(bis);
        SM2Result sm2Result = null;
        ASN1Primitive derObj = dis.readObject();
        Enumeration<ASN1Integer> e = ((ASN1Sequence) derObj).getObjects();
        BigInteger r = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger s = ((ASN1Integer) e.nextElement()).getValue();
        sm2Result = new SM2Result();
        sm2Result.r = r;
        sm2Result.s = s;
        sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
        boolean verifyFlag = sm2Result.r.equals(sm2Result.R);
        return verifyFlag;

    }


    /**
     * 只能用私钥签名公钥验签
     */
    public static void main(String[] args) throws Exception {
        String pubKey = "04D3416D26D15CDFF16F134769A9903344F73C9738988E6B5CBAA76A0CEEABEA09AE2D466BEBC7CA9320DC0E5CC1120041C5AF73A4A14E5E18ED47317D488438AC";
        String priKey = "00D81990AD8C58BE68F07548B1E53DC7A57C0ABF9B6A2F887E2ADFE79CD4AA2E5A";

        String str = "这是待签名的信息";
        System.out.println("原始内容 = " + str);
        String sign = SM2Sign(priKey, str,Constant.USER_ID);
//        sign = "3046022100DF881364253FC3511390CB3E193F75F818E4E3A6F3291C0DC6E4E439089B5B27022100F1EECC5F611ED274A044EA7003C4FFBA91A2F5C91C6C538DDA21F1A84EFAB73B";
        System.out.println("签名值   = " + sign);
        boolean b = SM2VerifySign(Util.hexStringToBytes(pubKey), str.getBytes(), Util.hexStringToBytes(sign),Constant.USER_ID);
        System.out.println("验证结果 = " + b);


    }

    /**
     * 只能公钥加密 私钥解密
     * @param args
     * @throws Exception
     */
//    public static void main(String[] args) throws Exception {
//        String pubKey = "0484FCA9C6BF03858CAAE216859187B0F0ACB3DA532FB8DEEC8D430C1C3ED25E1A10E1E90BF5204AECCBC29B2C7174F9CAF60E914D7F2CA438C317C395A3B76C37";
//        String priKey = "00EFAF26332C907CF354615BAE7DE4FA2072A7D2C4953C9DDCEF3FBFF974BF77B6";
//
//        String str = "这是待加密的信息";
//
//        String cipherText = SM2Encrypt(pubKey, str);
//        System.out.println("加密结果 = " + cipherText);
//
//        String plainText = SM2Decrypt(priKey, cipherText);
//
//        System.out.println("解密结果 = " + plainText);
//
//
//    }

}
