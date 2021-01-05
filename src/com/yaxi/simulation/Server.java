package com.yaxi.simulation;

import com.yaxi.sm.Util;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class Server {


    public ServerData businessProcess(Client.ClientData clientData) {

        try {
            System.out.println("server部分");
//        1、公钥验签
            String cipherMessage = clientData.cipherMessage;
            String encodedMessage = clientData.encodedMessage;
            String signature = clientData.signature;
            String cipherKey = clientData.cipherKey;
            String timeStamp = clientData.timeStamp;

            String source = cipherMessage + Constant.APP_SECRET + timeStamp + Constant.SERVICE_ID + Constant.CHANNEL;
            boolean verify = EncryptHelper.SM2VerifySign(Util.hexStringToBytes(Main.publicKey), source.getBytes(), Util.hexStringToBytes(signature),Constant.USER_ID);
            System.out.println("验签结果 = " + verify);
//        2、私钥解密key
            String key = EncryptHelper.SM2Decrypt(Main.privateKey, cipherKey);

            System.out.println("解密后的key：" + key);
//        3、解密数据
            String decodeMessage = URLDecoder.decode(encodedMessage,"utf-8");
            System.out.println("解码后的原文：" + decodeMessage);
            String messageSrc = EncryptHelper.SM4DecryptForCBC(key, decodeMessage,Constant.SM4_IV);
            System.out.println("解密后的原文：" + messageSrc);
//        4、返回数据加密
//        5、生成返回数据签名
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static class ServerData {
    }
}
