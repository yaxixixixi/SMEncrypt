package com.yaxi.simulation;

import com.yaxi.sm.Util;

import java.net.URLEncoder;
import java.util.Random;
import java.util.UUID;

public class Client {


    private String key = "";

    public ClientData encryptData(String message) throws Exception{


        System.out.println("原文 = " + message);
//        1、生成随机秘钥key
        key = generateAK();
        System.out.println("生成key= "+key);
//        2、获取当前时间戳
        String timeStamp = String.valueOf(System.currentTimeMillis());
        System.out.println("当前时间戳timeStamp= " + timeStamp);
//        3、sm4使用key对数据进行对称加密
        String cipherMessage = EncryptHelper.SM4EncryptForCBC(key, message,Constant.SM4_IV);
        System.out.println("加密后的密文= " + cipherMessage);
        String encodeMessage = URLEncoder.encode(cipherMessage, "UTF-8");
        System.out.println("编码后的密文= " + encodeMessage);
//        4、私钥签名  对  密文+secret+时间戳+接口编号+渠道号 进行签名
        String toSignature = cipherMessage + Constant.APP_SECRET + timeStamp + Constant.SERVICE_ID + Constant.CHANNEL;
        System.out.println("待签名的信息= " + toSignature);
        String signature = EncryptHelper.SM2Sign(Main.privateKey, toSignature,Constant.USER_ID);
        System.out.println("签名的信息= " + signature);

        boolean b = EncryptHelper.SM2VerifySign(Util.hexStringToBytes(Main.publicKey), toSignature.getBytes(), Util.hexStringToBytes(signature),Constant.USER_ID);
        System.out.println("sss=" + b);

//        5、使用sm2公钥对key进行加密
        String cipherKey = EncryptHelper.SM2Encrypt(Main.publicKey, key);
        System.out.println("加密的key= "+ cipherKey);


        ClientData clientData = new ClientData();
        clientData.timeStamp = timeStamp;
        clientData.cipherKey = cipherKey;
        clientData.signature = signature;
        clientData.cipherMessage = cipherMessage;
        clientData.encodedMessage = encodeMessage;

        return clientData;
    }


    public String handleResponse(){

        return null;
    }



    /**
     * 生成动态密钥
     * @return
     */
    private String generateAK(){
        return UUID.randomUUID().toString().replace("-", "");
    }




    public static class ClientData{
        public String timeStamp;
        public String cipherKey;
        public String signature;
        public String cipherMessage;
        public String encodedMessage;
    }
}
