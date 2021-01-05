package com.yaxi.simulation;

import com.yaxi.simulation.entity.SM2Keys;
import com.yaxi.sm.SM2Utils;
import com.yaxi.sm.Util;

public class Main {

    //sm2公钥
    public static String publicKey = "";
    //sm2私钥
    public static String privateKey = "";

    public static void main(String[] args) throws Exception{
	// write your code here
        generateKeyPare();

        String messageSrc = "混淆原则就是将密文、明文、密钥三者之间的统计关系和代数关系变得尽可能复杂，使得敌手即使获得了密文和明文，也无法求出密钥的任何信息;即使获得了密文和明文的统计规律，也无法求出明文的任何信息";


        Client client = new Client();
        Client.ClientData clientData = client.encryptData(messageSrc);

        Server server = new Server();
        server.businessProcess(clientData);




    }

    public static void generateKeyPare(){
        SM2Keys sm2Keys = SM2Utils.generateKeyPair();
        publicKey = Util.byteToHex(sm2Keys.publicKey.getEncoded(false));
        privateKey = Util.byteToHex(sm2Keys.privateKey.toByteArray());
        System.out.println("publicKey = " + publicKey);
        System.out.println("privateKey = " + privateKey);

    }
}
