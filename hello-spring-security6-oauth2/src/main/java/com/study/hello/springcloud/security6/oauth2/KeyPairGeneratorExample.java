package com.study.hello.springcloud.security6.oauth2;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyPairGeneratorExample {

    public static void main(String[] args) {
        try {
            // 创建KeyPairGenerator对象，并指定算法为RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 设置密钥长度为2048位
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 获取公钥和私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 将公钥和私钥编码为Base64字符串
            String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            // 打印Base64编码的公钥和私钥
            System.out.println("Public Key: " + publicKeyStr);
            System.out.println("Private Key: " + privateKeyStr);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

