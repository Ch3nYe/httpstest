package com.example.httpstest;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class ClientSSLSocketFactory  {
    private static final String KEY_STORE_PASSWORD = "clientpassword"; // 证书密码
    private static InputStream client_input;

    public static SSLSocketFactory getSocketFactory(Context context) {
        try {
            //客户端证书
            client_input = context.getResources().getAssets().open("client.p12");
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(client_input, KEY_STORE_PASSWORD.toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, KEY_STORE_PASSWORD.toCharArray());
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                client_input.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
}
