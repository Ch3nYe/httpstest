package com.example.httpstest;

import android.annotation.SuppressLint;

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsTrustAllCerts implements X509TrustManager {


    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { // 验证服务端证书需要重写该函数

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0]; //返回长度为0的数组，相当于return null
    }


    public static SSLSocketFactory createSSLSocketFactory() { // SSLSocketFactory 创建器
        SSLSocketFactory sSLSocketFactory = null;
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new HttpsTrustAllCerts()},new SecureRandom());
            sSLSocketFactory = sc.getSocketFactory();
        } catch (Exception e) {
        }
        return sSLSocketFactory;
    }


    public static class TrustAllHostnameVerifier implements HostnameVerifier { // 域名验证器
        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }
}
