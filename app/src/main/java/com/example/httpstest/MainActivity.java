package com.example.httpstest;
/*
* @ch3nye 2021/04/24
* 一个只会写python的人写java，代码规范就是闹着玩，抱歉只能凑活看了
*/

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.View;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Objects;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "[+]MainActivity";
    public static SSLContext sslContext = null;
    OkHttpClient client = new OkHttpClient();

    WebView mWebview;
    Button button_http_connect;
    Button button_https_connect_without_ca;
    Button button_https_connect_with_system_ca;
    Button button_SSL_PINNING_with_key;
    Button button_SSL_PINNING_with_CA;
    Button button_https_twoway;
    Button button_webview_ssl_without_ca;
    Button button_webview_ssl_with_system_ca;
    Button button_webview_ssl_pinning;
    Switch switch_check_proxy;
    TextView textView;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button_http_connect = (Button)findViewById(R.id.id_button_http_connect);
        button_https_connect_without_ca = (Button)findViewById(R.id.id_button_https_connect_without_ca);
        button_https_connect_with_system_ca = (Button)findViewById(R.id.id_button_https_connect_with_system_ca);
        button_SSL_PINNING_with_key = (Button)findViewById(R.id.id_button_SSL_PINNING_with_key);
        button_SSL_PINNING_with_CA = (Button)findViewById(R.id.id_button_SSL_PINNING_with_CA);
        button_https_twoway = (Button)findViewById(R.id.id_button_https_twoway);
        button_webview_ssl_without_ca = (Button)findViewById(R.id.id_button_webview_ssl_without_ca);
        button_webview_ssl_with_system_ca = (Button)findViewById(R.id.id_button_webview_ssl_with_system_ca);
        button_webview_ssl_pinning = (Button)findViewById(R.id.id_button_webview_ssl_pinning);
        textView = (TextView)findViewById(R.id.id_text);
        switch_check_proxy = (Switch)findViewById(R.id.id_check_proxy);
        mWebview = (WebView)findViewById(R.id.id_webview);

        // 注册Handler处理从thread中返回的url请求结果
        @SuppressLint("HandlerLeak") final Handler mHandler = new Handler(){
            public void handleMessage(Message msg) {
                // 处理消息
                super.handleMessage(msg);
                switch (msg.what) {
                    case 1:
                        textView.setText((CharSequence) msg.obj); break;
                }
            }
        };


        /*
         * http协议
         */
        button_http_connect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        OkHttpClient mClient = client.newBuilder().build();
                        Request request = new Request.Builder()
                                .url("http://www.vulnweb.com/")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = mClient.newCall(request).execute()) {
                            message.obj = "http_connect access vulnweb.com success";
                            Log.d(TAG, "http_connect access vulnweb.com success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj = "http_connect access vulnweb.com failed";
                            Log.d(TAG, "http_connect access vulnweb.com failed");
                            e.printStackTrace();
                        }
                        mHandler.sendMessage(message);
                    }
                }).start();
            }
        });

        /*
         * https协议
         * 忽略证书验证
         */
        button_https_connect_without_ca.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable(){
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        OkHttpClient mClient = client.newBuilder().sslSocketFactory(HttpsTrustAllCerts.createSSLSocketFactory(),new HttpsTrustAllCerts()).hostnameVerifier(new HttpsTrustAllCerts.TrustAllHostnameVerifier()).build();
                        Request request = new Request.Builder()
                                .url("https://www.baidu.com/?q=trustAllCerts")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = mClient.newCall(request).execute()) {
                            message.obj = "https_connect_without_ca success";
                            Log.d(TAG, "https_connect_without_ca success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj = "https_connect_without_ca failed";
                            Log.d(TAG, "https_connect_without_ca failed");
                            e.printStackTrace();
                        }
                        mHandler.sendMessage(message);
                    }
                }).start();
            }
        });

        /*
         * https协议
         * 默认证书链校验，只信任系统CA(根证书)
         *
         * tips: OKHTTP默认的https请求使用系统CA验证服务端证书（Android7.0以下还信任用户证书，Android7.0开始默认只信任系统证书）
         */
        button_https_connect_with_system_ca.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable(){
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        Request request = new Request.Builder()
                                .url("https://www.baidu.com/?q=defaultCerts")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = client.newCall(request).execute()) {
                            message.obj = "https_connect_with_system_ca success";
                            Log.d(TAG, "https_connect_with_system_ca success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj = "https_connect_with_system_ca failed";
                            Log.d(TAG, "https_connect_with_system_ca failed");
                            e.printStackTrace();
                        }
                        mHandler.sendMessage(message);
                    }
                }).start();
            }
        });

        /*
         * https协议 SSL Pinning
         * 证书公钥绑定：验证证书公钥 baidu.com 使用CertificatePinner
         * 证书文件绑定：验证证书文件 bing.com  使用SSLSocketFactory
         */
        button_SSL_PINNING_with_key.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable(){
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        final String CA_DOMAIN = "www.baidu.com";
                        //获取目标公钥: openssl s_client -connect www.baidu.com:443 -servername www.baidu.com | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
                        final String CA_PUBLIC_KEY = "sha256//558pd1Y5Vercv1ZoSqOrJWDsh9sTMEolM6T8csLucQ=";
                        //只校验公钥
                        CertificatePinner pinner = new CertificatePinner.Builder()
                                .add(CA_DOMAIN, CA_PUBLIC_KEY)
                                .build();
                        OkHttpClient pClient = client.newBuilder().certificatePinner(pinner).build();
                        Request request = new Request.Builder()
                                .url("https://www.baidu.com/?q=SSLPinningCode")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = pClient.newCall(request).execute()) {
                            message.obj = "https SSL_PINNING_with_key access baidu.com success";
                            Log.d(TAG, "https SSL_PINNING_with_key access baidu.com success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj = "https SSL_PINNING_with_key access baidu.com failed";
                            Log.d(TAG, "https SSL_PINNING_with_key access baidu.com failed");
                            e.printStackTrace();
                        }


                        try {
                            // 获取证书输入流
                            InputStream openRawResource = getApplicationContext().getResources().openRawResource(R.raw.bing); //R.raw.bing是bing.com的正确证书，R.raw.bing2_so是hostname=bing.com的so.com的证书，可视为用作测试的虚假bing.com证书
                            Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(openRawResource);
                            // 创建 Keystore 包含我们的证书
                            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                            keyStore.load(null, null);
                            keyStore.setCertificateEntry("ca", ca);
                            // 创建一个 TrustManager 仅把 Keystore 中的证书 作为信任的锚点
                            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // 建议不要使用自己实现的X509TrustManager，而是使用默认的X509TrustManager
                            trustManagerFactory.init(keyStore);
                            // 用 TrustManager 初始化一个 SSLContext
                            sslContext = SSLContext.getInstance("TLS");  //定义：public static SSLContext sslContext = null;
                            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

                            OkHttpClient pClient2 = client.newBuilder().sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagerFactory.getTrustManagers()[0]).build();
                            Request request2 = new Request.Builder()
                                    .url("https://www.bing.com/?q=SSLPinningCAfile")
                                    .build();
                            try (Response response2 = pClient2.newCall(request2).execute()) {
                                message.obj += "\nhttps SSL_PINNING_with_CA_file access bing.com success";
                                Log.d(TAG, "https SSL_PINNING_with_CA_file access bing.com success return code:"+response2.code());
                            } catch (IOException e) {
                                message.obj += "\nhttps SSL_PINNING_with_CA_file access bing.com failed";
                                Log.d(TAG, "https SSL_PINNING_with_CA_file access bing.com failed");
                                e.printStackTrace();
                            }

                        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | KeyManagementException e) {
                            e.printStackTrace();
                        }
                        mHandler.sendMessage(message);
                    }
                }).start();
            }
        });

        /*
        * https协议 SSL PINNING
        * 证书绑定验证 配置在 @xml/network_security_config 中
        * sogou.com 使用 sogou.pem 验证证书
        * so.com 使用 sha256 key 验证
        */
        button_SSL_PINNING_with_CA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable(){
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        OkHttpClient pClient = client.newBuilder().build();
                        Request request = new Request.Builder()
                                .url("https://www.sogou.com/web?query=SSLPinningXML")
                                .build();
                        Request request2 = new Request.Builder()
                                .url("https://www.zhihu.com/")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = pClient.newCall(request).execute()) {
                            message.obj = "https SSL_PINNING_with_CA, config in xml with CA.pem file access sogou.com success";
                            Log.d(TAG, "https SSL_PINNING_with_CA, config in xml with CA.pem file access sogou.com success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj = "https SSL_PINNING_with_CA, config in xml with CA.pem file access sogou.com failed";
                            Log.d(TAG, "https SSL_PINNING_with_CA, config in xml with CA.pem file access sogou.com failed");
                            e.printStackTrace();
                        }
                        try (Response response = pClient.newCall(request2).execute()) {
                            message.obj += "\nhttps SSL_PINNING_with_CA, config in xml with key access zhihu.com success";
                            Log.d(TAG, "https SSL_PINNING_with_CA, config in xml with key access zhihu.com success return code:"+response.code());
                        } catch (IOException e) {
                            message.obj += "\nhttps SSL_PINNING_with_CA, config in xml with key access zhihu.com failed";
                            Log.d(TAG, "https SSL_PINNING_with_CA, config in xml with key access zhihu.com failed");
                            e.printStackTrace();
                        }
                        mHandler.sendMessage(message);
                    }
                }).start();
            }
        });

        /*
         * 双向校验
         * 因该测试是自建服务器并自签名，所以需要先在res/xml/network_security_config中配置信任服务端证书
         */
        button_https_twoway.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable(){
                    @RequiresApi(api = Build.VERSION_CODES.N)
                    @Override
                    public void run() {
                        X509TrustManager trustManager = null;
                        try {
                            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

                            trustManagerFactory.init((KeyStore) null);
                            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
                            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                                throw new IllegalStateException("Unexpected default trust managers:" + Arrays.toString(trustManagers));
                            }
                            trustManager = (X509TrustManager) trustManagers[0];
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        OkHttpClient mClient = client.newBuilder().sslSocketFactory(Objects.requireNonNull(ClientSSLSocketFactory.getSocketFactory(getApplicationContext())), Objects.requireNonNull(trustManager)).hostnameVerifier(new HostnameVerifier() {
                            @Override
                            public boolean verify(String hostname, SSLSession session) {
                                HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
                                return hv.verify("www.test.com", session);
                            }
                        }).build();

                        Request request = new Request.Builder()
                                .url("https://www.test.com/?q=TwoWayVerify")
                                .build();
                        Message message = new Message();
                        message.what = 1;
                        try (Response response = mClient.newCall(request).execute()) {
                            Log.d("TestReq", response.body().string());
                            message.obj = "请求成功: " + response.body().string();
                            mHandler.sendMessage(message);
                        } catch (IOException e) {
                            message.obj = e.getLocalizedMessage();
                            mHandler.sendMessage(message);
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });


        /*
         * https协议
         * WebView 不进行证书校验
         */
        button_webview_ssl_without_ca.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MyWebViewClient mWebViewClient = new MyWebViewClient();
                mWebViewClient.setCheckflag("trustAllCerts");
                mWebview.setWebViewClient(mWebViewClient);
                mWebview.loadUrl("https://www.baidu.com/?q=WebView_without_CAcheck");
            }
        });

        /*
         * https协议
         * WebView 使用系统证书校验
         */
        button_webview_ssl_with_system_ca.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MyWebViewClient mWebViewClient = new MyWebViewClient();
                mWebViewClient.setCheckflag("checkCerts");
                mWebview.setWebViewClient(mWebViewClient);
                mWebview.loadUrl("https://www.baidu.com/?q=WebView_with_SystemCAcheck");
            }
        });

        /*
         * https协议 SSL PINNING WebView
         * 通过network_security_config.xml中定义的证书和密钥进行绑定
         */
        button_webview_ssl_pinning.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MyWebViewClient mWebViewClient = new MyWebViewClient();
                mWebViewClient.setCheckflag("checkCerts");
                mWebview.setWebViewClient(mWebViewClient);
                mWebview.loadUrl("https://www.sogou.com/web?query=WebView_SSLPinningXML"); // 证书文件校验
                // mWebview.loadUrl("https://www.zhihu.com/"); // 证书公钥校验
            }
        });


        /*
         * 检测代理
         * 目前仅限OkHttp发出的请求
         */
        switch_check_proxy.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if(isChecked){
                    client = new OkHttpClient().newBuilder().proxy(Proxy.NO_PROXY).build();
                }else {
                    client = new OkHttpClient();
                }
            }
        });
    }

    private class MyWebViewClient extends WebViewClient {
        private String checkflag="checkCerts"; // 是否忽略证书校验

        public void setCheckflag(String checkflag) {
            this.checkflag = checkflag;
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            if("trustAllCerts".equals(checkflag)){
                handler.proceed();
            }else {
                handler.cancel();
                Toast.makeText(MainActivity.this, "证书异常，停止访问", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
