package esg.security.utils.ssl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;


public class EchoSSLServerTest {
    private static SSLSocketFactory defaultSSLFact;
    
    @BeforeClass
    public static void setupOnce() {
        //System.setProperty("javax.net.debug","ssl,handshake,verbose");
        defaultSSLFact = HttpsURLConnection.getDefaultSSLSocketFactory();
    }
    
    @After
    public void teardown() {
        //not really necessary but informative
        HttpsURLConnection.setDefaultSSLSocketFactory(defaultSSLFact);
    }
    
    @Test
    public void testEchoSSLServer() throws Exception {
        // basic test
        EchoSSLServer server = new EchoSSLServer();
        server.start();
        int port = server.getPort();

        System.out.println("Running on " + port);
        assertTrue(port > 0);
        server.stop();
    }

    @Test
    public void testEchoSSLServerSetup() throws Exception {
        // more complex test
        EchoSSLServer server = new EchoSSLServer();
        int port = 9888;
        server.setPort(port);
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        Certificate cert = TrivialCertGenerator.createSelfSignedCertificate(kp,
                "CN=localhost, OU=Test unit, L=DE");
        server.setServerCertificate(kp.getPrivate(), new Certificate[] { cert });
        server.start();

        // get the certificate
        Certificate serverCert = CertUtils
                .retrieveCertificates("https://localhost:" + port, false)
                .getCertificates().get(0);
        assertEquals(cert, serverCert);
        
        server.stop();
    }

    @Test
    public void testEchoSSLServerBasic() throws Exception {
        EchoSSLServer server = new EchoSSLServer();
        server.start();
        
        //port
        int port = server.getPort();
        assertTrue(port > 0);
        
        //chain and access
        Certificate[] gotChain = CertUtils
                .retrieveCertificates("https://localhost:" + port, false)
                .getCertificates().toArray(new Certificate[0]);
        Certificate[] serverChain = server.getCertificateChain();
        assertNotNull(serverChain);
        assertArrayEquals(gotChain, serverChain);
        
        //cert
        Certificate cert = server.getCertificate();
        assertNotNull(cert);
        assertEquals(cert, serverChain[0]);
        
        //keystore
        KeyStore ks = server.getKeystore();
        String serverAlias = ks.getCertificateAlias(cert);
        assertTrue(ks.isKeyEntry(serverAlias));
        
        //addTrustCert
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        Certificate trustCert = TrivialCertGenerator.createSelfSignedCertificate(kp, "CN=Sometest, L=DE");
        assertNull(ks.getCertificateAlias(trustCert));
        server.trustCertificate(trustCert);
        assertNotNull(ks.getCertificateAlias(trustCert));
        assertFalse(ks.isKeyEntry(ks.getCertificateAlias(trustCert)));
        
    } 

    @Test
    public void testEchoSSLServerWrongDN() throws Exception {
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        EchoSSLServer server = new EchoSSLServer();
        
        //get a host that's not this one
        
        try {
            server.setServerCertificate(kp.getPrivate(),
                    new Certificate[] { TrivialCertGenerator
                            .createSelfSignedCertificate(kp,
                                    "CN=www.google.com, OU=Test unit, L=DE") });
            fail("This is not the localhost.");
        } catch (UnknownHostException e) {
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    @Test
    public void testEchoSSLClientValidationValid() throws Exception {
        EchoSSLServer server = new EchoSSLServer();
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        Certificate cert = TrivialCertGenerator.createSelfSignedCertificate(kp,
                "CN=localhost, OU=Test unit, L=DE");
        KeyStore keystore = TrivialCertGenerator.packKeyStore(null, new Certificate[]{cert}, kp.getPrivate(), null);
        KeyStore truststore = TrivialCertGenerator.packKeyStore(null, null, null, new Certificate[]{cert});
        
        //set the server to trust the cert (it will use own created keystore for the connection)
        KeyStore serverCert = TrivialCertGenerator.packKeyStore(
                null,
                null,
                null,
                server.getKeystore().getCertificateChain(
                        server.getKeystore().aliases().nextElement()));

        server.setValidateClient(truststore);
        server.start();

        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, "changeit".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(serverCert); //trust the server
        SSLContext sslc = SSLContext.getInstance("SSL");
        
        sslc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sslc.getSocketFactory());
        
        CertUtils.retrieveCertificates("https://localhost:" + server.getPort(), true);
        server.stop();
    }
    @Test
    public void testEchoSSLClientValidationWrong() throws Exception {
        EchoSSLServer server = new EchoSSLServer();
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        Certificate cert = TrivialCertGenerator.createSelfSignedCertificate(kp,
                "CN=localhost, OU=Test unit, L=DE");
        KeyStore truststore = TrivialCertGenerator.packKeyStore(null, null, null, new Certificate[]{cert});
        

        server.setValidateClient(truststore);
        server.start();
        
        try {
            CertUtils.retrieveCertificates("https://localhost:" + server.getPort(), true);
            fail("client was not validated!");
        } catch (SSLPeerUnverifiedException e) {
            //ok!
        }
        
        server.stop();
    }
    
    @Test
     public void testEchoMessage() throws Exception {
        EchoSSLServer server = new EchoSSLServer();
        String message = "This is a test message";
        server.setMessage(message);
        server.start();
        
        SSLContext sslc = SSLContext.getInstance("SSL");
        
        sslc.init(null, new TrustManager[] { new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {return null;}
            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
        }}, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sslc.getSocketFactory());

        //check the server is sending the message ( a couple of times to be sure it doesn't hang/stop)
        for (int i = 0; i < 3; i++) {
            InputStream in = new URL("https://localhost:" + server.getPort()).openConnection().getInputStream();        
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String response = br.readLine();
            br.close();
            
            assertEquals(message, response);
            System.out.println(i + "# message ok");
            try { Thread.sleep(100); } catch (Exception e) {}
        }
        
                
        server.stop();
    }
}
