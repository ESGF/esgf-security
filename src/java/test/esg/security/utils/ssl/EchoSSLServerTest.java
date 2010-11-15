package esg.security.utils.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Test;


public class EchoSSLServerTest {

    @Test
    public void testEchoSSLServer() throws Exception {
        // basic test
        EchoSSLServer server = new EchoSSLServer();
        server.start();
        int port = server.getPort();

        System.out.println("Running on " + port);
        assertTrue(port > 0);
        server.stopServer();
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
        server.setCertificate(kp.getPrivate(), new Certificate[] { cert });
        server.start();

        // get the certificate
        Certificate serverCert = CertUtils
                .retrieveCertificates("https://localhost:" + port, false)
                .getCertificates().get(0);
        assertEquals(cert, serverCert);
        
        server.stopServer();
    }

    @Test
    public void testEchoSSLServerWrongDN() throws Exception {
        KeyPair kp = TrivialCertGenerator.generateRSAKeyPair();
        EchoSSLServer server = new EchoSSLServer();
        
        //get a host that's not this one
        
        try {
            server.setCertificate(kp.getPrivate(),
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
        SSLContext.setDefault(sslc);
        
        CertUtils.retrieveCertificates("https://localhost:" + server.getPort(), true);
        server.stopServer();
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
        

        server.stopServer();
    }
}
