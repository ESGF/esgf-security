package esg.security.utils.ssl;

import static esg.security.utils.ssl.TrivialCertGenerator.createSelfSignedCertificate;
import static esg.security.utils.ssl.TrivialCertGenerator.generateRSAKeyPair;
import static esg.security.utils.ssl.TrivialCertGenerator.packKeyStore;
import static esg.security.utils.ssl.TrivialCertGenerator.sign;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.BindException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang.ArrayUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import sun.security.x509.X509CertImpl;

public class CertUtilsTest {
	private static boolean running = true;
	private static ServerSocket ssocket;
    private static final int chainLength = 4;
    private static KeyPair[] keyPairChain = new KeyPair[chainLength];
    private static X509CertImpl[] chain = new X509CertImpl[chainLength];
    private static SSLContext defaulsSSLContext;
    
	
	private static void startSSLServer(final int port, final KeyStore ks)  throws Exception {
        
        new Thread(new Runnable() {

            @Override
            public void run() {
                System.out.println("Test SSL Server init.");
                while (running) {
                    try {
                        SSLContext sc = SSLContext.getInstance("SSL");
                        KeyManagerFactory kmf =
                            KeyManagerFactory.getInstance("SunX509");
                        kmf.init(ks, "changeit".toCharArray());
                        sc.init(kmf.getKeyManagers(), null, new SecureRandom());
                        ServerSocketFactory ssocketFactory = SSLServerSocketFactory
                                .getDefault();
                        ssocket = ssocketFactory
                                .createServerSocket(port);
                        // Listen for connections
                        System.out.println("Waiting for first connection.");
                        ssocket.accept();
                        System.out.println("Got connection.");
                        Thread.sleep(5000);
                        running=false;
                    } catch (BindException e) {
                        running = false;
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
                System.out.println("Test SSL Server shut down.");
            }
            
        }).start();
	    
	}
	@BeforeClass
	public static void setupOnce() throws Exception {
	    //save this because we will be messing with it
	    defaulsSSLContext = SSLContext.getDefault();
	    
	    //generate root Certificate 
	    keyPairChain[0] = generateRSAKeyPair();
	    chain[0] = createSelfSignedCertificate(keyPairChain[0], "CN=localhost,OU=Root,L=DE");
        
        //generate a chain of certs
        for (int i = 1; i < chainLength; i++) {
            keyPairChain[i] = generateRSAKeyPair();
            chain[i] = createSelfSignedCertificate(keyPairChain[i], "CN=localhost,OU=Chain-" + i + " ,L=DE");
            chain[i] = sign(chain[i-1], keyPairChain[i-1].getPrivate(), chain[i]);
        }
      }
	
	@After
	public void teardown() {
	    //set the default ssl context back as required.
	    SSLContext.setDefault(defaulsSSLContext);
	}
	
	@AfterClass
	public static void tearOnce() {
		running = false;
		try {
			if (ssocket != null) ssocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testRetrieveSingleCertificate() throws Exception {
        int port = 9444;
        String urlRight = "https://localhost:" + port;
	    EchoSSLServer server = new EchoSSLServer();
	    
	    server.setCertificate(keyPairChain[0].getPrivate(), new Certificate[]{chain[0]});
	    server.setPort(port);
	    server.start();
        
	    //check some errors
	    try {
            CertUtils.retrieveCertificates("notAnURL!!!", false);
            fail("Malformed URL accepted.");
        } catch (MalformedURLException e) {
            // ok
        }
        try {
            CertUtils.retrieveCertificates("http://localhost", false);
            fail("Should not accept http connections (no certificate).");
        } catch (MalformedURLException e) {
            // ok
        }
        
        //check the right one
        CertPath cp = CertUtils.retrieveCertificates(urlRight, false);
        assertNotNull(cp);
        List<? extends Certificate> list = cp.getCertificates();
        assertEquals(1, list.size());
        assertEquals(chain[0], list.get(0));
        
        server.stopServer();
	}

    @Test
    public void testRetrieveCertificateChain() throws Exception {
        int port = 9445;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();

        server.setCertificate(keyPairChain[chain.length-1].getPrivate(),
                chain);
        server.setPort(port);
        server.start();

        CertPath cp = CertUtils.retrieveCertificates(urlRight, false);
        assertNotNull(cp);
        Certificate[] serverChain = cp.getCertificates().toArray(new Certificate[0]);
        //chain is backwards because it's easy to understand (0=root)
        assertEquals(chain.length, serverChain.length);
        ArrayUtils.reverse(serverChain);
        //check we got all certs
        
        for (int i = 0; i < chain.length; i++) {
            assertEquals(chain[i], serverChain[i]);
        }
        

        server.stopServer();
    }
    @Test
    public void testRetrieveTrustedCertificateFailed() throws Exception {
        int port = 9446;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();
        
        

        server.setCertificate(keyPairChain[0].getPrivate(), new Certificate[]{chain[0]});
        server.setPort(port);
        server.start();
        
        
        try {
            CertUtils.retrieveCertificates(urlRight, true);
            fail("Should have not been validated");
        } catch (SSLPeerUnverifiedException e) {
            //ok
            
        }
        server.stopServer();
    }
    
    /**
     * Cannot test Succes and failed in the same method. Still don't know why.
     * @throws Exception
     */
    @Test
    public void testRetrieveTrustedCertificateSuccess() throws Exception {
        
        int port = 9447;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();
        
        

        server.setCertificate(keyPairChain[0].getPrivate(), new Certificate[]{chain[0]});
        server.setPort(port);
        server.start();
        
       
        //no set up a default SSLContext and trust the certificate

        KeyStore ks = packKeyStore(null, null, null, new Certificate[]{chain[0]});
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);
        SSLContext sslc = SSLContext.getInstance("SSL");
        sslc.init(null, tmf.getTrustManagers(), new SecureRandom());
        SSLContext.setDefault(sslc);
        
        //this should work now
        assertEquals(chain[0],
                CertUtils.retrieveCertificates(urlRight, true).getCertificates().get(0));
        

        server.stopServer();
    }
}
