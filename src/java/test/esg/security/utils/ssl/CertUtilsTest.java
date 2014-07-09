/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.security.utils.ssl;

import static esg.security.utils.ssl.TrivialCertGenerator.createSelfSignedCertificate;
import static esg.security.utils.ssl.TrivialCertGenerator.generateRSAKeyPair;
import static esg.security.utils.ssl.TrivialCertGenerator.packKeyStore;
import static esg.security.utils.ssl.TrivialCertGenerator.sign;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.net.MalformedURLException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang.ArrayUtils;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import sun.security.x509.X509CertImpl;

public class CertUtilsTest {
    private static final int chainLength = 4;
    private static KeyPair[] keyPairChain = new KeyPair[chainLength];
    private static X509CertImpl[] chain = new X509CertImpl[chainLength];
    private static SSLSocketFactory defHttpsURLConnection;
    
	

	@BeforeClass
	public static void setupOnce() throws Exception {
	    //save this because we will be messing with it
	    defHttpsURLConnection = HttpsURLConnection.getDefaultSSLSocketFactory();
	    
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
	    HttpsURLConnection.setDefaultSSLSocketFactory(defHttpsURLConnection);
	}
	

	@Test
	public void testRetrieveSingleCertificate() throws Exception {
        int port = 9444;
        String urlRight = "https://localhost:" + port;
	    EchoSSLServer server = new EchoSSLServer();
	    
	    server.setServerCertificate(keyPairChain[0].getPrivate(), new Certificate[]{chain[0]});
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
        
        server.stop();
	}

    @Test
    public void testRetrieveCertificateChain() throws Exception {
        int port = 9445;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();

        server.setServerCertificate(keyPairChain[chain.length-1].getPrivate(),
                chain);
        server.setPort(port);
        server.start();

        CertPath cp = CertUtils.retrieveCertificates(urlRight, false);
        assertNotNull(cp);
        Certificate[] serverChain = cp.getCertificates().toArray(new Certificate[0]);

        //chain is backwards because it's easy to understand (0=root)
        assertEquals(chain.length, serverChain.length);
        ArrayUtils.reverse(serverChain);
        assertArrayEquals(chain, serverChain);
       

        server.stop();
    }
    
    @Test
    public void testRetrieveTrustedCertificate() throws Exception {
        int port = 9446;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();
        
        

        server.setServerCertificate(keyPairChain[0].getPrivate(), new Certificate[]{chain[0]});
        server.setPort(port);
        server.start();
        
        
        //assure we get an exception if the server is not validated
        try {
            CertUtils.retrieveCertificates(urlRight, true);
            fail("Should have not been validated");
        } catch (SSLPeerUnverifiedException e) {
            //ok
        }
        
        //now set up the default HttpsURLConnection and trust server's certificate
        KeyStore ks = packKeyStore(null, null, null, new Certificate[]{chain[0]});
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);
        SSLContext sslc = SSLContext.getInstance("SSL");
        sslc.init(null, tmf.getTrustManagers(), new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslc.getSocketFactory());
        
        
        //this should work now
        assertEquals(chain[0],
                CertUtils.retrieveCertificates(urlRight, true).getCertificates().get(0));
        
        server.stop();
    }
    
    @Test
    public void testRetrieveTrustedCertificateChain() throws Exception {
        int port = 9448;
        String urlRight = "https://localhost:" + port;
        EchoSSLServer server = new EchoSSLServer();
        
        
        //set the whole chain as certificate
        server.setServerCertificate(keyPairChain[chain.length-1].getPrivate(), chain);
        server.setPort(port);
        server.start();
        
        
        //assure we get an exception if the server is not validated
        try {
            CertUtils.retrieveCertificates(urlRight, true);
            fail("Should have not been validated");
        } catch (SSLPeerUnverifiedException e) {
            //ok
        }
        
        //now trust the root certificate only
        KeyStore ks = packKeyStore(null, null, null, new Certificate[]{chain[0]});
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);
        SSLContext sslc = SSLContext.getInstance("SSL");
        sslc.init(null, tmf.getTrustManagers(), new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslc.getSocketFactory());
        
        
        //this should work now
        Certificate[] certs =
                CertUtils.retrieveCertificates(urlRight, true).getCertificates().toArray(new Certificate[0]);
        
        //chain is backwards as it's easier to understand
        ArrayUtils.reverse(certs);
        assertEquals(chain.length, certs.length);
        assertArrayEquals(chain, certs);
        
        server.stop();
    }
    
}
