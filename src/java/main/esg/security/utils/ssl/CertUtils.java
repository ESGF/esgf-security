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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.ClassPathResource;

import esg.security.utils.xml.XmlChecker;


/**
 * Utility class to set the keystore and trustore environment to be used in SSL communication.
 */
public class CertUtils {
	
	
	final private static ClassLoader classloader = CertUtils.class.getClassLoader();
	final private static Log LOG = LogFactory.getLog(CertUtils.class);
	
	/**
	 * Method to set a keystore to the desired file in the classpath.
	 * A keystore is needed by the client to send its own certificate for authentication.
     * Note that the keystore must be trusted by the server.
     * 
	 * @param keystoreClassPathLocation
	 * @throws Exception
	 */
	public static void setKeystore(final String keystoreClassPathLocation) throws Exception {
		
		ClassPathResource keystore = new ClassPathResource(keystoreClassPathLocation, classloader);
		System.setProperty("javax.net.ssl.keyStore", keystore.getFile().getAbsolutePath()); 
		System.setProperty("javax.net.ssl.keyStorePassword","changeit");
		
	}

	/**
	 * Method to set the trustore to the desired file in the classpath.
	 * A trustore is needed for the client to trust the server certificate.
	 * The trustore must match the certificate used by the server
	 * 
	 * @param trustoreClassPathLocation
	 * @throws Exception
	 */
	public static void setTruststore(final String trustoreClassPathLocation) throws Exception {
		
		ClassPathResource trustore = new ClassPathResource(trustoreClassPathLocation, classloader);
		System.setProperty("javax.net.ssl.trustStore", trustore.getFile().getAbsolutePath()); 
		System.setProperty("javax.net.ssl.trustStorePassword","changeit");
		
	}
	
	/**
	 * Retrieve the certificate chain from a trusted server.
	 * @param url url of the SSL connection whose certificate chain is going to be retrieved.
	 * @param validate if the conenction should be validated before retrieving the certificate.
	 * @return a CertPath with all retrieved certificates (is a X509CertPath and the first one
	 * is that from the contacting server)
	 * @throws SSLPeerUnverifiedException If the certificate chain is not trusted. This implies validate==true(warning: extends IOException)
	 * @throws MalformedURLException URL is not well formed
	 * @throws IOException cannot access server
	 * @throws CertificateException cannot generate certificates
	 */
	public static CertPath retrieveCertificates(final String url, boolean validate) 
		throws SSLPeerUnverifiedException, MalformedURLException, IOException , CertificateException{
		CertPath cp = null;
		URLConnection c = (new URL(url)).openConnection();
		//we can't work with http connections
		if (!(c instanceof HttpsURLConnection)) throw new MalformedURLException("Only https allowed");
		
		HttpsURLConnection sslConnection = (HttpsURLConnection)c;
		if (!validate) {
			//to avoid validation an empty TrustManager must be set in place.
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				// Install an all-trusting trust manager 
				sc.init(null, 
						new TrustManager[] { new X509TrustManager() {
							@Override
							public X509Certificate[] getAcceptedIssuers() {return null;}
							@Override
							public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
							@Override
							public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
						}},
						new java.security.SecureRandom());
				sslConnection.setSSLSocketFactory(sc.getSocketFactory());
			} catch (NoSuchAlgorithmException e) {
				// If this does not work no SSL connection can be made
				throw new IOException("SSL context cannot be instantiated.", e);
			} catch (KeyManagementException e) {
				// This should never happen
				throw new IOException(e);
			}

		}
		try {
		    sslConnection.connect();
		} catch (SSLHandshakeException e) {
		    LOG.warn(e.getMessage());
		    sslConnection.disconnect();
            throw new SSLPeerUnverifiedException("Target is not trusted");
        }

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		cp = cf.generateCertPath(Arrays.asList(sslConnection.getServerCertificates()));
		
		//done
		sslConnection.disconnect();
		
		return cp;
		
	}


}
