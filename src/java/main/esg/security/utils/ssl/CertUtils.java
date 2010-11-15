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

import org.springframework.core.io.ClassPathResource;


/**
 * Utility class to set the keystore and trustore environment to be used in SSL communication.
 */
public class CertUtils {
	
	
	final static ClassLoader classloader = CertUtils.class.getClassLoader();
	
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
            throw new SSLPeerUnverifiedException("Target is not trusted");
        }

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		cp = cf.generateCertPath(Arrays.asList(sslConnection.getServerCertificates()));
		
		//done
		sslConnection.disconnect();
		
		return cp;
		
	}


}
