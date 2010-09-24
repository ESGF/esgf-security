package esg.security;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ProtocolException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import esg.security.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.exceptions.HttpsClientInitException;
import esg.security.exceptions.HttpsClientRetrievalException;

public class HttpsClient {
	private KeyManager[] keyManagers;
	private DnWhitelistX509TrustMgr x509TrustMgr;
	protected static String KEYSTORE_TYPE = "JKS";
	protected static String KEYMGR_FACTORY_TYPE = "SunX509";
	protected static String KEYSTORE_FILEPATH_PROP_NAME = 
		HttpsClient.class.getName() + ".keyStoreFilePath";
	protected static String KEYSTORE_PASSPHRASE_PROP_NAME = 
		HttpsClient.class.getName() + ".keyStorePassphrase";
	protected String keyStoreFilePath;
	protected String keyStorePassphrase;
	
	public HttpsClient(InputStream propertiesFile) 
		throws HttpsClientInitException {
		keyStorePassphrase = null;
		keyStoreFilePath = null;
		
		Properties props = loadProperties(propertiesFile);
		
		InputStream keyStoreIStream = null;
		try {
			keyStoreIStream = new FileInputStream(keyStoreFilePath);
			
		} catch (FileNotFoundException e) {
			throw new HttpsClientInitException("Error reading "+
					"\"" + keyStoreFilePath + "\" keystore", e);
		}
		loadKeyStore(keyStoreIStream, keyStorePassphrase);
		loadTrustMgr(props);
	}
	
	public HttpsClient(InputStream keyStoreIStream, String keyStorePassphrase,
			DnWhitelistX509TrustMgr x509TrustMgr) 
		throws HttpsClientInitException {
		loadKeyStore(keyStoreIStream, keyStorePassphrase);
		this.x509TrustMgr = x509TrustMgr;
	}
	
	protected Properties loadProperties(InputStream propertiesFile) 
		throws HttpsClientInitException {
    	// create application properties with default
    	Properties applicationProps = new Properties();
    	
    	try {
			applicationProps.load(propertiesFile);
		} catch (IOException e) {
			throw new HttpsClientInitException(
					"Error loading properties file", e);
		}
		
		// Key store file may be null in which case standard locations are
		// searched instead
		keyStoreFilePath = applicationProps.getProperty(
				KEYSTORE_FILEPATH_PROP_NAME, null);
		
		keyStorePassphrase = applicationProps.getProperty(
				KEYSTORE_PASSPHRASE_PROP_NAME, null);
		
		return applicationProps;
	}
	
	/**
	 * Instantiate trust manager from existing properties
	 * 
	 * @param properties
	 * @throws HttpsClientInitException
	 */
	protected void loadTrustMgr(Properties properties) 
		throws HttpsClientInitException {
		// Create trust managers with given whitelist and keystore settings
		// read from appropriate properties files
		try {
			x509TrustMgr = new DnWhitelistX509TrustMgr(properties);
			
		} catch (DnWhitelistX509TrustMgrInitException e) {
			throw new HttpsClientInitException("Creating trust manager", e);
		}		
	}
	
	protected void loadKeyStore(InputStream keyStoreIStream, 
			String keyStorePassphrase) 
		throws HttpsClientInitException {
		
		// Load client cert/key for SSL client authentication required for 
		// attribute service query
		keyManagers = null;
		if (keyStoreIStream != null) {
			KeyStore keyStore = null;
			try {
				keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
				
			} catch (KeyStoreException e) {
				throw new HttpsClientInitException("Instantiating "+
						"new Java keystore", e);
			}
			
			try {
				keyStore.load(keyStoreIStream, keyStorePassphrase.toCharArray());
				
			} catch (NoSuchAlgorithmException e) {
				throw new HttpsClientInitException("Error reading " +
						"input keystore", e);
	
			} catch (CertificateException e) {
				throw new HttpsClientInitException("Error reading "+
						"input keystore", e);
	
			} catch (IOException e) {
				throw new HttpsClientInitException("Error reading "+
						"input keystore", e);
			}	
			
			KeyManagerFactory keyManagerFactory = null;
			try {
				keyManagerFactory = KeyManagerFactory.getInstance(
						KEYMGR_FACTORY_TYPE);
				
			} catch (NoSuchAlgorithmException e) {
				throw new HttpsClientInitException("Making new key " +
						"manager factory", e);
			}
			
			try {
				keyManagerFactory.init(keyStore, keyStorePassphrase.toCharArray());
				
			} catch (UnrecoverableKeyException e) {
				throw new HttpsClientInitException("Initialising key " +
						"manager factory from input keystore", e);
	
			} catch (KeyStoreException e) {
				throw new HttpsClientInitException("Initialising key " +
						"manager factory from input keystore", e);
				
			} catch (NoSuchAlgorithmException e) {
				throw new HttpsClientInitException("Initialising key " +
						"manager factory from keystore input keystore", e);
			}
			
			keyManagers = keyManagerFactory.getKeyManagers();
		}
	}
	
	/**
	 * Invoke the given HTTPS URI retrieving the content
	 * 
	 * @param uri
	 * @param query
	 * @param requestMethod
	 * @param keyStoreFilePath
	 * @param keyStorePassphrase
	 * @return
	 * @throws HttpsClientRetrievalException
	 */
	public String retrieve(URL uri, String query, String requestMethod)
			throws HttpsClientRetrievalException {
		
		// Enable defaults for HTTP request method
		if (requestMethod == null) 
			if (query == null)
				requestMethod = "GET";
			else
				requestMethod = "POST";
		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("SSL");
			
		} catch (NoSuchAlgorithmException e) {
			throw new HttpsClientRetrievalException("Getting SSL context", e);
		}
		
		X509TrustManager tm[] = {x509TrustMgr};
		try {
			ctx.init(keyManagers, tm, null);
			
		} catch (KeyManagementException e) {
			throw new HttpsClientRetrievalException("Initialising SSL context", 
													 e);
		}
		
		SSLSocketFactory socketFactory = ctx.getSocketFactory();
		HttpsURLConnection connection = null;
		try {
			connection = (HttpsURLConnection)uri.openConnection();
		} catch (IOException e) {
			throw new HttpsClientRetrievalException("Making connection", e);
		}
		connection.setSSLSocketFactory(socketFactory);
		connection.setDoOutput(true);
		
		try {
			connection.setRequestMethod(requestMethod);
		} catch (ProtocolException e) {
			throw new HttpsClientRetrievalException(
					"Setting HTTP request method to \"POST\"", e);
		}
		
		if (requestMethod == "POST") {
			OutputStream ops = null;
			try {
				ops = connection.getOutputStream();
			} catch (IOException e) {
				throw new HttpsClientRetrievalException(
					"Getting output stream for query", e);
			}
			
			OutputStreamWriter osw = new OutputStreamWriter(ops);
			try {
				osw.write(query);
				osw.flush();
				osw.close();
			} catch (IOException e) {
				throw new HttpsClientRetrievalException(
					"Error writing query for dispatch", e);
			}
		}
		
		InputStream ins = null;
		try {
			ins = connection.getInputStream();
		} catch (IOException e) {
			throw new HttpsClientRetrievalException("Getting input stream", e);
		}
		
	    InputStreamReader isr = new InputStreamReader(ins);
	    BufferedReader in = new BufferedReader(isr);
	    StringBuffer buf = new StringBuffer();
	    String inputLine = null;

	    try {
			while ((inputLine = in.readLine()) != null) {
			    buf.append(inputLine);
			    buf.append(System.getProperty("line.separator"));
			}
			in.close();
		} catch (IOException e) {
			throw new HttpsClientRetrievalException("Reading content", e);
		}

		/*
		 * Parse the response
		 */
		String response = buf.toString();
		return response;
	}

}
