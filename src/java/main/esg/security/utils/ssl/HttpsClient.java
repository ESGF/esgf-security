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
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.utils.ssl.exceptions.HttpsClientInitException;
import esg.security.utils.ssl.exceptions.HttpsClientRetrievalException;


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
	
	public HttpsClient(InputStream propertiesFile) throws HttpsClientInitException {
		keyStorePassphrase = null;
		keyStoreFilePath = null;
		
		Properties props = loadProperties(propertiesFile);
		if (keyStoreFilePath != null && keyStorePassphrase != null) {
		
			InputStream keyStoreIStream = null;
			try {
				keyStoreIStream = new FileInputStream(keyStoreFilePath);
				
			} catch (FileNotFoundException e) {
				throw new HttpsClientInitException("Error reading "+
						"\"" + keyStoreFilePath + "\" keystore", e);
			}
			loadKeyStore(keyStoreIStream, keyStorePassphrase);
		}
		loadTrustMgr(props);
	}

	public HttpsClient(Properties props) throws HttpsClientInitException {
		keyStorePassphrase = null;
		keyStoreFilePath = null;
		
		if (keyStoreFilePath != null && keyStorePassphrase != null) {
		
			InputStream keyStoreIStream = null;
			try {
				keyStoreIStream = new FileInputStream(keyStoreFilePath);
				
			} catch (FileNotFoundException e) {
				throw new HttpsClientInitException("Error reading "+
						"\"" + keyStoreFilePath + "\" keystore", e);
			}
			loadKeyStore(keyStoreIStream, keyStorePassphrase);
		}
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
		
		if (propertiesFile == null) {
			throw new HttpsClientInitException("Null properties file");
		}
		
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
	
    //------------------------------------------------------------------------------
    //Stream-free version method calls
    //------------------------------------------------------------------------------

    //Added this method so that this object can be constructed with direct parameter values
    public HttpsClient(String keyStoreFilePath, 
                       String keyStorePassphrase, 
                       DnWhitelistX509TrustMgr x509TrustMgr) throws HttpsClientInitException {
        loadKeyStore(keyStoreFilePath, keyStorePassphrase);
        this.x509TrustMgr = x509TrustMgr;
    }
	
    //Added this method so that this object can be constructed with direct parameter values
    public void loadKeyStore(String keyStoreFilePath, String keyStorePassphrase) throws HttpsClientInitException {
        InputStream keyStoreIStream = null;
        try {
            keyStoreIStream = new FileInputStream(keyStoreFilePath);
            
        } catch (FileNotFoundException e) {
            throw new HttpsClientInitException("Error reading "+
                                               "\"" + keyStoreFilePath + "\" keystore", e);
        }
        loadKeyStore(keyStoreIStream, keyStorePassphrase);
    }
	protected void loadKeyStore(InputStream keyStoreIStream, String keyStorePassphrase) throws HttpsClientInitException {
		
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
	 * @throws IOException 
	 */
	public String retrieve(URL uri, String query, String requestMethod)
			throws HttpsClientRetrievalException, IOException {
		
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
		
		/*
		 * Leave IOException to be thrown from here so that caller can 
		 * delineate this kind of error from the SSL/keystore initialisation
		 */
		ins = connection.getInputStream();
		
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
