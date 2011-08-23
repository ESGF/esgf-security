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
/**
 * Support tool for SSL based authentication for ESG Security web services
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: DnWhitelistX509TrustMgr.java 7513 2010-09-24 12:55:36Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7513 $
 */
package esg.security.utils.ssl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;


/**
 * Extend PKIX X.509 Trust Manager to support whitelisting of peer certificate
 * Distinguished Names
 * 
 * @author pjkersha
 */
public class DnWhitelistX509TrustMgr implements X509TrustManager {

	protected static String TRUSTSTORE_FILEPATH_PROP_NAME = 
		DnWhitelistX509TrustMgr.class.getName() + ".trustStoreFilePath";
	protected static String TRUSTSTORE_PASSPHRASE_PROP_NAME = 
		DnWhitelistX509TrustMgr.class.getName() + ".trustStorePassphrase";
	protected static String DN_PROP_NAME = DnWhitelistX509TrustMgr.class.getName() + ".dn";
	
	protected static String BASE_TRUST_MGR_ID = "PKIX";
	protected static String TRUSTSTORE_TYPE = "JKS";
	
	/**
	 * list of peer certificate distinguished names that are acceptable to
	 * the client in SSL connections
	 */
	protected Set<X500Principal> certificateDnWhiteList;
	
    /**
     * The default PKIX X509TrustManager9.  Delegate decisions to it, and fall 
     * back to the logic in this class if the default X509TrustManager doesn't 
     * trust it.
     */
    X509TrustManager pkixTrustManager;
	
    /**
     * Load default trust manager and trust store if set
     * 
     * @param trustStoreFilePath trust store file path
     * @param trustStorePassphrase pass-phrase for this trust store - use null if none set
     */
    public DnWhitelistX509TrustMgr(String trustStoreFilePath,
                                   String trustStorePassphrase) throws DnWhitelistX509TrustMgrInitException {
    	certificateDnWhiteList = null;
    	loadTrustStore(trustStoreFilePath, trustStorePassphrase);
    }
    

    public synchronized DnWhitelistX509TrustMgr setWhitelist(Set<String> dns) {
        this.certificateDnWhiteList = new HashSet<X500Principal>();
        for(String dn : dns) {
            if(dn == null) continue;
            this.certificateDnWhiteList.add(new X500Principal(dn));
        }
        return this;
    }

    /**
     * Initialise trust store and default trust manager which is wrapped by this
     * class
     * 
     * @param trustStoreFilePath
     * @param trustStorePassphrase
     * @throws DnWhitelistX509TrustMgrInitException 
     */
    public void loadTrustStore(String trustStoreFilePath, 
                               String trustStorePassphrase) throws DnWhitelistX509TrustMgrInitException {
        TrustManagerFactory tmf = null;
		try {
			tmf = TrustManagerFactory.getInstance(BASE_TRUST_MGR_ID);
			
		} catch (NoSuchAlgorithmException e) {
			throw new DnWhitelistX509TrustMgrInitException("Instantiating "+
					"\"" + BASE_TRUST_MGR_ID + "\" trust manager", e);
		}
		
		FileInputStream trustStoreIStream = null;
        KeyStore trustStore = null;
		
		if (trustStoreFilePath != null)
		{
			try {
				trustStoreIStream = new FileInputStream(trustStoreFilePath);
				
			} catch (FileNotFoundException e) {
				throw new DnWhitelistX509TrustMgrInitException("Error reading "+
						"\"" + trustStoreFilePath + "\" truststore", e);
			}
		
			// Create a "default" JSSE X509TrustManager.
			try {
				trustStore = KeyStore.getInstance(TRUSTSTORE_TYPE);
				
			} catch (KeyStoreException e) {
				throw new DnWhitelistX509TrustMgrInitException("Instantiating "+
						"new Java keystore", e);
			}
			
	        try {
				trustStore.load(trustStoreIStream, trustStorePassphrase == null ? 
								null : trustStorePassphrase.toCharArray());
				
			} catch (NoSuchAlgorithmException e) {
				throw new DnWhitelistX509TrustMgrInitException("Error reading "+
						"\"" + trustStoreFilePath + "\" truststore", e);
	
			} catch (CertificateException e) {
				throw new DnWhitelistX509TrustMgrInitException("Error reading "+
						"\"" + trustStoreFilePath + "\" truststore", e);
	
			} catch (IOException e) {
				throw new DnWhitelistX509TrustMgrInitException("Error reading "+
						"\"" + trustStoreFilePath + "\" truststore", e);
			}
		}
		
        try {
			tmf.init(trustStore);
		} catch (KeyStoreException e) {
			throw new DnWhitelistX509TrustMgrInitException("Initialising "+
					"\"" + BASE_TRUST_MGR_ID + "\" trust manager", e);
		}
		
        TrustManager tms [] = tmf.getTrustManagers();

        /*
         * Iterate over the returned trust managers, look for an instance of 
         * X509TrustManager.  If found, use that as "default" trust manager.
         */
        for (Object tm : tms) {
            if (tm instanceof X509TrustManager) {
                pkixTrustManager = (X509TrustManager) tm;
                return;
            }
        }

        /*
         * Got to here so no X509TrustManager was found
         */
        throw new DnWhitelistX509TrustMgrInitException("No X509TrustManager " +
        		"found in trust manager factory instance");
    }
    
    /**
     * Instantiate based on property file input stream
     * 
     * @param propertiesFile properties file enables static setting of DN 
     * whitelist - the list of peer certificate distinguished 
     * names that are acceptable to the client in SSL connections
     * @throws DnWhitelistX509TrustMgrInitException invalid keystore or error
     * getting default trust manager
     */
    public DnWhitelistX509TrustMgr(InputStream propertiesFile) throws DnWhitelistX509TrustMgrInitException {
    	loadProperties(propertiesFile);
    }

    /**
     * Instantiate based on properties object
     * 
     * @param applicationProps
     * @throws DnWhitelistX509TrustMgrInitException
     */
    public DnWhitelistX509TrustMgr(Properties applicationProps) 
    	throws DnWhitelistX509TrustMgrInitException {
    	loadProperties(applicationProps);
	}

    /**
     * Load properties from input stream
     * 
     * @param propertiesFile
     * @return
     * @throws DnWhitelistX509TrustMgrInitException
     */
    public Properties loadProperties(InputStream propertiesFile) throws 
    			DnWhitelistX509TrustMgrInitException {

    	// create application properties with default
    	Properties applicationProps = new Properties();
    	
    	if (propertiesFile == null) {
    		throw new DnWhitelistX509TrustMgrInitException(
					"Properties file is null");
    	}
    	
    	try {
			applicationProps.load(propertiesFile);
		} catch (IOException e) {
			throw new DnWhitelistX509TrustMgrInitException(
					"Error loading properties file", e);
		}
		loadProperties(applicationProps);
		
		return applicationProps;
    }
		
    /**
     * Load properties from Properties object
     * 
     * @param applicationProps
     * @throws DnWhitelistX509TrustMgrInitException
     */
	public void loadProperties(Properties applicationProps) 
		throws DnWhitelistX509TrustMgrInitException {
		
		// Key store file may be null in which case standard locations are
		// searched instead
		String trustStoreFilePath = applicationProps.getProperty(
			TRUSTSTORE_FILEPATH_PROP_NAME, null);
		
		String trustStorePassphrase = applicationProps.getProperty(
				TRUSTSTORE_PASSPHRASE_PROP_NAME, null);
		
                loadWhitelistFromProperties(applicationProps);
                loadTrustStore(trustStoreFilePath, trustStorePassphrase);
    }

    //old stuff way too hard coded -gavin
    public synchronized void loadWhitelistFromProperties(Properties applicationProps) {
		/* 
		 * DN values are stored in the property file as e.g.
		 *
		 * esg.security.DnWhitelistX509TrustMgr.dn0 = ...
		 * esg.security.DnWhitelistX509TrustMgr.dn1 = ...
		 * esg.security.DnWhitelistX509TrustMgr.dn2 = ... 
		 *
		 * ... etc. 
		 */
		String dnValue = null;
		this.certificateDnWhiteList = new HashSet<X500Principal>();
		for (int i=0; i < applicationProps.size(); i++) {
			dnValue = applicationProps.getProperty(DN_PROP_NAME+i, null);
			if (dnValue == null)
				continue;
			
			this.certificateDnWhiteList.add(new X500Principal(dnValue));
		}
    }
    
    /**
     * Instantiate from a given certificate DN whitelist
     * 
     * @param trustStoreFilePath trust store file path
     * @param trustStorePassphrase pass-phrase for this trust store - use null if
     * none set
     * @param certificateDnWhiteList list of peer certificate distinguished 
     * names that are acceptable to the client in SSL connections
     * @throws DnWhitelistX509TrustMgrInitException invalid keystore or error
     * getting default trust manager
     */
    public DnWhitelistX509TrustMgr(String trustStoreFilePath,
                                   String trustStorePassphrase,
                                   X500Principal[] certificateDnWhiteList) throws DnWhitelistX509TrustMgrInitException {
    	
    	this(trustStoreFilePath, trustStorePassphrase);
        
    	if (certificateDnWhiteList != null)
    		for (X500Principal dn : certificateDnWhiteList)
    			this.certificateDnWhiteList.add(dn);			
    }
    
    /**
     * SSL Client certificate authentication
     * 
     * Delegate to the default trust manager but also includes DN whitelist 
     * checking
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        pkixTrustManager.checkClientTrusted(chain, authType);

        // If chain is OK following previous check, then execute whitelisting of DN
        checkPeerCertDN(chain);
    }

    /**
     * SSL Server certificate authentication
     * 
     * Delegate to the default trust manager but also includes DN whitelist 
     * checking
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    	
    	// Default trust manager may throw a certificate exception
        pkixTrustManager.checkServerTrusted(chain, authType);
        
        // If chain is OK following previous check, then execute whitelisting of DN
        checkPeerCertDN(chain);
    }

    /**
     * Check peer certificate DN against whitelist - use in checkServerTrusted
     * and checkClientTrusted
     * 
     * @param chain
     * @param peerCertDN
     * @throws CertificateException 
     */
    protected void checkPeerCertDN(X509Certificate[] chain) throws CertificateException {
        if (certificateDnWhiteList == null || certificateDnWhiteList.isEmpty())
            return;
        
        X500Principal peerCertDN = null;
        int basicConstraints = -1;
	
        for (X509Certificate cert : chain) {
            // Check for CA certificate first - ignore if this is the case
            basicConstraints = cert.getBasicConstraints();
            if (basicConstraints > -1)
                continue;

            peerCertDN = cert.getSubjectX500Principal();
			
            // Nb. direct X500Principal type equality test may fail as it's 
            // based on the canonical names of the two principals
            for (X500Principal dn : certificateDnWhiteList) {
                if (peerCertDN.getName().equals(dn.getName()))
                    return;
            }
        }
        throw new CertificateException("No match for peer certificate \"" + 
                                       peerCertDN + "\" against Certificate DN whitelist");
    }
    
    /**
     * Merely pass this through.
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return pkixTrustManager.getAcceptedIssuers();
    }

}
