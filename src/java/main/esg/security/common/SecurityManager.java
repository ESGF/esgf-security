/*******************************************************************************
 * Copyright (c) 2010 Earth System Grid Federation
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
package esg.security.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;

/**
 * Utility class to manage keystores and trustores for creating/verifying digital signatures.
 */
public class SecurityManager {
	
	private final static Log LOG = LogFactory.getLog(SecurityManager.class);
	
	/**
	 * Method to return a map of trusted credentials, indexed by alias, read from a given trustore.
	 * @param trustore : the location of the local trustore
	 * @param password : the password needed to access the trustore
	 * @return
	 */
	public static Map<String,Credential> getTrustedCredentials(final File trustore, final String password) 
		   throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
		
		// load the trustore
		//final ClassPathResource trustore = new ClassPathResource(trustoreClasspathLocation);
		final KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
	    final FileInputStream fis = new java.io.FileInputStream(trustore);
	    ts.load(fis, password.toCharArray());
	    fis.close();
		
	    // loop over content, load all trusted certificates
	    final Map<String,Credential> trustedCredentials = new HashMap<String,Credential>();
	    final Enumeration<String> aliases = ts.aliases();
	    while (aliases.hasMoreElements()) {
	    	
	    	final String alias = aliases.nextElement();
	    	if (LOG.isDebugEnabled()) LOG.debug("Trusted Certificate Alias="+alias);
		    final KeyStore.TrustedCertificateEntry tcEntry = (KeyStore.TrustedCertificateEntry)ts.getEntry(alias, null); // no password required
		    if (LOG.isTraceEnabled()) LOG.trace("Trusted Certificate="+tcEntry.getTrustedCertificate());
		    final PublicKey trustedPublicKey = tcEntry.getTrustedCertificate().getPublicKey();
		    final KeyPair keyPair = new KeyPair(trustedPublicKey, null); // no private key available
		    final BasicCredential trustedCredential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
		    trustedCredentials.put(alias, trustedCredential);
	    
	    }
	    
	    return trustedCredentials;
		
	}
	
	/**
	 * Method to load the local credentials (public + private key) from a known classpath location.
	 * @param keystore : the location of the local keystore
	 * @param password : the password needed to access the keystore
	 * @param alias : the alias of the keystore entry to return
	 */
	public static Credential getMyCredential(final File keystore, final String password, final String alias)
		throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
	
		//final ClassPathResource keystore = new ClassPathResource(keystoreClasspathLocation);
		final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

	    final FileInputStream fis = new FileInputStream(keystore);
	    ks.load(fis, password.toCharArray());
	    fis.close();
	    
	    if (LOG.isInfoEnabled()) {
		    final Enumeration<String> aliases = ks.aliases();
		    while (aliases.hasMoreElements()) {
		    	LOG.info("Keystore alias="+aliases.nextElement());
		    }
	    }
	    
	    // load requested public and private key
	    final KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
	    if (LOG.isInfoEnabled()) LOG.info("Used alias="+alias+" password="+password+" to load keystore entry="+pkEntry.toString());
	    final PrivateKey myPrivateKey = pkEntry.getPrivateKey();
	    final PublicKey myPublicKey = pkEntry.getCertificate().getPublicKey();
	    if (LOG.isDebugEnabled()) LOG.debug("Private key="+myPrivateKey.toString());
	    if (LOG.isDebugEnabled()) LOG.debug("Public key="+myPublicKey.toString());
	    
	    final KeyPair keyPair = new KeyPair(myPublicKey, myPrivateKey);
	    final BasicCredential myCredential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
	    myCredential.setEntityId( ((X509Certificate)pkEntry.getCertificate()).getSubjectDN().toString() );
	    return myCredential;
		
	}

}
