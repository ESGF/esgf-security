/**
 * 
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: YadisRetrieval.java 7513 2010-09-24 12:55:36Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7513 $
 */
package esg.security.yadis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import esg.security.DnWhitelistX509TrustMgr;
import esg.security.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.yadis.exception.XrdsParseException;
import esg.security.yadis.exception.YadisRetrievalException;

/**
 * Retrieve a Yadis document and parse it returning the required service
 * elements
 * 
 * @author pjkershaw
 */
public class YadisRetrieval
{	
	// Trust Manager enables DN whitelisting
	protected X509TrustManager x509TrustMgr;
	
	/**
	 * Initialise SSL connection properties
	 * 
	 * @param propertiesFile input stream for properties file
	 * @throws YadisRetrievalException 
	 */
	public YadisRetrieval(InputStream propertiesFile) throws YadisRetrievalException {
		
		// Create trust manager with given whitelist and keystore settings
		// read from properties file
		try {
			x509TrustMgr = new DnWhitelistX509TrustMgr(propertiesFile);
			
		} catch (DnWhitelistX509TrustMgrInitException e) {
			throw new YadisRetrievalException("Creating trust manager", e);
		}
	}
	
	/**
	 * Initialise from an existing trust manager
	 * @param x509TrustMgr
	 */
	public YadisRetrieval(X509TrustManager x509TrustMgr) {
		this.x509TrustMgr = x509TrustMgr;
	}
	
	/**
	 * Retrieve XRD document from Yadis endpoint
	 * 
	 * @param yadisURL URL to retrieve content from
	 * @return string containing the XRD document at the given URL
	 * @throws YadisRetrievalException
	 */
	public String retrieve(URL yadisURL) throws YadisRetrievalException 
	{		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("SSL");
			
		} catch (NoSuchAlgorithmException e) {
			throw new YadisRetrievalException("Getting SSL context", e);
		}
		
		X509TrustManager tm[] = {x509TrustMgr};
		try {
			ctx.init(null, tm, null);
		} catch (KeyManagementException e) {
			throw new YadisRetrievalException("Initialising SSL context", e);
		}
		
		SSLSocketFactory socketFactory = ctx.getSocketFactory();
		HttpsURLConnection connection = null;
		try {
			connection = (HttpsURLConnection)yadisURL.openConnection();
		} catch (IOException e) {
			throw new YadisRetrievalException("Making connection", e);
		}
		connection.setSSLSocketFactory(socketFactory);
				
		InputStream ins = null;
		try {
			ins = connection.getInputStream();
		} catch (IOException e) {
			throw new YadisRetrievalException("Getting input stream", e);
		}
	    InputStreamReader isr = new InputStreamReader(ins);
	    BufferedReader in = new BufferedReader(isr);
	    StringBuffer buf = new StringBuffer();
	    String inputLine = null;

	    try {
			while ((inputLine = in.readLine()) != null)
			{
			    buf.append(inputLine);
			    buf.append(System.getProperty("line.separator"));
			}
			in.close();
		} catch (IOException e) {
			throw new YadisRetrievalException("Reading content", e);
		}

	    return buf.toString();
	}
	
	/**
	 *  Retrieve and parse Yadis document returning the services it references
	 *  
	 * @param yadisURL URL to retrieve content from
	 * @param targetTypes retrieve only this subset of target (service types).
	 * See to null to retrieve all types.
	 * @return list of services for this Yadis endpoint
	 * @throws XrdsParseException error parsing XRD document
	 * @throws YadisRetrievalException error GETing the content
	 */
	public List retrieveAndParse(URL yadisURL, Set targetTypes) throws 
		XrdsParseException, YadisRetrievalException
	{
		String yadisDocContent;
		yadisDocContent = retrieve(yadisURL);

		XrdsDoc xrdsDoc = new XrdsDoc();
		List serviceElems = xrdsDoc.parse(yadisDocContent, targetTypes);
		return serviceElems;
	}
	
	public static void main(String[] args) throws IOException {
		// Input Whitelist DNs as a string array
		//	X500Principal [] whitelist = {
		//	new X500Principal("CN=ceda.ac.uk, OU=RAL-SPBU, O=Science and Technology Facilities Council, C=GB")
		//};
		
		// Input DNs from a file
		InputStream propertiesFile = 
			DnWhitelistX509TrustMgr.class.getResourceAsStream(
								"DnWhitelistX509TrustMgr.properties");

		YadisRetrieval yadis = null;
		try {
			yadis = new YadisRetrieval(propertiesFile);
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		URL yadisURL = new URL("https://ceda.ac.uk/openid/Philip.Kershaw");
//		URL yadisURL = new URL("https://localhost:7443/openid/PJKershaw");
		
		// 1) Retrieve as string content
		String content = null;
		try {
			content = yadis.retrieve(yadisURL);
			
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Yadis content = " + content);
		
		// 2) Retrieve as list of services
		List<XrdsServiceElem> serviceElems = null;
		
		// Retrieve only services matching these type(s)
		String elem [] = {"urn:esg:security:attribute-service"};
		Set<String> targetTypes = new HashSet(Arrays.asList(elem));
		try {
			serviceElems = yadis.retrieveAndParse(yadisURL, targetTypes);
			
		} catch (XrdsParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (YadisRetrievalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if (serviceElems.isEmpty())
			System.out.println("No services found for " + elem[0] + " type");
		
		for (XrdsServiceElem serviceElem : serviceElems)
			System.out.println(serviceElem);
	}
}
