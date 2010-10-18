/**
 * Earth System Grid/CMIP5
 *
 * Date: 09/08/10
 * 
 * Copyright: (C) 2010 Science and Technology Facilities Council
 * 
 * Licence: BSD
 * 
 * $Id: OpenId2EmailAddrResolution.java 7513 2010-09-24 12:55:36Z pjkersha $
 * 
 * @author pjkersha
 * @version $Revision: 7513 $
 */
package esg.security.openid2emailresolution;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

import esg.security.attr.service.api.exceptions.SAMLAttributeServiceClientResponseException;
import esg.security.attr.service.impl.SAMLAttributeServiceClientSoapImpl;
import esg.security.attr.service.impl.SAMLAttributesImpl;
import esg.security.common.SAMLParameters;
import esg.security.openid2emailresolution.exceptions.AttributeServiceQueryException;
import esg.security.openid2emailresolution.exceptions.NoMatchingXrdsServiceException;
import esg.security.utils.ssl.DnWhitelistX509TrustMgr;
import esg.security.utils.ssl.HttpsClient;
import esg.security.utils.ssl.exceptions.DnWhitelistX509TrustMgrInitException;
import esg.security.utils.ssl.exceptions.HttpsClientInitException;
import esg.security.utils.ssl.exceptions.HttpsClientRetrievalException;
import esg.security.yadis.XrdsServiceElem;
import esg.security.yadis.YadisRetrieval;
import esg.security.yadis.exceptions.XrdsParseException;
import esg.security.yadis.exceptions.YadisRetrievalException;


/**
 * Class resolves OpenIDs to e-mail addresses making use of the Yadis protocol
 * to look-up a SAML attribute service for a given OpenID and query this
 * service to get the corresponding e-mail address
 * 
 * @author pjkersha
 *
 */
public class OpenId2EmailAddrResolution {
	
	private String attributeQueryIssuer;
	private String attributeServiceType;
	private DnWhitelistX509TrustMgr yadisX509TrustMgr;
	private HttpsClient httpsClient;
	public static final String DEF_ATTRIBUTE_SERVICE_XRD_SERVICE_TYPE = 
		"urn:esg:security:attribute-service";
	
	/**
	 * Yadis and Attribute Service properties files set SSL settings for 
	 * queries to these respective services
	 * 
	 * @param attributeQueryIssuer
	 * @param attributeServiceType
	 * @param yadisPropertiesFile
	 * @param attributeServiceClientPropertiesFile
	 * @throws YadisRetrievalException
	 */
	public OpenId2EmailAddrResolution(String attributeQueryIssuer,
			String attributeServiceType,
			InputStream yadisPropertiesFile, 
			InputStream attributeServiceClientPropertiesFile) 
				throws DnWhitelistX509TrustMgrInitException {
		
		// Create trust managers with given whitelist and keystore settings
		// read from appropriate properties files
		try {
			yadisX509TrustMgr = new DnWhitelistX509TrustMgr(yadisPropertiesFile);
			
		} catch (DnWhitelistX509TrustMgrInitException e) {
			throw new DnWhitelistX509TrustMgrInitException("Creating trust " +
					"manager for Yadis query", e);
		}
		
		try {
			httpsClient = new HttpsClient(attributeServiceClientPropertiesFile);
			
		} catch (HttpsClientInitException e) {
			throw new DnWhitelistX509TrustMgrInitException("Creating HTTPS " +
					"client for Attribute Service query", e);
		}

		if (this.attributeServiceType == null)
			this.attributeServiceType = DEF_ATTRIBUTE_SERVICE_XRD_SERVICE_TYPE;
		else
			this.attributeServiceType = attributeServiceType;
		
		this.attributeQueryIssuer = attributeQueryIssuer;
	}
	
	public OpenId2EmailAddrResolution(String attributeQueryIssuer,
			InputStream yadisPropertiesFile, 
			InputStream attributeServiceClientPropertiesFile) 
	throws DnWhitelistX509TrustMgrInitException {
		this(attributeQueryIssuer, null, yadisPropertiesFile, 
				attributeServiceClientPropertiesFile);
	}
	
	/**
	 * 
	 * @param openidURL
	 * @return
	 * @throws NoMatchingXrdsServiceException
	 * @throws XrdsParseException
	 * @throws YadisRetrievalException
	 * @throws AttributeServiceQueryException
	 */
	public InternetAddress resolve(URL openidURL) throws 
		NoMatchingXrdsServiceException, 
		XrdsParseException, 
		YadisRetrievalException, 
		AttributeServiceQueryException {
		
		YadisRetrieval yadisRetriever = new YadisRetrieval(yadisX509TrustMgr);
		List<XrdsServiceElem> serviceElems = null;
		Set<String> targetTypes = new HashSet<String>() {
			private static final long serialVersionUID = 1L; {
			add(attributeServiceType);
			}
		};
		
		serviceElems = yadisRetriever.retrieveAndParse(openidURL, targetTypes);
		
		if (serviceElems == null || serviceElems.isEmpty())
			throw new NoMatchingXrdsServiceException("No matching XRDS " + 
					"service element returned for OpenID URI: " + openidURL);
		
		// Get Attribute Service URI from service element with the highest 
		// priority
		Collections.sort(serviceElems);
		XrdsServiceElem priorityAttributeServiceElem = serviceElems.get(0);
		URL attributeServiceEndpoint = null;
		try {
			attributeServiceEndpoint = new URL(priorityAttributeServiceElem.getUri());
		
		} catch (MalformedURLException e) {
			throw new AttributeServiceQueryException("Attribute Service " +
					"URI " + attributeServiceEndpoint + " is invalid", e);
		}
			 
		 // Call Attribute Service querying for e-mail address
		 InternetAddress emailAddr = queryAttributeService(
				 attributeServiceEndpoint,
				 openidURL);
		 return emailAddr;
	}
	
	/**
	 * Call Attribute Service to retrieve user's e-mail address
	 * 
	 * @param attributeServiceEndpoint
	 * @param openidURL
	 * @return
	 * @throws AttributeServiceQueryException
	 * @throws  
	 */
	protected InternetAddress queryAttributeService(
			URL attributeServiceEndpoint,
			URL openidURL) throws AttributeServiceQueryException
	{		
		SAMLAttributeServiceClientSoapImpl attributeServiceClient = 
			new SAMLAttributeServiceClientSoapImpl(attributeQueryIssuer);
		
		// Create query
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		Attribute emailAttribute = attributeBuilder.buildObject();
		emailAttribute.setName(SAMLParameters.EMAIL_ADDRESS);
		emailAttribute.setFriendlyName(SAMLParameters.EMAIL_ADDRESS_FRIENDLY);
		emailAttribute.setNameFormat("http://www.w3.org/2001/XMLSchema#string");
		
		List<Attribute> attributes = new ArrayList<Attribute>();
		attributes.add(emailAttribute);
		
		AttributeQuery attributeQuery = null;
		attributeQuery = attributeServiceClient.buildAttributeQuery(
															openidURL.toString(), 
															attributes);
		
		String query = null;
		try {
			query = attributeServiceClient.buildAttributeRequest(attributeQuery);
			
		} catch (MarshallingException e) {
			throw new AttributeServiceQueryException("Marshalling attribute " +
					"query to " + attributeServiceEndpoint + " for OpenID", e);			
		}
		
		String response = null;
		try {
			response = httpsClient.retrieve(attributeServiceEndpoint, query, null);
			
		} catch (HttpsClientRetrievalException e) {
			throw new AttributeServiceQueryException("Error dispatching " +
					"attribute query", e);
		}
		
		SAMLAttributesImpl samlAttrs = null;
		try {
			samlAttrs = (SAMLAttributesImpl) 
				attributeServiceClient.parseAttributeResponse(attributeQuery,
						response);
			
		} catch (XMLParserException e) {
			throw new AttributeServiceQueryException(
					"Parsing attribute query response", e);
		} catch (UnmarshallingException e) {
			throw new AttributeServiceQueryException(
					"Unmarshalling attribute query response", e);
			
		} catch (SAMLAttributeServiceClientResponseException e) {
			throw new AttributeServiceQueryException(
					"Error with attribute query response", e);
		}
		
		String sEmail = samlAttrs.getEmail();
		if (sEmail == null) {
			throw new AttributeServiceQueryException(
					"Error retrieving e-mail address for user " + openidURL +
					" from Attribute Service " + attributeServiceEndpoint);
		}
		
		InternetAddress email;
		try {
			email = new InternetAddress(sEmail);
		} catch (AddressException e) {
			throw new AttributeServiceQueryException(
					"Error parsing e-mail address", e);
		}
	    return email;
	}
}

