/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
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

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Properties;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

import esg.security.attr.service.api.SAMLAttributeServiceClient;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;


/**
 * Class resolves OpenIDs to e-mail addresses making use of the Yadis protocol
 * to look-up a SAML attribute service for a given OpenID and query this
 * service to get the corresponding e-mail address
 * 
 * @author pjkersha
 *
 */
public class OpenId2EmailAddrResolution implements esg.common.Resolver {

    private static final Log log = LogFactory.getLog(OpenId2EmailAddrResolution.class);
        
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

        this.init(attributeQueryIssuer,
                  attributeServiceType,
                  yadisPropertiesFile,
                  attributeServiceClientPropertiesFile);
        
    }

    public void init(String attributeQueryIssuer,
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

    //------------------------------------------------------------------------------
    //Stream-free version method calls
    //------------------------------------------------------------------------------

    public OpenId2EmailAddrResolution() { }

    public OpenId2EmailAddrResolution(String attributeQueryIssuer,
                                      String attributeServiceType,
                                      String trustStoreFilePath,
                                      String trustStorePassphrase,
                                      String keyStoreFilePath,
                                      String keyStorePassphrase) throws DnWhitelistX509TrustMgrInitException {

        init(attributeQueryIssuer,
             attributeServiceType,
             trustStoreFilePath,
             trustStorePassphrase,
             keyStoreFilePath,
             keyStorePassphrase);
        
    }
    
    //To statisfy Resolver interface, where all resolvers are initialized with a properties object.
    //Helper functionality: Here we convert the properties into their
    //constituent values and pass them to the "real" init implementation
    public void init(Properties props) throws DnWhitelistX509TrustMgrInitException {
        this.init(props.getProperty("security.attribute.query.issuer"),
                  props.getProperty("security.attribute.service.type"),
                  props.getProperty("security.truststore.file"),
                  props.getProperty("security.truststore.password"),
                  props.getProperty("security.keystore.file"),
                  props.getProperty("security.keystore.password"));
    }
    
    //Added this method so that this object can be initialized with direct parameter values
    public OpenId2EmailAddrResolution init(String attributeQueryIssuer,
                                           String attributeServiceType,
                                           String trustStoreFilePath,
                                           String trustStorePassphrase,
                                           String keyStoreFilePath,
                                           String keyStorePassphrase) throws DnWhitelistX509TrustMgrInitException {
        
        try {
            yadisX509TrustMgr = new DnWhitelistX509TrustMgr(trustStoreFilePath,trustStorePassphrase);
                        
        } catch (DnWhitelistX509TrustMgrInitException e) {
            throw new DnWhitelistX509TrustMgrInitException("*Creating trust " +
                                                           "manager for Yadis query", e);
        }
                
        try {
            //Note: The question here is can I share the trust manager instance for both yadis lookup
            //and attribute service lookup.  I don't see why not, but that is the change that I made 
            //here that departs from the what was here before.
            httpsClient = new HttpsClient(keyStoreFilePath, keyStorePassphrase, yadisX509TrustMgr);
                        
        } catch (HttpsClientInitException e) {
            throw new DnWhitelistX509TrustMgrInitException("Creating HTTPS " +
                                                           "client for Attribute Service query", e);
        }

        if (this.attributeServiceType == null)
            this.attributeServiceType = DEF_ATTRIBUTE_SERVICE_XRD_SERVICE_TYPE;
        else
            this.attributeServiceType = attributeServiceType;
                
        this.attributeQueryIssuer = attributeQueryIssuer;
        return this;
    }

    
    //To satisfy the Resolver interface
    public String resolve(String input) { 
        try {
            return (resolve(new URL(input))).toString(); 
        }catch(Throwable t) {
            log.error(t);
            return null;
        }
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
        SAMLAttributeServiceClient attributeServiceClient = 
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
        } catch (IOException e) {
            throw new AttributeServiceQueryException("I/O error dispatching " +
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

