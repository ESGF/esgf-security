package esg.security.attr.service.impl;

import java.net.URL;
import java.util.ArrayList;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AttributeQuery;

import esg.security.attr.service.api.AttributeServiceClient;
import esg.security.attr.service.api.SAMLAttributeServiceClient;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SOAPServiceClient;

public class AttributeServiceClientImpl implements AttributeServiceClient {
    
    /**
     * Client used to build the attribute query request.
     */
    private final SAMLAttributeServiceClient samlAttributeServiceClient;
    
    /**
     * Client used to send the request via SOAP to the remote AttributeService.
     */
    private final SOAPServiceClient soapClient;
    
    private final Log LOG = LogFactory.getLog(this.getClass());

    public AttributeServiceClientImpl(final String issuer) {
        
        this.samlAttributeServiceClient = new SAMLAttributeServiceClientSoapImpl(issuer);
        
        this.soapClient = SOAPServiceClient.getInstance();
        
    }

    @Override
    public SAMLAttributes getAttributes(URL url, String identifier, Set<String> types) {
       
        try {
            
            final AttributeQuery attributeQuery = samlAttributeServiceClient.buildStringAttributeQuery(identifier, new ArrayList<String>(types));
            final String attRequest = samlAttributeServiceClient.buildAttributeRequest(attributeQuery);
            if (LOG.isInfoEnabled()) LOG.info("Querying attribute service at URL="+url.toString()+" request="+attRequest); 
            
            final String attResponse = soapClient.doSoap(url.toString(), attRequest);
            if (LOG.isInfoEnabled()) LOG.info("Query response="+attResponse);
            
            final SAMLAttributes samlAttributes = samlAttributeServiceClient.parseAttributeResponse(attributeQuery, attResponse);
            return samlAttributes;
            
        } catch(Exception e) {
            LOG.warn(e.getMessage());
            // return empty attributes
            return new SAMLAttributesImpl(identifier, null);
        }
       
    }
    

}
