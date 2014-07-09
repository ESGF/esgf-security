package esg.security.attr.service.impl;

import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.springframework.util.StringUtils;

import esg.security.attr.service.api.AttributeServiceClient;
import esg.security.attr.service.api.IdentityResolver;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.attr.service.api.YadisClient;
import esg.security.common.SAMLParameters;

public class IdentityResolverImpl implements IdentityResolver {
    
    private final static String ATTRIBUTE_SERVICE_TYPE = "urn:esg:security:attribute-service";

    private final static String ISSUER = "ESGF client";
    
    /**
     * Client responsible for requesting the Yadis document.
     */
    YadisClient yadisClient = new YadisClientImpl();
    
    /**
     * Client responsible for querying the remote Attribute Services.
     */
    private final AttributeServiceClient attClient = new AttributeServiceClientImpl(ISSUER);


    @Override
    public SAMLAttributes resolve(String openid) throws Exception {
                
        // query Yadis endpoint
        final String attributeServiceURI = yadisClient.getServiceUri(openid, ATTRIBUTE_SERVICE_TYPE);
        
        // query attribute service for specific types
        if (StringUtils.hasText(attributeServiceURI)) {
            
            final Set<String> types = new HashSet<String>();
            types.add(SAMLParameters.FIRST_NAME);
            types.add(SAMLParameters.LAST_NAME);
            types.add(SAMLParameters.EMAIL_ADDRESS);
            return attClient.getAttributes(new URL(attributeServiceURI), openid, types);
            
        } else {
            throw new Exception("Cannot locate attribute service for openid="+openid);
        }
        
    }

}
