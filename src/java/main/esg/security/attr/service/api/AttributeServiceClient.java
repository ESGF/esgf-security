package esg.security.attr.service.api;

import java.net.URL;
import java.util.Set;

/**
 * High level client API for retrieving user attributes from a remote service.
 * 
 * @author Luca Cinquini
 *
 */
public interface AttributeServiceClient {
    
    /**
     * Method to request a set of attributes for a specific user from a remote service.
     * @param url
     * @param identifier
     * @param types
     * @return
     */
    SAMLAttributes getAttributes(URL url, String identifier, Set<String> types);

}
