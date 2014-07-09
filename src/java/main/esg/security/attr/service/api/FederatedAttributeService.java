package esg.security.attr.service.api;

import java.util.Map;
import java.util.Set;

/**
 * API for retrieving user attributes across the entire federation.
 * 
 * @author Luca Cinquini
 *
 */
public interface FederatedAttributeService {
    
    /**
     * 
     * @param identifier the user identifier (aka openid)
     * @return a map of (attribute type, attribute values[]) pairs (aka (group name, group roles[]) pairs)
     */
    public Map<String, Set<String>> getAttributes(String identifier) throws Exception;

}
