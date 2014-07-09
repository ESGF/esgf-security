package esg.security.attr.service.api;

/**
 * API for instructing information from a Yadis service.
 * 
 * @author Luca Cinquini
 *
 */
public interface YadisClient {
    
    /**
     * Retrieves the Yadis document for the openid identifier,
     * and returns the URI for the a specific service type.
     * @param openid
     * @param serviceType
     * @return
     */
    String getServiceUri(String openid, String serviceType) throws Exception;

}
