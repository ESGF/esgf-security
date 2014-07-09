package esg.security.attr.service.api;


/**
 * Client API for resolving a user openid
 * into personal data (first name, last name, email address).
 * 
 * @author Luca Cinquini
 *
 */
public interface IdentityResolver {
    
    SAMLAttributes resolve(String openid) throws Exception;

}
