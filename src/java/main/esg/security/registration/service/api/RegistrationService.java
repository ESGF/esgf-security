package esg.security.registration.service.api;

/**
 * API for registering users into groups, with given roles.
 * 
 * @author Luca Cinquini
 *
 */
public interface RegistrationService {
    
    /**
     * Method to register a given user in a group with a specified role.
     * The group and role must already exist in the database, 
     * while the user will be created if not existing already.
     * 
     * @param user
     * @param group
     * @param role
     */
    void register(String user, String group, String role) throws Exception;

}
