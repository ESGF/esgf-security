package esg.security.policy.service.api;

import java.util.List;

/**
 * API for establishing access control on resources.
 * 
 * @author luca.cinquini
 *
 */
public interface PolicyService {
	
	/**
	 * Method to retrieve the attributes that entitle the given action on the given resource.
	 * @param resource
	 * @param action
	 * @return
	 */
	List<PolicyAttribute> getRequiredAttributes(String resource, String action);

}
