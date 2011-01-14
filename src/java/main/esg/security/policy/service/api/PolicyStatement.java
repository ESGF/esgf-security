package esg.security.policy.service.api;

/**
 * A statement about what action can be executed on a resource by entities that carry a given attribute.
 * 
 * @author luca.cinquini
 *
 */
public interface PolicyStatement {
	
	/**
	 * The resource, or class of resources, this policy is about.
	 * @return
	 */
	String getResource();
	
	/**
	 * The attribute that entitles execution of the action on the resource.
	 * @return
	 */
	PolicyAttribute getAttribute();
	
	/**
	 * The action allowed by this policy on the given resource.
	 * @return
	 */
	PolicyAction getAction();

}
