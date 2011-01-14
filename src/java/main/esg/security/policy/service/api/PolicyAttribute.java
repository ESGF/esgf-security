package esg.security.policy.service.api;

/**
 * An attribute used to establish access control.
 * 
 * @author luca.cinquini
 *
 */
public interface PolicyAttribute {
	
	String getType();
	
	String getValue();

}
