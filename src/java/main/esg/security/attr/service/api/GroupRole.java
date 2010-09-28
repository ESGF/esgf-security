package esg.security.attr.service.api;

/**
 * Interface representing a complex attribute composed of a "group" and "role".
 * 
 * @author luca.cinquini
 *
 */
public interface GroupRole {
	
	void setGroup(String group);
	
	void setRole(String role);
	
	String getGroup();
	
	String getRole();

}
