package esg.security.attr.service.impl;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import esg.security.attr.service.api.GroupRole;

/**
 * Bean implementation of {@link GroupRole} interface.
 * Note that this class implements the {@link Comparable} interface 
 * so that instances can be naturally ordered in collections.
 * 
 * @author luca.cinquini
 *
 */
public class GroupRoleImpl implements GroupRole, Comparable<GroupRole> {

	private String group;
	private String role;
	
	public GroupRoleImpl(final String group, final String role) {
		setGroup(group);
		setRole(role);
	}
	
	public String getGroup() {
		return group;
	}
	public void setGroup(String group) {
		this.group = group;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}	

	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.getGroup()).append(this.getRole()).toHashCode();
	}
	
	@Override
	public boolean equals(final Object other) {

		if (!(other instanceof GroupRole)) {
			return false;
		}
		final GroupRole castOther = (GroupRole)other;
		return new EqualsBuilder().append(this.getGroup(), castOther.getGroup())
								  .append(this.getRole(), castOther.getRole())
		                          .isEquals();
	}

	@Override
	public int compareTo(final GroupRole other) {
		return  (this.getGroup().equals(other.getGroup()) ? 
				 this.getRole().compareTo(other.getRole()) : this.getGroup().compareTo(other.getGroup()));
	}
	
}
