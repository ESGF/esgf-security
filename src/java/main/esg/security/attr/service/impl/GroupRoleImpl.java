/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
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
