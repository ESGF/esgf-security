/*******************************************************************************
 * Copyright (c) 2010 Earth System Grid Federation
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
package esg.saml.attr.service.impl;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import esg.saml.attr.service.api.GroupRole;
import esg.saml.attr.service.api.SAMLAttributes;

/**
 * Bean implementation of the {@link SAMLAttributes} interface.
 * Note that this implementation naturally orders the attributes by SAML name.
 */
public class SAMLAttributesImpl implements SAMLAttributes {
	
	private String firstName;
	
	private String lastName;
	
	private String openid;
	
	private String email;
	
	public SAMLAttributesImpl() {}
	
	/**
	 * The authority that issued these attributes.
	 */
	private String issuer;
	
	/**
	 * Map storing string-based, multi-valued access control attributes.
	 * Note that (simple) attributes are naturally ordered by name.
	 */
	private Map<String,Set<String>> attributes = new TreeMap<String,Set<String>>();
	
	/**
	 * Map storing (group,role) attributes, naturally ordered by name.
	 */
	private Map<String, Set<GroupRole>> grouproles = new TreeMap<String,Set<GroupRole>>();

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getOpenid() {
		return openid;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Map<String,Set<String>> getAttributes() {
		return Collections.unmodifiableMap(attributes);
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	
	public void addAttribute(String name, String value) {
		if (attributes.get(name)==null) {
			attributes.put(name, new TreeSet<String>());
		}
		attributes.get(name).add(value);
	}

	@Override
	public void addGroupAndRole(String name, GroupRole grouprole) {
		if (grouproles.get(name)==null) {
			grouproles.put(name, new TreeSet<GroupRole>());
		}
		grouproles.get(name).add(grouprole);
	}

	@Override
	public Map<String, Set<GroupRole>> getGroupAndRoles() {
		return Collections.unmodifiableMap(grouproles);
	}
	
	
}
