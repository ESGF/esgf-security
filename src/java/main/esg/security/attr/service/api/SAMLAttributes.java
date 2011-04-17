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
package esg.security.attr.service.api;

import java.util.Map;
import java.util.Set;

/**
 * Interface representing the attributes contained in a SAML attribute assertion.
 * Note that attributes can be of three categories: 
 * <ul>
 * <li> "personal attributes" (first/last name and email) have a fixed type (a.k.a. SAML name) and single value, 
 *      and are set via specific setter properties; 
 * <li> generic access control attributes are simple strings, have a configurable type and multiple values, and are stored and retrieved through a map.
 * <li> complex access control attributes are of type GroupRole, have a configurable type, and are stored and retrieved through a map.
 * </ul>
 */
public interface SAMLAttributes {

	String getFirstName();

	void setFirstName(String firstName);

	String getLastName();

	void setLastName(String lastName);

	String getOpenid();

	void setOpenid(String openid);

	String getEmail();

	void setEmail(String email);
	
	String getIssuer();
	
	void setIssuer(String issuer);

	/**
	 * Retrieves string-based access control attributes.
	 * @return
	 */
	Map<String,Set<String>> getAttributes();

	/**
	 * Sets the string-based access control attributes.
	 * @return
	 */
    void setAttributes(Map<String,Set<String>> attributes);
	
	/**
	 * Adds a value to a named attribute
	 * (existing values are retained).
	 * @param name
	 * @param value
	 */
	void addAttribute(String name, String value);
	
	/**
	 * Retrieves complex (group,role) access control attributes.
	 * @return
	 */
	Map<String, Set<GroupRole>> getGroupAndRoles();
	
	/**
	 * Adds a (group,role) access control attribute.
	 * @param name
	 * @param grouprole
	 */
	void addGroupAndRole(String name, GroupRole grouprole);

}
