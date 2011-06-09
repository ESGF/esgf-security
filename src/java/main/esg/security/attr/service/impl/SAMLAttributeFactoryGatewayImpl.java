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
/**
   Description:
   Get AttributeService roles from an ESGF Gateway database.
   
**/
package esg.security.attr.service.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;


import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.ResultSetHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.node.security.UserInfo;
import esg.security.attr.service.impl.SAMLAttributesImpl;
import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;




public class SAMLAttributeFactoryGatewayImpl implements SAMLAttributeFactory {

    /**
     * 
     */

	final private String issuer;
    private SAMLAttributes attributes = null;

    //EG Query
    private static final String openidQuery = 
	"SELECT id, firstname, lastname, email, dn " +
	"FROM security.user " +
	"WHERE openid = ?";
    
    private static final String groupQuery = 
	"SELECT g.name, role.name " +
	"FROM security.user u, security.group g, role, status, membership m " +
	"WHERE u.openid = ? " +
	"  AND m.user_id=u.id AND m.group_id=g.id AND m.role_id=role.id AND m.status_id=status.id AND status.name='valid' ";
    
    
    
    //-------------------

    private static final Log log = LogFactory.getLog(SAMLAttributeFactoryGatewayImpl.class);

    private Properties props = null;
    private Connection conn = null;
    private ResultSetHandler<Map<String,Set<String>>> userGroupsResultSetHandler = null;
    private ResultSetHandler<Integer> idResultSetHandler = null;
    private DataSource dataSource;
    
	public SAMLAttributeFactoryGatewayImpl(final String issuer, DataSource dataSource) throws Exception {
		this.issuer = issuer;
		
		//!TODO: A bit clunky.  Could use better DB interface.
		conn = dataSource.getConnection();
    
        this.props = props;

        
	}


	@Override
	public SAMLAttributes newInstance(String identifier) throws SAMLUnknownPrincipalException {
		GatewayAttributeInfo attributeInfo = null;
		
		try {
			attributeInfo = getAttributeInfoById(identifier);
		}
		catch (Exception e) {
			log.debug("Failed AttributeInfo lookup for " + identifier);
			//!TODO: this is for debugging only.  It isn't necessarily an error.
			log.error("Failing exception is", e);
			throw new SAMLUnknownPrincipalException("Unknown identifier: "+identifier);
		}		

		attributes = new SAMLAttributesImpl(identifier, issuer);
		attributes.setFirstName(attributeInfo.getFirstName());
		attributes.setLastName(attributeInfo.getLastName());
		attributes.setOpenid(attributeInfo.getOpenid());
		attributes.setEmail(attributeInfo.getEmail());
		attributes.setAttributes(attributeInfo.getPermissions());
		
		return attributes;
	
	}
    
	@Override
	public String getIssuer() {
		return issuer;
	}

	private GatewayAttributeInfo getAttributeInfoById(String identifier) throws Exception {
		GatewayAttributeInfo attributeInfo = null;
		log.debug("Getting Gateway info for " + identifier);
		
		try {
			PreparedStatement query1 = conn.prepareStatement(openidQuery);
			query1.setString(1, identifier);
			ResultSet resultSet = query1.executeQuery();
			
			// Sanity check
			assert resultSet.getMetaData().getColumnCount() == 1;
			resultSet.next();
			
			String uuid = resultSet.getString(1);			
			attributeInfo = new GatewayAttributeInfo(
							resultSet.getString(2), 
							resultSet.getString(3), 
							identifier, 
							resultSet.getString(3)
							);

			log.debug("Lookup found " + attributeInfo.toString());
			
			PreparedStatement query2 = conn.prepareStatement(groupQuery);
			query2.setString(1, uuid);
			resultSet = query2.executeQuery();
			
			while (resultSet.next()) {
				log.debug("Group found: " + resultSet.getString(1) + " : " + resultSet.getString(2));
				attributeInfo.addPermission(resultSet.getString(1), resultSet.getString(2));
			}
			
		}
		catch (SQLException e) {
			throw new Exception("SQL query failed");
		}
		
		return attributeInfo;
	}
	
}

class GatewayAttributeInfo {
	/*
	 * Note: this object is written in mainly Immutable style.  Most attributes are only set on instantiation.
	 */
	private String firstname;
	private String lastname;
	private String openid;
	private String email;
	private Map<String,Set<String>> permissions;

	public GatewayAttributeInfo(String firstname, String lastname, String openid, String email) {
			this.firstname = firstname;
			this.lastname = lastname;
			this.openid = openid;
			this.email = email;
			this.permissions = new HashMap<String,Set<String>>();
	}
	
	public String getFirstName() {
		return firstname;
	}
	public String getLastName() {
		return lastname;
	}
	public String getOpenid() {
		return openid;
	}
	public String getEmail() {
		return email;
	}
	
	public Map<String, Set<String>> getPermissions() {
		return permissions;
	}

	public void setPermissions(Map<String, Set<String>> permissions) {
		this.permissions = permissions;
	}

	public void addPermission(String group, String role) {
		if (!permissions.containsKey(group)) {
			permissions.put(group, new HashSet<String>());
		}
		permissions.get(group).add(role);
	}
	public void removePermission(String group, String role) {
		permissions.get(group).remove(role);
	}

	@Override
	public String toString() {
		return "GatewayAttributeInfo [email=" + email + ", firstname=" + firstname
				+ ", lastname=" + lastname + ", openid=" + openid + "]";
	}
	
}