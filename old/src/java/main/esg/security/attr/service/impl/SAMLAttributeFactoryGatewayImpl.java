/*******************************************************************************
BSD Licence
Copyright (c) 2011, Science & Technology Facilities Council (STFC)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following disclaimer
      in the documentation and/or other materials provided with the
      distribution.
    * Neither the name of the Science & Technology Facilities Council
      (STFC) nor the names of its contributors may be used to endorse or
      promote products derived from this software without specific prior
      written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ******************************************************************************/
/**
   Description:
   Get AttributeService roles from an ESGF Gateway database.
   
**/
package esg.security.attr.service.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Types;


import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;


public class SAMLAttributeFactoryGatewayImpl implements SAMLAttributeFactory {

	private final String ESG_GROUP_ROLE_URN = "urn:esg:group:role";

	final private String issuer;

    //EG Query
    private static final String openidQuery = 
	"SELECT id, firstname, lastname, email, dn " +
	"FROM security.user " +
	"WHERE openid = ?";
    
    private static final String groupQuery = 
	"SELECT g.name, r.name " +
	"FROM security.group g, security.role r, security.status s, security.membership m " +
	"WHERE m.user_id=? AND m.group_id=g.id AND m.role_id=r.id AND m.status_id=s.id AND s.name='valid' ";
    
    
    
    //-------------------

    private static final Log log = LogFactory.getLog(SAMLAttributeFactoryGatewayImpl.class);

    private Connection conn = null;
    
	public SAMLAttributeFactoryGatewayImpl(final String issuer, DataSource dataSource) throws Exception {
		this.issuer = issuer;
		
		log.debug("Creating SAMLAttributeFactory for issuer " + issuer);
		log.debug(dataSource.toString());
		
		//!TODO: A bit clunky.  Could use better DB interface.
		conn = dataSource.getConnection();
    
	}


	@Override
	public SAMLAttributes newInstance(String identifier) throws SAMLUnknownPrincipalException {
		SAMLAttributes attributes= null;
		
		try {
			attributes = getAttributesById(identifier);
		}
		catch (SQLException e) {
			log.error("SQL Exception is ", e);
			throw new SAMLUnknownPrincipalException("SQL Exception during attribute lookup for " + identifier);
		}		
		
		return attributes;
	
	}
    
	@Override
	public String getIssuer() {
		return issuer;
	}

	
	private SAMLAttributes getAttributesById(String identifier) throws SQLException, SAMLUnknownPrincipalException {
		String uuid = null;
	    SAMLAttributes attributes = null;
				
		log.debug("Getting Gateway info for " + identifier);
		
		//!TODO: better exception handling
		PreparedStatement query1 = conn.prepareStatement(openidQuery);
		query1.setString(1, identifier);

		ResultSet resultSet = query1.executeQuery();
		if (!resultSet.next()) {
			throw new SAMLUnknownPrincipalException("Unknown identifier: "+identifier);
		}
			
		uuid = resultSet.getString("id");
		attributes = new SAMLAttributesImpl(identifier, issuer);
		attributes.setFirstName(resultSet.getString("firstname"));
		attributes.setLastName(resultSet.getString("lastname"));
		attributes.setOpenid(identifier);
		attributes.setEmail(resultSet.getString("email"));

		PreparedStatement query2 = conn.prepareStatement(groupQuery);
		query2.setObject(1, uuid, Types.OTHER);
		resultSet = query2.executeQuery();
			
		while (resultSet.next()) {
			log.debug("Group found: " + resultSet.getString(1) + " : " + resultSet.getString(2));
			attributes.addGroupAndRole(ESG_GROUP_ROLE_URN, new GroupRoleImpl(resultSet.getString(1), resultSet.getString(2)));
		}
			
		
		return attributes;
	}
	
}

