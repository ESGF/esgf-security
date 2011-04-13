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

import java.util.Properties;

import esg.node.security.UserInfo;
import esg.node.security.UserInfoDAO;
import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;

/**
 * Implementation of {@link SAMLAttributeFactory} backed up by node's "esgcet" RDBMS database.
 * 
 * @author gavin.bell
 */
public class SAMLAttributeFactoryDAOImpl implements SAMLAttributeFactory {
	
	final private String issuer;

    private SAMLAttributes attributes = null;
    private UserInfoDAO userInfoDAO = null;
	
	public SAMLAttributeFactoryDAOImpl(final String issuer, Properties props) throws Exception {
		
		this.issuer = issuer;
		
        this.userInfoDAO = new UserInfoDAO(props);
        		
	}

	@Override
	public SAMLAttributes newInstance(String identifier) throws SAMLUnknownPrincipalException {        
        UserInfo userInfo = userInfoDAO.getUserById(identifier);

        //Note: as an optimization could put an LRU cache mapping
        //identifier to resultant attributes object so don't have to
        //hit the database as much.
		if (userInfo.isValid()) {
            attributes = new SAMLAttributesImpl(identifier, issuer);
            attributes.setFirstName(userInfo.getFirstName());
            attributes.setLastName(userInfo.getLastName());
            attributes.setOpenid(userInfo.getOpenid());
            attributes.setEmail(userInfo.getEmail());
            attributes.setAttributes(userInfo.getPermissions());
			return attributes;
		} else {
			throw new SAMLUnknownPrincipalException("Unknown identifier: "+identifier);
		}
	}
    
	@Override
	public String getIssuer() {
		return issuer;
	}
	
	/**
	 * Debug method.
	 */
	public void print() {
        System.out.println(attributes);
	}

}
