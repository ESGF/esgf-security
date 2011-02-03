package esg.security.attr.service.impl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.xml.Parser;

import esg.node.components.security.UserInfo;
import esg.node.components.security.UserInfoDAO;

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
		if (userInfo != null) {
            attributes = new SAMLAttributesImpl(identifier, issuer);
            attributes.setFirstName(userInfo.getFirstName());
            attributes.setLastName(userInfo.getLastName());
            attributes.setOpenid(userInfo.getOpenid());
            attributes.setEmail(userInfo.getEmail());
            attributes.setAttributes(userInfo.getGroups());
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
