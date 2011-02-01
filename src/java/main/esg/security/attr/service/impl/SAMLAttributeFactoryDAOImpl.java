package esg.security.attr.service.impl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.springframework.core.io.ClassPathResource;

import esg.security.attr.service.api.SAMLAttributeFactory;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.utils.xml.Parser;

import esg.node.components.idp.SAMLDAO;
import esg.node.components.idp.SAMLUserInfo;

/**
 * Implementation of {@link SAMLAttributeFactory} backed up by node's "esgcet" RDBMS database.
 * 
 * @author gavin.bell
 */
public class SAMLAttributeFactoryDAOImpl implements SAMLAttributeFactory {
	
	final private String issuer;

    private SAMLAttributes attributes = null;
    private SAMLDAO samlDAO = null;
	
	public SAMLAttributeFactoryDAOImpl(final String issuer, Properties props) throws Exception {
		
		this.issuer = issuer;
        this.samlDAO = new SAMLDAO(props);
		
	}

	@Override
	public SAMLAttributes newInstance(String identifier) throws SAMLUnknownPrincipalException {        
        samlDAO.setIdentifier(identifier);
        SAMLMUserInfo samlUserInfo = samlDAO.getAttributesForId();

        //Note: as an optimization could put an LRU cache mapping
        //identifier to resultant attributes object so don't have to
        //hit the database as much.
		if (samlUserInfo != null) {
            attributes = new SAMLAttributes();
            attributes.setFirstName(samlUserInfo.getFirstName());
            attributes.setLastName(samlUserInfo.getLastName());
            attributes.setOpenid(samlUserInfo.getOpenid());
            attributes.setEmail(samlUserInfo.getEmail());
            attributes.setIssuer(this.issuer);
            //TODO: what do I do about attribute_type and attribute_value??
			return attributes.get(identifier);
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
		
		for (final String identity : attributes.keySet()) {
			System.out.println("User="+identity);
			System.out.println(attributes.get(identity));
		}
		
	}

}
