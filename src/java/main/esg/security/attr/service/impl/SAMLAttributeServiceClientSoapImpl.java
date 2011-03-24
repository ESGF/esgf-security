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
package esg.security.attr.service.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.attr.service.api.SAMLAttributeServiceClient;
import esg.security.attr.service.api.SAMLAttributeStatementHandler;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.attr.service.api.exceptions.SAMLAttributeServiceClientResponseException;
import esg.security.common.SAMLBuilder;

/**
 * Implementation of {@link SAMLAttributeServiceClient} specific to SOAP binding.
 */
public class SAMLAttributeServiceClientSoapImpl implements SAMLAttributeServiceClient {
	
	private final SAMLAttributeQueryRequestBuilderImpl requestBuilder;
	private final SAMLAttributeStatementHandler statementHandler;
	private final SAMLBuilder samlBuilder;
	
	private String issuer;
	
	private final static Log LOG = LogFactory.getLog(SAMLAttributeServiceClientSoapImpl.class);
	
	private final static String STRING_TYPE = "http://www.w3.org/2001/XMLSchema#string";
	private final static String GROUPROLE = "urn:esg:group:role"; // FIXME
	
	public SAMLAttributeServiceClientSoapImpl(final String issuer) {
		
		this.issuer = issuer;
				
		// instantiate SAMLBuilder
		this.samlBuilder = SAMLBuilder.getInstance();
		
		// instantiate SAML handlers
		this.requestBuilder = new SAMLAttributeQueryRequestBuilderImpl();	
		this.statementHandler = new SAMLAttributeStatementHandlerImpl();
		
	}

	/**
	 * Build attribute query with given set of query attributes. Note null attributes will set default ESG attributes. 
	 * 
	 * P J Kershaw 08/09/10
	 * 
	 * @param openid
	 * @param attributes
	 * @return query
	 * @throws MarshallingException
	 */
	public AttributeQuery buildAttributeQuery(final String openid, final List<Attribute> attributes) {
		
		// build attribute query
		AttributeQuery attributeQuery = requestBuilder.buildAttributeQueryRequest(openid, issuer, attributes);
		
		return attributeQuery;
	}
	
	public AttributeQuery buildStringAttributeQuery(final String openid, final List<String> attributes) {
		
		final List<Attribute> _attributes = new ArrayList<Attribute>();
		final AttributeBuilder attributeBuilder = new AttributeBuilder();
		for (final String attribute : attributes) {
			Attribute att = attributeBuilder.buildObject();
			att.setName(attribute);
			att.setNameFormat(STRING_TYPE);
			_attributes.add(att);
		}
		// FIXME: temporary always request GroupRole for compatibility with legacy system
		final Attribute att = attributeBuilder.buildObject();
        att.setName(GROUPROLE);
        att.setNameFormat(STRING_TYPE);
        _attributes.add(att);
		
		return this.buildAttributeQuery(openid, _attributes);
		
	}
	
	/**
	 * Embed query into SOAP envelop
	 * @param attributeQuery
	 * @throws MarshallingException 
	 */
	private String serialiseAttributeQuery(final AttributeQuery attributeQuery) throws MarshallingException {
		final Envelope soapRequestEnvelope = samlBuilder.getSOAPEnvelope();
		final Body soapRequestBody = samlBuilder.getSOAPBody();
		soapRequestBody.getUnknownXMLObjects().add(attributeQuery);
		soapRequestEnvelope.setBody(soapRequestBody);
		
		// serialize
		final Element soapRequestElement = samlBuilder.marshall(soapRequestEnvelope);
		final String xml = XMLHelper.prettyPrintXML((Node)soapRequestElement);
		if (LOG.isDebugEnabled()) LOG.debug("SOAP request:\n"+xml);
		
		return xml;
	}

	/**
	 * Make attributeQuery and serialize
	 * @throws MarshallingException 
	 */
	public String buildAttributeRequest(final String openid, final List<Attribute> attributes) 
		throws MarshallingException {
		
		AttributeQuery attributeQuery = buildAttributeQuery(openid, attributes);
		return serialiseAttributeQuery(attributeQuery);
	}
	
	/**
	 * Make serialised query
	 */
	public String buildAttributeRequest(final AttributeQuery attributeQuery) 
		throws MarshallingException {
		
		return serialiseAttributeQuery(attributeQuery);
	}
	
	/**
	 * {@inheritDoc}
	 * @throws SAMLAttributeServiceClientResponseException 
	 */
	public SAMLAttributes parseAttributeResponse(final AttributeQuery attributeQuery, final String attributeResponse) 
		throws XMLParserException, UnmarshallingException, 
			SAMLAttributeServiceClientResponseException {
		
		// empty attributes by default
		SAMLAttributes attributes = new SAMLAttributesImpl();
		if (LOG.isDebugEnabled()) LOG.debug("Parsing attribute response=\n"+attributeResponse);
		
		// string > DOM
        final Element soapResponseElement = samlBuilder.parse(attributeResponse);
        
        // DOM > SAML objects
        final Envelope soapResponseEnvelope = (Envelope)samlBuilder.unmarshall(soapResponseElement);
        final Body soapResponseBody = soapResponseEnvelope.getBody();
        final Response samlResponse = (Response)soapResponseBody.getUnknownXMLObjects().get(0);
        
        if (attributeQuery != null) {
	        String queryID = attributeQuery.getID();
	        if (! queryID.equals(samlResponse.getInResponseTo())) {
	        	throw new SAMLAttributeServiceClientResponseException(
	        			"SAML Attribute response InResponseTo ID \"" +
	        			samlResponse.getInResponseTo() + 
	        			"\" doesn't match the original query ID \"" + queryID
	        			 + "\"");        	
	        }
        } else {
        	if (LOG.isDebugEnabled()) LOG.debug("Skipping InResponseTo ID " +
        		"check - the corresponding query was not passed to this method");
        }
        
        Status status = samlResponse.getStatus();
        String statusValue = status.getStatusCode().getValue();
        if (! statusValue.equals(StatusCode.SUCCESS_URI)) {
        	throw new SAMLAttributeServiceClientResponseException(
        			"SAML Attribute query response set an " +
        			"error status: " + statusValue + ", " +
        			status.getStatusMessage().getMessage());
        }
        
        // SAML object > User object
        final Collection<Assertion> assertions = samlResponse.getAssertions();
        for (final Assertion assertion : assertions) {
        	attributes = statementHandler.parseAttributeStatement(assertion);
        }

        return attributes;
	}

}