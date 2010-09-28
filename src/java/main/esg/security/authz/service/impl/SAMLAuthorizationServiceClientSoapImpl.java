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
package esg.security.authz.service.impl;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.security.authz.service.api.SAMLAuthorizationQueryRequestBuilder;
import esg.security.authz.service.api.SAMLAuthorizationServiceClient;
import esg.security.authz.service.api.SAMLAuthorizationStatementHandler;
import esg.security.authz.service.api.SAMLAuthorizations;
import esg.security.common.SAMLBuilder;

/**
 * Implementation of {@link SAMLAuthorizationServiceClient} specific to SOAP binding.
 */
public class SAMLAuthorizationServiceClientSoapImpl implements SAMLAuthorizationServiceClient {
	
	private final SAMLAuthorizationQueryRequestBuilder requestBuilder;
	private final SAMLBuilder samlBuilder;
	private final SAMLAuthorizationStatementHandler statementHandler;
	
	private final String issuer;
	
	private final static Log LOG = LogFactory.getLog(SAMLAuthorizationServiceClientSoapImpl.class);
	
	public SAMLAuthorizationServiceClientSoapImpl(final String issuer) {
		
		this.issuer = issuer;
				
		// instantiate SAMLBuilder
		this.samlBuilder = SAMLBuilder.getInstance();
		
		// instantiate SAML handlers
		this.requestBuilder = new SAMLAuthorizationQueryRequestBuilderImpl();	
		this.statementHandler = new SAMLAuthorizationStatementHandlerImpl();
		
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String buildAuthorizationRequest(final String openid, String resource, String action) throws MarshallingException {
		
		// build attribute query
		final AuthzDecisionQuery authzDecisionQuery = requestBuilder.buildAuthorizationQueryRequest(openid, resource, action, issuer);
		
		// embed into SOAP envelop
		final Envelope soapRequestEnvelope = samlBuilder.getSOAPEnvelope();
		final Body soapRequestBody = samlBuilder.getSOAPBody();
		soapRequestBody.getUnknownXMLObjects().add(authzDecisionQuery);
		soapRequestEnvelope.setBody(soapRequestBody);
		
		// serialize
		final Element soapRequestElement = samlBuilder.marshall(soapRequestEnvelope);
		final String xml = XMLHelper.prettyPrintXML((Node)soapRequestElement);
		if (LOG.isDebugEnabled()) LOG.debug("SOAP request:\n"+xml);
		
		return xml;

	}

	/**
	 * {@inheritDoc}
	 */
	public SAMLAuthorizations parseAuthorizationResponse(final String authorizationResponse) throws XMLParserException, UnmarshallingException {
		
		SAMLAuthorizations authorizations = new SAMLAuthorizationsImpl();
		if (LOG.isDebugEnabled()) LOG.debug("Parsing authorization response=\n"+authorizationResponse);
		
		// string > DOM
        final Element soapResponseElement = samlBuilder.parse(authorizationResponse);

        // DOM > SAML objects
        final Envelope soapResponseEnvelope = (Envelope)samlBuilder.unmarshall(soapResponseElement);
        final Body soapResponseBody = soapResponseEnvelope.getBody();
        final Response samlResponse = (Response)soapResponseBody.getUnknownXMLObjects().get(0);
        
        // SAML object > User object
        final Collection<Assertion> assertions = samlResponse.getAssertions();
        for (final Assertion assertion : assertions) {
        	authorizations = statementHandler.parseAuthzDecisionStatement(assertion);
        }
        return authorizations;
	}

}
