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

import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import esg.saml.attr.service.api.SAMLAttributeFactory;
import esg.saml.attr.service.api.SAMLAttributeQueryResponseBuilder;
import esg.saml.attr.service.api.SAMLAttributeService;
import esg.saml.common.SAMLBuilder;

/**
 * Implementation of {@link SAMLAttributeService} for SOAP binding.
 */
//@Service("samlAttributeService")
public class SAMLAttributeServiceSoapImpl implements SAMLAttributeService {
	
	private final SAMLAttributeQueryResponseBuilder samlAttributeQueryResponseBuilder;
	private final SAMLBuilder samlBuilder;
	
	private final static Log LOG = LogFactory.getLog(SAMLAttributeServiceSoapImpl.class);
	
	@Autowired
	public SAMLAttributeServiceSoapImpl(final @Qualifier("samlAttributeFactory") SAMLAttributeFactory samlAttributesFactory) {
		
		// instantiate SAMLBuilder
		this.samlBuilder = SAMLBuilder.getInstance();
		
		// instantiate SAML handlers
		this.samlAttributeQueryResponseBuilder = new SAMLAttributeQueryResponseBuilderImpl(samlAttributesFactory);	
		
	}
	
	/**
	 * Constructor used for testing (with includeFlag=false).
	 * Note that this constructor has default package visibility.
	 * @param accountService
	 * @param gateway
	 * @param includeFlag
	 */
	SAMLAttributeServiceSoapImpl(final SAMLAttributeFactory samlAttributesFactory, final boolean includeFlag) {
		
		this(samlAttributesFactory);
		((SAMLAttributeQueryResponseBuilderImpl)samlAttributeQueryResponseBuilder).setIncludeFlag(includeFlag);
	
	}

	/**
	 * {@inheritDoc}
	 */
	public String processAttributeQuery(final InputStream inputStream) throws Exception {
		
		// read SAML attribute request from input stream	
        final Element soapRequestElement = samlBuilder.parse(inputStream);
        if (LOG.isDebugEnabled()) LOG.debug("SOAP request:\n"+XMLHelper.prettyPrintXML((Node)soapRequestElement) );
        final Envelope soapRequestEnvelope = (Envelope)samlBuilder.unmarshall(soapRequestElement);
        final Body soapRequestBody = soapRequestEnvelope.getBody();
        final AttributeQuery samlRequest = (AttributeQuery)soapRequestBody.getUnknownXMLObjects().get(0);
        
        // construct SAML response
        final Response samlResponse = samlAttributeQueryResponseBuilder.buildAttributeQueryResponse(samlRequest);
 
        // embed SAML response inside SOAP envelope
        final Envelope soapResponseEnvelope = samlBuilder.getSOAPEnvelope();
        final Body soapResponseBody = samlBuilder.getSOAPBody();
        soapResponseBody.getUnknownXMLObjects().add(samlResponse);
        soapResponseEnvelope.setBody(soapResponseBody);
        final Element soapResponseElement = samlBuilder.marshall(soapResponseEnvelope);
        final String xml = XMLHelper.prettyPrintXML((Node)soapResponseElement);
        if (LOG.isDebugEnabled()) LOG.debug("SOAP response:\n"+xml );
        
        return xml;

	}
	
}
