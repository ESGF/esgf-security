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
package esg.saml.common;

import java.io.InputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.ActionBuilder;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeQueryBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.AuthzDecisionQueryBuilder;
import org.opensaml.saml2.core.impl.AuthzDecisionStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSGroupRole;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSGroupRoleBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.springframework.util.Assert;
import org.w3c.dom.Element;


/**
 * Utility class to build, marshal, serialize and embed SAML objects.
 * This class is a singleton to enforce sharing of factories and XML parsers.
 */
public class SAMLBuilder {
	
	// SAMLObject builders
    private XMLObjectBuilderFactory builderFactory;
    private ActionBuilder actionBuilder;
    private AssertionBuilder assertionBuilder;
    private AttributeBuilder attributeBuilder;
    private AuthzDecisionQueryBuilder authzDecisionQueryBuilder;
    private AuthzDecisionStatementBuilder authzDecisionStatementBuilder;
    private AuthnStatementBuilder authnStatementBuilder;
    private AttributeStatementBuilder attributeStatementBuilder;
    private AuthnContextBuilder authnContextBuilder;
    private AuthnContextClassRefBuilder authnContextClassRefBuilder;
    private XSStringBuilder stringBuilder;
    private XSAnyBuilder anyBuilder;
    private XSGroupRoleBuilder groupRoleBuilder = new XSGroupRoleBuilder();
    private IssuerBuilder issuerBuilder;
    private SubjectBuilder subjectBuilder;
    private NameIDBuilder nameIdBuilder;
    private AttributeQueryBuilder attributeQueryBuilder;
    private ResponseBuilder responseBuilder;
    private StatusBuilder statusBuilder;
    private StatusCodeBuilder statusCodeBuilder;
    private SAMLObjectBuilder<Endpoint> endpointBuilder;
    private EnvelopeBuilder envelopeBuilder;
    private BodyBuilder bodyBuilder;
    private SignatureBuilder signatureBuilder;
    private ConditionsBuilder conditionsBuilder;

    // SAML documents parsers pool
    private BasicParserPool parserPoolManager;
    
    // factories for marshalling XML to/from DOM
    private UnmarshallerFactory unmarshallerFactory;
    private MarshallerFactory marshallerFactory;

    private final static Log LOG = LogFactory.getLog(SAMLBuilder.class);
    
    private static boolean INITIALIZED = false;
    
    /**
     * Singleton instance.
     */
    private final static SAMLBuilder instance = new SAMLBuilder();
    
    /**
     * Static initializer bootstraps the SAML library
     * but will not crash the whole application if initialization fails
     * (due to missing/wrong endorsed jars).
     */
    static {
    	
    	try {
    		
			// initialize SAML library
			DefaultBootstrap.bootstrap();
			
			INITIALIZED = true;
			// initialize singleton instance
			instance.init();
			
			if (LOG.isInfoEnabled()) LOG.info("SAML libraries initialized correctly");
			
    	} catch(ConfigurationException e) {
    		LOG.warn("Error initailizing SAML libraries", e);
    	} catch(UnsupportedOperationException e) {
			LOG.warn("SAML libraries NOT properly initialized, likely missing correct endorsed jars");
		}

    }
    
    /**
     * Static method to check whether the SAML library has been properly initialized.
     * @return
     */
    public static boolean isInitailized() {
    	return INITIALIZED;
    }
    
    /**
     * Factory method to access the singleton instance.
     * @return
     */
    public static SAMLBuilder getInstance() {
    	return instance;
    }
    
    /**
     * Private constructor to enforce single instance.
     */
    private SAMLBuilder() {}
    
	/**
	 * Initialization method, made private so it cannot be invoked by external clients.
	 */
    @SuppressWarnings("unchecked")
	private void init() {
				    
		if (INITIALIZED) {
			// get Java object builders
			builderFactory = Configuration.getBuilderFactory();
			actionBuilder = (ActionBuilder)this.builderFactory.getBuilder(Action.DEFAULT_ELEMENT_NAME);
		    assertionBuilder = (AssertionBuilder)this.builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		    attributeBuilder = (AttributeBuilder)this.builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		    authzDecisionQueryBuilder = (AuthzDecisionQueryBuilder)this.builderFactory.getBuilder(AuthzDecisionQuery.DEFAULT_ELEMENT_NAME);
		    authzDecisionStatementBuilder = (AuthzDecisionStatementBuilder)this.builderFactory.getBuilder(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
		    attributeStatementBuilder = (AttributeStatementBuilder)this.builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		    authnStatementBuilder = (AuthnStatementBuilder)this.builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		    authnContextBuilder = (AuthnContextBuilder)this.builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		    authnContextClassRefBuilder = (AuthnContextClassRefBuilder)this.builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		    stringBuilder = (XSStringBuilder)this.builderFactory.getBuilder(XSString.TYPE_NAME);
		    anyBuilder = new XSAnyBuilder();
	        groupRoleBuilder = new XSGroupRoleBuilder();
	        issuerBuilder = (IssuerBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	        subjectBuilder = (SubjectBuilder)builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
	        nameIdBuilder = (NameIDBuilder)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
	        attributeQueryBuilder = (AttributeQueryBuilder)builderFactory.getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
	        responseBuilder = (ResponseBuilder)builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
	        statusBuilder = (StatusBuilder)builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
	        statusCodeBuilder = (StatusCodeBuilder)builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
	        conditionsBuilder = (ConditionsBuilder)builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
	        
	        endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	        envelopeBuilder = (EnvelopeBuilder) builderFactory.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
	        bodyBuilder = (BodyBuilder) builderFactory.getBuilder(Body.DEFAULT_ELEMENT_NAME);
	        
	        signatureBuilder = (SignatureBuilder)builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
	        		    
	        // get Java objects - DOM marshaller/unmarshaller
		    marshallerFactory = Configuration.getMarshallerFactory();
		    unmarshallerFactory = Configuration.getUnmarshallerFactory();
		    	
		    // get pool of XML parsers
	        parserPoolManager = new BasicParserPool();
	        parserPoolManager.setNamespaceAware(true);
		}
	    	    
	}
	
	// <saml:AuthzDecisionStatement>
	public AuthzDecisionStatement getAuthzDecisionStatement() {
		return authzDecisionStatementBuilder.buildObject();
	}
	
	// <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName">Test Gateway</saml:Issuer>
	public Issuer getIssuer(final String value) {
		Assert.notNull(issuerBuilder, "Cannot build SAML assertion, likely SAML libraries are not configured properly");
        final Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(NameIDType.X509_SUBJECT);
        issuer.setValue(value);
        return issuer;
	}
	
    // <saml:Subject>
    // 		<saml:NameID Format="urn:esg:openid">http://test.openid.com/testUserValid</saml:NameID>
    // </saml:Subject>
	public Subject getSubject(final String openid) {
        final Subject subject = subjectBuilder.buildObject();
        final NameID nameId = nameIdBuilder.buildObject();
        nameId.setFormat(SAMLParameters.OPENID);
        nameId.setValue(openid);     
        subject.setNameID(nameId);
        return subject;
	}
	
	// <saml:Action xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">read</saml:Action>
	public Action getAction(final String action) {
        final Action actionObj = actionBuilder.buildObject();
        //actionObj.setNamespace(SAMLParameters.AC_ACTION);
        actionObj.setAction(action);
        return actionObj;
	}
	
	// <saml:Conditions NotBefore="2009-08-04T11:16:53.632Z" NotOnOrAfter="2009-08-05T11:16:53.632Z"/>
	public Conditions getConditions(final DateTime notBefore, final DateTime notOnOrAfter) {
		final Conditions conditions = conditionsBuilder.buildObject();
		conditions.setNotBefore(notBefore);
		conditions.setNotOnOrAfter(notOnOrAfter);
		return conditions;
	}
	
	// <?xml version="1.0" encoding="UTF-8"?>
	// <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
	//                       ID="c9a2bd30-6186-46d7-a8f3-e51367921f51" IssueInstant="2009-07-28T15:24:52.895Z" Version="2.0"/>
	public AttributeQuery getAttributeQuery(final boolean includeFlag) {
		final AttributeQuery attributeQuery = attributeQueryBuilder.buildObject();	
        if (includeFlag) {
        	attributeQuery.setID(UUID.randomUUID().toString());
        	attributeQuery.setIssueInstant(new DateTime());
        }
        return attributeQuery;
	}
	
	// <?xml version="1.0" encoding="UTF-8"?>
	//    <samlp:AuthzDecisionQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="b0f70731-8d1b-4744-a842-0fd26d2d0089"
	//                       IssueInstant="2010-01-25T21:20:03.549Z" Version="2.0">
	public AuthzDecisionQuery getAuthzDecisionQuery(final boolean includeFlag) {
		final AuthzDecisionQuery authzDecisionQuery = authzDecisionQueryBuilder.buildObject();
        if (includeFlag) {
        	authzDecisionQuery.setID(UUID.randomUUID().toString());
        	authzDecisionQuery.setIssueInstant(new DateTime());
        }
        return authzDecisionQuery;
	}
	
	// <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
	//                 ID="bed4bf11-188e-4d7c-bf55-4a11aa606720" 
	//                 IssueInstant="2009-07-26T21:24:51.757Z" Version="2.0">
	public Assertion getAssertion(final boolean includeFlag) {
	   Assert.notNull(assertionBuilder, "Cannot build SAML assertion, likely SAML libraries are not configured properly");
       final Assertion assertion = this.assertionBuilder.buildObject();
        assertion.setVersion(SAMLVersion.VERSION_20);
        if (includeFlag) {
        	assertion.setID(UUID.randomUUID().toString());
        	assertion.setIssueInstant(new DateTime());
        }
        return assertion;
	}
	
	// <saml:AttributeStatement>
	public AttributeStatement getAttributeStatement() {
		return attributeStatementBuilder.buildObject();
	}
	
	public AuthnStatement getAuthnStatement(final DateTime dateTime) {
		
		final AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        if (dateTime!=null) authnStatement.setAuthnInstant(dateTime);
        final AuthnContext authnContext = (AuthnContext)authnContextBuilder.buildObject();
        final AuthnContextClassRef classRef = (AuthnContextClassRef)authnContextClassRefBuilder.buildObject();
        classRef.setAuthnContextClassRef(AuthnContext.X509_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(classRef);
        authnStatement.setAuthnContext(authnContext);
        return authnStatement;
		
	}
	
    // <saml:Attribute FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
    //		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Tester</saml:AttributeValue>
    // </saml:Attribute>
    // <saml:Attribute FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
    // 		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">ValidUser</saml:AttributeValue>
    // </saml:Attribute>
    // <saml:Attribute FriendlyName="EmailAddress" Name="urn:esg:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string">
    // 		<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">testUserValid@test.com</saml:AttributeValue>
    // </saml:Attribute>
	public Attribute getAttribute(final String name, final String friendlyName, final String value) {
		
		final Attribute attribute = attributeBuilder.buildObject();
		attribute.setName(name);
	    attribute.setNameFormat("http://www.w3.org/2001/XMLSchema#string");
	    attribute.setFriendlyName(friendlyName);
	    if (value!=null) {
	    	final XSString attString = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
	    	attString.setValue(value);
	    	attribute.getAttributeValues().add(attString);
	    }
	    return attribute;
	    
	}
	
    //  <saml:Attribute FriendlyName="GroupRole" Name="urn:esgf:jpl:role" NameFormat="groupRole">
	public Attribute getGroupRoleAttribute(final String name) {
        final Attribute grAttribute = attributeBuilder.buildObject();
        grAttribute.setName(name);
        grAttribute.setNameFormat(XSGroupRole.TYPE_LOCAL_NAME);
        grAttribute.setFriendlyName(SAMLParameters.GROUP_ROLE_FRIENDLY);
        return grAttribute;
	}

    //	<saml:AttributeValue>
    //		<esg:groupRole xmlns:esg="http://www.esg.org" group="Test Group A" role="default"/>
	//	</saml:AttributeValue>
	public XSAny getGroupRoleAttributeValue(final String group, final String role) {
		
        final XSGroupRole groupRoleValue = groupRoleBuilder.buildObject(SAMLParameters.ESG_NAMESPACE, "groupRole", SAMLParameters.ESG_PREFIX);
        groupRoleValue.setGroup(group);
        groupRoleValue.setRole(role);
        final XSAny grAttributeValue = (XSAny)anyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        grAttributeValue.getUnknownXMLObjects().add(groupRoleValue);
        return grAttributeValue;
        
	}
	
	// <?xml version="1.0" encoding="UTF-8"?>
	// 		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="e41d7a47-4850-4750-b2cc-2c0e9f300580" InResponseTo="9566201b-63ad-4f14-b6c0-6cf6b35a90e0" IssueInstant="2009-07-28T23:13:19.823Z" Version="2.0"/>
	public Response getResponse(final String requestID, final boolean includeFlag) {
		final Response response = responseBuilder.buildObject();
		response.setVersion(SAMLVersion.VERSION_20);
        if (includeFlag) {
        	response.setID(UUID.randomUUID().toString());
        	response.setIssueInstant(new DateTime());
        }
        response.setInResponseTo(requestID);
		return response;
	}
	
	//  <samlp:Status>
    //		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    //	</samlp:Status>
	public Status getStatus(final boolean success) {
		
		final Status status = statusBuilder.buildObject();
		final StatusCode statusCode = statusCodeBuilder.buildObject();
		if (success) {
			statusCode.setValue(StatusCode.SUCCESS_URI);
		} else {
			statusCode.setValue(StatusCode.UNKNOWN_PRINCIPAL_URI);
		}
		
		status.setStatusCode(statusCode);
		return status;
		
	}
	
	public Endpoint getEndpoint() {
		
		final Endpoint samlEndpoint = endpointBuilder.buildObject();
		return samlEndpoint;
		
	}
	
	public Envelope getSOAPEnvelope() {
		return envelopeBuilder.buildObject();
	}
	
	public Body getSOAPBody() {
		return bodyBuilder.buildObject();
	}
		
	/**
	 * Method to parse a generic {@link InputStream} into a SAML/XML document element.
	 * @param inputStream
	 * @return
	 * @throws XMLParserException
	 */
	public Element parse(final InputStream inputStream) throws XMLParserException {
		return parserPoolManager.parse(inputStream).getDocumentElement();
	}
	
	/**
	 * Method to parse a SAML/XML document serialized as a string.
	 * @param inputStream
	 * @return
	 * @throws XMLParserException
	 */
	public Element parse(final String string) throws XMLParserException {
		return parserPoolManager.parse( new StringReader(string)).getDocumentElement();
	}

	/**
	 * Method to marshall a generic SAML object into XML.
	 * @param xmlObject
	 * @return
	 * @throws MarshallingException
	 */
	public Element marshall(final XMLObject xmlObject) throws MarshallingException {
		final Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
        return marshaller.marshall(xmlObject);
	}

	/**
	 * Method to marshall and sign a signable XML object.
	 * @param xmlObject
	 * @param credential
	 * @return
	 * @throws MarshallingException
	 */
	public Element marshallAndSign(final SignableXMLObject xmlObject, final Credential credential) throws MarshallingException, SignatureException {
		
	    final Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(credential);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
        xmlObject.setSignature(signature);
        
        final Element element = this.marshall(xmlObject);
        Signer.signObject(signature);
        return element;

	}
	
	/**
	 * Method to validate the signature of a SAML assertion versus a set of trusted credentials.
	 * @param signedAssertion
	 * @param trustedCredentials
	 * @return
	 * @throws SecurityException
	 */
	public boolean validateSignature(final Assertion signedAssertion, final Map<String, Credential> trustedCredentials) throws SecurityException {
				
        final CollectionCredentialResolver credResolver = new CollectionCredentialResolver(trustedCredentials.values());
        final KeyInfoCredentialResolver kiResolver = new BasicProviderKeyInfoCredentialResolver(new ArrayList<KeyInfoProvider>());
         final ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        
        final CriteriaSet criteriaSet = new CriteriaSet( new EntityIDCriteria(NameIDType.X509_SUBJECT) );
        final boolean valid = trustEngine.validate(signedAssertion.getSignature(), criteriaSet);
        if (LOG.isDebugEnabled()) LOG.debug("Validated assertion signature: result="+valid);
        return valid;
        
	}
	
	/**
	 * Method to unmarshall a generic SAML object from XML.
	 * @param element
	 * @return
	 * @throws UnmarshallingException
	 */
	public XMLObject unmarshall(final Element element) throws UnmarshallingException {
		final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		return unmarshaller.unmarshall(element);
	}
		
}
