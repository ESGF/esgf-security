package esg.security.authz.service.impl;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.DecisionTypeEnumeration;

import esg.security.attr.service.api.SAMLAttributeServiceClient;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.attr.service.impl.SAMLAttributeServiceClientSoapImpl;
import esg.security.authz.service.api.SAMLAuthorization;
import esg.security.authz.service.api.SAMLAuthorizationFactory;
import esg.security.authz.service.api.SAMLAuthorizations;
import esg.security.common.SAMLUnknownPrincipalException;
import esg.security.common.SOAPServiceClient;
import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;
import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.api.UnknownPolicyAttributeTypeException;
import esg.xml.EsgWhitelist.TrustedServices.Gateway.AttributeService;

/**
 * Implementation of {@link SAMLAuthorizationFactory} that combined the information from the following collaborators:
 * <ul>
 * 	<li>The resource policies from a {@link PolicyService}
 *  <li>The {@link AttributeService} endpoint from a {@link RegistryService}
 *  <li>The user attributes from the located {@link AttributeService}.
 * </ul>
 * 
 * @author luca.cinquini
 *
 */
public class SAMLAuthorizationFactoryImpl implements SAMLAuthorizationFactory {
	
	private final String issuer;
	
	private PolicyService policyService;
	
	private RegistryService registryService;
	
	// clients used to build the attribute query request
	private final SAMLAttributeServiceClient samlAttributeServiceClient;
	
	// client used to send the request via SOAP to the remote AttributeService
	private final SOAPServiceClient soapClient = new SOAPServiceClient();
	
	private final static Log LOG = LogFactory.getLog(SAMLAuthorizationFactoryImpl.class);
	
	public SAMLAuthorizationFactoryImpl(final String issuer, final PolicyService policyService, final RegistryService registryService) {
		
		this.issuer = issuer;
		this.policyService = policyService;
		this.registryService = registryService;
		
		samlAttributeServiceClient = new SAMLAttributeServiceClientSoapImpl(this.issuer);
		

	}

	@Override
	public SAMLAuthorizations newInstance(String identifier, String resource, Vector<String> actions) throws SAMLUnknownPrincipalException {
		
		final SAMLAuthorizations authorizations = new SAMLAuthorizationsImpl(identifier, this.issuer);
		
		// loop over requested actions, retrieve required attribute types
		final Map<URL, List<String>> attServiceMap = new HashMap<URL, List<String>>();
		for (final String action : actions) {
			
			// default decision for this action
			String decision = DecisionTypeEnumeration.INDETERMINATE.toString();
			
			final List<PolicyAttribute> policies = policyService.getRequiredAttributes(resource, action);	
			
			// loop over required attribute types, group them by attribute service
			attServiceMap.clear();
			for (final PolicyAttribute policy : policies) {
				
				log("Action="+action+ " on Resource="+resource+" requires attribute type="+policy.getType()+" value="+policy.getValue());
				try {
					
					// URL of AttributeService serving this attribute type
					final URL attributeServiceUrl = registryService.getAttributeService(policy.getType());
					log("Attribute type="+policy.getType()+" is managed by AttributeService at: "+attributeServiceUrl.toString());
					if (attServiceMap.get(attributeServiceUrl)==null) {
						attServiceMap.put(attributeServiceUrl, new ArrayList<String>() );
					}
					attServiceMap.get(attributeServiceUrl).add( policy.getType() );
					
				} catch(UnknownPolicyAttributeTypeException e) {
					log(e.getMessage());
	
				}
			}
			
			// retrieve user attributes from each service
			for (final URL url : attServiceMap.keySet()) {
				
				try {
					final AttributeQuery attributeQuery = samlAttributeServiceClient.buildStringAttributeQuery(identifier, attServiceMap.get(url));
					final String attRequest = samlAttributeServiceClient.buildAttributeRequest(attributeQuery);
					log("Querying attribute service at URL="+url.toString()+" request="+attRequest);		
					final String attResponse = soapClient.doSoap(url.toString(), attRequest);
					log("Query response="+attResponse);
					
					// loop through the access control attributes to identify a match by value
					final SAMLAttributes samlAttributes = samlAttributeServiceClient.parseAttributeResponse(attributeQuery, attResponse);
					final Map<String,Set<String>> userAttributes = samlAttributes.getAttributes();
					
					for (final PolicyAttribute policy : policies) {
						// the user attribute values for this attribute type
						final Set<String> userAttValues = userAttributes.get(policy.getType());
						if (userAttValues!=null && userAttValues.contains(policy.getValue())) {
							decision = DecisionTypeEnumeration.PERMIT.toString();
							break;
						}
					}
				
				} catch(Exception e) {
					log(e.getMessage());
				}
				
				
			}
			
			// create authorization statement for this resource, action
			final SAMLAuthorization samlAuthorization = new SAMLAuthorizationImpl();
			samlAuthorization.setResource(resource);
			samlAuthorization.getActions().add(action);
			samlAuthorization.setDecision(decision);
			authorizations.addAuthorization( samlAuthorization );
			
		} // loop over request actions
		
		return authorizations;
	}

	@Override
	public String getIssuer() {
		return issuer;
	}
	
	private void log(String s) {
		if (LOG.isDebugEnabled()) System.out.println(s);
	}

}
