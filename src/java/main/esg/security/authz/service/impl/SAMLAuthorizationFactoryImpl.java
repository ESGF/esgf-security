package esg.security.authz.service.impl;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
import esg.security.attr.service.impl.SAMLAttributesImpl;
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
 *  <li>The {@link AttributeService}s endpoints from a {@link RegistryService}
 *  <li>The user attributes from the located {@link AttributeService}.
 * </ul>
 * 
 * @author luca.cinquini
 *
 */
public class SAMLAuthorizationFactoryImpl implements SAMLAuthorizationFactory {
	
	/**
	 * The identity issuing the authorization assertions.
	 */
	private final String issuer;
	
	/**
	 * Service that maps resources to required attribute types and values.
	 */
	private PolicyService policyService;
	
	/**
	 * Service responsible for locating the AttributeService managing the required attribute types.
	 */
	private RegistryService registryService;
	

	/**
	 * Client used to build the attribute query request.
	 */
	private final SAMLAttributeServiceClient samlAttributeServiceClient;
	
	/**
	 * Client used to send the request via SOAP to the remote AttributeService
	 */
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
		
		// get map(action, att_type+): for each action it maps to the attribute types that must be queried from the attribute service
		final Map<String, List<PolicyAttribute>> policyMap = this.getPolicies(resource, actions);
		
		// get map(att_service_url, att_type+): for each attribute service it maps all the attribute types that must be queried (across all actions)
		final Map<URL, Set<String>> attServiceMap = this.getAttributeServices(resource, policyMap);
		
		// cache map(att_service_url, (att_type & att_value)+):
		// for each attribute service URL it caches the user attributes (type and value) retrieved from that service.
		final Map<URL, SAMLAttributes> userAttributesMap = new HashMap<URL, SAMLAttributes>();
		for (final String action : actions) {
			
			// default decision for this action
			String decision = DecisionTypeEnumeration.DENY.toString();
			
			// retrieve user attributes from each service, if it was not queried already
			for (final URL url : attServiceMap.keySet()) {
				
				if (!userAttributesMap.containsKey(url)) {
					// query remote attribute service
					final SAMLAttributes samlAttributes = this.getUserAttributes(identifier, url, attServiceMap.get(url));
					userAttributesMap.put(url, samlAttributes);
				}
				
				// match resource policies for this action to user attributes from this attribute service
				boolean authorized = this.match(policyMap.get(action), userAttributesMap.get(url));
				if (authorized) {
					decision = DecisionTypeEnumeration.PERMIT.toString();
					// don't query any more attribute services, for this action
					break;
				}
				
			} // loop over attribute services
			
			// create authorization statement for this resource, action
			final SAMLAuthorization samlAuthorization = new SAMLAuthorizationImpl();
			samlAuthorization.setResource(resource);
			samlAuthorization.getActions().add(action);
			samlAuthorization.setDecision(decision);
			authorizations.addAuthorization( samlAuthorization );
			
		} // loop over request actions
		
		return authorizations;
	}
	
	/**
	 * Internal method to retrieve the user attributes for the given types from a remote attribute service
	 * @param url
	 * @param attributeTypes
	 * @return
	 */
	protected SAMLAttributes getUserAttributes(final String identifier, final URL url, Set<String> attributeTypes) {
		
		try {
			final AttributeQuery attributeQuery = samlAttributeServiceClient.buildStringAttributeQuery(identifier, new ArrayList<String>(attributeTypes));
			final String attRequest = samlAttributeServiceClient.buildAttributeRequest(attributeQuery);
			log("Querying attribute service at URL="+url.toString()+" request="+attRequest);		
			final String attResponse = soapClient.doSoap(url.toString(), attRequest);
			log("Query response="+attResponse);
			final SAMLAttributes samlAttributes = samlAttributeServiceClient.parseAttributeResponse(attributeQuery, attResponse);
			return samlAttributes;
		} catch(Exception e) {
			log(e.getMessage());
			// return empty attributes
			return new SAMLAttributesImpl(identifier, null);
		}
		
	}
	
	/**
	 * Internal method to compare the policies set enable a given action on a given resource,
	 * to the user attributes retrieved from an attribute service
	 * @param policies
	 * @param samlAttributes
	 * @return
	 */
	boolean match(List<PolicyAttribute> policies, SAMLAttributes samlAttributes) {
		
		if (samlAttributes!=null) { // may be null because of retrieval error
			for (final PolicyAttribute policy : policies) {
				
			    // loop through the access control attributes to identify a match by value
				final Map<String,Set<String>> userAttributes = samlAttributes.getAttributes();
	
				// the user attribute values for this attribute type
				final Set<String> userAttValues = userAttributes.get(policy.getType());
				if (userAttValues!=null && userAttValues.contains(policy.getValue())) {
					return true;
				}
			}
		}
		
		return false;

	}
	
	/**
	 * Internal method that build a map of action versus required policies.
	 * 
	 * @param identifier
	 * @param resource
	 * @param actions
	 * @return
	 */
	Map<String, List<PolicyAttribute>> getPolicies(String resource, Vector<String> actions) {
		
		final Map<String, List<PolicyAttribute>> policyMap = new HashMap<String, List<PolicyAttribute>>();
		for (final String action : actions) {
			final List<PolicyAttribute> policies = policyService.getRequiredAttributes(resource, action);
			policyMap.put(action, policies);
		}
		
		return policyMap;

	}
	
	/**
	 * Internal method that builds a map of AttributeServices to be queried.
	 * 
	 * @param identifier
	 * @param resource
	 * @param actions
	 * @return
	 */
	Map<URL, Set<String>> getAttributeServices(String resource, Map<String, List<PolicyAttribute>> policyMap) {
		
		final Map<URL, Set<String>> attServiceMap = new HashMap<URL, Set<String>>();
		
		// loop over requested actions, retrieve required attribute types
		for (final String action : policyMap.keySet()) {
									
			// loop over required attribute types, group them by attribute service
			for (final PolicyAttribute policy : policyMap.get(action)) {				
				log("Action="+action+ " on Resource="+resource+" requires attribute type="+policy.getType()+" value="+policy.getValue());
				
				try {
					
					// URL of AttributeService serving this attribute type
					final URL attributeServiceUrl = registryService.getAttributeService(policy.getType());
					log("Attribute type="+policy.getType()+" is managed by AttributeService at: "+attributeServiceUrl.toString());
					if (attServiceMap.get(attributeServiceUrl)==null) {
						attServiceMap.put(attributeServiceUrl, new HashSet<String>() );
					}
					attServiceMap.get(attributeServiceUrl).add( policy.getType() );
					
				} catch(UnknownPolicyAttributeTypeException e) {
					LOG.warn(e.getMessage());
	
				}
			}

		} // loop over actions
		
		return attServiceMap;
	}

	@Override
	public String getIssuer() {
		return issuer;
	}
	
	private void log(String s) {
		if (LOG.isDebugEnabled()) System.out.println(s);
	}

}
