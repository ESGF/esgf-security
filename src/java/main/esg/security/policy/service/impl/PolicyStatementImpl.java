package esg.security.policy.service.impl;

import esg.security.policy.service.api.PolicyAction;
import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyStatement;

/**
 * Bean implementation of {@link PolicyStatement}.
 * 
 * @author luca.cinquini
 *
 */
public class PolicyStatementImpl implements PolicyStatement {
	
	private final String resource;
	
	private final PolicyAttribute attribute;
	
	private final PolicyAction action;
	
	public PolicyStatementImpl(final String resource, final String attributeType, final String attributeValue, final String action) {
		this.resource = resource;
		this.attribute = new PolicyAttributeImpl(attributeType, attributeValue);
		this.action = PolicyAction.valueOf(action);
	}

	@Override
	public String getResource() {
		return resource;
	}

	@Override
	public PolicyAttribute getAttribute() {
		return attribute;
	}

	@Override
	public PolicyAction getAction() {
		return action;
	}
	
	@Override
	public String toString() {
		return "Resource="+resource+" Attribute type="+attribute.getType()+" Attribute value="+attribute.getValue()+" action="+action.toString();
	}

}
