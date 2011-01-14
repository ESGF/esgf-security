package esg.security.policy.service.impl;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import esg.security.policy.service.api.PolicyAttribute;

/**
 * Java bean implementation of {@link PolicyAttribute}.
 * 
 * @author luca.cinquini
 *
 */
public class PolicyAttributeImpl implements PolicyAttribute {
	
	private final String type;
	
	private final String value;
	
	public PolicyAttributeImpl(final String type, final String value) {
		this.type = type;
		this.value = value;
	}

	@Override
	public String getType() {
		return type;
	}

	@Override
	public String getValue() {
		return value;
	}
	
	@Override
	public String toString() {
		return "Type="+this.getType()+" Value="+this.getValue();
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.getType()).append(this.getValue()).toHashCode();
	}
	
	@Override
	public boolean equals(final Object other) {

		if (!(other instanceof PolicyAttributeImpl)) {
			return false;
		}
		final PolicyAttributeImpl castOther = (PolicyAttributeImpl)other;
		return new EqualsBuilder().append(this.getType(), castOther.getType())
								  .append(this.getValue(), castOther.getValue())
		                          .isEquals();
	}

}
