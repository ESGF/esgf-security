/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
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
