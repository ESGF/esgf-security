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
package esg.security.authn.service.api;

import java.util.Date;

/**
 * Encapsulates the results returned from the SAML validation process.
 */
public final class SAMLAuthentication {
    private final String identity;
    private final String saml;
    private final Date validTo;
    private final Date validFrom;

    /**
     * @param identity the validated identity (openId)
     * @param saml the complete SAMLXml which got parsed for creating it.
     * @param validTo information valid until this date.
     * @param validFrom information valid since this date. 
     */
    public SAMLAuthentication(String identity, String saml, Date validTo, Date validFrom) {
        this.identity = identity;
        this.saml = saml;
        this.validTo = validTo;
        this.validFrom = validFrom;
    }
    
    /**
     * @return openid
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * @return the complete SAMLXml.
     */
    public String getSaml() {
        return saml;
    }

    /**
     * @return saml validity end date.
     */
    public Date getValidTo() {
        return validTo;
    }

    /**
     * @return valid since
     */
    public Date getValidFrom() {
        return validFrom;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "indet=" + identity + ", validto=" + validTo;
    }
}
