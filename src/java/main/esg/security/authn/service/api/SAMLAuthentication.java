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