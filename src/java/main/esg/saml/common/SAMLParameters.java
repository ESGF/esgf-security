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

/**
 * Interface containing commonly used SAML parameters.
 */
public interface SAMLParameters {
	
	public final static String CONTENT_TYPE_XML = "text/xml";
	
    public final static String FIRST_NAME = "urn:esg:first:name";
    public final static String LAST_NAME = "urn:esg:last:name";
    public final static String EMAIL_ADDRESS = "urn:esg:email:address";
    public final static String OPENID = "urn:esg:openid";
    
    //public final static String GROUP_ROLE = "urn:esg:group:role";
    //public final static String AC_ATTRIBUTE = "urn:badc:security:authz:1.0:attr";
    
    public final static String FIRST_NAME_FRIENDLY = "FirstName";
    public final static String LAST_NAME_FRIENDLY = "LastName";
    public final static String EMAIL_ADDRESS_FRIENDLY = "EmailAddress";
    public final static String GROUP_ROLE_FRIENDLY = "GroupRole";
    
    public final static String ESG_NAMESPACE = "http://www.esg.org";
    public final static String ESG_PREFIX = "esg";
    
    public final static int ASSERTION_LIFETIME_IN_SECONDS = 86400;
    
}
