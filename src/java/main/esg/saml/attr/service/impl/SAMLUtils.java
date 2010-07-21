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

/**
 * Utility class containing utility methods to process SAML attributes.
 */
class SAMLUtils {
	

    /**
     * Method to parse a SAML attribute and return the group and role names.
     *
     * @param attribute : the SAML attribute
     *
     * @return the group and role
     */
    public static String[] getGroupAndRole(final String attribute) {

            final int i = attribute.indexOf("group_");
            final int j = attribute.indexOf("_role_");

            // return empty group and role if authority string cannot be parsed correctly
            final String[] names = new String[] { "", "" };

            if ((i == 0) && (j > 0)) {
                    names[0] = attribute.substring(i + "group_".length(), j); // group name
                    names[1] = attribute.substring(j + "_role_".length()); // role name
            }
            return names;
    }

    /**
     * Method to build a SAML attribute from a group and role names.
     *
     * @param groupName
     *            the group name
     * @param roleName
     *            the role name
     *
     * @return the SAML attribute
     */
    public static String getAttribute(final String groupName, final String roleName) {

            return "group_" + groupName + "_role_" + roleName;
    }


}
