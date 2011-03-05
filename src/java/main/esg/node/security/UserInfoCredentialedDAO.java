/***************************************************************************
*                                                                          *
*  Organization: Earth System Grid Federation                              *
*                                                                          *
****************************************************************************
*                                                                          *
*   Copyright (c) 2009, Lawrence Livermore National Security, LLC.         *
*   Produced at the Lawrence Livermore National Laboratory                 *
*   LLNL-CODE-420962                                                       *
*                                                                          *
*   All rights reserved. This file is part of the:                         *
*   Earth System Grid (ESG) Data Node Software Stack, Version 1.0          *
*                                                                          *
*   For details, see http://esg-repo.llnl.gov/esg-node/                    *
*   Please also read this link                                             *
*    http://esg-repo.llnl.gov/LICENSE                                      *
*                                                                          *
*   * Redistribution and use in source and binary forms, with or           *
*   without modification, are permitted provided that the following        *
*   conditions are met:                                                    *
*                                                                          *
*   * Redistributions of source code must retain the above copyright       *
*   notice, this list of conditions and the disclaimer below.              *
*                                                                          *
*   * Redistributions in binary form must reproduce the above copyright    *
*   notice, this list of conditions and the disclaimer (as noted below)    *
*   in the documentation and/or other materials provided with the          *
*   distribution.                                                          *
*                                                                          *
*   Neither the name of the LLNS/LLNL nor the names of its contributors    *
*   may be used to endorse or promote products derived from this           *
*   software without specific prior written permission.                    *
*                                                                          *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS    *
*   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT      *
*   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS      *
*   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL LAWRENCE    *
*   LIVERMORE NATIONAL SECURITY, LLC, THE U.S. DEPARTMENT OF ENERGY OR     *
*   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,           *
*   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT       *
*   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF       *
*   USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND    *
*   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,     *
*   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT     *
*   OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF     *
*   SUCH DAMAGE.                                                           *
*                                                                          *
***************************************************************************/
package esg.node.security;

import java.util.Properties;
import esg.security.utils.encryption.PasswordEncoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
   Description:

   Provides public access to UserInfoDAO functions only if call has
   proper credentials; Access control guarded sensitive methods.

*/
public class UserInfoCredentialedDAO {
    
    private static final Log log = LogFactory.getLog(UserInfoCredentialedDAO.class);

    private Credentials cred = null;
    private UserInfoDAO userInfoDAO = null;

    public UserInfoCredentialedDAO(Credentials cred, Properties props) {
        System.out.println("Instantiating DAO using "+cred+" privs");
        userInfoDAO = new UserInfoDAO(props);
        checkCredentials(cred);
    }

    public UserInfoCredentialedDAO(String id, String password, Properties props) {
        this(new Credentials(id,password),props);
    }

    final boolean checkCredentials(Credentials cred) {
        //TODO: So ideally there will be a policy that gets enforced
        //here to determine things like Which users can do what
        //actions etc...  for now... I'll make it "rootAdmin" only...
        UserInfo user = null;
        log.info("Checking credentials: "+cred);
        if(cred != null) {
            //NOTE: we want to deprecate the use of the "ById" call
            //and use the "ByOpenid" call this way we do everything by
            //openid... however, for ease of testing purposes and thus
            //general laziness right now, we will use the "ById"
            //version.
            user = userInfoDAO.getUserById(cred.getid());
            if(!user.isValid()) { log.trace("User ["+cred.getid()+"] is NOT a valid user on this system"); return false; }
            if(!user.getUserName().equals("rootAdmin")) { log.trace("Sorry, Must be ROOT to use this DAO"); return false; }
        }
        if(userInfoDAO.checkPassword(user.getOpenid(),cred.getPassword())) {
            this.cred = cred;
            return true;
        }else{
            log.info("Password for "+cred+" NOT valid");
        }
        return false;
    }

    //NOTE: The credential check criteria is simple, but we
    //encapsulate it here so we can make things arbitrarily
    //complicated later and only have to do that in one place,
    //here. :-)
    public final boolean checkCredentials() { return (null != cred); }

    public UserInfo getUserByOpenid(String openid) {
        return userInfoDAO.getUserByOpenid(openid);
    }
    public UserInfo getUserById(String id) {
        return userInfoDAO.getUserById(id);
    }
    
    public UserInfo refresh(UserInfo userInfo) {
        return userInfoDAO.refresh(userInfo);
    }

    public boolean addUserInfo(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addUserInfo(userInfo);
    }    
    public boolean addUser(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addUser(userInfo);
    }

    public boolean deleteUserInfo(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteUserInfo(userInfo);
    }
    public boolean deleteUser(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteUser(userInfo);
    }    
    public boolean deleteUser(String openid) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteUser(openid);
    }
    

    //-------------------------------------------------------
    //Password Manipulations
    //-------------------------------------------------------

    //Sets the password value for a given user (openid)
    public boolean setPassword(UserInfo userInfo, String newPassword) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setPassword(userInfo,newPassword);
    }
    
    public boolean setPassword(String openid, String newPassword) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setPassword(openid,newPassword);
    }
    
    //Given a password, check to see if that password matches what is
    //in the database for this user (openid)
    public boolean checkPassword(UserInfo userInfo, String queryPassword) {
        return userInfoDAO.checkPassword(userInfo,queryPassword);
    }
    public boolean checkPassword(String openid, String queryPassword) {
        return userInfoDAO.checkPassword(openid,queryPassword);
    }
    
    //Given the old password and the new password for a given user
    //(openid) update the password, only if the old password matches
    public boolean changePassword(UserInfo userInfo, String queryPassword, String newPassword) {
        return userInfoDAO.changePassword(userInfo,queryPassword,newPassword);
    }
    public boolean changePassword(String openid, String queryPassword, String newPassword) {
        return userInfoDAO.changePassword(openid,queryPassword,newPassword);
    }
    

    //-------------------------------------------------------
    //Permission Manipulations (Guarded)
    //-------------------------------------------------------

    public boolean addPermission(UserInfo userInfo, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addPermission(userInfo,groupName,roleName);
    }
    public boolean addPermission(int userid, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addPermission(userid,groupName,roleName);
    }
    
    public boolean deletePermission(UserInfo userInfo, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deletePermission(userInfo,groupName,roleName);
    }
    public boolean deletePermission(int userid, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deletePermission(userid,groupName,roleName);
    }
    
    public boolean deleteAllUserPermissions(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteAllUserPermissions(userInfo);
    }
    
    public boolean deleteAllUserPermissions(String openid) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteAllUserPermissions(openid);
    }
    
    //-------------------------------------------------------

    public PasswordEncoder getEncoder() {
        return userInfoDAO.getEncoder();
    }
    
    public void setEncoder(PasswordEncoder encoder) {
        userInfoDAO.setEncoder(encoder);
    }
    
    //-------------------------------------------------------
    
    public String toString() {
        return userInfoDAO.toString()+" "+cred;
    }
    


}