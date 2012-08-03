/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.node.security;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.List;

import esg.security.utils.encryption.PasswordEncoder;

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
        log.trace("Instantiating DAO using "+cred+" privs");
        userInfoDAO = new UserInfoDAO(props);
        useCredentials(cred);
    }

    public UserInfoCredentialedDAO(String id, String password, Properties props) {
        this(new Credentials(id,password),props);
    }

    public final boolean useCredentials(Credentials cred) {
        //TODO: So ideally there will be a policy that gets enforced
        //here to determine things like Which users can do what
        //actions etc...  for now... I'll make it "rootAdmin" only...
        UserInfo user = null;
        log.trace("Checking credentials: "+cred);
        if(cred != null) {
            //NOTE: we want to deprecate the use of the "ById" call
            //and use the "ByOpenid" call this way we do everything by
            //openid... however, for ease of testing purposes and thus
            //general laziness right now, we will use the "ById"
            //version.
            user = userInfoDAO.getUserById(cred.getid());
            if(!user.isValid()) { log.info("User ["+cred.getid()+"] is NOT a valid user on this system"); return false; }
            if(!user.getUserName().equals("rootAdmin")) { log.trace("Sorry, Must be ROOT to use this DAO"); return false; }

            if((user != null) && userInfoDAO.checkPassword(user.getOpenid(),cred.getPassword())) {
                this.cred = cred;
                return true;
            }else{
                log.warn("Password for "+cred+" NOT valid");
            }
        }else {
            log.warn("can't use ["+cred+"] credentials... ");
        }
        return false;
    }

    //NOTE: The credential check criteria is simple, but we
    //encapsulate it here so we can make things arbitrarily
    //complicated later and only have to do that in one place,
    //here. :-) -gavin
    public final boolean checkCredentials() { return (null != cred); }

    //NOTE: Maybe checking for credentials to get a blank user info
    //object is over kill? The real critical operation is adding one
    //into the system.  But I think that I would like you to get
    //stopped much earlier in the process than later in the process
    //after you have potentially spent a bunch of time preparing the
    //object. right?  So the general philosophy is don't make one if
    //you can't raise one ;-). -gavin
    public UserInfo getNewUserInfo() {
        UserInfo userInfo = null;
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        userInfo = new UserInfo();
        return userInfo;
    }

    public UserInfo getUserByOpenid(String openid) {
        return userInfoDAO.getUserByOpenid(openid);
    }
    public UserInfo getUserById(String id) {
        return userInfoDAO.getUserById(id);
    }
    
    public boolean isPermissionApproved(String userOpenid, String groupName, String roleName) {
        return userInfoDAO.isPermissionApproved(userOpenid, groupName, roleName);
    }
    
    public UserInfo refresh(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.refresh(userInfo);
    }

    public UserInfo commit(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.commit(userInfo);
    }

    //---
    //We want to make sure these manipulation calls are guarded
    //---
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
        return this.setPassword(openid,newPassword,false);
    }
    public boolean setPassword(String openid, String newPassword, boolean literal) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setPassword(openid,newPassword,literal);
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
    //Account Status Manipulations
    //-------------------------------------------------------
    //Sets the status code value for a given user (openid)
    public boolean setStatusCode(UserInfo userInfo, int newStatusCode) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setStatusCode(userInfo,newStatusCode);
    }
    public synchronized boolean setStatusCode(String openid, int newStatusCode) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setStatusCode(openid,newStatusCode);
    }

    //Given the old password and the new password for a given user
    //(openid) update the password, only if the old password matches
    public boolean changeStatus(UserInfo userInfo, int newStatusCode, String verificationToken) {
        return userInfoDAO.changeStatus(userInfo,newStatusCode,verificationToken);
    }
    public synchronized boolean changeStatus(String openid, int newStatusCode, String verificationToken) {
        return userInfoDAO.changeStatus(openid,newStatusCode,verificationToken);
    }

    public String genVerificationToken(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.genVerificationToken(userInfo);
    }
    public String genVerificationToken(String openid) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.genVerificationToken(openid);
    }
    public String getVerificationToken(UserInfo userInfo) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.getVerificationToken(userInfo);
    }
    public String getVerificationToken(String openid) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.getVerificationToken(openid);
    }

    public List<String[]> getOpenidsForEmail(String email) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.getOpenidsForEmail(email);
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
    public boolean addPermission(String userName, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addPermission(userName,groupName,roleName);
    }
    public boolean addPermissionByOpenid(String openid, String groupName, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.addPermissionByOpenid(openid,groupName,roleName);
    }
    public boolean setPermission(int userid, String groupName, String roleName, boolean approved) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.setPermission(userid,groupName,roleName,approved);
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
    
    public boolean deleteGroupFromUserPermissions(UserInfo userInfo, String groupName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteGroupFromUserPermissions(userInfo,groupName);
    }

    public boolean deleteRoleFromUserPermissions(UserInfo userInfo, String roleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.deleteRoleFromUserPermissions(userInfo,roleName);
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
    //User Movement between Groups/Roles Query en mass
    //-------------------------------------------------------

    public boolean moveAllUsersInGroupTo(String sourceGroupName, String targetGroupName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.moveAllUsersInGroupTo(sourceGroupName, targetGroupName);
    }
    public boolean moveAllUsersWithRoleTo(String sourceRoleName, String targetRoleName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return userInfoDAO.moveAllUsersWithRoleTo(sourceRoleName, targetRoleName);
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
