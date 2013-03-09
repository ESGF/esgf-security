/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation ALL RIGHTS
 * RESERVED.  U.S. Government sponsorship acknowledged.
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
/**
   Description:
   Perform sql query to find out all the people who
   Return Tuple of info needed (dataset_id, recipients/(user), names of updated files)
   
**/
package esg.node.security;

import java.io.Serializable;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.common.db.DatabaseResource;

public class GroupRoleCredentialedDAO implements Serializable {

    //-------------------
    //Insertion queries
    //-------------------

    /*
      Let me say this right up front.  I am NOT a DBA nor a SQL maven.
      I know how to pull things out of a database by hook or by crook
      (as is probably quite evident below). If you are a SQL jedi then
      please feel free to optimize the queries accordingly as long as
      the output is identical!  -gavin
     */
    
	private static final long serialVersionUID = 1L;
	
    //-------------------
    
    private static final Log log = LogFactory.getLog(GroupRoleCredentialedDAO.class);

    private Properties props = null;

    //This is the object we are delegating through to...
    private GroupRoleDAO groupRoleDAO = null;
    private UserInfo userInfo = null;
    
    //uses default values in the DatabaseResource to connect to database
    public GroupRoleCredentialedDAO(UserInfo userInfo) {
        this(userInfo, null);
    }

    public GroupRoleCredentialedDAO(UserInfo userInfo, Properties props) {
        if(userInfo == null) {
            throw new ESGFSecurityIllegalAccessException("Sorry, Must instantiate with a valid user info object");
        }
        this.setUserInfo(userInfo);
        this.setProperties(props);
        log.trace("Instantiating DAO using "+userInfo.getOpenid()+" privs");
    }

    public void setProperties(Properties props) { 
        this.props = props; 
        this.groupRoleDAO = new GroupRoleDAO(props);
    }

    public GroupRoleCredentialedDAO setUserInfo(UserInfo userInfo) { this.userInfo = userInfo; return this; }

    public UserInfo getUserInfo() { return this.userInfo; }

    //NOTE: This should be called once the user (as represented by the
    //userInfo object) is done with this DAO Since the userInfo is
    //"closed over" the methods used it needs to be cleared to avoid
    //an uninteded userInfo object being used when interrogating
    //method calls.
    public void clearUserInfo() { this.userInfo = null; }
    

    //-----------------------------------------------------------------
    //NOTE: The credential check criteria is simple, but we
    //encapsulate it here so we can make things arbitrarily
    //complicated later and only have to do that in one place,
    //here. :-) -gavin
    public final boolean checkCredentials() {
        System.out.println("checkCredientials() -> Matthew, please implement me! :-) ");
        return true; 
    }
    public final boolean checkGroupRolePrivs() {
        System.out.println("checkGrouprRolePrivs() -> Matthew, please implement me! :-) ");
        return true; 
    }
    //-----------------------------------------------------------------
    


    public boolean addGroup(String groupName) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return addGroup(groupName,"",true,true);
    }
    public synchronized boolean addGroup(String groupName, String groupDesc) {
        if(!checkCredentials()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return addGroup(groupName,groupDesc,true,true);
    }
    
    public synchronized boolean addGroup(String groupName, String groupDesc, boolean groupVisible, boolean groupAutoApprove) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.addGroup(groupName, groupDesc, groupVisible, groupAutoApprove);
    }
    
    public boolean isGroupValid(String groupName) {
        return groupRoleDAO.isGroupValid(groupName);
    }
    
    public boolean isRoleValid(String roleName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.isRoleValid(roleName);
    }
    
    public synchronized boolean setAutoApprove(String groupName, boolean autoApprove) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.setAutoApprove(groupName,autoApprove);
    }

    public synchronized boolean renameGroup(String origName, String newName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.renameGroup(origName,newName);
    }
    
    //TODO: What to really do here to make this happen
    public synchronized boolean deleteGroup(String groupName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.deleteGroup(groupName);
    }
    
    public boolean addRole(String roleName) {
        return addRole(roleName,"");
    }

    public synchronized boolean addRole(String roleName, String roleDesc) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.addRole(roleName,roleDesc);
    }

    public synchronized boolean renameRole(String origName, String newName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.renameRole(origName,newName);
    }
    
    //TODO: What to really do here to make this happen
    public synchronized boolean deleteRole(String roleName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.deleteRole(roleName);
    }
    
    //-------------------------------------------------------
    //Basic Selection "show" Queries
    //-------------------------------------------------------

    public List<String[]> getGroupEntry(String groupname) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getGroupEntry(groupname);
    }
    
    public boolean isAutomaticApproval(String groupname) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.isAutomaticApproval(groupname);
    }
    
    public List<String[]> getGroupEntries() {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getGroupEntries();
    }
    
    public List<String[]> getGroupEntriesFor(String openid) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getGroupEntriesFor(openid);
    }

    public List<String[]> getGroupEntriesNotFor(String openid) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getGroupEntriesNotFor(openid);
    }

    public List<String[]> getUsersInGroup(String groupname) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getUsersInGroup(groupname);
    }

    public List<String[]> getRoleEntry(String rolename) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getRoleEntry(rolename);
    }

    public List<String[]> getRoleEntries() {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getRoleEntries();
    }

    public List<String[]> getUsersInRole(String rolename) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.getUsersInRole(rolename);
    }

    public List<String[]> showUsersInGroupNotApproved(String groupName){
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.showUsersInGroupNotApproved(groupName);
    }

    public synchronized boolean updateWholeGroup(int id, String groupName, String groupDesc, boolean vis, boolean autoApprove) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.updateWholeGroup(id,groupName,groupDesc,vis,autoApprove);
    }

    public List<String[]> allNonApproved() {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.allNonApproved();
    }
    
    public List<String[]> setApproved(int userId, int groupId) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.setApproved(userId,groupId);
    }

    //More Friendly Signature
    public List<String[]> setApproved(String openid, String groupName) {
        if(!checkGroupRolePrivs()) {
            throw new ESGFSecurityIllegalAccessException("Sorry, you do not have the appropriate privilege for this operation");
        }
        return groupRoleDAO.setApproved(openid,groupName);
    }

    //------------------------------------
    
    public String toString() { return groupRoleDAO.toString(); }

}
