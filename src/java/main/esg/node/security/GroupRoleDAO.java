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
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.ResultSetHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.common.db.DatabaseResource;

public class GroupRoleDAO implements Serializable {

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
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	//Group Queries...
    private static final String hasGroupNameQuery =
        "SELECT * from esgf_security.group "+
        "WHERE name = ?";
    private static final String setAutoApproveGroupQuery =
        "UPDATE esgf_security.group "+
        "SET auto_approve = ? "+
        "WHERE id = ?";
    private static final String updateGroupQuery = 
        "UPDATE esgf_security.group "+
        "SET name=? "+
        "WHERE id=?";
    //private static final String getNextGroupPrimaryKeyValQuery = 
    //    "SELECT NEXTVAL('esgf_security.group_id_seq')";
    private static final String addGroupQuery = 
        "INSERT INTO esgf_security.group (name, description, visible, automatic_approval) "+
        "VALUES ( ?, ?, ?, ?)";
    private static final String delGroupQuery =
        "DELETE FROM esgf_security.group where name = ?";

    //Role Queries...
    private static final String hasRoleNameQuery =
        "SELECT * from esgf_security.role "+
        "WHERE name = ?";
    private static final String updateRoleQuery = 
        "UPDATE esgf_security.role "+
        "SET name=? "+
        "WHERE id=?";
    //private static final String getNextRolePrimaryKeyValQuery  =
    //    "SELECT NEXTVAL('esgf_security.role_id_seq')";
    private static final String addRoleQuery = 
        "INSERT INTO esgf_security.role (name, description) "+
        "VALUES ( ? ,? )";
    private static final String delRoleQuery =
        "DELETE FROM esgf_security.role where name = ?";

    //-------------------
    private static final String showGroupQuery =
        "SELECT * FROM esgf_security.group WHERE name = ?";
    
    private static final String isAutomaticApprovalQuery =
        "SELECT automatic_approval FROM esgf_security.group WHERE name = ?";

    private static final String showGroupsQuery =
        "SELECT * FROM esgf_security.group";

    private static final String showRoleQuery =
        "SELECT * FROM esgf_security.role WHERE name = ?";

    private static final String showRolesQuery =
        "SELECT * FROM esgf_security.role";

    //-------------------
    
    private static final String showUsersInGroupQuery =
        "SELECT username, firstname, lastname, openid FROM esgf_security.user WHERE id IN (SELECT p.user_id FROM esgf_security.permission as p WHERE p.group_id = (SELECT id FROM esgf_security.group WHERE name = ? )) AND p.approved = 't'";

    private static final String showUsersInRoleQuery =
        "SELECT username, firstname, lastname, openid FROM esgf_security.user WHERE id IN (SELECT p.user_id FROM esgf_security.permission as p WHERE p.role_id = (SELECT id FROM esgf_security.role WHERE name = ? )) AND p.approved = 't'";

    //-------------------

    private static final String showGroupsNotSubscribedToQuery =
        "SELECT * from esgf_security.group WHERE id NOT in (SELECT DISTINCT group_id FROM esgf_security.permission as p WHERE user_id = (SELECT id FROM esgf_security.user WHERE openid = ? ))";

    private static final String showGroupsSubscribedToQuery =
        "SELECT * FROM esgf_security.group WHERE id IN (SELECT DISTINCT group_id FROM esgf_security.permission as p WHERE user_id = (SELECT id FROM esgf_security.user WHERE openid = ? )) AND p.approved = 't'";

     //-------------------

    private static final String showUsersInGroupNotApprovedQuerey = 
        "SELECT u.firstname, u.middlename, u.lastname, u.email, u.username, u.organization, u.city, u.state, u.country, r.name as role " +
        "FROM esgf_security.permission as p, esgf_security.user as u, esgf_security.role as r, esgf_security.group " + 
        "WHERE p.group_id = g.id" + 
        "AND p.approved = 'f' " + 
        "AND p.user_id = u.id " + 
        "AND p.role_id = r.id " + 
        "AND g.name = ?";

    //-------------------
    
    private static final String allNonApprovedQuery = 
      "SELECT g.name, g.id, u.username, u.id, r.name, r.id "+
      "FROM esgf_security.group as g, esgf_security.permission as p, esgf_security.user as u, esgf_security.role as r " + 
      "WHERE p.approved = 'f' AND g.id = p.group_id AND u.id = p.user_id AND r.id = p.role_id";
    
    //-------------------
 
    private static final Log log = LogFactory.getLog(GroupRoleDAO.class);

    private Properties props = null;
    private DataSource dataSource = null;
    private QueryRunner queryRunner = null;
    private ResultSetHandler<Map<String,Set<String>>> userGroupsResultSetHandler = null;
    private ResultSetHandler<Integer> idResultSetHandler = null;
    private ResultSetHandler<List<String[]>> basicResultSetHandler = null;
    private ResultSetHandler<Boolean> booleanResultSetHandler = null;

    //uses default values in the DatabaseResource to connect to database
    public GroupRoleDAO() {
        this(new Properties());
    }

    public GroupRoleDAO(Properties props) {
        if (props == null) {
            log.warn("Input Properties parameter is: ["+props+"] - creating empty Properties obj");
            props = new Properties();
        }
        
        //This is kind of tricky because the DatabaseResource is meant
        //to be set up once in the earliest part of this application.
        //Subsequent to it's initialziation and setup then any program
        //that needs to use the database can call getInstance.  Since
        //I am not sure where in the codebase I can initialize the
        //DatabaseResource I am doing it here but guarding repeated
        //calls to setupDatasource so that it is ostensibly in the
        //singleton as well.
        
        if (DatabaseResource.getInstance() == null) {
            DatabaseResource.init(props.getProperty("db.driver","org.postgresql.Driver")).setupDataSource(props);
        }
        
        this.setDataSource(DatabaseResource.getInstance().getDataSource());
        this.setProperties(props);
        init();
    }

    public void init() {
        
        this.idResultSetHandler = new ResultSetHandler<Integer>() {
		    public Integer handle(ResultSet rs) throws SQLException {
                if(!rs.next()) { return -1; }
                return rs.getInt(1);
		    }
		};
		
        this.booleanResultSetHandler = new ResultSetHandler<Boolean>() {
            public Boolean handle(ResultSet rs) throws SQLException {
                if (!rs.next()) { return false; }
                return rs.getBoolean(1);
            }
        };
        
        userGroupsResultSetHandler = new ResultSetHandler<Map<String,Set<String>>>() {
            Map<String,Set<String>> groups = null;    
            Set<String> roleSet = null;
            
            public Map<String,Set<String>> handle(ResultSet rs) throws SQLException{
                while(rs.next()) {
                    addGroup(rs.getString(1),rs.getString(2));
                }
                return groups;
            }
            
            public void addGroup(String name, String value) {
                //lazily instantiate groups map
                if(groups == null) {
                    groups = new HashMap<String,Set<String>>();
                }
                
                //lazily instantiate the set of values for group if not
                //there
                if((roleSet = groups.get(name)) == null) {
                    roleSet = new HashSet<String>();
                }
                
                //enter group associated with group value set
                roleSet.add(value);
                groups.put(name, roleSet);
            }


        };

        basicResultSetHandler = new ResultSetHandler<List<String[]>>() {
            public List<String[]> handle(ResultSet rs) throws SQLException {
                ArrayList<String[]> results = new ArrayList<String[]>();
                String[] record = null;
                assert (null!=results);

                ResultSetMetaData meta = rs.getMetaData();
                int cols = meta.getColumnCount();
                log.trace("Number of fields: "+cols);

                log.trace("adding column data...");
                record = new String[cols];
                for(int i=0;i<cols;i++) {
                    try{
                        record[i]=meta.getColumnLabel(i+1);
                    }catch (SQLException e) {
                        log.error(e);
                    }
                }
                results.add(record);

                for(int i=0;rs.next();i++) {
                    log.trace("Looking at record "+(i+1));
                    record = new String[cols];
                    for (int j = 0; j < cols; j++) {
                        record[j] = rs.getString(j + 1);
                        log.trace("gathering result record column "+(j+1)+" -> "+record[j]);
                    }
                    log.trace("adding record ");
                    results.add(record);
                    record = null; //gc courtesy
                }
                return results;
            }
        };

    }
    
    public void setProperties(Properties props) { this.props = props; }

    public void setDataSource(DataSource dataSource) {
        log.trace("Setting Up GroupRoalDAO's Pooled Data Source");
        this.dataSource = dataSource;
        this.queryRunner = new QueryRunner(dataSource);
    }
    
    public boolean addGroup(String groupName) {
        return addGroup(groupName,"",true,true);
    }
    public synchronized boolean addGroup(String groupName, String groupDesc) {
        return addGroup(groupName,groupDesc,true,true);
    }
    public synchronized boolean addGroup(String groupName, String groupDesc, boolean groupVisible, boolean groupAutoApprove) {
        int groupid = -1;
        int numRowsAffected = -1;
        
        try{
            //Check to see if there is an entry by this name already....
            groupid = queryRunner.query(hasGroupNameQuery,idResultSetHandler,groupName);
            
            //If there *is*... then there is nothing to add!
            if(groupid > 0) { return true; }
            
            //If this group does not exist in the database then add (INSERT) a new one
            //groupid = queryRunner.query(getNextGroupPrimaryKeyValQuery, idResultSetHandler);
            numRowsAffected = queryRunner.update(addGroupQuery,groupName,groupDesc,groupVisible,groupAutoApprove);
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    public boolean isGroupValid(String groupName) {

        try {           
            int groupid = queryRunner.query(hasGroupNameQuery,idResultSetHandler,groupName);
            if (groupid > 0) { return true; }            
        } catch(SQLException ex) {
            log.error(ex);
        }        
        return false;
     
    }
    
    public boolean isRoleValid(String roleName) {

        try {           
            int roleid = queryRunner.query(hasRoleNameQuery,idResultSetHandler, roleName);
            if (roleid > 0) { return true; }            
        } catch(SQLException ex) {
            log.error(ex);
        }        
        return false;
     
    }
    
    public synchronized boolean setAutoApprove(String groupName, boolean autoApprove) {
        int groupid = -1;
        int numRowsAffected = -1;

        try{
            //Check to see if there is an entry by this name already....
            groupid = queryRunner.query(hasGroupNameQuery,idResultSetHandler,groupName);

            //If there *is*... then continue on to modifying the value
            if(groupid < 1) { return false; }

            //If this group does not exist in the database then add (INSERT) a new one
            //groupid = queryRunner.query(getNextGroupPrimaryKeyValQuery, idResultSetHandler);
            numRowsAffected = queryRunner.update(setAutoApproveGroupQuery,autoApprove,groupid);
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    public synchronized boolean renameGroup(String origName, String newName) {
        int groupid = -1;
        int numRowsAffected = -1;
        
        try{
            //Check to see if there is an entry by this name already....
            groupid = queryRunner.query(hasGroupNameQuery,idResultSetHandler,origName);
            
            //If there *is*... then UPDATE that record
            if(groupid > 0) {
                numRowsAffected = queryRunner.update(updateGroupQuery, newName, groupid);
            }
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    //TODO: What to really do here to make this happen
    public synchronized boolean deleteGroup(String groupName) {
        int numRowsAffected = -1;
        try{
            System.out.print("Deleting Group "+groupName);
            numRowsAffected = queryRunner.update(delGroupQuery, groupName);
            if (numRowsAffected > 0) System.out.println("[OK]"); else System.out.println("[FAIL]");
            System.out.println(numRowsAffected+" entries removed");
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    public boolean addRole(String roleName) {
        return addRole(roleName,"");
    }
    public synchronized boolean addRole(String roleName, String roleDesc) {
        int roleid = -1;
        int numRowsAffected = -1;
        try{
            //Check to see if there is an entry by this name already....
            roleid = queryRunner.query(hasRoleNameQuery,idResultSetHandler,roleName);
            
            //If there *is*... then it is already there!
            if(roleid > 0) { return true; }
            
            //If this role does not exist in the database then add (INSERT) a new one
            //roleid = queryRunner.query(getNextRolePrimaryKeyValQuery,idResultSetHandler);
            numRowsAffected = queryRunner.update(addRoleQuery,roleName,roleDesc);
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }

    public synchronized boolean renameRole(String origName, String newName) {
        int roleid = -1;
        int numRowsAffected = -1;
        try{
            //Check to see if there is an entry by this name already....
            roleid = queryRunner.query(hasRoleNameQuery,idResultSetHandler,origName);
            
            //If there *is*... then UPDATE (rename) that record
            if(roleid > 0) {
                numRowsAffected = queryRunner.update(updateRoleQuery, newName, roleid);
            }
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    //TODO: What to really do here to make this happen
    public synchronized boolean deleteRole(String roleName) {
        int numRowsAffected = -1;
        try{
            System.out.print("Deleting Role "+roleName);
            numRowsAffected = queryRunner.update(delRoleQuery, roleName);
            if (numRowsAffected > 0) System.out.println("[OK]"); else System.out.println("[FAIL]");
            System.out.println(numRowsAffected+" entries removed");
        }catch(SQLException ex) {
            log.error(ex);
        }
        return (numRowsAffected > 0);
    }
    
    //-------------------------------------------------------
    //Basic Selection "show" Queries
    //-------------------------------------------------------

    public List<String[]> getGroupEntry(String groupname) {
        try{
            log.trace("Fetching raw group data from database table");
            List<String[]> results = queryRunner.query(showGroupQuery, basicResultSetHandler, groupname);
            log.trace("Query is: "+showGroupQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }
    
    public boolean isAutomaticApproval(String groupname) {
        boolean result = false;
        try{
            log.trace("Query is: "+isAutomaticApprovalQuery);
            result = queryRunner.query(isAutomaticApprovalQuery, booleanResultSetHandler, groupname);
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return result;
    }

    public List<String[]> getGroupEntries() {
        try{
            log.trace("Fetching raw groups data from database table");
            List<String[]> results = queryRunner.query(showGroupsQuery, basicResultSetHandler);
            log.trace("Query is: "+showGroupsQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> getGroupEntriesFor(String openid) {
        try{
            log.trace("Fetching raw groups data from database table of groups "+openid+" is in");
            List<String[]> results = queryRunner.query(showGroupsSubscribedToQuery, basicResultSetHandler, openid);
            log.trace("Query is: "+showGroupsSubscribedToQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> getGroupEntriesNotFor(String openid) {
        try{
            log.trace("Fetching raw groups data from database table of groups "+openid+" is NOT in");
            List<String[]> results = queryRunner.query(showGroupsNotSubscribedToQuery, basicResultSetHandler, openid);
            log.trace("Query is: "+showGroupsNotSubscribedToQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }


    public List<String[]> getUsersInGroup(String groupname) {
        try{
            log.trace("Fetching users for the given group "+groupname);
            List<String[]> results = queryRunner.query(showUsersInGroupQuery, basicResultSetHandler, groupname);
            log.trace("Query is: "+showUsersInGroupQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> getRoleEntry(String rolename) {
        try{
            log.trace("Fetching raw role data from database table");
            List<String[]> results = queryRunner.query(showRoleQuery, basicResultSetHandler, rolename);
            log.trace("Query is: "+showRoleQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> getRoleEntries() {
        try{
            log.trace("Fetching raw roles data from database table");
            List<String[]> results = queryRunner.query(showRolesQuery, basicResultSetHandler);
            log.trace("Query is: "+showRolesQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> getUsersInRole(String rolename) {
        try{
            log.trace("Fetching users for the given role "+rolename);
            List<String[]> results = queryRunner.query(showUsersInRoleQuery, basicResultSetHandler, rolename);
            log.trace("Query is: "+showUsersInRoleQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> showUsersInGroupNotApprovedQuerey(String groupName){
        try{
            log.trace("Fetching users not approved for the group "+groupName);
            List<String[]> results = queryRunner.query(showUsersInGroupNotApprovedQuerey, basicResultSetHandler, groupName);
            log.trace("Query is: "+showUsersInGroupNotApprovedQuerey);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    public List<String[]> allNonApprovedQuery(){
        try{
            log.trace("Fetching list of all groups and users not approved for the group ");
            List<String[]> results = queryRunner.query(allNonApprovedQuery, basicResultSetHandler);
            log.trace("Query is: "+allNonApprovedQuery);
            assert (null != results);
            if(results != null) { log.trace("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }

    //------------------------------------
    
    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append("DAO:["+this.getClass().getName()+"] - "+((dataSource == null) ? "[OK]" : "[INVALID]\n"));
        return out.toString();
    }
}
