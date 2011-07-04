/***************************************************************************
 *                                                                          *
 *  Organization: Lawrence Livermore National Lab (LLNL)                    *
 *   Directorate: Computation                                               *
 *    Department: Computing Applications and Research                       *
 *      Division: S&T Global Security                                       *
 *        Matrix: Atmospheric, Earth and Energy Division                    *
 *       Program: PCMDI                                                     *
 *       Project: Earth Systems Grid (ESG) Data Node Software Stack         *
 *  First Author: Gavin M. Bell (gavin@llnl.gov)                            *
 *                                                                          *
 ****************************************************************************
 *                                                                          *
 *   Copyright (c) 2009, Lawrence Livermore National Security, LLC.         *
 *   Produced at the Lawrence Livermore National Laboratory                 *
 *   Written by: Gavin M. Bell (gavin@llnl.gov)                             *
 *   LLNL-CODE-420962                                                       *
 *                                                                          *
 *   All rights reserved. This file is part of the:                         *
 *   Earth System Grid (ESG) Data Node Software Stack, Version 1.0          *
 *                                                                          *
 *   For details, see http://esgf.org/esg-node/                             *
 *   Please also read this link                                             *
 *    http://esgf.org/LICENSE                                               *
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

/**
   Description:
   Perform sql query to find out all the people who
   Return Tuple of info needed (dataset_id, recipients/(user), names of updated files)
   
**/
package esg.node.security;

import static esg.common.Utils.getFQDN;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.sql.ResultSetMetaData;
import javax.sql.DataSource;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.ResultSetHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import esg.common.db.DatabaseResource;
import esg.common.util.ESGFProperties;
import esg.security.utils.encryption.MD5CryptPasswordEncoder;
import esg.security.utils.encryption.PasswordEncoder;

public class UserInfoDAO {

    private static final long serialVersionUID = 1L;
    
    //-------------------
    //Selection queries (fills in the UserInfo data carrying object)
    //-------------------
    private static final String idQuery = 
        "SELECT id, openid, firstname, middlename, lastname, username, email, dn, organization, organization_type, city, state, country, status_code "+
        "FROM esgf_security.user "+
        "WHERE openid = ?";

    //-------------------
    //Insertion queries
    //-------------------
    
    //User Queries...
    private static final String hasUserOpenidQuery =
        "SELECT id from esgf_security.user "+
        "WHERE openid = ?";
    private static final String updateUserQuery = 
        "UPDATE esgf_security.user "+
        "SET openid = ?, firstname = ?, middlename = ?, lastname = ?, username = ?, email = ?, dn = ?, organization = ?, organization_type = ?, city = ?, state = ?, country = ?, status_code = ? "+
        "WHERE id = ? ";
    private static final String getNextUserPrimaryKeyValQuery = 
        "SELECT NEXTVAL('esgf_security.user_id_seq')";
    private static final String addUserQuery = 
        "INSERT INTO esgf_security.user (id, openid, firstname, middlename, lastname, username, email, dn, organization, organization_type, city, state, country, status_code) "+
        "VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String delUserQuery =
        "DELETE FROM esgf_security.user "+
        "WHERE openid = ?";

    //Permission Queries...
    private static final String getPermissionsQuery = 
        "SELECT g.name, r.name from esgf_security.group as g, esgf_security.role as r, esgf_security.permission as p, esgf_security.user as u "+
        "WHERE p.user_id = u.id and u.openid = ? and p.group_id = g.id and p.role_id = r.id "+
        "ORDER BY g.name";
    private static final String addPermissionQuery = 
        "INSERT INTO esgf_security.permission (user_id, group_id, role_id) "+
        "VALUES ( ?, (SELECT id FROM esgf_security.group WHERE name = ? ), (SELECT id FROM esgf_security.role WHERE name = ?))";
    private static final String delPermissionQuery = 
        "DELETE FROM esgf_security.permission "+
        "WHERE user_id = ?, "+
        "group_id = (SELECT id FROM esgf_security.group WHERE name = ?), "+
        "role_id = (SELECT id FROM esgf_security.role WHERE name = ?)";
    private static final String delAllUserPermissionsQuery =
        "DELETE FROM esgf_security.permission WHERE user_id = (SELECT id FROM esgf_security.user WHERE openid = ?)";
    private static final String existsPermissionQuery = 
        "SELECT COUNT(*) FROM esgf_security.permission "+
        "WHERE user_id = ? "+
        "AND group_id = (SELECT id FROM esgf_security.group WHERE name = ? ) "+
        "AND role_id = (SELECT id FROM esgf_security.role WHERE name = ? )";

    //Status Queries
    private static final String setStatusCodeQuery = 
        "UPDATE esgf_security.user SET status_code = ? "+
        "WHERE openid = ?";

    private static final String changeStatusQuery = 
        "UPDATE esgf_security.user SET status_code = ? "+
        "WHERE verification_token = ? AND openid = ? ";

    private static final String setVerificationTokenQuery =
        "UPDATE esgf_security.user SET verification_token = ? "+
        "WHERE openid = ? ";

    private static final String getVerificationTokenQuery = 
        "SELECT verification_token FROM esgf_security.user WHERE openid = ?";
        
    //Password Queries...
    private static final String setPasswordQuery = 
        "UPDATE esgf_security.user SET password = ? "+
        "WHERE openid = ?";

    private static final String getPasswordQuery = 
        "SELECT password FROM esgf_security.user WHERE openid = ?";

    //-------------------

    private static final String showUsersQuery =
        "SELECT username, firstname, lastname, openid from FROM esgf_security.user";

    //-------------------
    
    private static final Log log = LogFactory.getLog(UserInfoDAO.class);

    private Properties props = null;
    private DataSource dataSource = null;
    private QueryRunner queryRunner = null;
    private ResultSetHandler<UserInfo> userInfoResultSetHandler = null;
    private ResultSetHandler<Map<String,Set<String>>> userPermissionsResultSetHandler = null;
    private ResultSetHandler<Integer> idResultSetHandler = null;
    private ResultSetHandler<Boolean> existsResultSetHandler = null;
    private ResultSetHandler<String> singleStringResultSetHandler = null;
    private ResultSetHandler<String> passwordQueryHandler = null;
    private ResultSetHandler<List<String[]>> basicResultSetHandler = null;

    private static final String  adminName = "rootAdmin";
    
    //private static final Pattern openidUrlPattern = Pattern.compile("https://([^/ ]*)/.*[/]*/([^/ @*%#!()<>+=]*$)");
    private static final Pattern openidUrlPattern = Pattern.compile("https://([^:/]*)(:(?:[0-9]*))?/([^ &@*%#!()<>+=]*/)*([^/ &@*%#!()<>+=]*$)");
    private static final Pattern usernamePattern = Pattern.compile("^[^/ &@*%#!()<>+=]*$");
    
    private PasswordEncoder encoder = new MD5CryptPasswordEncoder();
    
    //uses default values in the DatabaseResource to connect to database
    public UserInfoDAO() {
        this(new Properties());
    }
    
    public UserInfoDAO(Properties props) {
        if (props == null) {
            log.warn("Input Properties parameter is: ["+props+"] - creating empty Properties obj");
            try{
                props = new ESGFProperties();
            }catch(Exception ex) {
                log.warn("Problem Creating ESGFProperties() - "+ex.getMessage());
                log.error(ex);
            }
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
        
        this.existsResultSetHandler = new ResultSetHandler<Boolean>() {
            public Boolean handle(ResultSet rs) throws SQLException {
                if(!rs.next()) { return false; }
                return (rs.getInt(1) > 0);
            }
        };
        
        this.singleStringResultSetHandler = new ResultSetHandler<String>() {
            public String handle(ResultSet rs) throws SQLException {
                if(!rs.next()) { return null; }
                return rs.getString(1);
            }
        };
        
        passwordQueryHandler = new ResultSetHandler<String>() {
            public String handle(ResultSet rs) throws SQLException {
                String password = null;
                while(rs.next()) {
                    password = rs.getString(1);
                }
                return password;
            }
        };
        
        //To handle the single record result
        userInfoResultSetHandler =  new ResultSetHandler<UserInfo>() {
            public UserInfo handle(ResultSet rs) throws SQLException {
                UserInfo userInfo = null;
                while(rs.next()) {
                    userInfo = new UserInfo();
                    userInfo.setid(rs.getInt(1))
                        .setOpenid(rs.getString(2))
                        .setFirstName(rs.getString(3))
                        .setMiddleName(rs.getString(4))
                        .setLastName(rs.getString(5))
                        .setUserName(rs.getString(6))
                        .setEmail(rs.getString(7))
                        .setDn(rs.getString(8))
                        .setOrganization(rs.getString(9))
                        .setOrgType(rs.getString(10))
                        .setCity(rs.getString(11))
                        .setState(rs.getString(12))
                        .setCountry(rs.getString(13))
                        .setStatusCode(rs.getInt(14));
                }
                return userInfo;
            }
        };
        
        userPermissionsResultSetHandler = new ResultSetHandler<Map<String,Set<String>>>() {
            Map<String,Set<String>> permissions = new HashMap<String,Set<String>>();
            Set<String> roleSet = null;
            
            public Map<String,Set<String>> handle(ResultSet rs) throws SQLException{
                permissions.clear();
                if(!rs.next()) { return permissions; }
                do {
                    addPermission(rs.getString(1),rs.getString(2));
                } while(rs.next()) ;
                return permissions;
            }
            
            public void addPermission(String groupName, String roleName) {
                //lazily instantiate the set of values for group if not
                //there
                if((roleSet = permissions.get(groupName)) == null) {
                    roleSet = new HashSet<String>();
                }
                
                //enter group associated with group value set
                roleSet.add(roleName);
                permissions.put(groupName, roleSet);
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

        new InitAdmin();
    }
    
    public void setProperties(Properties props) { this.props = props; }
    
    public void setDataSource(DataSource dataSource) {
        log.trace("Setting Up UserInfoDAO's Pooled Data Source");
        this.dataSource = dataSource;
        this.queryRunner = new QueryRunner(dataSource);
    }


    //-------------------------------------------------------
    //User Manipulations
    //-------------------------------------------------------

    
    //------------------------------------
    //Query function calls... 
    //(NOTE: synchronized since there are two calls to database - can optimize around later)
    //------------------------------------

    /**
       Fetches data from the backing store (database) using the openid
       and put into UserInfo object (Additionally checks the openid
       pattern for structural validity).  This call is <b>preferred</b> over
       the other version of this method <code>getUserById</code>.
       
       @param openid openid of the user to be represented.
       @return The UserInfo object that contains the salient state of
       user associated with passed in openid. Null if openid pattern
       is spurious.
     */
    public synchronized UserInfo getUserByOpenid(String openid) {
        if ((openidUrlPattern.matcher(openid)).find()) {
            return getUserById(openid);
        }
        return null;
    }

    /**
       Fetched data from the backing store (database) using either the
       full open id or just the user name (the last token of the
       openid url).  If the username is used the rest of the openid
       url is applied to it as if it was a <b>local</b> openid
       serviced by this IDP.  Because this assumption is not always
       valid and there can indeed be openids that are present in the
       system that are not serviced locally, the use of <i>this
       convenience feature is <b>discouraged</b></i> and the openid
       should be used explicitly or use the
       <code>getUserByOpenid</code> method directly.

       @param openid openid of the user to be represented.
       @return The UserInfo object that contains the salient state of
       user associated with passed in openid. Null if openid pattern
       is spurious.

     */
    public synchronized UserInfo getUserById(String id) {
        UserInfo userInfo = null;

        log.info("getUserById ( "+id+" )");

        try{
            int affectedRecords = 0;
            String openid = null;
            String username = null;
            
            //Discern if they user put in a an openid url or just a username, 
            //set values accordingly...
            Matcher openidMatcher = openidUrlPattern.matcher(id);
            Matcher usernameMatcher = null;
            String openidHost = null;
            String openidPort = "";
            String openidPath = null;
            if(openidMatcher.find()) {
                openid = id;
                openidHost = openidMatcher.group(1);
                openidPort = openidMatcher.group(2);
                openidPath = openidMatcher.group(3);
                username = openidMatcher.group(4);
                
                log.trace("submitted openid = "+id);
                log.trace("openidHost = "+openidHost);
                log.trace("openidPort = "+openidPort);
                log.trace("openidPath = "+openidPath);
                log.trace("username   = "+username);
                
                if(openidPort == null || openidPort.equals(":443")) {
                    log.trace("scrubbing out default openidPort ["+openidPort+"]");
                    openidPort="";
                }
                
                //reconstruct the url scrubbing out port if necessary...
                openid = "https://"+openidHost+openidPort+"/"+openidPath+username;
                
            }else{
                usernameMatcher = usernamePattern.matcher(id);
                if(usernameMatcher.find()) {
                    openidHost = props.getProperty("esgf.host",getFQDN());
                    openidPort = props.getProperty("esgf.https.port","");
                    username = id;
                    
                    log.trace("submitted id = "+id);
                    log.trace("openidHost = "+openidHost);
                    log.trace("openidPort = "+openidPort);
                    log.trace("username   = "+username);
                    
                    //Do not use the port value if it is the default value for https i.e. 443
                    //BAD  = https://esgf-node1.llnl.gov:443/esgf-idp/openid/gavinbell
                    //GOOD = https://esgf-node1.llnl.gov/esgf-idp/openid/gavinbell
                    log.info("openid port = "+openidPort);
                    if(openidPort.equals("") || openidPort.equals("443")) {
                        openidPort="";
                    }else{
                        openidPort=":"+openidPort;
                    }
                    
                    openid = "https://"+openidHost+openidPort+"/esgf-idp/openid/"+username;
                    
                }else {
                    log.info("Sorry money, your id is not well formed");
                    return null;
                }
            }
            
            log.trace("(re)constructed openid = "+openid);
            
            try{
                log.trace("Issuing Query for info associated with id: ["+openid+"], from database");
                if (openid==null) { return null; }
                userInfo = queryRunner.query(idQuery,userInfoResultSetHandler,openid);
                
                //IF does not already exist in our system, then create a
                //skeleton instance suitable for adding to... (setting
                //openid and username) You know this object is not in the
                //system because it's id will be -1.
                if(userInfo == null) {
                    userInfo = new UserInfo();
                    userInfo.setOpenid(openid);
                    userInfo.setUserName(username);
                }else {
                    userInfo.setPermissions(queryRunner.query(getPermissionsQuery,userPermissionsResultSetHandler,openid));
                }
                
                //A bit of debugging and sanity checking...
                log.trace(userInfo.toString());
                
            }catch(SQLException ex) {
                log.error(ex);      
                throw new ESGFDataAccessException(ex);
            }
        }catch(Throwable t) {
            //If shit hits the fan, bottom line... not letting anyone in.
            //returning a negative answer for getting user information
            log.error("t.getMessage()");
            log.error(t);
        }
        return userInfo;
    }
    
    /**
       Takes a <i>valid</i> UserInfo object input and replenishes it with data
       directly from the backing store (database).  This method is
       intended to be used in the case where there are manipulations
       made directly to the database regarding information that may be
       present in the UserInfo object's state.  This method will sync
       the UserInfo object in question with the information from the
       backing store (database) - ostensibly rewriting the object such
       that it accurately reflects the state of the database.

       @param userInfo Object containing state of data representing a user
       @return UserInfo object reflecting the state of the database for this user.
     */
    public synchronized UserInfo refresh(UserInfo userInfo) {
        if((userInfo.getid() > 0) && userInfo.isValid()) {
            log.info("Refreshing ["+userInfo.getUserName()+"]...");
            log.trace(" Openid: ["+userInfo.getOpenid()+"]");
            userInfo.copy(getUserById(userInfo.getOpenid()));
        }
        return userInfo;
    }

    /**
       Provides a round trip path from an input UserInfo data object
       (ingress) to returned object reflecting stat of database
       information (egreess). Takes the contents of a <i>valid</i>
       UserInfo object and commits that data into the backing store
       (database).  The data in the input UserInfo object is
       rewritten/replenished directly from the backing store
       (database) into the input UserInfo object and returned.  This
       means that if the UserInfo was not posted to the backing store
       (database) competely the returned object may not be the same as
       the submitted object.  In practical matters this should not
       happen since an unsuccessfull commit to the database will not
       allow a rewrite of the input UserInfo object.

       @param userInfo Object containing state of data representing a
       user.  This may be a brand new user or previous user.
       @return UserInfo object reflecting the state of the database for this user.
    */
    public synchronized UserInfo commit(UserInfo userInfo) {
        if((userInfo.getid() > 0) && userInfo.isValid() ) {
            log.info("Committing ["+userInfo.getUserName()+"]...");
            log.trace(" Openid: ["+userInfo.getOpenid()+"]");
            if(addUserInfo(userInfo)) {
                userInfo.copy(getUserById(userInfo.getOpenid()));
            }else {
                //TODO: throw exception here.
            }
        }
        return userInfo;        
    }

    /**
       Push the state of the UserInfo object into the backing stosre
       (database).  New UserInfo objects (that have all non-null
       fields assigned) may use this method to create an entirely new
       UserInfo presence. <i> same exact method as addUser </i>

       @param userInfo Object containing state of data representing a user
       @return boolean - true if adding was successfull, false if not
    */
    boolean addUserInfo(UserInfo userInfo) {
        return this.addUser(userInfo);
    }

    /**
       Push the state of the UserInfo object into the backing stosre
       (database).  New UserInfo objects (that have all non-null
       fields assigned) may use this method to create an entirely new
       UserInfo presence. <i> same exact method as addUserInfo </i>

       @param userInfo Object containing state of data representing a user
       @return boolean - true if adding was successfull, false if not
    */
    synchronized boolean addUser(UserInfo userInfo) {
        int userid = -1;
        int groupid = -1;
        int roleid = -1;
        int numRowsAffected = -1;
        try{
            log.trace("Inserting UserInfo associated with username: ["+userInfo.getUserName()+"], into database");

            if(userInfo.getOpenid() == null) {
                if(userInfo.getUserName() == null) return false;
                String openidHost = props.getProperty("esgf.host",getFQDN());
                String openidPort = props.getProperty("esgf.https.port","");
                if(openidPort.equals("") || openidPort.equals("443")) {
                    openidPort="";
                }else{
                    openidPort=":"+openidPort;
                }

                String openid = "https://"+openidHost+openidPort+"/esgf-idp/openid/"+userInfo.getUserName();
                log.debug("Constructing default openid: "+openid);
                userInfo.setOpenid(openid);
            }

            log.trace("Openid is ["+userInfo.getOpenid()+"]");
            
            //Check to see if there is an entry by this openid already....
            userid = queryRunner.query(hasUserOpenidQuery,idResultSetHandler,userInfo.getOpenid());
            
            //If there *is*... then UPDATE that record
            if(userid > 0) {
                log.trace("I HAVE A USERID: "+userid);
                assert (userid == userInfo.getid()) : "The database id ("+userid+") for this openid ("+userInfo.getOpenid()+") does NOT match this object's ("+userInfo.getid()+")";
                numRowsAffected = queryRunner.update(updateUserQuery,
                                                     userInfo.getOpenid(),
                                                     userInfo.getFirstName(),
                                                     userInfo.getMiddleName(),
                                                     userInfo.getLastName(),
                                                     userInfo.getUserName(),
                                                     userInfo.getEmail(),
                                                     userInfo.getDn(),
                                                     userInfo.getOrganization(),
                                                     userInfo.getOrgType(),
                                                     userInfo.getCity(),
                                                     userInfo.getState(),
                                                     userInfo.getCountry(),
                                                     userInfo.getStatusCode(),
                                                     userid
                                                     );

                log.trace("SUBMITTING PERMISSIONS (update):");
                if(userInfo.getPermissions() != null) {
                    for(String groupName : userInfo.getPermissions().keySet()) {
                        for(String roleName : userInfo.getPermissions().get(groupName)) {
                            addPermission(userid,groupName,roleName);
                        }
                    }
                }    
                
                return (numRowsAffected > 0);
            }
            
            //If this user does not exist in the database then add (INSERT) a new one
            log.trace("Whole new user: "+userInfo.getUserName());
            userid = queryRunner.query(getNextUserPrimaryKeyValQuery ,idResultSetHandler);
            log.trace("New ID to be assigned: "+userid);
            
            numRowsAffected = queryRunner.update(addUserQuery,
                                                 userid,
                                                 userInfo.getOpenid(),
                                                 userInfo.getFirstName(),
                                                 userInfo.getMiddleName(),
                                                 userInfo.getLastName(),
                                                 userInfo.getUserName(),
                                                 userInfo.getEmail(),
                                                 userInfo.getDn(),
                                                 userInfo.getOrganization(),
                                                 userInfo.getOrgType(),
                                                 userInfo.getCity(),
                                                 userInfo.getState(),
                                                 userInfo.getCountry(),
                                                 userInfo.getStatusCode()
                                                 );
            
            
            //A bit of debugging and sanity checking...
            userInfo.setid(userid);
            log.trace(userInfo);
            
            log.trace("SUBMITTING PERMISSIONS (new):");
            if(userInfo.getPermissions() != null) {
                for(String groupName : userInfo.getPermissions().keySet()) {
                    for(String roleName : userInfo.getPermissions().get(groupName)) {
                        addPermission(userid,groupName,roleName);
                    }
                }
            }
            
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }

    /**
       Removes user described by this UserInfo object. (same method as
       <code>deleteUser</code>)
       
       @param userInfo <i>valid</i> UserInfo object presenting the user you wish to remove.
       @return boolean - true if was able to successfully delete, false if not
     */
    boolean deleteUserInfo(UserInfo userInfo) {
        return this.deleteUser(userInfo);
    }

    /**
       Removes user described by this UserInfo object. (same method as
       <code>deleteUserInfo</code>)

       @param userInfo <i>valid</i> UserInfo object presenting the user you wish to remove.
       @return boolean - true if was able to successfully delete, false if not
     */
    boolean deleteUser(UserInfo userInfo) {
        if (userInfo == null) {
            log.trace("deleteUser("+userInfo+") bad parameter!!!");
            return false;
        }
        if(userInfo.getid() > 0) {
            return this.deleteUser(userInfo.getOpenid());
        }
        return false;
    }
    
    /**
       Removes user associated with the input openid. 
       
       @param openid The openid value associated with the user to be deleted.
       @return boolean - <i>true</i> if was able to successfully delete, <i>false</i> if not.
    */
    synchronized boolean deleteUser(String openid) {
        int numRowsAffected = -1;
        Matcher openidMatcher = openidUrlPattern.matcher(openid);
        if(openidMatcher.find()) {
            if(adminName.equals(openidMatcher.group(4))) {
                log.warn("WARNING: Not permitted to delete "+adminName);
                return false;
            }
        }else {
            log.warn("Sorry, this openid ["+openid+"] is in valid!! Malformed");
            return false;
        }
        
        try {
            log.trace("Deleting user with openid ["+openid+"] ");
            this.deleteAllUserPermissions(openid);
            numRowsAffected = queryRunner.update(delUserQuery,openid);
            if (numRowsAffected >0) log.trace("[OK]"); else log.trace("[FAIL]");            
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }
    

    //-------------------------------------------------------
    //Password Manipulations
    //-------------------------------------------------------

    //Sets the password value for a given user (openid)
    boolean setPassword(UserInfo userInfo, String newPassword) {
        if(!userInfo.isValid()) {
            log.warn("Cannot Set Password of an invalid user");
            return false;
        }
        return this.setPassword(userInfo.getOpenid(),newPassword);
    }
    
    synchronized boolean setPassword(String openid, String newPassword) {
        if((newPassword == null) || (newPassword.equals(""))) return false; //should throw and esgf exception here with meaningful message
        int numRowsAffected = -1;
        try{
            numRowsAffected = queryRunner.update(setPasswordQuery, encoder.encrypt(newPassword), openid);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }
    
    //Given a password, check to see if that password matches what is
    //in the database for this user (openid)
    public boolean checkPassword(UserInfo userInfo, String queryPassword) {
        if(!userInfo.isValid()) {
            log.warn("Cannot Check Password of an invalid user");            
            return false;
        }
        return this.checkPassword(userInfo.getOpenid(),queryPassword);   
    }
    public boolean checkPassword(String openid, String queryPassword) {
        boolean isMatch = false;
        try{
            String cryptPassword = queryRunner.query(getPasswordQuery, passwordQueryHandler, openid);
            if(cryptPassword == null) {
                log.error("PASSWORD RETURNED FROM DATABASE for ["+openid+"] IS: "+cryptPassword);
                return false;
            }
            isMatch = encoder.equals(queryPassword,cryptPassword);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return isMatch;
    }
    
    //Given the old password and the new password for a given user
    //(openid) update the password, only if the old password matches
    public synchronized boolean changePassword(UserInfo userInfo, String queryPassword, String newPassword) {
        if(!userInfo.isValid()) {
            log.warn("Cannot Change Password of an invalid user");
            return false;
        }
        return this.changePassword(userInfo.getOpenid(),queryPassword,newPassword);
    }
    public synchronized boolean changePassword(String openid, String queryPassword, String newPassword) {
        boolean isSuccessful = false;
        if(checkPassword(openid,queryPassword)){
            isSuccessful = setPassword(openid,newPassword);
        }
        return isSuccessful;
    }

    //-------------------------------------------------------
    //Account Status Manipulations
    //-------------------------------------------------------

    //Sets the status code value for a given user (openid)
    boolean setStatusCode(UserInfo userInfo, int newStatusCode) {
        if(!userInfo.isValid()) {
            log.warn("Cannot Set Status of an invalid user");
            return false;
        }
        return this.setStatusCode(userInfo.getOpenid(),newStatusCode);
    }
    synchronized boolean setStatusCode(String openid, int newStatusCode) {
        int numRowsAffected = -1;
        try{
            numRowsAffected = queryRunner.update(setStatusCodeQuery, newStatusCode, openid);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }

    //Given the old password and the new password for a given user
    //(openid) update the password, only if the old password matches
    public boolean changeStatus(UserInfo userInfo, int newStatusCode, String verificationToken) {
        if(!userInfo.isValid()) {
            log.warn("Cannot Change Status of an invalid user");
            return false;
        }
        return this.changeStatus(userInfo.getOpenid(),newStatusCode,verificationToken);
    }
    public synchronized boolean changeStatus(String openid, int newStatusCode, String verificationToken) {
        int numRowsAffected = -1;
        try {
            numRowsAffected = queryRunner.update(changeStatusQuery, newStatusCode, verificationToken, openid);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }
    String genVerificationToken(UserInfo userInfo) {
        return genVerificationToken(userInfo.getOpenid());
    }
    String genVerificationToken(String openid) {
        int numRowsAffected = -1;
        //zoiks make new token
        String verificationToken = java.util.UUID.randomUUID().toString();
        try {
            numRowsAffected = queryRunner.update(setVerificationTokenQuery, verificationToken, openid);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0) ? verificationToken : getVerificationToken(openid);
    }

    String getVerificationToken(UserInfo userInfo) {
        return this.getVerificationToken(userInfo.getOpenid());
    }
    String getVerificationToken(String openid) {
        String verificationToken = "null";
        try {
            verificationToken = queryRunner.query(getVerificationTokenQuery, singleStringResultSetHandler, openid);
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return verificationToken;
    }

    //-------------------------------------------------------
    //Permission Manipulations
    //-------------------------------------------------------

    synchronized boolean addPermission(UserInfo userInfo, String groupName, String roleName) {
        if(!userInfo.isValid()) { 
            //TODO: Throw an exception here
            log.error("Cannot addPermission on an invalid user ");
            return false; 
        }
        return this.addPermission(userInfo.getid(),groupName,roleName);
    }
    synchronized boolean addPermission(int userid, String groupName, String roleName) {
        int numRowsAffected = -1;
        try{

            log.trace("Adding Permission ("+userid+", "+groupName+", "+roleName+") ");
            if(!queryRunner.query(existsPermissionQuery, existsResultSetHandler, userid, groupName, roleName)) {
                numRowsAffected = queryRunner.update(addPermissionQuery, userid, groupName, roleName);
                if (numRowsAffected > 0) {
                    log.trace("[ADDED]"); 
                }else {
                    log.warn("Was not able to add permission ("+userid+",["+groupName+"],["+roleName+"]) to database, already EXISTS?? Possible intra database concurrency issue!!!");
                }
            }else {
                log.trace("[PERMISSION ALREADY EXISTS]");
            }
            
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }

    synchronized boolean deletePermission(UserInfo userInfo, String groupName, String roleName) {
        if(!userInfo.isValid()) { 
            //TODO: Throw an exception here
            log.error("Cannot deletePermission on an invalid user");
            return false; 
        }
        return this.deletePermission(userInfo.getid(),groupName,roleName);
    }
    synchronized boolean deletePermission(int userid, String groupName, String roleName) {
        int numRowsAffected = -1;
        try{
            log.trace("Deleting Permission ("+userid+", "+groupName+", "+roleName+") ");
            numRowsAffected = queryRunner.update(delPermissionQuery, userid, groupName, roleName);
            if (numRowsAffected >0) log.trace("[OK]"); else log.trace("[FAIL]");
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }

    boolean deleteAllUserPermissions(UserInfo userInfo) {
        return this.deleteAllUserPermissions(userInfo.getOpenid());
    }
    synchronized boolean deleteAllUserPermissions(String openid) {
        int numRowsAffected = -1;
        try{
            log.trace("Deleting All Permissions for openid = ["+openid+"] ");
            numRowsAffected = queryRunner.update(delAllUserPermissionsQuery, openid);
            if (numRowsAffected > 0) log.trace("[OK]"); else log.trace("[FAIL]");
            log.trace(numRowsAffected+" permission entries removed");
        }catch(SQLException ex) {
            log.error(ex);
            throw new ESGFDataAccessException(ex);
        }
        return (numRowsAffected > 0);
    }
    

    //-------------------------------------------------------
    //Users "Show" Query
    //-------------------------------------------------------

    //TODO: (zoiks) implement me
    //still need the query and then to call it.
    public List<String[]> getUserEntries() {
        try{
            log.trace("Fetching raw user data from database table");
            List<String[]> results = queryRunner.query(showUsersQuery, basicResultSetHandler);
            log.trace("Query is: "+showUsersQuery);
            assert (null != results);
            if(results != null) { log.info("Retrieved "+(results.size()-1)+" records"); }
            return results;
        }catch(SQLException ex) {
            log.error(ex);
        }catch(Throwable t) {
            log.error(t);
        }
        return new ArrayList<String[]>();
    }


    //------------------------------------
    public PasswordEncoder getEncoder() {
        return encoder;
    }
    
    public void setEncoder(PasswordEncoder encoder) {
        this.encoder = encoder;
    }
    
    //------------------------------------
    
    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append("DAO:["+this.getClass().getName()+"] - "+((dataSource == null) ? "[OK]" : "[INVALID]"));
        return out.toString();
    }
    
    
    //------------------------------------
    //Encapsulate the Initialization of Admin user
    //------------------------------------
    private final class InitAdmin {
        InitAdmin() { 
            log.info("Initializing rootAdmin");
            UserInfo rootAdmin = getUserById("rootAdmin");
            if (rootAdmin.isValid()) {
                rootAdmin.
                    setFirstName("Gert").
                    setMiddleName("B").
                    setLastName("Frobe").
                    setEmail(UserInfoDAO.this.props.getProperty("security.admin.email","rootAdmin@some-esg-node.org")).
                    setOrganization(UserInfoDAO.this.props.getProperty("security.admin.org","ESGF.org")).
                    setCity(UserInfoDAO.this.props.getProperty("security.admin.city","Brooklyn")).
                    setState(UserInfoDAO.this.props.getProperty("security.admin.state","NY")).
                    setCountry(UserInfoDAO.this.props.getProperty("security.admin.country","USA")).
                    setStatusCode(1).
                    addPermission("wheel","super");
                UserInfoDAO.this.addUserInfo(rootAdmin);
                UserInfoDAO.this.setPassword(rootAdmin,UserInfoDAO.this.props.getProperty("security.admin.password","esgrocks"));
            }
            log.info("rootAdmin: "+rootAdmin);
        }
    }
}
