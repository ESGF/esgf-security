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
*   Earth System Grid Federation (ESGF)                                    *
*   Data Node Software Stack, Version 1.0                                  *
*                                                                          *
*   For details, see http://esgf.org/esg-node-site/                        *
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
package esg.node.util.migrate;

import java.io.*;
import java.util.*;

import java.util.Properties;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.PoolingDataSource;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.ResultSetHandler;

import esg.node.security.*;
import esg.common.util.ESGFProperties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

/**
   Description:
   A tool for migrating user accounts from the "gateway" to the "idp" node

*/
public final class UserMigrationTool {

    private static Log log = LogFactory.getLog(UserMigrationTool.class);

    //For source database access...
    private PoolingDataSource sourceDataSource = null;
    private GenericObjectPool connectionPool = null;
    private QueryRunner queryRunner = null;


    //For target (local) database access...
    private UserInfo userInfo = null;
    private UserInfoCredentialedDAO userDAO = null;
    private GroupRoleDAO groupRoleDAO = null;

    //-------------------------------------------------------
    //Remote "Gateway" queries
    //-------------------------------------------------------
    private static final String sourceUserInfoQuery = "select firstname, lastname, email, username, password, dn, organization, city, state, country from security.user where username!=''";
    private static final String sourceGroupInfoQuery = "select g.name as name, g.description as description, g.visible as visible, g.automatic_approval as automatic_approval from security.group as g";
    private static final String sourceRoleInfoQuery = "select name, description from security.role";
    private static final String sourcePermissionInfoQuery = "select u.username as uname, g.name as gname, r.name as rname from security.user as u, security.group as g, security.role as r, security.membership as m, security.status as st where u.username not in ('', 'rootAdmin') and m.user_id=u.id and m.group_id=g.id and m.role_id=r.id and m.status_id=st.id and st.name='valid'";
    //-------------------------------------------------------

    public UserMigrationTool() { }

    //ToDo: should throw exception here
    public UserMigrationTool init(Properties props) {
        log.trace("props = "+props);
        if(setupTargetResources()) setupSourceResources(props);
        return this;
    }

    //-------------------------------------------------------
    //Remote "Gateway" resouce setup...
    //-------------------------------------------------------
    public UserMigrationTool setupSourceResources(Properties props) {

        log.info("Setting up source data source ");
        if(props == null) { log.error("Property object is ["+props+"]: Cannot setup up data source"); return this; }
        String user = props.getProperty("db.user","dbsuper");
        String password = props.getProperty("db.password");

        //Ex: jdbc:postgresql://pcmdi3.llnl.gov:5432/esgcet
        String database = props.getProperty("db.database","gateway-esg");
        String host = props.getProperty("db.host","localhost");
        String port = props.getProperty("db.port","5432"); //or perhaps 8080
        String protocol = props.getProperty("db.protocol","jdbc:postgresql:");

        return this.setupSourceResources(protocol,host,port,database,user,password);

    }

    public UserMigrationTool setupSourceResources(String protocol,
                                                  String host,
                                                  String port,
                                                  String database,
                                                  String user,
                                                  String password) {

        System.out.println("Setting up source resources...");

        String connectURI = protocol+"//"+host+":"+port+"/"+database; //zoiks
        log.debug("Source Connection URI  = "+connectURI);
        log.debug("Source Connection User = "+user);
        log.debug("Source Connection Password = "+(null == password ? password : "********"));
        this.connectionPool = new GenericObjectPool(null);
        ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(connectURI,user,password);
        PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory,connectionPool,null,null,false,true);
        this.sourceDataSource = new PoolingDataSource(connectionPool);
        this.queryRunner = new QueryRunner(sourceDataSource);
        return this;
    }

    //-------------------------------------------------------
    //Target (local) resource setup...
    //-------------------------------------------------------
    private boolean setupTargetResources() { return this.setupTargetResources(null,null); }

    private boolean setupTargetResources(UserInfoCredentialedDAO userDAO_, GroupRoleDAO groupRoleDAO_) {

        System.out.println("Setting up target (local) resources...");

        try{
            ESGFProperties env = new ESGFProperties();
            if(userDAO_ == null) {
                log.trace("need to instantiate user data object...");
                this.userDAO = new UserInfoCredentialedDAO("rootAdmin",
                                                           env.getAdminPassword(),
                                                           env);
            }else {
                this.userDAO = userDAO;
            }
            log.trace("userDAO = "+(userDAO == null ? "[NULL]" : "[OK]"));

            if(groupRoleDAO_ == null) {
                log.trace("need to instantiate group/role data object...");
                this.groupRoleDAO = new GroupRoleDAO(env);
            }else {
                log.trace("re-using previously instantiated group/role data object");
                this.groupRoleDAO = groupRoleDAO_;
            }
            log.trace("group/role = "+(groupRoleDAO == null ? "[NULL]" : "[OK]"));

        }catch(java.io.IOException e) { e.printStackTrace(); }

        return ((null != this.userDAO) && (null != this.groupRoleDAO));
    }

    public void shutdownSourceResources() {
        log.info("Shutting Down Source Database Resource...");
        try{
            connectionPool.close();
        }catch(Exception ex) {
            log.error("Problem with closing connection Pool!",ex);
        }
        sourceDataSource = null;
    }


    //-------------------------------------------------------
    //Pump the data from source --to-> target
    //-------------------------------------------------------

    public int migrate() {
        migrateRoles();
        migrateGroups();
        migrateUsers();
        migratePermissions();
        return 0;
    }

    public int migrateRoles() {
        int ret = 0;
        ResultSetHandler<Integer> rolesResultSetHandler = new ResultSetHandler<Integer>() {
            public Integer handle(ResultSet rs) throws SQLException{
                int i=0;
                while(rs.next()) {
                    //                                              [name]         [description]
                    if(UserMigrationTool.this.groupRoleDAO.addRole(rs.getString(1),rs.getString(2))) {
                        i++;
                        System.out.println("Migrated role #"+i+": "+rs.getString(1));
                    }
                }
                return i;
            }
        };

        try {
            ret = queryRunner.query(sourceRoleInfoQuery, rolesResultSetHandler);
            log.info("Migrated ["+ret+"] role records");
        }catch(SQLException e) {
            e.printStackTrace();
        }

        return ret;
    }

    public int migrateGroups() {
        int ret = 0;
        ResultSetHandler<Integer> groupsResultSetHandler = new ResultSetHandler<Integer>() {
            public Integer handle(ResultSet rs) throws SQLException{
                int i=0;
                while(rs.next()) {
                    //                                               [name]         [description]    [visible]         [automatic_approval]
                    if(UserMigrationTool.this.groupRoleDAO.addGroup(rs.getString(1),rs.getString(2), rs.getBoolean(3), rs.getBoolean(4))) {
                        i++;
                        System.out.println("Migrated group #"+i+": "+rs.getString(1));
                    }
                }
                return i;
            }
        };

        try {
            ret = queryRunner.query(sourceGroupInfoQuery, groupsResultSetHandler);
            log.info("Migrated ["+ret+"] group records");
        }catch(SQLException e) {
            e.printStackTrace();
        }

        return ret;
    }

    public int migrateUsers() {
        int ret  = 0;
        ResultSetHandler<Integer> usersResultSetHandler = new ResultSetHandler<Integer>() {
            public Integer handle(ResultSet rs) throws SQLException{
                int i=0;
                int errorCount=0;
                String currentUsername=null;
                while(rs.next()) {
                    try{
                        currentUsername = rs.getString("username");
                        if(currentUsername.equals("rootAdmin")) {
                            System.out.println("NOTE: Will not overwrite local rootAdmin information");
                            continue;
                        }
                        log.trace("Inspecting username: "+currentUsername);
                        UserInfo userInfo = UserMigrationTool.this.userDAO.getUserById(currentUsername);
                        userInfo.setFirstName(rs.getString("firstname")).
                            //setMiddleName(rs.getString("middlename")).
                            setLastName(rs.getString("lastname")).
                            setEmail(rs.getString("email")).
                            setUserName(rs.getString("username")).
                            setDn(rs.getString("dn")).
                            setOrganization(rs.getString("organization")).
                            //setOrgType(rs.getString("organization_type")).
                            setCity(rs.getString("city")).
                            setState(rs.getString("state")).
                            setCountry(rs.getString("country"));
                        //NOTE: verification token not applicable
                        //Status code msut be set separately... (below) field #13
                        //Password literal must be set separately... (see setPassword - with true boolean, below) field #14

                        UserMigrationTool.this.userDAO.addUser(userInfo);
                        //UserMigrationTool.this.userDAO.setStatusCode(userInfo.getOpenid(),rs.getInt(13)); //statusCode
                        UserMigrationTool.this.userDAO.setPassword(userInfo.getOpenid(),rs.getString("password"),true); //password (literal)
                        i++;
                        System.out.println("Migrated User #"+i+": "+userInfo.getUserName()+" --> "+userInfo.getOpenid());
                    }catch(Throwable t) {
                        log.error("Sorry, could NOT migrate user: "+currentUsername);
                        errorCount++;
                    }
                }
                log.info("Inspected "+i+" User Records, with "+errorCount+" failed");
                return i;
            }
        };

        try {
            ret = queryRunner.query(sourceUserInfoQuery, usersResultSetHandler);
            log.info("Migrated ["+ret+"] user records");
        }catch(SQLException e) {
            e.printStackTrace();
        }
        return ret;

    }

    public int migratePermissions() {
        int ret = 0;
        ResultSetHandler<Integer> permissionsResultSetHandler = new ResultSetHandler<Integer>() {
            public Integer handle(ResultSet rs) throws SQLException{
                int i=0;
                String uname=null;
                String gname=null;
                String rname=null;
                while(rs.next()) {
                    try{
                        uname=rs.getString(1);
                        gname=rs.getString(2);
                        rname=rs.getString(3);
                        log.trace("Migrating permission tuple: u["+uname+"] g["+gname+"] r["+rname+"] ");
                        if(UserMigrationTool.this.userDAO.addPermission(uname,gname,rname)) {
                            i++;
                            System.out.println("Migrated Permission #"+i+": ["+rs.getString(1)+"] ["+rs.getString(2)+"] ["+rs.getString(3)+"]");
                        }
                    }catch(ESGFDataAccessException e) {
                        log.error("Sorry, could NOT create permission tuple: u["+uname+"] g["+gname+"] r["+rname+"] ");
                    }
                }
                return i;
            }
        };

        try{
            ret = queryRunner.query(sourcePermissionInfoQuery, permissionsResultSetHandler);
            log.info("Migrated ["+ret+"] permission records");
        }catch(SQLException e) {
            e.printStackTrace();
        }
        return ret;
    }

    //-------------------------------------------------------
    //Main
    //-------------------------------------------------------
    public static void main(String[] args) {
        try {
            //Enter the connection URI information
            //setup source connection
            Properties props = new Properties();
            if(args.length >= 4) {
                for(int i=0;i<(args.length-1);i++) {
                    System.out.println();
                    if("-U".equals(args[i])) {
                        i++;
                        System.out.print("user = ");
                        if(args[i].startsWith("-")) { --i; continue; }
                        props.setProperty("db.user",args[i]);
                        System.out.print(args[i]);
                        continue;
                    }
                    if("-h".equals(args[i])) {
                        i++;
                        System.out.print("host = ");
                        if(args[i].startsWith("-")) { --i; continue; }
                        props.setProperty("db.host",args[i]);
                        System.out.print(args[i]);
                        continue;
                    }
                    if("-p".equals(args[i])) {
                        i++;
                        System.out.print("port = ");
                        if(args[i].startsWith("-")) { --i; continue; }
                        props.setProperty("db.port",args[i]);
                        System.out.print(args[i]);
                        continue;
                    }
                    if("-d".equals(args[i])) {
                        i++;
                        System.out.print("database = ");
                        if(args[i].startsWith("-")) { --i; continue; }
                        props.setProperty("db.database",args[i]);
                        System.out.print(args[i]);
                        continue;
                    }
                }
                System.out.println();
            }else {
                System.out.println("\nUsage:");
                System.out.println("  java -jar esgf-security-user-migration-x.x.x.jar -U <username> -h <host> -p <port> -d <database>");
                System.out.println("  (hit return and then enter your password)\n");
                System.exit(1);
            }

            char password[] = null;
            try {
                password = PasswordField.getPassword(System.in, "Enter source database password: ");
            }catch(IOException ioe) {
                System.err.println("Ooops sumthin' ain't right with the input... :-(");
                System.exit(1);
                ioe.printStackTrace();
            }
            if(password == null ) {
                System.out.println("No password entered");
                System.exit(1);
            }

            props.setProperty("db.password",String.valueOf(password));

            System.out.println();

            (new UserMigrationTool()).init(props).migrate();

        }catch(Throwable t) {
            System.out.println(t.getMessage());
            System.out.println("\n Sorry, please check your database connection information again, was not able to migrate users :-(\n");
            System.exit(1);
        }

        System.out.println("\ndone :-)\n");
        System.out.println(" Thank you for migrating to the ESGF P2P Node");
        System.out.println(" http://esgf.org\n");
    }

}
