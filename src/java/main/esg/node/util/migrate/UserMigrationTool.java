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
package esg.idp.util.migrate;

import esg.common.db.DatabaseResource;

import java.util.Properties;
import javax.sql.DataSource;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.commons.dbcp.ConnectionFactory;
import org.apache.commons.dbcp.PoolingDataSource;
import org.apache.commons.dbcp.PoolableConnectionFactory;
import org.apache.commons.dbcp.DriverManagerConnectionFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

/**
   Description:
   A tool for migrating user accounts from the "gateway" to the "idp" node

*/
public class UserMigrationTool {

    private static Log log = LogFactory.getLog(UserMigrationTool.class);
    
    private PoolingDataSource sourceDataSource = null;

    //for source database access...
    private DatabaseResource sourceDbResource = null;
    private UserInfo userInfo = null;
    private UserInfoCredentialedDAO userDAO = null;
    private GroupRoleDAO groupRoleDAO = null;
    
    public UserMigrationTool() { }
    
    public UserMigrationTool init(Properties props) {
        setupTargetResources();
        setupSourceResources(props);
        return this;
    }

    //-------------------------------------------------------
    //Remote "Gateway" resouce setup...
    //-------------------------------------------------------
    private void setupSourceResources(Properties props) {
        
        log.trace("Setting up source data source ");
        if(props == null) { log.error("Property object is ["+props+"]: Cannot setup up data source"); return this; }
        //Ex: jdbc:postgresql://pcmdi3.llnl.gov:5432/esgcet
        String protocol = props.getProperty("db.protocol","jdbc:postgresql:");
        String host = props.getProperty("db.host","localhost");
        String port = props.getProperty("db.port","5432");
        String database = props.getProperty("db.database","esgcet");
        String user = props.getProperty("db.user","dbsuper");
        String password = props.getProperty("db.password");
        
        String connectURI = protocol+"//"+host+":"+port+"/"+database; //zoiks
        log.debug("Connection URI = "+connectURI);
        connectionPool = new GenericObjectPool(null);
        ConnectionFactory connectionFactory = new DriverManagerConnectionFactory(connectURI,user,password);
        PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory,connectionPool,null,null,false,true);
        sourceDataSource = new PoolingDataSource(connectionPool);
        
    }

    //-------------------------------------------------------
    //Target (local) resource setup...
    //-------------------------------------------------------
    private boolean setupTargetResources() {
        return this.setupTargetResources(null,null);
    }
    private boolean setupTargetResource(UserDAO userDAO, GroupRoleDAO groupRoleDAO) {
        ESGFProperties env = new ESGFProperties();
        if(userDAO == null) {
            this.userDAO = new UserInfoCredentialedDAO("rootAdmin",
                                                       env.getAdminPassword(),
                                                       env);
        }else {
            this.userDAO = userDAO;
        }
        
        if(groupRoleDAO == null) {
            groupRoleDAO = new GroupRoleDAO(env.getEnv());
        }else {
            this.groupRoleDAO = groupRoleDAO;
        }

        return ((null != userDAO) && (null != groupRoleDAO));
    }

    public void shutdownSourceResources() {
        log.info("Shutting Down Source Database Resource! ("+driverName+")");
        try{
            connectionPool.close();
        }catch(Exception ex) {
            log.error("Problem with closing connection Pool!",ex);
        }
        sourceDataSource = null;        
    }
    
    //Pump the data from source --to-> target
    public int migrate() {
        
    }

    //-------------------------------------------------------
    //Main
    //-------------------------------------------------------
    public static void main(String[] args) {
        //Enter the connection URI information
        //setup source connection
        UserMigrationTool umt = new UserMigrationTool();
        umt.init(Properties dbProperties);
        umt.migrate();
    }
    
}