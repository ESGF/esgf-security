/***************************************************************************
*                                                                          *
*  Organization: Lawrence Livermore National Lab (LLNL)                    *
*   Directorate: Computation                                               *
*    Department: Computing Applications and Research                       *
*      Division: S&T Global Security                                       *
*        Matrix: Atmospheric, Earth and Energy Division                    *
*       Program: PCMDI                                                     *
*       Project: Earth Systems Grid Federation (ESGF) Data Node Software   *
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
*   Earth System Grid Federation (ESGF) Data Node Software Stack           *
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
package esg.node.security.shell.cmds;

/**
   Description:
   ESGF's "realize" command..."

   This command takes a dataset directory and inspects its catalog to
   find missing files (files listed in the dataset catalog but not
   locally present on the filesystem) and brings them local. The
   second half of the 'replication' process - for a single dataset.
**/

import esg.common.util.*;
import esg.common.shell.*;
import esg.common.shell.cmds.*;

import esg.node.security.*;

import org.apache.commons.cli.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

public class ESGFassociate extends ESGFSecurityCommand {

private static Log log = LogFactory.getLog(ESGFassociate.class);

    public ESGFassociate() { super(); }

    public void init(ESGFEnv env) { checkPermission(env); }
    public String getCommandName() { return "associate"; }

    public void doInitOptions() {
        getOptions().addOption("i", "prompt", false, "request confirmation before making associations");

        Option username = 
            OptionBuilder.withArgName("username")
            .hasArg(true)
            .withDescription("user name you wish to associate")
            .withLongOpt("username")
            //.isRequired(true)
            .create("u");
        getOptions().addOption(username);

        Option groupname = 
            OptionBuilder.withArgName("groupname")
            .hasArg(true)
            .withDescription("group name you wish to associate")
            .withLongOpt("groupname")
            //.isRequired(true)
            .create("g");
        getOptions().addOption(groupname);

        Option rolename = 
            OptionBuilder.withArgName("rolename")
            .hasArg(true)
            .withDescription("role name you wish to associate")
            .withLongOpt("rolename")
            .create("r");
        getOptions().addOption(rolename);

        Option removeAll = new Option("remove-all", false, "removes all group and roles associated with user");
        Option remove    = new Option("remove", false, "removes the specified group and role from specified user");
        OptionGroup removeGroup = new OptionGroup();
        removeGroup.addOption(removeAll);
        removeGroup.addOption(remove);
        getOptions().addOptionGroup(removeGroup);

    }
    
    public ESGFEnv doEval(CommandLine line, ESGFEnv env) {
        log.trace("inside the \"associate\" command's doEval");
        boolean prompt = line.hasOption( "i" );
        
        boolean removeAllPermissions = line.hasOption( "remove-all" );
        if(removeAllPermissions && prompt) {
            env.getWriter().println("remove-all: ["+removeAllPermissions+"]");
            env.getWriter().flush();
        }

        boolean removePermission = line.hasOption( "remove" );
        if(removePermission && prompt) {
            env.getWriter().println("remove: ["+removePermission+"]");
            env.getWriter().flush();
        }

        String username = null;
        if(line.hasOption( "u" )) {
            username = line.getOptionValue( "u" );
            if(prompt) {
                env.getWriter().println("username: ["+username+"]");
                env.getWriter().flush();
            }
        }

        String groupname = null;
        if(line.hasOption( "g" )) {
            groupname = line.getOptionValue( "g" );
            if(prompt){
                env.getWriter().println("groupname: ["+groupname+"]");
                env.getWriter().flush();
            }
        }

        String rolename = "default";
        if(line.hasOption( "r" )) {
            rolename = line.getOptionValue( "r" );
            if(prompt) {
                env.getWriter().println("rolename: ["+rolename+"]");
                env.getWriter().flush();
            }
        }

        //paranoia check :-)
        if ((null == username) || (null == groupname) || (null == rolename)) {
            throw new esg.common.ESGRuntimeException("User (-u) and group (-g) fields are required [role's (-r) value defaults to \"default\"], see --help");
        }
        
        if( removePermission && !line.hasOption("r") ) {
            throw new esg.common.ESGRuntimeException("Role (-r) must be explicitly specified when removing association");
        }
        
        
        //------------------
        //NOW DO SOME LOGIC
        //------------------

        if(prompt || removePermission || removeAllPermissions) {
            try{
                String answer = env.getReader().readLine("Is this information correct and ready to be submitted? [Y/n] > ");
                if(!answer.equals("") && !answer.equalsIgnoreCase("y")) {
                    return env;
                }
            }catch(java.io.IOException e) { System.err.println(e.getMessage()); }
        }

        //------------------
        //Check access privs and setup resource object
        //------------------

        UserInfoCredentialedDAO userDAO = null;
        if (!(userDAO = getUserDAO(env)).checkCredentials()) {
            userDAO = null;
            throw new ESGFCommandPermissionException("Credentials are not sufficient, sorry...");
        }
        //------------------

        UserInfo user = null;
        if(username != null) user = userDAO.getUserById(username);

        if(null == user) {
            throw new esg.common.ESGRuntimeException("Sorry, the username ["+username+"] was not well formed");            
        }
        
        if(user.isValid()) {
         
            if(removePermission) {
                //Deleting specified groupo and role from user
                if(user.getUserName().equals("rootAdmin") && rolename.equals("admin")) {
                    throw new esg.common.ESGRuntimeException("Sorry, cannot remove the role ["+rolename+"] from ["+username+"]");
                }
                if(userDAO.deletePermission(user,groupname,rolename)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{
                    log.info("[FAIL]");                     
                }
            }else if(removeAllPermissions) {
                //Deleting ALL permissions for a user
                if(user.getUserName().equals("rootAdmin")) {
                    throw new esg.common.ESGRuntimeException("Sorry, this operationis not permitted for user ["+username+"]");
                }
                if(userDAO.deleteAllUserPermissions(user)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{
                    log.info("[FAIL]"); 
                }
            }else{
                //Adding permission / attribute tuple to database
                if(userDAO.addPermission(user,groupname,rolename)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{ 
                    log.info("[FAIL]"); 
                }
            }
            removePermission=false;
            removeAllPermissions=false;
            
        }else {
            throw new esg.common.ESGRuntimeException("The user you specified ["+username+"] is invalid");
        }

        env.getWriter().flush();

        //------------------
        return env;
    }
}
