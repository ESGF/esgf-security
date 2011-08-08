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
        getOptions().addOption("n", "no_prompt", false, "suppress request confirmation before making associations");

        Option username = 
            OptionBuilder.withArgName("username")
            .hasArg(true)
            .withDescription("user name you wish to associate")
            .withLongOpt("username")
            .isRequired(true)
            .create("u");
        getOptions().addOption(username);

        Option groupname = 
            OptionBuilder.withArgName("groupname")
            .hasArg(true)
            .withDescription("group name you wish to associate")
            .withLongOpt("groupname")
            .isRequired(false)
            .create("g");
        getOptions().addOption(groupname);

        Option rolename = 
            OptionBuilder.withArgName("rolename")
            .hasArg(true)
            .withDescription("role name you wish to associate")
            .withLongOpt("rolename")
            .isRequired(false)
            .create("r");
        getOptions().addOption(rolename);

        Option add = new Option("add", false, "creates a permission entry from the given (user,group,role) tuple");
        Option remove    = new Option("remove", false, "removes the specified group and role from specified user");
        Option removeGroupFromUser  = new Option("remove_group_from_user", false, "removes the specified group from specified user");
        Option removeRoleFromUser   = new Option("remove_role_from_user",  false, "removes the specified role from specified user");
        Option removeAll = new Option("remove_all", false, "removes all group and roles associated with user");
        
        OptionGroup directiveOptionGroup = new OptionGroup();
        directiveOptionGroup.addOption(add);
        directiveOptionGroup.addOption(remove);
        directiveOptionGroup.addOption(removeGroupFromUser);
        directiveOptionGroup.addOption(removeRoleFromUser);
        directiveOptionGroup.addOption(removeAll);
        getOptions().addOptionGroup(directiveOptionGroup);
    }
    
    public ESGFEnv doEval(CommandLine line, ESGFEnv env) {
        log.trace("inside the \"associate\" command's doEval");
        boolean noPrompt = line.hasOption( "n" );

        String username = null;
        if(line.hasOption( "u" )) {
            username = line.getOptionValue( "u" );
            if(!noPrompt) {
                env.getWriter().println("username: ["+username+"]");
                env.getWriter().flush();
            }
        }

        String groupname = null;
        if(line.hasOption( "g" )) {
            groupname = line.getOptionValue( "g" );
            if(!noPrompt){
                env.getWriter().println("groupname: ["+groupname+"]");
                env.getWriter().flush();
            }
        }

        String rolename = null;
        if(line.hasOption( "r" )) {
            rolename = line.getOptionValue( "r" );
            if(!noPrompt) {
                env.getWriter().println("rolename: ["+rolename+"]");
                env.getWriter().flush();
            }
        }

        boolean addPermission = false;
        addPermission = line.hasOption( "add" );
        if(addPermission && !noPrompt) {
            env.getWriter().println("add: ["+addPermission+"]");
            env.getWriter().flush();
        }

        boolean removePermission = false;
        removePermission = line.hasOption( "remove" );
        if(removePermission && !noPrompt) {
            env.getWriter().println("remove: ["+removePermission+"]");
            env.getWriter().flush();
        }

        boolean removeGroupFromUserPermissions = false;
        removeGroupFromUserPermissions = line.hasOption( "remove_group_from_user" );
        if(removeGroupFromUserPermissions && !noPrompt) {
            env.getWriter().println("remove: ["+removeGroupFromUserPermissions+"]");
            env.getWriter().flush();
        }

        boolean removeRoleFromUserPermissions = false;
        removeRoleFromUserPermissions = line.hasOption( "remove_role_from_user" );
        if(removeRoleFromUserPermissions && !noPrompt) {
            env.getWriter().println("remove: ["+removeRoleFromUserPermissions+"]");
            env.getWriter().flush();
        }

        boolean removeAllPermissions = false;
        removeAllPermissions = line.hasOption( "remove_all" );
        if(removeAllPermissions && !noPrompt) {
            env.getWriter().println("remove-all: ["+removeAllPermissions+"]");
            env.getWriter().flush();
        }
        
        
        //------------------
        //NOW DO SOME LOGIC
        //------------------

        if(!noPrompt) {
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
            if(addPermission) {
                //Adding permission / attribute tuple to database
                if((username == null ) || (groupname == null ) || (rolename == null)) {
                    if(username==null) env.getWriter().println("username required");
                    if(groupname==null) env.getWriter().println("groupname required");
                    if(rolename==null) env.getWriter().println("rolename required");
                    throw new esg.common.ESGRuntimeException("Sorry, cannot issue operation: check args (see --help)");
                }
                if(userDAO.addPermission(user,groupname,rolename)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{ 
                    log.info("[FAIL]"); 
                }
            } else if(removePermission) {
                //Deleting specified groupo and role from user
                if((username == null ) || (groupname == null ) || (rolename == null)) {
                    if(username==null) env.getWriter().println("username required");
                    if(groupname==null) env.getWriter().println("groupname required");
                    if(rolename==null) env.getWriter().println("rolename required");
                    throw new esg.common.ESGRuntimeException("Sorry, cannot issue operation: check args (see --help)");
                }
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
            } else if(removeGroupFromUserPermissions) {
                //Deleting specified groupo and role from user
                if((username == null ) || (groupname == null )) {
                    if(username==null) env.getWriter().println("username required");
                    if(groupname==null) env.getWriter().println("groupname required");
                    throw new esg.common.ESGRuntimeException("Sorry, cannot issue operation: check args (see --help)");
                }
                if(user.getUserName().equals("rootAdmin") && groupname.equals("wheel")) {
                    throw new esg.common.ESGRuntimeException("Sorry, cannot remove the role ["+rolename+"] from ["+username+"]");
                }
                if(userDAO.deleteGroupFromUserPermissions(user,groupname)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{
                    log.info("[FAIL]");                     
                }
            } else if(removeRoleFromUserPermissions) {
                //Deleting specified groupo and role from user
                if((username == null ) || (rolename == null) ) {
                    if(username==null) env.getWriter().println("username required");
                    if(rolename==null) env.getWriter().println("rolename required");
                    throw new esg.common.ESGRuntimeException("Sorry, cannot issue operation: check args (see --help)");
                }
                if(user.getUserName().equals("rootAdmin") && rolename.equals("admin")) {
                    throw new esg.common.ESGRuntimeException("Sorry, cannot remove the role ["+rolename+"] from ["+username+"]");
                }
                if(userDAO.deleteRoleFromUserPermissions(user,rolename)) {
                    log.info("[OK]");
                    user = userDAO.refresh(user);
                    env.getWriter().println(user);
                }else{
                    log.info("[FAIL]");
                }
            }else if(removeAllPermissions) {
                //Deleting ALL permissions for a user
                if(username == null ) {
                    if(username==null) env.getWriter().println("username required");
                    throw new esg.common.ESGRuntimeException("Sorry, cannot issue operation: check args (see --help)");
                }
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
            }else {
                env.getWriter().println("Must supply a directive for this command.  See --help");
            }
        }else {
            throw new esg.common.ESGRuntimeException("The user you specified ["+username+"] is invalid");
        }
        
        addPermission = false;
        removePermission = false;
        removeGroupFromUserPermissions = false;
        removeRoleFromUserPermissions = false;
        removeAllPermissions = false;
        
        env.getWriter().flush();

        //------------------
        return env;
    }
}
