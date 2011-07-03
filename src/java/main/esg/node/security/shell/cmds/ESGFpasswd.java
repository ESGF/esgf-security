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

import esg.common.shell.*;
import esg.common.shell.cmds.*;
import esg.node.security.*;

import org.apache.commons.cli.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

public class ESGFpasswd extends ESGFSecurityCommand {

private static Log log = LogFactory.getLog(ESGFpasswd.class);

    public ESGFpasswd() { super();}

    public void init(ESGFEnv env) { checkPermission(env); }
    public String getCommandName() { return "passwd"; }

    public void doInitOptions() {
        getOptions().addOption("i", "prompt", false, "request confirmation before performing action");
        getOptions().addOption("d", "disable", false, "disable this account");
        
        Option user = 
            OptionBuilder.withArgName("user")
            .hasArg(true)
            .withDescription("User for which you wish to change password")
            .withLongOpt("user")
            .create("u");
        getOptions().addOption(user);
        
    }
    
    public ESGFEnv doEval(CommandLine line, ESGFEnv env) {
        log.trace("inside the \"passwd\" command's doEval");
        //TODO: Query for options and perform execution logic
        
        boolean prompt = line.hasOption( "i" );
        boolean disable = line.hasOption( "d" );
        
        String whoami = (String)env.getContext(ESGFEnv.SYS,"user.name");
        String username = null;
        if(line.hasOption( "u" )) {
            username = line.getOptionValue( "u" );
            if(prompt) env.getWriter().println("username: ["+username+"]");
        }
        
        int i=0;
        for(String arg : line.getArgs()) {
            log.info("arg("+(i++)+"): "+arg);
        }
        
        //Scrubbing... (need to go into cli code and toss in some regex's to clean this type of shit up)
        java.util.List<String> argsList = new java.util.ArrayList<String>();
        String[] args = null;
        for(String arg : line.getArgs()) {
            if(!arg.isEmpty()) {
                argsList.add(arg);
            }
        }
        args = argsList.toArray(new String[]{});

        if(disable || prompt) { 
            env.getWriter().println("disable: ["+disable+"]");
        }
        
        String origPassword = null;
        String newPassword = null;
        if(args.length <= 0) {
            throw new esg.common.ESGRuntimeException("Sorry, no arguements present, see --help");                        
        }
        if(args.length == 1) {
            newPassword = args[0];
            if(prompt) env.getWriter().println("*new password: ["+((newPassword != null) ? "*********" : newPassword)+"]");
        }
        if(args.length == 2) {
            origPassword = args[0];
            newPassword = args[1];
            if(prompt) env.getWriter().println("orig password: ["+((origPassword != null) ? "*********" : newPassword)+"]");
            if(prompt) env.getWriter().println("new password: ["+((newPassword != null) ? "*********" : newPassword)+"]");
        }
        
        //------------------
        //NOW DO SOME LOGIC
        //------------------
        
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
        
            if((origPassword == null) && (newPassword != null) && 
               (user.getUserName().equals(whoami)) ) {
                if(userDAO.setPassword(user.getOpenid(),newPassword)) {
                    env.getWriter().println("password updated :-)");
                }else {
                    throw new esg.common.ESGRuntimeException("Sorry, could not update your password");            
                }
            }
        
            if(user.getUserName().equals("rootAdmin")) {
                if(userDAO.setPassword(user.getOpenid(),newPassword)) {
                    env.getWriter().println("password updated for ["+user.getUserName()+"] :-)");
                    env.getWriter().flush();
                }else {
                    throw new esg.common.ESGRuntimeException("Sorry, could not update password for ["+user.getUserName()+"]");            
                }
            }else {
                userDAO.changePassword(user.getOpenid(),origPassword,newPassword);
            }
            
        }else {
            throw new esg.common.ESGRuntimeException("The user you specified ["+username+"] is invalid");
        }

        env.getWriter().flush();


        //------------------
        return env;
    }
}
