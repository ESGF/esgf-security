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

import java.util.List;

import esg.node.security.*;

import esg.common.shell.*;
import esg.common.shell.cmds.*;

import org.apache.commons.cli.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

public class ESGFshow extends ESGFCommand {

private static Log log = LogFactory.getLog(ESGFshow.class);

    public ESGFshow() { super(); }

    public String getCommandName() { return "show"; }

    public void doInitOptions() {

        getOptions().addOption("v", "verbose", false, "show more verbose output");
        getOptions().addOption("d",  "details",    false, "show details");
        getOptions().addOption("all",    false, "show all details");

        getOptions().addOption("au", "all-users",  false, "show all users on the system");
        getOptions().addOption("ag", "all-groups", false, "show all groups on the system");
        getOptions().addOption("ar", "all-roles", false,  "show all roles on the system");
        
        Option user = 
            OptionBuilder.withArgName("user")
            .hasArg(true)
            .withDescription("User to inspect")
            .withLongOpt("user")
            .create("u");
        getOptions().addOption(user);
        
        Option group = 
            OptionBuilder.withArgName("group")
            .hasArg(true)
            .withDescription("Group to inspect")
            .withLongOpt("group")
            .create("g");
        getOptions().addOption(group);
        
        Option role =
            OptionBuilder.withArgName("role")
            .hasArg(true)
            .withDescription("Group to inspect")
            .withLongOpt("role")
            .create("r");
        getOptions().addOption(role);
        
    }
    
    public ESGFEnv doEval(CommandLine line, ESGFEnv env) {
        log.trace("inside the \"show\" command's doEval");
        //TODO: Query for options and perform execution logic

        boolean all        = line.hasOption("all");
        boolean verbose    = line.hasOption("verbose");
        boolean details    = line.hasOption("details");
        boolean all_users  = (line.hasOption("all-users") || all);
        boolean all_groups = (line.hasOption("all-groups") || all);
        boolean all_roles  = (line.hasOption("all-roles") || all);

        if(verbose) {
            env.getWriter().println("details: ["+details+"]");
            env.getWriter().println("all: ["+all+"]");
            env.getWriter().println("all-users: ["+all_users+"]");
            env.getWriter().println("all-groups: ["+all_groups+"]");
            env.getWriter().println("all-roles: ["+all_roles+"]");
        }

        String user = null;
        if(line.hasOption( "u" )) {
            user = line.getOptionValue( "u" );
            if(verbose) env.getWriter().println("user: ["+user+"]");
        }

        String group = null;
        if(line.hasOption( "g" )) {
            group = line.getOptionValue( "g" );
            if(verbose) env.getWriter().println("group: ["+group+"]");
        }

        String role = null;
        if(line.hasOption( "r" )) {
            group = line.getOptionValue( "r" );
            if(verbose) env.getWriter().println("role: ["+role+"]");
        }
        
        //------------------
        //NOW DO SOME LOGIC (USER / GROUP)
        //------------------
        
        //-----
        //for the USER queries...
        //-----
        if(all_users || (user != null)) {
            UserInfoDAO userDAO = new UserInfoDAO(env.getEnv());
            if(all_users) {
                List<String[]> results = userDAO.getUserEntries();

                env.getWriter().println("Users:");

                //Cycle through results...
                for(String[] record : results) {
                    StringBuilder sb = new StringBuilder();
                    for(String column : record) {
                        sb.append(column+"\t");
                    }
                    env.getWriter().println(sb.toString());
                }
                
            }else if((user != null)) {
                env.getWriter().println("User: "+user);
                UserInfo userInfo = userDAO.getUserById(user);
                if(userInfo.isValid()) {
                    env.getWriter().println(userInfo);
                }else{
                    env.getWriter().println("User: ["+user+"] is NOT present on this system");
                }
            }
            env.getWriter().println();
        }

        //-----
        //for GROUP and ROLE queries...
        //-----

        GroupRoleDAO groupRoleDAO = null;
        if(all_groups || (group != null)) {
            groupRoleDAO = (groupRoleDAO == null) ? groupRoleDAO = new GroupRoleDAO(env.getEnv()) : groupRoleDAO;
            List<String[]> results =  null;
            if(all_groups) {
                results = groupRoleDAO.getGroupEntries();
                env.getWriter().println("Groups:");
            }else if((group != null)) {
                results = groupRoleDAO.getGroupEntry(group);
                env.getWriter().println("Group: "+group);
            }

            //Cycle through results...
            for(String[] record : results) {
                StringBuilder sb = new StringBuilder();
                for(String column : record) {
                    sb.append(column+"\t");
                }
                env.getWriter().println(sb.toString());
            }
            env.getWriter().println();
        }

        if(all_roles || (role != null)) {
            groupRoleDAO = (groupRoleDAO == null) ? groupRoleDAO = new GroupRoleDAO(env.getEnv()) : groupRoleDAO;
            List<String[]> results =  null;
            if(all_roles) {
                results = groupRoleDAO.getRoleEntries();
                env.getWriter().println("Roles:");
            }else if((role != null)) {
                results = groupRoleDAO.getRoleEntry(role);
                env.getWriter().println("Role: "+role);
            }

            //Cycle through results...
            for(String[] record : results) {
                StringBuilder sb = new StringBuilder();
                for(String column : record) {
                    sb.append(column+"\t");
                }
                env.getWriter().println(sb.toString());
            }
            env.getWriter().println();
        }
        
        //------------------
        env.getWriter().flush();
        return env;
    }
}
