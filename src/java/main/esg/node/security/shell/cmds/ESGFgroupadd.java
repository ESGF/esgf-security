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

import esg.node.security.*;

import esg.common.shell.*;
import esg.common.shell.cmds.*;

import org.apache.commons.cli.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.impl.*;

public class ESGFgroupadd extends ESGFSecurityCommand {

private static Log log = LogFactory.getLog(ESGFgroupadd.class);

    public ESGFgroupadd() { super(); }

    public void init(ESGFEnv env) { checkPermission(env); }
    public String getCommandName() { return "groupadd"; }

    public void doInitOptions() {
        OptionGroup autoGroup = new OptionGroup();
        autoGroup.addOption(new Option("auto", "auto-approve", false, "Set auto approval for joining this group"));
        autoGroup.addOption(new Option("no_auto", "no-auto-approve", false, "Set auto approval for joining this group"));
        getOptions().addOptionGroup(autoGroup);
        
        OptionGroup visGroup = new OptionGroup();
        visGroup.addOption(new Option("vis", "visible", false, "Sets whether this group is visible to registry"));
        visGroup.addOption(new Option("no_vis", "not-visible", false, "Sets whether this group is visible to registry"));
        getOptions().addOptionGroup(visGroup);

        Option description = 
            OptionBuilder.withArgName("description")
            .hasArg(true)
            .withDescription("Description of group")
            .withLongOpt("description")
            .create("d");
        getOptions().addOption(description);

        Option name = 
            OptionBuilder.withArgName("name")
            .hasArg(true)
            .withDescription("Description of group")
            .withLongOpt("description")
            .isRequired(true)
            .create("n");
        getOptions().addOption(name);

    }

    public ESGFEnv doEval(CommandLine line, ESGFEnv env) {
        System.out.println("inside the \"groupadd\" command's doEval: "+line);

        //------------------
        //Collect args...
        //------------------
        
        //Don't burn cycles if don't need to...
        //if(log.isInfoEnabled()) {
              int i=0;
              for(String arg : line.getArgs()) {
                  log.info("groupadd arg("+(i++)+"): "+arg);
              }
        //}
        
        String groupname = null;
        if(line.hasOption( "n" )) {
            groupname = line.getOptionValue( "n" );
            env.getWriter().println("group name: ["+groupname+"]");
        }

        if (groupname == null) throw new esg.common.ESGRuntimeException("You must provide the group name to create");

        String description = "";
        if(line.hasOption( "d" )) {
            description = line.getOptionValue( "d" );
            env.getWriter().println("description: ["+description+"]");
        }
        
        boolean autoapprove = true;
        if(line.hasOption( "auto" )) { autoapprove = true; }
        if(line.hasOption( "no_auto" )) { autoapprove = false; }
        env.getWriter().println("auto approval: ["+autoapprove+"]");

        boolean visible = true; //default
        if(line.hasOption( "vis" )) { visible = true; }
        if(line.hasOption( "no_vis" )) { visible = false; }
        env.getWriter().println("visible: ["+visible+"]");
        
        
        if(groupname == null) throw new esg.common.ESGRuntimeException("no group name specified");

        //------------------
        //NOW DO SOME LOGIC
        //------------------

        GroupRoleDAO groupRoleDAO = new GroupRoleDAO(env.getEnv());
        System.out.println("Group Name: "+groupname);
        System.out.println("Description: "+description);
        System.out.println("visible: "+visible);
        System.out.println("Auto Approve: "+autoapprove);
        if(groupRoleDAO.addGroup(groupname, description, visible, autoapprove)) {
            System.out.println("groupRoleDAO.addGroup("+groupname+", "+description+", "+visible+", "+autoapprove+")");
            env.getWriter().println("[OK]");
        }else{
            env.getWriter().println("[FAILED]");
        }
        
        //------------------
        env.getWriter().flush();
        return env;
    }
}
