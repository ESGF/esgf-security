package esg.security.registration.service.impl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Service;

import esg.common.util.ESGFProperties;
import esg.node.security.GroupRoleDAO;
import esg.node.security.UserInfo;
import esg.node.security.UserInfoCredentialedDAO;
import esg.security.registration.service.api.RegistrationService;

/**
 * Implementation of {@link RegistrationService} versus the ESGF relational database.
 * 
 * @author Luca Cinquini
 *
 */
@Service
public class RegistrationServiceImpl implements RegistrationService {
    
    private static final Log LOG = LogFactory.getLog(RegistrationServiceImpl.class);
    private UserInfoCredentialedDAO userInfoDAO = null;
    private GroupRoleDAO groupRoleDAO = null;
    
    public RegistrationServiceImpl() throws IOException, FileNotFoundException {
        
        final ESGFProperties props = new ESGFProperties();
        userInfoDAO = new UserInfoCredentialedDAO("rootAdmin", props.getAdminPassword(), props);
        groupRoleDAO = new GroupRoleDAO(new Properties());

    }
    
    public void register(String openid, String group, String role) throws Exception {
        
        // check group exists in database
        List<String[]> entries = groupRoleDAO.getGroupEntry(group);
        if (entries.size()<=1) throw new Exception("Group not found in database: "+group);
        
        // check role exists in database
        entries = groupRoleDAO.getRoleEntry(role);
        System.out.println(entries.size());
        if (entries.size()<=1) throw new Exception("Role not found in database: "+role);
        
        // retrieve user, or create new one with empty fields
        final UserInfo userInfo = userInfoDAO.getUserById(openid);
        if (userInfo.isValid()) {
            if (LOG.isTraceEnabled()) LOG.info("User "+openid+" found in database");
        }else{
            if (LOG.isTraceEnabled()) LOG.info("Creating user="+openid+" in database");
            String username = openid.substring(openid.lastIndexOf("/")+1);
            userInfo.setOpenid(openid)
                    .setFirstName("x")
                    .setLastName("x")
                    .setUserName(username) // FIXME: username must not be unique
                    .setEmail("x");
            if (userInfoDAO.addUserInfo(userInfo)) {
                if (LOG.isTraceEnabled()) LOG.trace("User="+openid+" created in database");
            } else {
                if (LOG.isTraceEnabled()) LOG.info("User creation failed");
            }
        }
        
        // insert (user, group, role) tuple (if not existing already)
        boolean created = userInfoDAO.addPermission(userInfo, group, role);
        if (LOG.isTraceEnabled()) LOG.trace("Permission created="+created);

        
    }
    
    public static void main(String[] args) throws Exception {
        
        RegistrationService self = new RegistrationServiceImpl();
        
        String group = "CMIP5 Research";
        String role = "User";
        String user = "https://esg-datanode.jpl.nasa.gov/esgf-idp/openid/testUser";
        self.register(user, group, role);
        
    }

}
