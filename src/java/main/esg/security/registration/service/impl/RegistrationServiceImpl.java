package esg.security.registration.service.impl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Service;

import esg.common.util.ESGFProperties;
import esg.node.security.GroupRoleDAO;
import esg.node.security.UserInfo;
import esg.node.security.UserInfoCredentialedDAO;
import esg.security.common.SAMLParameters.RegistrationOutcome;
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
    
    /**
     * {@inheritDoc}
     */
    public RegistrationOutcome register(String openid, String group, String role) throws Exception {
                
        // check group exists in database
        if (!groupRoleDAO.isGroupValid(group)) throw new Exception("Group not found in database: "+group);
         
        // check role exists in database
        if (!groupRoleDAO.isRoleValid(role)) throw new Exception("Role not found in database: "+role);
        
        // retrieve user, or create new one with empty fields
        final UserInfo userInfo = userInfoDAO.getUserById(openid);
        if (userInfo.isValid()) {
            if (LOG.isTraceEnabled()) LOG.info("User "+openid+" found in database");
        } else {
            if (LOG.isTraceEnabled()) LOG.info("Creating user="+openid+" in database");
            String username = openid.substring(openid.lastIndexOf("/")+1);
            userInfo.setOpenid(openid)
                    .setFirstName("")
                    .setLastName("")
                    .setUserName(username) // FIXME: username may not be unique
                    .setEmail("");
            if (userInfoDAO.addUserInfo(userInfo)) {
                if (LOG.isTraceEnabled()) LOG.trace("User="+openid+" created in database");
            } else {
                throw new Exception("User creation failed");
            }
        }
        
        // insert (user, group, role) tuple (if not existing already)
        RegistrationOutcome outcome = RegistrationOutcome.UNKNOWN;
        boolean created = userInfoDAO.addPermission(userInfo, group, role);
        if (created) {             
            if (groupRoleDAO.isAutomaticApproval(group)) {
                outcome = RegistrationOutcome.SUCCESS;
            } else {
                outcome = RegistrationOutcome.PENDING;
            }
        } else {
            if (userInfoDAO.isPermissionApproved(openid, group, role)) {
                outcome = RegistrationOutcome.EXISTING;
            } else {
                outcome = RegistrationOutcome.PENDING;
            }
        }
        
        if (LOG.isTraceEnabled()) LOG.trace("Permission created="+created+" outcome="+outcome);
        return outcome;
        
    }

}
