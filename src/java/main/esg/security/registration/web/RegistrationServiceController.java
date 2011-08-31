package esg.security.registration.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.JDOMException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import esg.security.common.SAMLParameters;
import esg.security.registration.service.api.RegistrationService;
import esg.security.registration.service.impl.RegistrationServiceImpl;

/**
 * Controller that front-ends a {@link RegistrationService}.
 * @author Luca Cinquini
 *
 */
@RequestMapping("/secure/registrationService.htm")
public class RegistrationServiceController {
    
    private final RegistrationService registrationService;
    
    private static final Log LOG = LogFactory.getLog(RegistrationServiceController.class);
        
    public RegistrationServiceController(final RegistrationService registrationService) {
        this.registrationService = registrationService;
    }
    
    @RequestMapping(method = { RequestMethod.POST } )
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException, JDOMException {
        
        // retrieve request parameters
        final String user = request.getParameter(SAMLParameters.HTTP_PARAMETER_USER);
        final String group = request.getParameter(SAMLParameters.HTTP_PARAMETER_GROUP);
        final String role = request.getParameter(SAMLParameters.HTTP_PARAMETER_ROLE);
        
        if (LOG.isTraceEnabled()) LOG.trace("Registering user: "+user+" in group: "+group+" with role: "+role);
        
        String xml = "";
        try {
            
            // invoke back-end service
            registrationService.register(user, group, role);
            
            // encode success response in XML
            xml = RegistrationResponseUtils.serialize(SAMLParameters.RegistrationOutcome.SUCCESS, 
                                                      "User: "+user+" was registered in group: "+group+" with role: "+role);            
            
        } catch(Exception e) {
            
            // encode error response in XML
            xml = RegistrationResponseUtils.serialize(SAMLParameters.RegistrationOutcome.ERROR, e.getMessage());
        }
        
        response.setContentType("text/xml");
        response.getWriter().write( xml );
        
    }

}
