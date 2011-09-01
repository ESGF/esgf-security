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

/**
 * Controller that front-ends a {@link RegistrationService}.
 * 
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
    
    /**
     * Method that processes POST requests. GET requests are NOT supported.
     * @param request
     * @param response
     * @throws IOException
     * @throws JDOMException
     */
    @RequestMapping(method = { RequestMethod.POST } )
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException, JDOMException {
        
        // retrieve XML request parameter
        final String requestXml = request.getParameter(SAMLParameters.HTTP_PARAMETER_XML);
        
        // parse XML
        final String[] reqqpars = RegistrationRequestUtils.deserialize(requestXml);
        
        final String user = reqqpars[0];
        final String group = reqqpars[1];
        final String role = reqqpars[2];
        
        if (LOG.isInfoEnabled()) LOG.info("Registering user: "+user+" in group: "+group+" with role: "+role);
        
        String responseXml = "";
        try {
            
            // invoke back-end service
            registrationService.register(user, group, role);
            
            // encode success response in XML
            responseXml = RegistrationResponseUtils.serialize(
                    SAMLParameters.RegistrationOutcome.SUCCESS, 
                    "User: "+user+" was registered in group: "+group+" with role: "+role);  
            
            response.setContentType("text/xml");
            response.getWriter().write( responseXml );
            
        } catch(Exception e) {
            
            // send HTTP 500 response code
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            
        }
                
    }

}
