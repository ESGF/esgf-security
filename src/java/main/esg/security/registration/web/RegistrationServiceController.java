package esg.security.registration.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdom.JDOMException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import esg.security.common.SAMLParameters;
import esg.security.common.SAMLParameters.RegistrationOutcome;
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
        if (LOG.isInfoEnabled()) LOG.info("Request XML="+requestXml);
        
        // parse XML
        final String[] reqqpars = RegistrationRequestUtils.deserialize(requestXml);
        
        final String user = reqqpars[0];
        final String group = reqqpars[1];
        final String role = reqqpars[2];
        
        this.process(user, group, role, response);

                
    }
    
    /**
     * Method that processes GET request
     * @param request
     * @param response
     * @throws IOException
     * @throws JDOMException
     */
    @RequestMapping(method = { RequestMethod.GET } )
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, JDOMException, ServletException {
        
        final String user = this.getMandatoryRequestParameter(SAMLParameters.HTTP_PARAMETER_USER, request);
        final String group = this.getMandatoryRequestParameter(SAMLParameters.HTTP_PARAMETER_GROUP, request);
        final String role = this.getMandatoryRequestParameter(SAMLParameters.HTTP_PARAMETER_ROLE, request);
        if (LOG.isInfoEnabled()) LOG.info("Registering user: "+user+" in group: "+group+" with role: "+role);
        
        // FIXME
        //if (!group.equals("Test Group")) throw new ServletException("GET method only supports registration in 'Test Group'");
        //if (!role.equals("User")) throw new ServletException("GET method only supports registration for role 'User'");
        
        this.process(user, group, role, response);
        
    }
       
    /**
     * Common business logic to GET/POST requests.
     * @param user
     * @param group
     * @param role
     * @param response
     * @throws IOException
     * @throws JDOMException
     */
    private void process(final String user, final String group, final String role, final HttpServletResponse response) throws IOException, JDOMException {
                
        String responseXml = "";
        try {
            
            // invoke back-end service
            final RegistrationOutcome outcome = registrationService.register(user, group, role);
            
            // encode registration result in XML response
            responseXml = RegistrationResponseUtils.serialize(outcome, "Registration outcome: user="+user+", group="+group+", role="+role);  
            
            response.setContentType("text/xml");
            response.getWriter().write( responseXml );
            
        } catch(Exception e) {
            
            // send HTTP 500 response code
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            
        }
        
    }
    
    private String getMandatoryRequestParameter(final String parName, final HttpServletRequest request) throws ServletException {
        final String parValue = request.getParameter(parName);
        if (StringUtils.hasText(parValue)) return parValue;
        else throw new ServletException("Missing mandatory request parameter: "+parName);
    }



}
