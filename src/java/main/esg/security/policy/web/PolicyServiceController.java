package esg.security.policy.web;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import esg.security.common.SAMLParameters;
import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;
import esg.security.registry.service.api.RegistryService;
import esg.security.registry.service.api.UnknownPolicyAttributeTypeException;

/**
 * HTTP controller that front-ends the PolicyService.
 * This controller also includes information from the RegistryService
 * to enable registration workflows.
 * 
 * @author Luca Cinquini
 *
 */
@Controller
@RequestMapping("/policyService.htm")
public class PolicyServiceController {
    
    private PolicyService policyService;
    private RegistryService registryService;
    
    private final Log LOG = LogFactory.getLog(this.getClass());
    
    public PolicyServiceController(final PolicyService policyService, final RegistryService registryService) {
        this.policyService = policyService;
        this.registryService = registryService;
    }
    
    /**
     * Only controller method, processes HTTP requests of type GET and POST.
     * @param httpRequest
     * @param httpResponse
     * @throws Exception
     */
    @RequestMapping(method = { RequestMethod.GET, RequestMethod.POST } )
    public void process(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) throws Exception {

        // retrieve mandatory request parameters
        final String resource = httpRequest.getParameter(SAMLParameters.HTTP_PARAMETER_RESOURCE);
        if (!StringUtils.hasText(resource)) throw new ServletException("Missing required HTTP parameter: "+SAMLParameters.HTTP_PARAMETER_RESOURCE);
        final String action = httpRequest.getParameter(SAMLParameters.HTTP_PARAMETER_ACTION);
        if (!StringUtils.hasText(action)) throw new ServletException("Missing required HTTP parameter: "+SAMLParameters.HTTP_PARAMETER_ACTION);        
        if (LOG.isTraceEnabled()) LOG.trace("Querying policy for resource="+resource+" action="+action);
        
        // invoke policy service
        final List<PolicyAttribute> policyAttributes = policyService.getRequiredAttributes(resource, action);
        
        // invoke registry service to determine registration endpoints
        final Map<PolicyAttribute, List<URL>> policyAttributeMap = new LinkedHashMap<PolicyAttribute,List<URL>>();
        for (final PolicyAttribute pa : policyAttributes) {
            try {
                final List<URL> paEndpoints = registryService.getRegistrationServices(pa.getType());
                policyAttributeMap.put(pa, paEndpoints);
            } catch(UnknownPolicyAttributeTypeException e) {
                // no registration URL available
                policyAttributeMap.put(pa, new ArrayList<URL>());
                LOG.warn(e);
            }
            
        }
        
        // encode result as XML
        final String xml = PolicySerializer.serialize(policyAttributeMap);
        if (LOG.isTraceEnabled()) LOG.trace(xml);
        
        // write XML to HTTP response
        httpResponse.setContentType(SAMLParameters.CONTENT_TYPE_XML);
        httpResponse.getWriter().write( xml );
        
    }
    

}