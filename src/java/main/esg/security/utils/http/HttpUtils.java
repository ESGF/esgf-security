package esg.security.utils.http;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

/**
 * Class containing utility for issuing HTTP GET/POST requests.
 * @author Luca Cinquini
 *
 */
public class HttpUtils {
    
    private static final Log LOG = LogFactory.getLog(HttpUtils.class);
    
    /**
     * Method to execute a GET request.
     * 
     * @param uri : the URL to be requested without any query parameters
     * @param params: optional map of HTPP (name,value) query parameters
     * @return
     */
    public final static String get(final String uri, final Map<String, String> pars) throws Exception {
        
        // create an instance of HttpClient.
    	CloseableHttpClient client = HttpClients.createDefault();
        
        // build full URL with query string
        String url = uri;
        String delimiter = "?";
        for (final String key : pars.keySet()) {
            url += delimiter + URLEncoder.encode(key,"UTF-8") + "=" + URLEncoder.encode(pars.get(key),"UTF-8");
            delimiter = "&";
        }

        // create GET request
        HttpGet httpGet = new HttpGet(url);
        
        // provide custom retry handler is necessary
        //method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(3, false));

        CloseableHttpResponse response = client.execute(httpGet);
        try {
            
          // execute the method.
          int statusCode = response.getStatusLine().getStatusCode();

          if (statusCode != HttpStatus.SC_OK) {
            throw new Exception("HTTP GET request failed: url="+url+" error=" + response.getStatusLine());
          }

          // read the response body.
          HttpEntity entity = response.getEntity();
          String body = EntityUtils.toString(entity);

          // note: must fully consume the response
          EntityUtils.consume(entity);
          return body;

        } catch (HttpException e) {
            LOG.warn(e.getMessage());
            throw new Exception("Fatal protocol violation: " + e.getMessage());
        } catch (IOException e) {
            LOG.warn(e.getMessage());
            throw new Exception("Fatal transport error: " + e.getMessage());
        } finally {
          // release the connection.
          response.close();
        }  
        
    }
    
    /**
     * Method to execute a POST request.
     * 
     * @param url : the URL to be requested without any query parameters
     * @param params: optional map of HTPP (name,value) query parameters
     * @return
     */
    public final static String post(final String url, final Map<String, String> pars) throws Exception {
        
        // create an instance of HttpClient.
    	CloseableHttpClient client = HttpClients.createDefault();
        
        // create a POST request
    	HttpPost httpPost = new HttpPost(url);
        
        // add request parameters
    	List <NameValuePair> nvps = new ArrayList <NameValuePair>();
        for (final String key : pars.keySet()) {
        	nvps.add(new BasicNameValuePair(key, pars.get(key)));
        }
        httpPost.setEntity(new UrlEncodedFormEntity(nvps));
 
        
        // provide custom retry handler is necessary
        //method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(3, false));

        CloseableHttpResponse response = client.execute(httpPost);
        try {
            
          // execute the method.
          int statusCode = response.getStatusLine().getStatusCode();

          if (statusCode != HttpStatus.SC_OK) {
            throw new Exception("HTTP POST request failed: url="+url+" error=" + response.getStatusLine());
          }
          
          // read the response body.
          HttpEntity entity = response.getEntity();
          String body = EntityUtils.toString(entity);

          // note: must fully consume the response
          EntityUtils.consume(entity);
          return body;


        } catch (HttpException e) {
            LOG.warn(e.getMessage());
            throw new Exception("Fatal protocol violation: " + e.getMessage());
        } catch (IOException e) {
            LOG.warn(e.getMessage());
            throw new Exception("Fatal transport error: " + e.getMessage());
        } finally {
          // release the connection.
          response.close();
        }  
        
    }

}
