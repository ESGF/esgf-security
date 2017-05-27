/*******************************************************************************
 * Copyright (c) 2011 Earth System Grid Federation
 * ALL RIGHTS RESERVED. 
 * U.S. Government sponsorship acknowledged.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package esg.security.common;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

/**
 * Generic client class to send a SAML request via SOAP/HTTP, and return a SOAP response from the server.
 * This class uses the Apache {@link HttpClient} to execute the actual HTTP invocation.
 * Note: this class needs to be a singleton to avoid instantiating too many HTTP connection managers.
 */
public class SOAPServiceClient {
        
    private static SOAPServiceClient self = new SOAPServiceClient();
	
	private final CloseableHttpClient client;
	
	protected final static Log LOG = LogFactory.getLog(SOAPServiceClient.class);

	
	/**
	 * Single instance access method.
	 * 
	 * @return
	 */
	public static SOAPServiceClient getInstance() {
	    return  self;
	}
	
	/**
	 * Private constructor to force singleton behavior.
	 */
	private SOAPServiceClient() {

		client = HttpClients.createDefault();
			    
	}
		
	/**
	 * Method that executes the SOAP invocation.
	 * 
	 * @param endpoint
	 * @param soapRequest
	 * @return
	 */
	public String doSoap(final String endpoint, final String soapRequest) {
		
		//if (LOG.isDebugEnabled()) LOG.debug("Querying SOAP endpoint: "+endpoint+" timeout="+TIMEOUT+" milliseconds");
	    final HttpPost httpPost = new HttpPost(endpoint);

	    CloseableHttpResponse response = null;
		    
		    try {
		    	
			    // insert SOAP request as HTTP request body
				log(soapRequest);
			    final byte[] bytes = soapRequest.getBytes();		    
			    final ByteArrayEntity requestEntity = new ByteArrayEntity(bytes);
			    httpPost.setEntity(requestEntity);
							
			    // Execute the method.
			    response = client.execute(httpPost);

		    	// check response status
		    	StatusLine statusLine = response.getStatusLine();
		    	if (LOG.isDebugEnabled()) LOG.debug("Response status line: "+statusLine);
		    	int statusCode = statusLine.getStatusCode();
			    if (statusCode != HttpStatus.SC_OK) {
			        String error = "HTTP Method failed: " + statusLine;
			    	log(error);
			    	throw new RuntimeException(error);
			    }

			    // read response headers
			    final Header[] headers = response.getAllHeaders();
			    for (final Header header : headers) {
			    	if (LOG.isDebugEnabled()) LOG.debug("Response header name="+header.getName()+" value="+header.getValue());
			    }

			    // read the response body (may be null)
		        HttpEntity entity = response.getEntity();
		        final String soapResponse = EntityUtils.toString(entity);
		        log(soapResponse);
		        
		        EntityUtils.consume(entity);
		        
		        return soapResponse;
		        
		    } catch(IOException e) {
		    	log(e.getMessage());
		    	throw new RuntimeException(e);
		        
		    } finally {
		        if (response!=null) {
		        	try {
		        		response.close();
		        	} catch(IOException e) {}
		        }
		    }

		  
	}
	
	private void log(final String message) {
		if (LOG.isDebugEnabled()) LOG.debug(message);
	}
	
	/**
	 * Method that cleans up the HttpClient, but not necessarily guaranteed to be called in Java.
	 */
	protected void finalize() throws Throwable {
		if (client!=null) {
			client.close();
		}
		super.finalize();
	}

}
