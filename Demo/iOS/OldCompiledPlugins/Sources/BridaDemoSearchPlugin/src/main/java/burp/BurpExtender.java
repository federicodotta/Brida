package burp;

import java.io.PrintWriter;
import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;

import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;

public class BurpExtender implements IBurpExtender, IHttpListener {

    private PrintWriter stdout;
    private PrintWriter stderr;	
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

		// Set the name of the extension
		callbacks.setExtensionName("Brida Demo Search Plugin");
		
        // Initialize stdout and stderr (configurable from the Extension pane)
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);  
        
        // Save references to useful objects
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Register ourselves as an HttpListener, in this way all requests and responses will be forwarded to us
        callbacks.registerHttpListener(this);
		
	}

	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

		// Process only Repeater, Scanner and Intruder requests
		if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || 
		   toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ||		
		   toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
			
			// Modify "test" parameter of Repeater requests			
			if(messageIsRequest) {
				
				// Get request bytes
				byte[] request = messageInfo.getRequest();
				
				// Get a IRequestInfo object, useful to work with the request
				IRequestInfo requestInfo = helpers.analyzeRequest(request);
				
				// Get "test" parameter
				IParameter contentParameter = helpers.getRequestParameter(request, "content");
								
				if(contentParameter != null) {
					
					String urlDecodedContentParameterValue = helpers.urlDecode(contentParameter.getValue());
					
					String ret = "";
					
					// Ask Brida to encrypt our attack vector
					String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
										
					try {
						
						PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
						ret = (String)pp.call("callexportfunction","encrypt",new String[]{urlDecodedContentParameterValue});
						pp.close();
						
					} catch(Exception e) {
						
						stderr.println(e.toString());
		        		StackTraceElement[] exceptionElements = e.getStackTrace();
		        		for(int i=0; i< exceptionElements.length; i++) {
		        			stderr.println(exceptionElements[i].toString());
		        		}							
					}
										
					
					// Create the new parameter
					IParameter newTestParameter = helpers.buildParameter(contentParameter.getName(), ret, contentParameter.getType());
					
					// Create the new request with the updated parameter
					byte[] newRequest = helpers.updateParameter(request, newTestParameter);
					
					// Update the messageInfo object with the modified request (otherwise the request remains the old one)
					messageInfo.setRequest(newRequest);
					
		
				}				
				
			// Response
			} else {
				
				// Get request bytes in order to check if the request contain "content" parameter
				byte[] request = messageInfo.getRequest();				
				IRequestInfo requestInfo = helpers.analyzeRequest(request);
				IParameter contentParameter = helpers.getRequestParameter(request, "content");
								
				if(contentParameter != null) {
				
					// Get response bytes
					byte[] response = messageInfo.getResponse();
					
					// Get a IResponseInfo object, useful to work with the request
					IResponseInfo responseInfo = helpers.analyzeResponse(response);
					
					// Get the offset of the body
					int bodyOffset = responseInfo.getBodyOffset();
					
					// Get the body (byte array and String)
					byte[] body = Arrays.copyOfRange(response, bodyOffset, response.length);
					String bodyString = helpers.bytesToString(body);
							
					String ret = "";
					
					// Ask Brida to decrypt the response
					String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
					
					try {
						
						PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
						ret = (String)pp.call("callexportfunction","decrypt",new String[]{bodyString});
						pp.close();
													
					} catch(Exception e) {
						
						stderr.println(e.toString());
		        		StackTraceElement[] exceptionElements = e.getStackTrace();
		        		for(int i=0; i< exceptionElements.length; i++) {
		        			stderr.println(exceptionElements[i].toString());
		        		}							
					}
						
					// Update the messageInfo object with the modified request (otherwise the request remains the old one)
					byte[] newResponse = ArrayUtils.addAll(Arrays.copyOfRange(response, 0, bodyOffset),ret.getBytes());
					messageInfo.setResponse(newResponse);
					
				}
					
			}
			
		}
		
		
	}

}
