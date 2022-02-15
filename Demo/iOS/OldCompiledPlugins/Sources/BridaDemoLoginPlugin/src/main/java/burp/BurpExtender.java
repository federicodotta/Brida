package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;

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
		callbacks.setExtensionName("Brida Demo Login Plugin");
		
        // Initialize stdout and stderr (configurable from the Extension pane)
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);  
        
        // Save references to useful objects
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Register ourselves as an HttpListener, in this way all requests and responses will be forwarded to us
        callbacks.registerHttpListener(this);
		
	}
	
	/*
	 * int toolFlag: A flag indicating the Burp tool that issued the request. Burp tool flags are defined in the IBurpExtenderCallbacks interface. 
	 * boolean messageIsRequest: Flags whether the method is being invoked for a request or response.
	 * IHttpRequestResponse messageInfo: Details of the request / response to be processed. Extensions can call the setter methods on this object to update the current message and so modify Burp's behavior.
	 */
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
				IParameter passwordParameter = helpers.getRequestParameter(request, "password");
								
				if(passwordParameter != null) {
					
					String urlDecodedPasswordParameterValue = helpers.urlDecode(passwordParameter.getValue());
					
					String ret = "";
					
					// Ask Brida to encrypt our attack vector
					String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
					
					try {
						
						PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
						ret = (String)pp.call("callexportfunction","encryptpassword",new String[]{urlDecodedPasswordParameterValue});
						pp.close();
											
					} catch(Exception e) {
						
						stderr.println(e.toString());
		        		StackTraceElement[] exceptionElements = e.getStackTrace();
		        		for(int i=0; i< exceptionElements.length; i++) {
		        			stderr.println(exceptionElements[i].toString());
		        		}	
		        		
					}
					
					
					// Create the new parameter
					IParameter newTestParameter = helpers.buildParameter(passwordParameter.getName(), ret, passwordParameter.getType());
					
					// Create the new request with the updated parameter
					byte[] newRequest = helpers.updateParameter(request, newTestParameter);
					
					// Update the messageInfo object with the modified request (otherwise the request remains the old one)
					messageInfo.setRequest(newRequest);
					
		
				}				
				
			} 
			
		}
		
		
	}

}
