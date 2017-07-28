package burp;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;

import org.json.*;

public class BurpExtender implements IBurpExtender, IHttpListener {
	
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;	

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
        // Keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Signal Interceptor");
        
        // register ourselves as an HttpListener
        callbacks.registerHttpListener(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);  
		
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

		
		if(messageIsRequest) {
		
			byte[] request = messageInfo.getRequest();
			IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
			List<String> headers = analyzedRequest.getHeaders();
			
			int bodyOffset = analyzedRequest.getBodyOffset();
			
			byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
			String bodyString = new String(body);
			
			if(bodyString.contains("destinationRegistrationId")) {
				
				JSONObject objRoot = new JSONObject(bodyString);
				JSONObject objMessage = objRoot.getJSONArray("messages").getJSONObject(0);

				String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
				try {
					PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
					String newMessage = (String)pp.call("callexportfunction","changemessage",new String[]{"pwned"});
					pp.close();
					
					Pattern pattern = Pattern.compile(".*content = \"(.*?)\".*");
					Matcher matcher = pattern.matcher(newMessage);
					
					if (matcher.find())	{
						
						newMessage = matcher.group(1);
						
						objMessage.put("content", newMessage);
						
						String newBodyString = objRoot.toString();
						String newBodyString2 = newBodyString.replace("/", "\\/");
						
						byte[] newRequest = helpers.buildHttpMessage(headers, newBodyString2.getBytes());
						
						messageInfo.setRequest(newRequest);
						
					}

					
				} catch(IOException e) {
					stderr.println(e.toString());
				}
				
			}
			

			
		}
		
	}

	

}
