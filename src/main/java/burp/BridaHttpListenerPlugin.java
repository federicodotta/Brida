package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridaHttpListenerPlugin extends CustomPlugin implements IHttpListener, IProxyListener {
	
	private ArrayList<Integer> customPluginTools;
	private boolean processOnlyInScope;
	
    public BridaHttpListenerPlugin(ArrayList<Integer> customPluginTools, boolean processOnlyInScope, BurpExtender mainPlugin, 
    		String customPluginName, String customPluginExportedFunctionName,
			CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnContextName,
			CustomPluginExecuteValues customPluginExecute,
			String customPluginExecuteString, CustomPluginParameterValues customPluginParameter,
			String customPluginParameterString, List<BurpExtender.Transformation> customPluginParameterEncoding,
			CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
			List<BurpExtender.Transformation> customPluginOutputEncoding,
			List<BurpExtender.Transformation> customPluginOutputDecoding) {
    	
		super(mainPlugin, customPluginName, customPluginExportedFunctionName, customPluginExecuteOn, customPluginExecuteOnContextName,
				customPluginExecute, customPluginExecuteString, customPluginParameter,
				customPluginParameterString, customPluginParameterEncoding, customPluginFunctionOutput,
				customPluginFunctionOutputString, customPluginOutputEncoding, customPluginOutputDecoding);
		
		this.customPluginTools = customPluginTools;
		this.processOnlyInScope = processOnlyInScope;
		
		this.setType(CustomPlugin.CustomPluginType.IHTTPLISTENER);
		
	}
    
    @Override
	public String exportPlugin() {
		
		String result = "";
		
		result = result + getType().ordinal() + ";";
		
		String pluginTools = "";
		for(int i=0;i<customPluginTools.size();i++) {
			pluginTools = pluginTools + customPluginTools.get(i) + ",";
		}
		if(customPluginTools.size() > 0) {
			pluginTools = pluginTools.substring(0,pluginTools.length()-1);
		}
		
		result = result + pluginTools + ";";
		result = result + processOnlyInScope + ";";		
		
		result = result + Base64.getEncoder().encodeToString(getCustomPluginName().getBytes()) + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExportedFunctionName().getBytes()) + ";";
		result = result + getCustomPluginExecuteOn().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExecuteOnContextName().getBytes()) + ";";
		result = result + getCustomPluginExecute().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExecuteString().getBytes()) + ";";
		result = result + getCustomPluginParameter().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginParameterString().getBytes()) + ";";
		result = result + getCustomPluginParameterEncoding().toString() + ";";		
		result = result + getCustomPluginFunctionOutput().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginFunctionOutputString().getBytes()) + ";";
		result = result + getCustomPluginOutputEncoding().toString() + ";";
		result = result + getCustomPluginOutputDecoding().toString();
				
		return result;
		
	}
    
	public void enable() {		
		
		if(customPluginTools.contains(IBurpExtenderCallbacks.TOOL_PROXY) && customPluginTools.size() == 1) {
			// Process only proxy requests/responses
			getMainPlugin().callbacks.registerProxyListener(this);			
		} else if(!customPluginTools.contains(IBurpExtenderCallbacks.TOOL_PROXY)) {
			// Process only NON proxy requests/responses
			getMainPlugin().callbacks.registerHttpListener(this);
		} else {
			getMainPlugin().callbacks.registerProxyListener(this);
			getMainPlugin().callbacks.registerHttpListener(this);
		}
		
    	setOnOff(true);
    	
    }
    
    public void disable() {
    	
    	if(customPluginTools.contains(IBurpExtenderCallbacks.TOOL_PROXY) && customPluginTools.size() == 1) {
			getMainPlugin().callbacks.removeProxyListener(this);			
		} else if(!customPluginTools.contains(IBurpExtenderCallbacks.TOOL_PROXY)) {
			getMainPlugin().callbacks.removeHttpListener(this);
		} else {
			getMainPlugin().callbacks.removeProxyListener(this);
			getMainPlugin().callbacks.removeHttpListener(this);
		}
    	
    	setOnOff(false);
    }
    
    
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		
		byte[] requestResponseBytes = (messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse());
		
		boolean scopeCheck = true;
		if(processOnlyInScope) {
			scopeCheck = getMainPlugin().callbacks.isInScope(getMainPlugin().helpers.analyzeRequest(messageInfo).getUrl());
		}
		
		if(scopeCheck && customPluginTools.contains(toolFlag) && isPluginEnabled(requestResponseBytes, messageIsRequest) && toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
			
			executeBridaFunction(messageInfo, messageIsRequest);
			
		}		
		
	}


	public ArrayList<Integer> getCustomPluginTools() {
		return customPluginTools;
	}


	public void setCustomPluginTools(ArrayList<Integer> customPluginTools) {
		this.customPluginTools = customPluginTools;
	}

	public boolean isProcessOnlyInScope() {
		return processOnlyInScope;
	}

	public void setProcessOnlyInScope(boolean processOnlyInScope) {
		this.processOnlyInScope = processOnlyInScope;
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		
		IHttpRequestResponse messageInfo = message.getMessageInfo();
		byte[] requestResponseBytes = (messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse());
		
		boolean scopeCheck = true;
		if(processOnlyInScope) {
			scopeCheck = getMainPlugin().callbacks.isInScope(getMainPlugin().helpers.analyzeRequest(messageInfo).getUrl());
		}
		
		if(scopeCheck && customPluginTools.contains(IBurpExtenderCallbacks.TOOL_PROXY) && isPluginEnabled(requestResponseBytes, messageIsRequest)) {
			
			executeBridaFunction(messageInfo, messageIsRequest);
			
		}
		
	}
	
	public void executeBridaFunction(IHttpRequestResponse messageInfo, boolean messageIsRequest) {
		
		byte[] requestResponseBytes = (messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse());
		
		// DEBUG print
		printToExternalDebugFrame("*** START ***\n\n");
		printToExternalDebugFrame("** Original " + (messageIsRequest ? "request" : "response") + "\n");
		printToExternalDebugFrame(new String(requestResponseBytes));
		printToExternalDebugFrame("\n\n");
		
		List<byte[]> parameters = getParametersCustomPlugin(requestResponseBytes,messageIsRequest);
		
		// DEBUG print
		if(parameters.size() > 0) {
			printToExternalDebugFrame("** Frida parameters (after encoding)\n");
			for(int i=0;i<parameters.size();i++) {
				printToExternalDebugFrame("* Parameter " + (i+1) + ": " + new String(parameters.get(i)) + "\n");
			}
			printToExternalDebugFrame("\n\n");
		} else {
			printToExternalDebugFrame("** NO Frida parameters\n\n");
		}
		
		byte[] ret = callFrida(parameters);
		
		// DEBUG print
		printToExternalDebugFrame("** Frida returned value (after deconding/encoding)\n");
		printToExternalDebugFrame(new String(ret));
		printToExternalDebugFrame("\n\n");
		
		if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.BRIDA) {
			getMainPlugin().printSuccessMessage("* Brida exported function " + getCustomPluginExportedFunctionName() + " output: " + new String(ret));
			
			// DEBUG print
			printToExternalDebugFrame("** Output to Brida console\n\n");
				
		} else if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.HEADERS) {
						
			byte[] newMessage = replaceOutputHeaders(requestResponseBytes, messageIsRequest, new String(ret));
			
			if(messageIsRequest) {				
				messageInfo.setRequest(newMessage);				
			} else {														
				messageInfo.setResponse(newMessage);				
			}
			
			// DEBUG print
			printToExternalDebugFrame("** Replacing the headers of the message. Modified " + (messageIsRequest ? "request" : "response") + ":\n");
			printToExternalDebugFrame(new String(newMessage));
			printToExternalDebugFrame("\n\n** \n\n");
			
		} else if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.BODY) {
			
			byte[] newMessage = replaceOutputBody(requestResponseBytes, messageIsRequest, ret);
			if(messageIsRequest) {				
				messageInfo.setRequest(newMessage);				
			} else {														
				messageInfo.setResponse(newMessage);				
			}	
			
			// DEBUG print
			printToExternalDebugFrame("** Replacing the body of the message. Modified " + (messageIsRequest ? "request" : "response") + ":\n");
			printToExternalDebugFrame(new String(newMessage));
			printToExternalDebugFrame("\n\n** \n\n");
		
		} else if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.COMPLETE_RECALCULATE || getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.COMPLETE_NOT_RECALCULATE) {
						
			byte[] messageWithCorrectContentLength;			
			if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.COMPLETE_NOT_RECALCULATE) {
				
				messageWithCorrectContentLength = ret;
				
			} else {
				
				messageWithCorrectContentLength = recalculateMessageBodyLength(ret,messageIsRequest);
				
			}
					
			if(messageIsRequest) {				
				messageInfo.setRequest(messageWithCorrectContentLength);				
			} else {														
				messageInfo.setResponse(messageWithCorrectContentLength);				
			}
			
			// DEBUG print
			printToExternalDebugFrame("** Replacing entire " + (messageIsRequest ? "request" : "response") + ". Modified one:\n");
			printToExternalDebugFrame(new String(messageWithCorrectContentLength));
			printToExternalDebugFrame("\n\n** \n\n");

		} else if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.REGEX) {
			Pattern patternCustomPlugin = Pattern.compile(getCustomPluginFunctionOutputString());
			Matcher matcherCustomPlugin = patternCustomPlugin.matcher(new String(requestResponseBytes));
			if(matcherCustomPlugin.find()) {									
				
				String replacedRequestResponse = new StringBuilder(new String(requestResponseBytes)).replace(matcherCustomPlugin.start(1), matcherCustomPlugin.end(1), ((ret != null) ? new String(ret) : "")).toString();
				byte[] replacedRequestResponseBytes = replacedRequestResponse.getBytes();
				
				if(messageIsRequest) {
					
					// Replacing values in the body causes incorrect content length. By rebuilding the request with the Burp API the content length is fixed					
					IRequestInfo analyzedRequest = getMainPlugin().helpers.analyzeRequest(replacedRequestResponseBytes);					
					byte[] requestWithCorrectContentLength = getMainPlugin().helpers.buildHttpMessage(analyzedRequest.getHeaders(), Arrays.copyOfRange(replacedRequestResponseBytes, analyzedRequest.getBodyOffset(), replacedRequestResponseBytes.length));
					
					messageInfo.setRequest(requestWithCorrectContentLength);
					replacedRequestResponse = new String(requestWithCorrectContentLength);
					
				} else {					
					
					// Replacing values in the body causes incorrect content length. By rebuilding the response with the Burp API the content length is fixed
					IResponseInfo analyzedResponse = getMainPlugin().helpers.analyzeResponse(replacedRequestResponseBytes);
					byte[] responseWithCorrectContentLength = getMainPlugin().helpers.buildHttpMessage(analyzedResponse.getHeaders(), Arrays.copyOfRange(replacedRequestResponseBytes, analyzedResponse.getBodyOffset(), replacedRequestResponseBytes.length));

					messageInfo.setResponse(responseWithCorrectContentLength);
					replacedRequestResponse = new String(responseWithCorrectContentLength);
					
				}
				
				// DEBUG print
				printToExternalDebugFrame("** Modified " + (messageIsRequest ? "request" : "response") + "\n");
				printToExternalDebugFrame(replacedRequestResponse);
				printToExternalDebugFrame("\n\n** \n\n");
				
			} else {
				
				getMainPlugin().printException(null,"No match found in supplied output REGEX. Outputting to Brida console.");
				getMainPlugin().printSuccessMessage("* Brida exported function " + getCustomPluginExportedFunctionName() + " output: " + ret);
				
				// DEBUG print
				printToExternalDebugFrame("** Output to Brida console because REGEX did not match\n\n");
				
			}								
		}
		
		// DEBUG print
		printToExternalDebugFrame("*** END ***\n\n");
		
	}
	
	
	
}
