package burp;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BridaHttpListenerPlugin extends CustomPlugin implements IHttpListener {
	
	private ArrayList<Integer> customPluginTools;
	private boolean processOnlyInScope;
	
    public BridaHttpListenerPlugin(ArrayList<Integer> customPluginTools, boolean processOnlyInScope, BurpExtender mainPlugin, 
    		String customPluginName, String customPluginExportedFunctionName,
			CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnContextName,
			CustomPluginExecuteValues customPluginExecute,
			String customPluginExecuteString, CustomPluginParameterValues customPluginParameter,
			String customPluginParameterString, CustomPluginEncodingValues customPluginParameterEncoding,
			CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
			CustomPluginEncodingValues customPluginOutputEncoding,
			CustomPluginEncodingValues customPluginOutputDecoding) {
		super(mainPlugin, customPluginName, customPluginExportedFunctionName, customPluginExecuteOn, customPluginExecuteOnContextName,
				customPluginExecute, customPluginExecuteString, customPluginParameter,
				customPluginParameterString, customPluginParameterEncoding, customPluginFunctionOutput,
				customPluginFunctionOutputString, customPluginOutputEncoding, customPluginOutputDecoding);
		
		this.customPluginTools = customPluginTools;
		this.processOnlyInScope = processOnlyInScope;
		
		this.setType(CustomPlugin.CustomPluginType.IHTTPLISTENER);
		
	}
    
	public void enable() {
    	getMainPlugin().callbacks.registerHttpListener(this);
    	setOnOff(true);
    }
    
    public void disable() {
    	getMainPlugin().callbacks.removeHttpListener(this);
    	setOnOff(false);
    }
    
    
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		
		byte[] requestResponseBytes = (messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse());
		
		boolean scopeCheck = true;
		if(processOnlyInScope) {
			scopeCheck = getMainPlugin().callbacks.isInScope(getMainPlugin().helpers.analyzeRequest(messageInfo).getUrl());
		}
		
		if(scopeCheck && customPluginTools.contains(toolFlag) && isPluginEnabled(requestResponseBytes, messageIsRequest)) {
			
			// DEBUG print
			printToExternalDebugFrame("*** START ***\n\n");
			printToExternalDebugFrame("** Original " + (messageIsRequest ? "request" : "response") + "\n");
			printToExternalDebugFrame(new String(requestResponseBytes));
			printToExternalDebugFrame("\n\n");
			
			String[] parameters = getParametersCustomPlugin(requestResponseBytes,messageIsRequest);
			
			// DEBUG print
			if(parameters.length > 0) {
				printToExternalDebugFrame("** Frida parameters (after encoding)\n");
				for(int i=0;i<parameters.length;i++) {
					printToExternalDebugFrame("* Parameter " + (i+1) + ": " + parameters[i] + "\n");
				}
				printToExternalDebugFrame("\n\n");
			} else {
				printToExternalDebugFrame("** NO Frida parameters\n\n");
			}
			
			String ret = callFrida(parameters);
			
			// DEBUG print
			printToExternalDebugFrame("** Frida returned value (after deconding/encoding)\n");
			printToExternalDebugFrame(ret);
			printToExternalDebugFrame("\n\n");
			
			if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.BRIDA) {
				getMainPlugin().printSuccessMessage("* Brida exported function " + getCustomPluginExportedFunctionName() + " output: " + ret);
				
				// DEBUG print
				printToExternalDebugFrame("** Output to Brida console\n\n");
				
			} else if(getCustomPluginFunctionOutput() == CustomPluginFunctionOutputValues.REGEX) {
				Pattern patternCustomPlugin = Pattern.compile(getCustomPluginFunctionOutputString());
				Matcher matcherCustomPlugin = patternCustomPlugin.matcher(new String(requestResponseBytes));
				if(matcherCustomPlugin.find()) {									
					
					String replacedRequestResponse = new StringBuilder(new String(requestResponseBytes)).replace(matcherCustomPlugin.start(1), matcherCustomPlugin.end(1), ret).toString();
					if(messageIsRequest) {
						messageInfo.setRequest(replacedRequestResponse.getBytes());
					} else {
						messageInfo.setResponse(replacedRequestResponse.getBytes());
					}
					
					// DEBUG print
					printToExternalDebugFrame("** Modified " + (messageIsRequest ? "request" : "response") + "\n");
					printToExternalDebugFrame(replacedRequestResponse);
					printToExternalDebugFrame("** \n\n");
					
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


	public ArrayList<Integer> getCustomPluginTools() {
		return customPluginTools;
	}


	public void setCustomPluginTools(ArrayList<Integer> customPluginTools) {
		this.customPluginTools = customPluginTools;
	}
	
	

}
