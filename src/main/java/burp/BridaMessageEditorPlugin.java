package burp;

import java.awt.Component;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;


public class BridaMessageEditorPlugin extends CustomPlugin implements IMessageEditorTabFactory {
	
	private String tabCaption;	
	private CustomPluginEncodingValues customPluginEditedContentEncodingFridaInput;
	private String customPluginEditedContentLocationString;
	private CustomPluginEncodingValues customPluginEditedContentFridaOutputDecoding;
	private String customPluginEditedContentFridaFunctionName;
	private CustomPluginEncodingValues customPluginEditedContentOutputEncoding;
	private BridaMessageEditorPluginOutputLocation customPluginEditedContentLocation;
	
    public static enum BridaMessageEditorPluginOutputLocation {
    	NONE,
    	CONSOLE,
    	COMPLETE,
    	BODY,
    	REGEX
    }
		
	public BridaMessageEditorPlugin(BridaMessageEditorPluginOutputLocation customPluginEditedContentLocation,
									String customPluginEditedContentLocationString,
									CustomPluginEncodingValues customPluginEditedContentEncodingFridaInput,
									CustomPluginEncodingValues customPluginEditedContentFridaOutputDecoding,
									String customPluginEditedContentFridaFunctionName,
									CustomPluginEncodingValues customPluginEditedContentOutputEncoding,
									BurpExtender mainPlugin, String customPluginName, String customPluginExportedFunctionName,
									CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnContextName, 
									CustomPluginExecuteValues customPluginExecute, String customPluginExecuteString,
									CustomPluginParameterValues customPluginParameter, String customPluginParameterString,
									CustomPluginEncodingValues customPluginParameterEncoding,
									CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
									CustomPluginEncodingValues customPluginOutputEncoding,
									CustomPluginEncodingValues customPluginOutputDecoding)  {
		
        super(mainPlugin, customPluginName, customPluginExportedFunctionName,
				customPluginExecuteOn, customPluginExecuteOnContextName, 
				customPluginExecute, customPluginExecuteString,
				customPluginParameter, customPluginParameterString,
				customPluginParameterEncoding,
				customPluginFunctionOutput, customPluginFunctionOutputString,
				customPluginOutputEncoding,
				customPluginOutputDecoding);
                
        this.tabCaption = customPluginFunctionOutputString;        
        this.customPluginEditedContentLocation = customPluginEditedContentLocation;
        this.customPluginEditedContentLocationString = customPluginEditedContentLocationString;
        this.customPluginEditedContentEncodingFridaInput = customPluginEditedContentEncodingFridaInput;
        this.customPluginEditedContentFridaOutputDecoding = customPluginEditedContentFridaOutputDecoding;
        this.customPluginEditedContentFridaFunctionName = customPluginEditedContentFridaFunctionName;
        this.customPluginEditedContentOutputEncoding = customPluginEditedContentOutputEncoding;
        
        this.setType(CustomPlugin.CustomPluginType.IMESSAGEEDITORTAB);
        
	}
	
	@Override
	public String exportPlugin() {
		
		String result = "";
		
		result = result + getType().ordinal() + ";";
		result = result + customPluginEditedContentLocation.ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(customPluginEditedContentLocationString.getBytes()) + ";";
		result = result + customPluginEditedContentEncodingFridaInput.ordinal() + ";";
		result = result + customPluginEditedContentFridaOutputDecoding.ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(customPluginEditedContentFridaFunctionName.getBytes()) + ";";
		result = result + customPluginEditedContentOutputEncoding.ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginName().getBytes()) + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExportedFunctionName().getBytes()) + ";";
		result = result + getCustomPluginExecuteOn().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExecuteOnContextName().getBytes()) + ";";
		result = result + getCustomPluginExecute().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExecuteString().getBytes()) + ";";
		result = result + getCustomPluginParameter().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginParameterString().getBytes()) + ";";
		result = result + getCustomPluginParameterEncoding().ordinal() + ";";		
		result = result + getCustomPluginFunctionOutput().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginFunctionOutputString().getBytes()) + ";";
		result = result + getCustomPluginOutputEncoding().ordinal() + ";";
		result = result + getCustomPluginOutputDecoding().ordinal();
				
		return result;
		
	}
	
	public void enable() {
    	getMainPlugin().callbacks.registerMessageEditorTabFactory(this);
    	setOnOff(true);
    }
    
    public void disable() {
    	getMainPlugin().callbacks.removeMessageEditorTabFactory(this);
    	setOnOff(false);
    }
    
    @Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new BridaMessageEditorPluginInner(controller,editable);
	}
    
    public class BridaMessageEditorPluginInner implements IMessageEditorTab {
    	
    	private IMessageEditorController controller;
    	private ITextEditor txtInput;
    	private byte[] currentMessage;
    	private boolean isRequest;
    	
    	public BridaMessageEditorPluginInner(IMessageEditorController controller, boolean editable) {
    		this.controller = controller;
    		this.txtInput = getMainPlugin().callbacks.createTextEditor();
            this.txtInput.setEditable(editable);
    	}    	

		@Override
		public String getTabCaption() {
			return tabCaption;
		}
	
		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}
	
		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			
			this.isRequest = isRequest;
			return isPluginEnabled(content,isRequest);
	
		}
	
		@Override
		public boolean isModified() {
			return txtInput.isTextModified();
		}
	
		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
	
		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			
			if (content == null) {
	            
				// clear our display
	            txtInput.setText(null);
	            
			} else {
	
				String[] parameters = getParametersCustomPlugin(content,isRequest);
				String ret = callFrida(parameters);
				
				// DEBUG print
				printToExternalDebugFrame("*** START ***\n\n");
				printToExternalDebugFrame("** Original " + (isRequest ? "request" : "response") + "\n");
				printToExternalDebugFrame(new String(content));
				printToExternalDebugFrame("\n\n");
				if(parameters.length > 0) {
					printToExternalDebugFrame("** Frida parameters (after encoding)\n");
					for(int i=0;i<parameters.length;i++) {
						printToExternalDebugFrame("* Parameter " + (i+1) + ": " + parameters[i] + "\n");
					}
					printToExternalDebugFrame("\n\n");
				} else {
					printToExternalDebugFrame("** NO Frida parameters\n\n");
				}
				printToExternalDebugFrame("** Frida returned value (after deconding/encoding), printed in the tab\n");
				printToExternalDebugFrame(ret);
				printToExternalDebugFrame("\n\n");
				printToExternalDebugFrame("*** END ***\n\n");
			
				txtInput.setText(ret.getBytes());	
				currentMessage = content;
				
			}
			
		}	
	
		@Override
		public byte[] getMessage() {
			
			// In view mode no content is updated
			if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.NONE) {
				return currentMessage;							
			}
			
			if (txtInput.isTextModified()) {
				
				// Parameter -> edited message
				byte[] editedContent = txtInput.getText();
				
				// Encode parameter
				String[] parameters = new String[] {encodeCustomPluginValue(editedContent,customPluginEditedContentEncodingFridaInput)};

				// Call frida
				if(getMainPlugin().serverStarted && getMainPlugin().applicationSpawned) {
					
					// DEBUG print
					printToExternalDebugFrame("*** START EDITED TAB ***\n\n");
					printToExternalDebugFrame("** Edited value from plugin Message Editor tab (after encoding)\n");
					printToExternalDebugFrame(parameters[0]);
					printToExternalDebugFrame("\n\n");
			    	
			    	// Call Brida						
					String pyroUrl = "PYRO:BridaServicePyro@" + getMainPlugin().pyroHost.getText().trim() + ":" + getMainPlugin().pyroPort.getText().trim();
					String ret = null;
					try {
						PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
						ret = (String)pp.call("callexportfunction",customPluginEditedContentFridaFunctionName,parameters);
						pp.close();
					} catch(IOException e) {
						getMainPlugin().printException(e,"Error when calling Frida exported function " + customPluginEditedContentFridaFunctionName + " through Pyro in custom plugin");
						return currentMessage;
					}
										
					// Handle output
					if(ret != null) {
						 
						// Decode function output if requested
						byte[] customPluginEditedContentOutputDecoded =  decodeCustomPluginOutput(ret,customPluginEditedContentFridaOutputDecoding);
						
						// Encode plugin output if requested
						String customPluginEditedContentOutputEncoded = encodeCustomPluginValue(customPluginEditedContentOutputDecoded, customPluginEditedContentOutputEncoding);
						
						// DEBUG print
						printToExternalDebugFrame("** Frida returned value (after deconding/encoding) on edited content\n");
						printToExternalDebugFrame(ret);
						printToExternalDebugFrame("\n\n");						
						
						if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.CONSOLE) {
							getMainPlugin().printSuccessMessage("Return value of edited function " + tabCaption);
							getMainPlugin().printSuccessMessage(customPluginEditedContentOutputEncoded);

							// DEBUG print
							printToExternalDebugFrame("** Output to Brida console and returned original request/response\n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return currentMessage;
							
						} else if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.COMPLETE) {
							
							// DEBUG print
							printToExternalDebugFrame("** Replacing entire " + (isRequest ? "request" : "response") + ". Modified one:\n");
							printToExternalDebugFrame(customPluginEditedContentOutputEncoded);
							printToExternalDebugFrame("** \n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return customPluginEditedContentOutputEncoded.getBytes();
							
						} else if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.BODY) {
							
							List<java.lang.String> currentHeaders;
							if(isRequest) {
								IRequestInfo currentRequestInfo = getMainPlugin().helpers.analyzeRequest(currentMessage);
								currentHeaders = currentRequestInfo.getHeaders();
							} else {
								IResponseInfo currentResponseInfo = getMainPlugin().helpers.analyzeResponse(currentMessage);
								currentHeaders = currentResponseInfo.getHeaders();
							}
							
							byte[] newHttpMessage = getMainPlugin().helpers.buildHttpMessage(currentHeaders, customPluginEditedContentOutputEncoded.getBytes());
							
							// DEBUG print
							printToExternalDebugFrame("** Replacing the body of the message. Modified " + (isRequest ? "request" : "response") + ":\n");
							printToExternalDebugFrame(new String(newHttpMessage));
							printToExternalDebugFrame("** \n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return newHttpMessage;
							
						} else {
							
							// REGEX
							Pattern patternMessageEditorModified = Pattern.compile(customPluginEditedContentLocationString);
							Matcher matcherMessageEditorModified = patternMessageEditorModified.matcher(new String(currentMessage));
							if(matcherMessageEditorModified.find()) {
								
								String newHttpMessage = new StringBuilder(new String(currentMessage)).replace(matcherMessageEditorModified.start(1), matcherMessageEditorModified.end(1), customPluginEditedContentOutputEncoded).toString();
								
								// DEBUG print
								printToExternalDebugFrame("** Modified " + (isRequest ? "request" : "response") + " after REGEX substitution:\n");
								printToExternalDebugFrame(newHttpMessage);
								printToExternalDebugFrame("** \n\n");
								printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
								
								return newHttpMessage.getBytes();
								
							} else {
								getMainPlugin().printException(null,"No group found in REGEX for edited content of IMessageEditor tab " + tabCaption + ". Printing the result in Brida console and returning original request/response.");
								getMainPlugin().printSuccessMessage("Return value of edited function " + tabCaption);
								getMainPlugin().printSuccessMessage(customPluginEditedContentOutputEncoded);
								
								// DEBUG print
								printToExternalDebugFrame("** Output to Brida console and returning original " + (isRequest ? "request" : "response") + " because REGEX did not match\n\n");
								printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
								
								return currentMessage;
							}	
							
						}
						
					} else {
						
						getMainPlugin().printException(null,"Frida exported function " + customPluginEditedContentFridaFunctionName + " returns an empty response. Returning original message from IMessageEditorTab");
						
						// DEBUG print
						printToExternalDebugFrame("** Frida function returns no output\n\n");
						printToExternalDebugFrame("*** END EDITED TAB ***\n\n");						
						
						return currentMessage;
						
					}
					
				} else {
					getMainPlugin().printException(null,"Error when calling Frida exported function " + customPluginEditedContentFridaFunctionName + " through Pyro in custom plugin. First start Pyro server and spawn application!");
					return currentMessage;
				}
				
				
			} else {
				return currentMessage;
			}
		}
	
    }

	public CustomPluginEncodingValues getCustomPluginEditedContentEncodingFridaInput() {
		return customPluginEditedContentEncodingFridaInput;
	}

	public void setCustomPluginEditedContentEncodingFridaInput(
			CustomPluginEncodingValues customPluginEditedContentEncodingFridaInput) {
		this.customPluginEditedContentEncodingFridaInput = customPluginEditedContentEncodingFridaInput;
	}

	public String getCustomPluginEditedContentLocationString() {
		return customPluginEditedContentLocationString;
	}

	public void setCustomPluginEditedContentLocationString(String customPluginEditedContentLocationString) {
		this.customPluginEditedContentLocationString = customPluginEditedContentLocationString;
	}

	public CustomPluginEncodingValues getCustomPluginEditedContentFridaOutputDecoding() {
		return customPluginEditedContentFridaOutputDecoding;
	}

	public void setCustomPluginEditedContentFridaOutputDecoding(
			CustomPluginEncodingValues customPluginEditedContentFridaOutputDecoding) {
		this.customPluginEditedContentFridaOutputDecoding = customPluginEditedContentFridaOutputDecoding;
	}

	public String getCustomPluginEditedContentFridaFunctionName() {
		return customPluginEditedContentFridaFunctionName;
	}

	public void setCustomPluginEditedContentFridaFunctionName(String customPluginEditedContentFridaFunctionName) {
		this.customPluginEditedContentFridaFunctionName = customPluginEditedContentFridaFunctionName;
	}

	public CustomPluginEncodingValues getCustomPluginEditedContentOutputEncoding() {
		return customPluginEditedContentOutputEncoding;
	}

	public void setCustomPluginEditedContentOutputEncoding(
			CustomPluginEncodingValues customPluginEditedContentOutputEncoding) {
		this.customPluginEditedContentOutputEncoding = customPluginEditedContentOutputEncoding;
	}

	public BridaMessageEditorPluginOutputLocation getCustomPluginEditedContentLocation() {
		return customPluginEditedContentLocation;
	}

	public void setCustomPluginEditedContentLocation(
			BridaMessageEditorPluginOutputLocation customPluginEditedContentLocation) {
		this.customPluginEditedContentLocation = customPluginEditedContentLocation;
	}
    
    

}
