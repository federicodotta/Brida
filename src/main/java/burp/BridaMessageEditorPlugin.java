package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;


public class BridaMessageEditorPlugin extends CustomPlugin implements IMessageEditorTabFactory {
	
	private String tabCaption;	
	private List<BurpExtender.Transformation> customPluginEditedContentEncodingFridaInput;
	private String customPluginEditedContentLocationString;
	private List<BurpExtender.Transformation> customPluginEditedContentFridaOutputDecoding;
	private String customPluginEditedContentFridaFunctionName;
	private List<BurpExtender.Transformation> customPluginEditedContentOutputEncoding;
	private BridaMessageEditorPluginOutputLocation customPluginEditedContentLocation;
	
    public static enum BridaMessageEditorPluginOutputLocation {
    	NONE ("Discard (view only mode)"),
    	CONSOLE ("Print in Brida console and return original request/response"),
    	COMPLETE_RECALCULATE ("Replace complete request/response (length updated)"),
    	COMPLETE_NOT_RECALCULATE ("Replace complete request/response (length NOT updated)"),
    	BODY ("Replace request/response body"),
    	HEADERS ("Replace request/response headers"),
    	REGEX ("Regex (with parenthesys)");
    	
    	private final String name;
		
		private BridaMessageEditorPluginOutputLocation(String n) {
			name = n;
		}
		
		public String toString() {
			return this.name;
		}
		
		public static BridaMessageEditorPluginOutputLocation getEnumByName(String name){
	        for(BridaMessageEditorPluginOutputLocation r : BridaMessageEditorPluginOutputLocation.values()){
	            if(r.name.equals(name)) return r;
	        }
	        return null;
	    }
    }
	
	public BridaMessageEditorPlugin(BridaMessageEditorPluginOutputLocation customPluginEditedContentLocation,
									String customPluginEditedContentLocationString,
									List<BurpExtender.Transformation> customPluginEditedContentEncodingFridaInput,
									List<BurpExtender.Transformation> customPluginEditedContentFridaOutputDecoding,
									String customPluginEditedContentFridaFunctionName,
									List<BurpExtender.Transformation> customPluginEditedContentOutputEncoding,
									BurpExtender mainPlugin, String customPluginName, String customPluginExportedFunctionName,
									CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnContextName, 
									CustomPluginExecuteValues customPluginExecute, String customPluginExecuteString,
									CustomPluginParameterValues customPluginParameter, String customPluginParameterString,
									List<BurpExtender.Transformation> customPluginParameterEncoding,
									CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
									List<BurpExtender.Transformation> customPluginOutputEncoding,
									List<BurpExtender.Transformation> customPluginOutputDecoding)  {
		
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
		result = result + customPluginEditedContentEncodingFridaInput.toString() + ";";
		result = result + customPluginEditedContentFridaOutputDecoding.toString() + ";";
		result = result + Base64.getEncoder().encodeToString(customPluginEditedContentFridaFunctionName.getBytes()) + ";";
		result = result + customPluginEditedContentOutputEncoding.toString() + ";";
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
	
				List<byte[]> parameters = getParametersCustomPlugin(content,isRequest);
				byte[] ret = callFrida(parameters);
				
				// DEBUG print
				printToExternalDebugFrame("*** START ***\n\n");
				printToExternalDebugFrame("** Original " + (isRequest ? "request" : "response") + "\n");
				printToExternalDebugFrame(new String(content));
				printToExternalDebugFrame("\n\n");
				if(parameters.size() > 0) {
					printToExternalDebugFrame("** Frida parameters (after encoding)\n");
					for(int i=0;i<parameters.size();i++) {
						printToExternalDebugFrame("* Parameter " + (i+1) + ": " + new String(parameters.get(i)) + "\n");
					}
					printToExternalDebugFrame("\n\n");
				} else {
					printToExternalDebugFrame("** NO Frida parameters\n\n");
				}
				printToExternalDebugFrame("** Frida returned value (after deconding/encoding), printed in the tab\n");
				printToExternalDebugFrame(new String(ret));
				printToExternalDebugFrame("\n\n");
				printToExternalDebugFrame("*** END ***\n\n");
			
				txtInput.setText(((ret != null) ? ret : new byte[0]));	
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
				List<byte[]> parameters = new ArrayList<byte[]>();
				parameters.add(encodeCustomPluginValue(editedContent,customPluginEditedContentEncodingFridaInput, getMainPlugin()));

				// Call frida
				if(getMainPlugin().serverStarted && getMainPlugin().applicationSpawned) {
					
					// DEBUG print
					printToExternalDebugFrame("*** START EDITED TAB ***\n\n");
					printToExternalDebugFrame("** Edited value from plugin Message Editor tab (after encoding)\n");
					printToExternalDebugFrame(new String(parameters.get(0)));
					printToExternalDebugFrame("\n\n");
			    	
			    	// Call Brida						
					String pyroUrl = "PYRO:BridaServicePyro@" + getMainPlugin().pyroHost.getText().trim() + ":" + getMainPlugin().pyroPort.getText().trim();
					String ret = null;
					try {
						PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
						//ret = (String)pp.call("callexportfunction",customPluginEditedContentFridaFunctionName,parameters);
						ret = (String)getMainPlugin().executePyroCall(pp,"callexportfunction",new Object[] {customPluginEditedContentFridaFunctionName,convertParametersForFrida(parameters, getMainPlugin())});
						pp.close();
					} catch(Exception e) {
						getMainPlugin().printException(e,"Error when calling Frida exported function " + customPluginEditedContentFridaFunctionName + " through Pyro in custom plugin");
						return currentMessage;
					}
										
					// Handle output
					if(ret != null) {
						 
						// Decode function output if requested
						byte[] customPluginEditedContentOutputDecoded =  decodeCustomPluginOutput(ret,customPluginEditedContentFridaOutputDecoding, getMainPlugin());
						
						// Encode plugin output if requested
						byte[] customPluginEditedContentOutputEncoded = encodeCustomPluginValue(customPluginEditedContentOutputDecoded, customPluginEditedContentOutputEncoding, getMainPlugin());
						
						// DEBUG print
						printToExternalDebugFrame("** Frida returned value (after deconding/encoding) on edited content\n");
						printToExternalDebugFrame(ret);
						printToExternalDebugFrame("\n\n");						
						
						if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.CONSOLE) {
							getMainPlugin().printSuccessMessage("Return value of edited function " + tabCaption);
							getMainPlugin().printSuccessMessage(new String(customPluginEditedContentOutputEncoded));

							// DEBUG print
							printToExternalDebugFrame("** Output to Brida console and returned original request/response\n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return currentMessage;
						
						} else if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.COMPLETE_RECALCULATE || customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.COMPLETE_NOT_RECALCULATE) {
							
							byte[] messageWithCorrectContentLength;			
							if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.COMPLETE_NOT_RECALCULATE) {
								
								messageWithCorrectContentLength = customPluginEditedContentOutputEncoded;
								
							} else {
								
								messageWithCorrectContentLength = recalculateMessageBodyLength(customPluginEditedContentOutputEncoded,isRequest);
								
							}
							
							// DEBUG print
							printToExternalDebugFrame("** Replacing entire " + (isRequest ? "request" : "response") + ". Modified one:\n");
							printToExternalDebugFrame(new String(messageWithCorrectContentLength));
							printToExternalDebugFrame("\n\n** \n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return messageWithCorrectContentLength;
							
						} else if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.HEADERS) {
							
							
							byte[] newHttpMessage = replaceOutputHeaders(currentMessage, isRequest, new String(customPluginEditedContentOutputEncoded));
														
							// DEBUG print
							printToExternalDebugFrame("** Replacing the headers of the message. Modified " + (isRequest ? "request" : "response") + ":\n");
							printToExternalDebugFrame(new String(newHttpMessage));
							printToExternalDebugFrame("\n\n** \n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return newHttpMessage;
								
						} else if(customPluginEditedContentLocation == BridaMessageEditorPluginOutputLocation.BODY) {
							
							byte[] newHttpMessage = replaceOutputBody(currentMessage, isRequest, customPluginEditedContentOutputEncoded);
																					
							// DEBUG print
							printToExternalDebugFrame("** Replacing the body of the message. Modified " + (isRequest ? "request" : "response") + ":\n");
							printToExternalDebugFrame(new String(newHttpMessage));
							printToExternalDebugFrame("\n\n** \n\n");
							printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
							
							return newHttpMessage;
							
						} else {
							
							// REGEX
							Pattern patternMessageEditorModified = Pattern.compile(customPluginEditedContentLocationString);
							Matcher matcherMessageEditorModified = patternMessageEditorModified.matcher(new String(currentMessage));
							if(matcherMessageEditorModified.find()) {
								
								String newHttpMessage = new StringBuilder(new String(currentMessage)).replace(matcherMessageEditorModified.start(1), matcherMessageEditorModified.end(1), new String(customPluginEditedContentOutputEncoded)).toString();
								
								// DEBUG print
								printToExternalDebugFrame("** Modified " + (isRequest ? "request" : "response") + " after REGEX substitution:\n");
								printToExternalDebugFrame(newHttpMessage);
								printToExternalDebugFrame("\n\n** \n\n");
								printToExternalDebugFrame("*** END EDITED TAB ***\n\n");
								
								return newHttpMessage.getBytes();
								
							} else {
								getMainPlugin().printException(null,"No group found in REGEX for edited content of IMessageEditor tab " + tabCaption + ". Printing the result in Brida console and returning original request/response.");
								getMainPlugin().printSuccessMessage("Return value of edited function " + tabCaption);
								getMainPlugin().printSuccessMessage(new String(customPluginEditedContentOutputEncoded));
								
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

	public List<BurpExtender.Transformation> getCustomPluginEditedContentEncodingFridaInput() {
		return customPluginEditedContentEncodingFridaInput;
	}

	public void setCustomPluginEditedContentEncodingFridaInput(
			List<BurpExtender.Transformation> customPluginEditedContentEncodingFridaInput) {
		this.customPluginEditedContentEncodingFridaInput = customPluginEditedContentEncodingFridaInput;
	}

	public String getCustomPluginEditedContentLocationString() {
		return customPluginEditedContentLocationString;
	}

	public void setCustomPluginEditedContentLocationString(String customPluginEditedContentLocationString) {
		this.customPluginEditedContentLocationString = customPluginEditedContentLocationString;
	}

	public List<BurpExtender.Transformation> getCustomPluginEditedContentFridaOutputDecoding() {
		return customPluginEditedContentFridaOutputDecoding;
	}

	public void setCustomPluginEditedContentFridaOutputDecoding(
			List<BurpExtender.Transformation> customPluginEditedContentFridaOutputDecoding) {
		this.customPluginEditedContentFridaOutputDecoding = customPluginEditedContentFridaOutputDecoding;
	}

	public String getCustomPluginEditedContentFridaFunctionName() {
		return customPluginEditedContentFridaFunctionName;
	}

	public void setCustomPluginEditedContentFridaFunctionName(String customPluginEditedContentFridaFunctionName) {
		this.customPluginEditedContentFridaFunctionName = customPluginEditedContentFridaFunctionName;
	}

	public List<BurpExtender.Transformation> getCustomPluginEditedContentOutputEncoding() {
		return customPluginEditedContentOutputEncoding;
	}

	public void setCustomPluginEditedContentOutputEncoding(
			List<BurpExtender.Transformation> customPluginEditedContentOutputEncoding) {
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
