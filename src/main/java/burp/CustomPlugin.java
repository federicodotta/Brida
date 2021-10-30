package burp;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;

public abstract class CustomPlugin {

	private BurpExtender mainPlugin;
	
	private boolean isEnabled;
	
    // Custom hook variables
	private String customPluginName;
	private String customPluginExportedFunctionName;
    private CustomPluginExecuteOnValues customPluginExecuteOn;
    private String customPluginExecuteOnContextName;
    private CustomPluginExecuteValues customPluginExecute;
    private String customPluginExecuteString;
    private CustomPluginParameterValues customPluginParameter;
    private String customPluginParameterString;
    private List<BurpExtender.Transformation> customPluginParameterEncoding;
    private CustomPluginFunctionOutputValues customPluginFunctionOutput;
    private String customPluginFunctionOutputString;
    private List<BurpExtender.Transformation> customPluginOutputEncoding;
    private List<BurpExtender.Transformation> customPluginOutputDecoding;    
    private CustomPluginType type;
    
    private JTextArea debugTextArea;
    private boolean isDebugEnabled;
    
    public CustomPlugin(BurpExtender mainPlugin, String customPluginName, String customPluginExportedFunctionName,
			CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnContextName, 
			CustomPluginExecuteValues customPluginExecute, String customPluginExecuteString,
			CustomPluginParameterValues customPluginParameter, String customPluginParameterString,
			List<BurpExtender.Transformation> customPluginParameterEncoding,
			CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
			List<BurpExtender.Transformation> customPluginOutputEncoding,
			List<BurpExtender.Transformation> customPluginOutputDecoding) {
		
		this.mainPlugin = mainPlugin;
		this.customPluginName = customPluginName;
		this.customPluginExportedFunctionName = customPluginExportedFunctionName;
		this.customPluginExecuteOn = customPluginExecuteOn;
		this.customPluginExecuteOnContextName = customPluginExecuteOnContextName;
		this.customPluginExecute = customPluginExecute;
		this.customPluginExecuteString = customPluginExecuteString;
		this.customPluginParameter = customPluginParameter;
		this.customPluginParameterString = customPluginParameterString;
		this.customPluginParameterEncoding = customPluginParameterEncoding;
		this.customPluginFunctionOutput = customPluginFunctionOutput;
		this.customPluginFunctionOutputString = customPluginFunctionOutputString;
		this.customPluginOutputEncoding = customPluginOutputEncoding;
		this.customPluginOutputDecoding = customPluginOutputDecoding;
		
		this.isEnabled = false;
		
		this.debugTextArea = null;
		this.isDebugEnabled = false;
		
	}
    
    public abstract void enable();
    public abstract void disable();
    public abstract String exportPlugin();
    	
    public static enum CustomPluginType {
    	IHTTPLISTENER,
    	IMESSAGEEDITORTAB,
    	ICONTEXTMENU,
    	JBUTTON
    }
	
    public static enum CustomPluginExecuteOnValues {
    	ALL,
    	REQUESTS,
    	RESPONSES,
    	CONTEXT,
    	BUTTON
    }
    public static enum CustomPluginExecuteValues {
    	ALWAYS,
    	PLAINTEXT,
    	REGEX
    }
    public static enum CustomPluginParameterValues {
    	NONE ("none"),
    	COMPLETE ("complete request/response"),
    	HEADERS ("headers"),
    	BODY ("body"),
    	CONTEXT ("highlighted value in request/response"),
    	REGEX ("regex (with parenthesis)"),
    	FIXED ("fixed (#,# as separator)"),
    	POPUP ("ask to user with popup (#,# as separator)");
    	
    	private final String name;
		
		private CustomPluginParameterValues(String n) {
			name = n;
		}
		
		public String toString() {
			return this.name;
		}
		
		public static CustomPluginParameterValues getEnumByName(String name){
	        for(CustomPluginParameterValues r : CustomPluginParameterValues.values()){
	            if(r.name.equals(name)) return r;
	        }
	        return null;
	    }
    }
    
    public static EnumSet<CustomPluginParameterValues> functionParametersIHttpListener = EnumSet.of(
    		CustomPluginParameterValues.NONE,
    		CustomPluginParameterValues.COMPLETE, 
    		CustomPluginParameterValues.HEADERS, 
    		CustomPluginParameterValues.BODY, 
    		CustomPluginParameterValues.REGEX, 
    		CustomPluginParameterValues.FIXED);
	public static EnumSet<CustomPluginParameterValues> functionParametersIMessageEditorTab = EnumSet.of(
			CustomPluginParameterValues.NONE,
    		CustomPluginParameterValues.COMPLETE, 
    		CustomPluginParameterValues.HEADERS, 
    		CustomPluginParameterValues.BODY, 
    		CustomPluginParameterValues.REGEX, 
    		CustomPluginParameterValues.FIXED, 
    		CustomPluginParameterValues.POPUP);
	public static EnumSet<CustomPluginParameterValues> functionParametersIContextMenu = EnumSet.of(
			CustomPluginParameterValues.NONE,
    		CustomPluginParameterValues.COMPLETE, 
    		CustomPluginParameterValues.HEADERS, 
    		CustomPluginParameterValues.BODY, 
    		CustomPluginParameterValues.REGEX, 
    		CustomPluginParameterValues.CONTEXT,
    		CustomPluginParameterValues.FIXED, 
    		CustomPluginParameterValues.POPUP);
	public static EnumSet<CustomPluginParameterValues> functionParametersJButton = EnumSet.of(
			CustomPluginParameterValues.NONE,
    		CustomPluginParameterValues.FIXED, 
    		CustomPluginParameterValues.POPUP);
    
    public static enum CustomPluginFunctionOutputValues {
    	BRIDA ("print in Brida console"),
    	POPUP ("print in popup"),
    	CONTEXT ("replace highlighted value in request/response"),
    	REGEX ("replace in request/response with regex (with parenthesys)"),
    	MESSAGE_EDITOR ("Print in Message Editor tab named"),
    	HEADERS ("Replace request/response headers"),
    	BODY ("Replace request/response body"),
    	COMPLETE_RECALCULATE ("Replace complete request/response (length updated)"),
    	COMPLETE_NOT_RECALCULATE ("Replace complete request/response (length NOT updated)");
    	
    	private final String name;
		
		private CustomPluginFunctionOutputValues(String n) {
			name = n;
		}
		
		public String toString() {
			return this.name;
		}
		
		public static CustomPluginFunctionOutputValues getEnumByName(String name){
	        for(CustomPluginFunctionOutputValues r : CustomPluginFunctionOutputValues.values()){
	            if(r.name.equals(name)) return r;
	        }
	        return null;
	    }
    }
    
    public static EnumSet<CustomPluginFunctionOutputValues> functionOutputValuesIHttpListener = EnumSet.of(
    			CustomPluginFunctionOutputValues.BRIDA,
    			CustomPluginFunctionOutputValues.COMPLETE_RECALCULATE,
    			CustomPluginFunctionOutputValues.COMPLETE_NOT_RECALCULATE,
    			CustomPluginFunctionOutputValues.HEADERS,
    			CustomPluginFunctionOutputValues.BODY,
    			CustomPluginFunctionOutputValues.REGEX);
    public static EnumSet<CustomPluginFunctionOutputValues> functionOutputValuesIMessageEditorTab = EnumSet.of(
    			CustomPluginFunctionOutputValues.MESSAGE_EDITOR);
    public static EnumSet<CustomPluginFunctionOutputValues> functionOutputValuesIContextMenu = EnumSet.of(
    			CustomPluginFunctionOutputValues.BRIDA, 
    			CustomPluginFunctionOutputValues.POPUP,
    			CustomPluginFunctionOutputValues.CONTEXT,
    			CustomPluginFunctionOutputValues.COMPLETE_RECALCULATE,
    			CustomPluginFunctionOutputValues.COMPLETE_NOT_RECALCULATE,
    			CustomPluginFunctionOutputValues.HEADERS,
    			CustomPluginFunctionOutputValues.BODY,
    			CustomPluginFunctionOutputValues.REGEX);
    public static EnumSet<CustomPluginFunctionOutputValues> functionOutputValuesJButton = EnumSet.of(
    			CustomPluginFunctionOutputValues.BRIDA);
    
    public boolean isPluginEnabled(byte[] requestResponseBytes, boolean isRequest) {
    	
    	// If all is enabled
    	if(mainPlugin.serverStarted && mainPlugin.applicationSpawned) {
    		
    		// If we want inspect request/response/all
			if(customPluginExecuteOn == CustomPluginExecuteOnValues.ALL || 
			  (customPluginExecuteOn == CustomPluginExecuteOnValues.REQUESTS && isRequest) ||
			  (customPluginExecuteOn == CustomPluginExecuteOnValues.RESPONSES && !isRequest)) {
				
				String reqResponseString = new String(requestResponseBytes);
				
				Matcher matcherExecute = null;
				if(customPluginExecute == CustomPluginExecuteValues.REGEX) {
					Pattern patternExecute = Pattern.compile(customPluginExecuteString);
					matcherExecute = patternExecute.matcher(reqResponseString);
				}
				
				// If we are processing a request/response that we want to inspect
				if(customPluginExecute == CustomPluginExecuteValues.ALWAYS ||
				   (customPluginExecute == CustomPluginExecuteValues.PLAINTEXT && reqResponseString.contains(customPluginExecuteString)) || 
				   (customPluginExecute == CustomPluginExecuteValues.REGEX && matcherExecute.find())) {
										
					return true;
					
				}			
				
			}
    		
    	}
    	
    	return false;
    	
    }
    
    public static String[] convertParametersForFrida(List<byte[]> parameters, BurpExtender mainPlugin) {
    	
    	String[] output = new String[parameters.size()];
    	for(int i=0;i<parameters.size();i++) {
    		try {
    			output[i] = new String(parameters.get(i), "ISO-8859-1");
    		} catch (UnsupportedEncodingException e) {
    			mainPlugin.printException(e,"Error converting parameter to ISO-8859-1, defaulting to standard encoding");
    			output[i] = new String(parameters.get(i));
    		} 	
    	}
    	return output;
    }
    
    public byte[] callFrida(List<byte[]> parameters) {
    	
    	// If all is enabled
    	if(mainPlugin.serverStarted && mainPlugin.applicationSpawned) {
    	
	    	// Call Brida						
			String pyroUrl = "PYRO:BridaServicePyro@" + mainPlugin.pyroHost.getText().trim() + ":" + mainPlugin.pyroPort.getText().trim();
			String ret = null;
			try {
				PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
				//ret = (String)pp.call("callexportfunction",customPluginExportedFunctionName,parameters);
				ret = (String)mainPlugin.executePyroCall(pp,"callexportfunction",new Object[] {customPluginExportedFunctionName,convertParametersForFrida(parameters, mainPlugin)});
				pp.close();
			} catch(Exception e) {
				mainPlugin.printException(e,"Error when calling Frida exported function " + customPluginExportedFunctionName + " through Pyro in custom plugin");
			}   
			
			// Handle output
			if(ret != null) {
				 
				// Decode function output if requested
				byte[] customPluginOutputDecoded =  decodeCustomPluginOutput(ret,customPluginOutputDecoding, mainPlugin);
				
				// Encode plugin output if requested
				byte[] customPluginOutputEncoded = encodeCustomPluginValue(customPluginOutputDecoded, customPluginOutputEncoding, mainPlugin);
					
				return customPluginOutputEncoded;
				
			} else {
				
				return null;
				
			}
    	
    	} else {
    		mainPlugin.printException(null, "Impossible to call Frida if Pyro is not started and application is not spawned");
    		return null;
    	}
    	
    }
    
    public void printToExternalDebugFrame(String message) {
    	
    	if(isDebugEnabled) {
    		    		
    		debugTextArea.append(message);
    	}
    	
    }
    
    public void enableDebugToExternalFrame() {
    	    	
    	if(!isDebugEnabled && type != CustomPluginType.JBUTTON) {
    	
			JFrame frame = new JFrame(customPluginName + " debugging window");	
			frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);			
			frame.setPreferredSize(new Dimension(1200, 800));			
			frame.setLayout(new BorderLayout());
			
			WindowListener exitListener = new WindowAdapter() {
	
			    @Override
			    public void windowClosing(WindowEvent e) {
			        //stdout.println("CLOSING!!!");
			    	debugTextArea = null;
			    	isDebugEnabled = false;
			        frame.dispose();
			    }
			};
			frame.addWindowListener(exitListener);
			
			debugTextArea = new JTextArea();
			debugTextArea.setEditable(false);
	        JScrollPane scrollDebugTextArea = new JScrollPane(debugTextArea);
	        scrollDebugTextArea.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
	        scrollDebugTextArea.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	        			
	        frame.getContentPane().add(scrollDebugTextArea);
			
	  		frame.pack();
	  		frame.setVisible(true);
	  		
	  		isDebugEnabled = true;
	  		
    	} else if(type == CustomPluginType.JBUTTON) {
    		
    		getMainPlugin().printException(null, "Debug window not enabled on JButton plugins (current plugin:  " + customPluginName + ")");
    		
    	} else {
    		
    		getMainPlugin().printException(null, "Debug is already enabled for plugin " + customPluginName);
    		
    	}
    	
    	
    }
    
    public List<byte[]> getParametersCustomPlugin(byte[] requestResponseBytes, boolean isRequest) {
    	
    	// Parameters
    	List<byte[]> parametersCustomPlugin = new ArrayList<byte[]>();
		if(customPluginParameter == CustomPluginParameterValues.NONE) {							
			//parametersCustomPlugin = new ArrayList<byte[]>();							
		} else if(customPluginParameter == CustomPluginParameterValues.COMPLETE) {							
			parametersCustomPlugin.add(encodeCustomPluginValue(requestResponseBytes,customPluginParameterEncoding, mainPlugin));
		} else if(customPluginParameter == CustomPluginParameterValues.BODY) {
			int curBodyIndex;
			if(isRequest) {
				IRequestInfo currentRequestInfo = mainPlugin.helpers.analyzeRequest(requestResponseBytes);
				curBodyIndex = currentRequestInfo.getBodyOffset();								
			} else {
				IResponseInfo currentResponseInfo = mainPlugin.helpers.analyzeResponse(requestResponseBytes);
				curBodyIndex = currentResponseInfo.getBodyOffset();
			}
			parametersCustomPlugin.add(encodeCustomPluginValue(Arrays.copyOfRange(requestResponseBytes, curBodyIndex, requestResponseBytes.length),customPluginParameterEncoding, mainPlugin));
		} else if(customPluginParameter == CustomPluginParameterValues.HEADERS) {
			int curBodyIndex;
			if(isRequest) {
				IRequestInfo currentRequestInfo = mainPlugin.helpers.analyzeRequest(requestResponseBytes);
				curBodyIndex = currentRequestInfo.getBodyOffset();								
			} else {
				IResponseInfo currentResponseInfo = mainPlugin.helpers.analyzeResponse(requestResponseBytes);
				curBodyIndex = currentResponseInfo.getBodyOffset();
			}
			parametersCustomPlugin.add(encodeCustomPluginValue(Arrays.copyOfRange(requestResponseBytes, 0, curBodyIndex-4),customPluginParameterEncoding, mainPlugin));
		/*} else if(customPluginParameter == CustomPluginParameterValues.CONTEXT) {
			
			IHttpRequestResponse[] selectedItems = mainPlugin.currentInvocation.getSelectedMessages();
			int[] selectedBounds = mainPlugin.currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = mainPlugin.currentInvocation.getInvocationContext();
			
			byte[] selectedRequestOrResponse = null;
			if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST || selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
				selectedRequestOrResponse = selectedItems[0].getRequest();
			} else {
				selectedRequestOrResponse = selectedItems[0].getResponse();
			}
			
			byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
			parametersCustomPlugin = new String[] { encodeCustomPluginValue(selectedPortion,customPluginParameterEncoding) } ;
			*/
		} else if(customPluginParameter == CustomPluginParameterValues.REGEX) {
			Pattern patternCustomPlugin = Pattern.compile(customPluginParameterString);
			Matcher matcherCustomPlugin = patternCustomPlugin.matcher(new String(requestResponseBytes));
			if(matcherCustomPlugin.find()) {
				//parametersCustomPlugin = new String[matcherCustomPlugin.groupCount()];
				for(int i=1;i<=matcherCustomPlugin.groupCount();i++) {
					parametersCustomPlugin.add(encodeCustomPluginValue(matcherCustomPlugin.group(i).getBytes(),customPluginParameterEncoding, mainPlugin));
				}
			} else {
				mainPlugin.printException(null,"No parameter found in REGEX. Calling function without parameters");
				//parametersCustomPlugin = new String[0];	
			}							
		} else if(customPluginParameter == CustomPluginParameterValues.FIXED) {
			String[] parametersStringSplitted = customPluginParameterString.split("#,#");
			for(int i=0;i<parametersStringSplitted.length;i++) {
				parametersCustomPlugin.add(encodeCustomPluginValue(parametersStringSplitted[i].getBytes(),customPluginParameterEncoding, mainPlugin));
			}
		} else if(customPluginParameter == CustomPluginParameterValues.POPUP) {			
			String parametersPopup = JOptionPane.showInputDialog("Enter parameter(s), delimited by \"#,#\"");						
			if(parametersPopup != null) {			
				String[] parametersStringSplitted = parametersPopup.split("#,#");					
				for(int i=0;i<parametersStringSplitted.length;i++) {
					parametersCustomPlugin.add(encodeCustomPluginValue(parametersStringSplitted[i].getBytes(),customPluginParameterEncoding, mainPlugin));
				}				
			} else {								
				//parametersCustomPlugin = new String[0];
			}			
		}
		
		return parametersCustomPlugin;
    	
    }
	
	public boolean isOn() {
		return isEnabled;
	}
	
	public void setOnOff(boolean enabled) {
		this.isEnabled = enabled; 
	}
	
	// TODO: Change name
	public static byte[] encodeCustomPluginValue(byte[] parameter, List<BurpExtender.Transformation> encodingTransformations, BurpExtender mainPlugin) {
		byte[] output = parameter;
		for (BurpExtender.Transformation t : encodingTransformations) {
			try {
				output = t.encode(output);
			} catch (Exception e) {
				mainPlugin.printException(e,"Error while trying to encoding " + t.toString());
			}
		}
		return output;		
	}
	
	public static byte[] decodeCustomPluginOutput(String toDecode, List<BurpExtender.Transformation> decodingTransformations, BurpExtender mainPlugin) {
		if(toDecode != null) {		
			byte[] output = toDecode.getBytes();
			for (BurpExtender.Transformation t : decodingTransformations) {
				try {
					output = t.decode(output);
				} catch (Exception e) {
					mainPlugin.printException(e,"Error while trying to decode " + t.toString());
				}
			}
			return output;
		} else {
			return new byte[0];
		}
	}
	
	public byte[] recalculateMessageBodyLength(byte[] message, boolean messageIsRequest) {
		
		int bodyOffset;
		List<String> headers;
		if(messageIsRequest) {
								
			IRequestInfo analyzedRequest = getMainPlugin().helpers.analyzeRequest(message);		
			bodyOffset = analyzedRequest.getBodyOffset();
			headers = analyzedRequest.getHeaders();
						
		} else {					
			
			IResponseInfo analyzedResponse = getMainPlugin().helpers.analyzeResponse(message);
			bodyOffset = analyzedResponse.getBodyOffset();
			headers = analyzedResponse.getHeaders();
						
		}
				
		byte[] messageWithCorrectContentLength = getMainPlugin().helpers.buildHttpMessage(headers, Arrays.copyOfRange(message, bodyOffset, message.length));
		
		return messageWithCorrectContentLength;
		
	}
	
	// TODO: maybe move headerString tyep to byte[]
	public byte[] replaceOutputHeaders(byte[] originalMessage, boolean messageIsRequest, String headersString) {
		
		List<String> newHeaders = new ArrayList<String>(Arrays.asList(headersString.split("\r\n")));
		
		int bodyOffset;
		if(messageIsRequest) {
			IRequestInfo currentRequestInfo = getMainPlugin().helpers.analyzeRequest(originalMessage);
			bodyOffset = currentRequestInfo.getBodyOffset();
		} else {
			IResponseInfo currentResponseInfo = getMainPlugin().helpers.analyzeResponse(originalMessage);
			bodyOffset = currentResponseInfo.getBodyOffset();
		}
		
		byte[] newHttpMessage = getMainPlugin().helpers.buildHttpMessage(newHeaders, Arrays.copyOfRange(originalMessage, bodyOffset, originalMessage.length));
		
		return newHttpMessage;		
		
	}
	
	public byte[] replaceOutputBody(byte[] originalMessage, boolean messageIsRequest, byte[] bodyString) {
	
		List<java.lang.String> currentHeaders;
		if(messageIsRequest) {
			IRequestInfo currentRequestInfo = getMainPlugin().helpers.analyzeRequest(originalMessage);
			currentHeaders = currentRequestInfo.getHeaders();
		} else {
			IResponseInfo currentResponseInfo = getMainPlugin().helpers.analyzeResponse(originalMessage);
			currentHeaders = currentResponseInfo.getHeaders();
		}
		
		byte[] newHttpMessage = getMainPlugin().helpers.buildHttpMessage(currentHeaders, bodyString);
				
		return newHttpMessage;
		
	}

	public BurpExtender getMainPlugin() {
		return mainPlugin;
	}

	public void setMainPlugin(BurpExtender mainPlugin) {
		this.mainPlugin = mainPlugin;
	}

	public String getCustomPluginExportedFunctionName() {
		return customPluginExportedFunctionName;
	}

	public void setCustomPluginExportedFunctionName(String customPluginExportedFunctionName) {
		this.customPluginExportedFunctionName = customPluginExportedFunctionName;
	}

	public CustomPluginExecuteOnValues getCustomPluginExecuteOn() {
		return customPluginExecuteOn;
	}

	public void setCustomPluginExecuteOn(CustomPluginExecuteOnValues customPluginExecuteOn) {
		this.customPluginExecuteOn = customPluginExecuteOn;
	}

	public String getCustomPluginExecuteOnContextName() {
		return customPluginExecuteOnContextName;
	}

	public void setCustomPluginExecuteOnContextName(String customPluginExecuteOnContextName) {
		this.customPluginExecuteOnContextName = customPluginExecuteOnContextName;
	}

	public CustomPluginExecuteValues getCustomPluginExecute() {
		return customPluginExecute;
	}

	public void setCustomPluginExecute(CustomPluginExecuteValues customPluginExecute) {
		this.customPluginExecute = customPluginExecute;
	}

	public String getCustomPluginExecuteString() {
		return customPluginExecuteString;
	}

	public void setCustomPluginExecuteString(String customPluginExecuteString) {
		this.customPluginExecuteString = customPluginExecuteString;
	}

	public CustomPluginParameterValues getCustomPluginParameter() {
		return customPluginParameter;
	}

	public void setCustomPluginParameter(CustomPluginParameterValues customPluginParameter) {
		this.customPluginParameter = customPluginParameter;
	}

	public String getCustomPluginParameterString() {
		return customPluginParameterString;
	}

	public void setCustomPluginParameterString(String customPluginParameterString) {
		this.customPluginParameterString = customPluginParameterString;
	}

	public List<BurpExtender.Transformation> getCustomPluginParameterEncoding() {
		return customPluginParameterEncoding;
	}

	public void setCustomPluginParameterEncoding(List<BurpExtender.Transformation> customPluginParameterEncoding) {
		this.customPluginParameterEncoding = customPluginParameterEncoding;
	}

	public CustomPluginFunctionOutputValues getCustomPluginFunctionOutput() {
		return customPluginFunctionOutput;
	}

	public void setCustomPluginFunctionOutput(CustomPluginFunctionOutputValues customPluginFunctionOutput) {
		this.customPluginFunctionOutput = customPluginFunctionOutput;
	}

	public String getCustomPluginFunctionOutputString() {
		return customPluginFunctionOutputString;
	}

	public void setCustomPluginFunctionOutputString(String customPluginFunctionOutputString) {
		this.customPluginFunctionOutputString = customPluginFunctionOutputString;
	}

	public List<BurpExtender.Transformation> getCustomPluginOutputEncoding() {
		return customPluginOutputEncoding;
	}

	public void setCustomPluginOutputEncoding(List<BurpExtender.Transformation> customPluginOutputEncoding) {
		this.customPluginOutputEncoding = customPluginOutputEncoding;
	}

	public List<BurpExtender.Transformation> getCustomPluginOutputDecoding() {
		return customPluginOutputDecoding;
	}

	public void setCustomPluginOutputDecoding(List<BurpExtender.Transformation> customPluginOutputDecoding) {
		this.customPluginOutputDecoding = customPluginOutputDecoding;
	}

	public CustomPluginType getType() {
		return type;
	}

	public void setType(CustomPluginType type) {
		this.type = type;
	}

	public String getCustomPluginName() {
		return customPluginName;
	}

	public void setCustomPluginName(String customPluginName) {
		this.customPluginName = customPluginName;
	}
	
	
		
}
