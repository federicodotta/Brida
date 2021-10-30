package burp;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.swing.JPanel;

public class BridaButtonPlugin extends CustomPlugin {
	
	private JPanel buttonPanel;
	private DefaultHook hookOrFunction;
	
	public BridaButtonPlugin(int platform, boolean isInterceptorHook,
			BurpExtender mainPlugin, String customPluginName, String customPluginExportedFunctionName,
			CustomPluginExecuteOnValues customPluginExecuteOn, String customPluginExecuteOnButtonName,
			CustomPluginParameterValues customPluginParameter,
			String customPluginParameterString, List<BurpExtender.Transformation> customPluginParameterEncoding,
			CustomPluginFunctionOutputValues customPluginFunctionOutput, String customPluginFunctionOutputString,
			List<BurpExtender.Transformation> customPluginOutputEncoding,
			List<BurpExtender.Transformation> customPluginOutputDecoding) {
		super(mainPlugin, customPluginName, customPluginExportedFunctionName, customPluginExecuteOn, customPluginExecuteOnButtonName,
				null, null, customPluginParameter,
				customPluginParameterString, customPluginParameterEncoding, customPluginFunctionOutput,
				customPluginFunctionOutputString, customPluginOutputEncoding, customPluginOutputDecoding);
		
		if(isInterceptorHook) {			
			// It is not possible to pass parameters to hooks
			hookOrFunction = new DefaultHook(customPluginExecuteOnButtonName,platform,customPluginExportedFunctionName,isInterceptorHook,new ArrayList<byte[]>(),null,false);
		} else if(customPluginParameter == CustomPlugin.CustomPluginParameterValues.POPUP) {
			hookOrFunction = new DefaultHook(customPluginExecuteOnButtonName,platform,customPluginExportedFunctionName,isInterceptorHook,new ArrayList<byte[]>(),customPluginParameterEncoding,true);
		} else {
			hookOrFunction = new DefaultHook(customPluginExecuteOnButtonName,platform,customPluginExportedFunctionName,isInterceptorHook,getParametersCustomPlugin(null,false),customPluginParameterEncoding,false);
		}
		this.setType(CustomPlugin.CustomPluginType.JBUTTON);
		
	}
	
	@Override
	public String exportPlugin() {
		
		String result = "";
		
		result = result + getType().ordinal() + ";";
		
		result = result + hookOrFunction.getOs() + ";";
		result = result + hookOrFunction.isInterceptorHook() + ";";
		
		result = result + Base64.getEncoder().encodeToString(getCustomPluginName().getBytes()) + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExportedFunctionName().getBytes()) + ";";
		result = result + getCustomPluginExecuteOn().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginExecuteOnContextName().getBytes()) + ";";
		result = result + getCustomPluginParameter().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginParameterString().getBytes()) + ";";
		result = result + getCustomPluginParameterEncoding().toString() + ";";		
		result = result + getCustomPluginFunctionOutput().ordinal() + ";";
		result = result + Base64.getEncoder().encodeToString(getCustomPluginFunctionOutputString().getBytes()) + ";";
		result = result + getCustomPluginOutputEncoding().toString() + ";";
		result = result + getCustomPluginOutputDecoding().toString();
				
		return result;
		
	}
	
	@Override
	public void enable() {
		buttonPanel = getMainPlugin().addButtonToHooksAndFunctions(hookOrFunction);
		setOnOff(true);
		
	}

	@Override
	public void disable() {
		if(isOn()) {
			// Disabling can fail for hooks if application is started. In this case the plugin should remain enabled.
			if(getMainPlugin().removeButtonFromHooksAndFunctions(buttonPanel, hookOrFunction)) {
				setOnOff(false);
			}
		}
	}

	public DefaultHook getHookOrFunction() {
		return hookOrFunction;
	}

	public void setHookOrFunction(DefaultHook hookOrFunction) {
		this.hookOrFunction = hookOrFunction;
	}
	
	

}
