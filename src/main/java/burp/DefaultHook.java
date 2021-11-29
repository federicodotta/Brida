package burp;

import java.util.List;

public class DefaultHook {
	
	private String name;
	private int os;
	private String fridaExportName;
	private boolean isInterceptorHook;
	private boolean isEnabled;
	private List<byte[]> parameters;
	private List<BurpExtender.Transformation> parametersEncoding;
	private boolean popupParameters;
		
	public DefaultHook(String name, int os, String code, boolean isInterceptorHook, List<byte[]> parameters, List<BurpExtender.Transformation> parametersEncoding, boolean popupParameters) {
		this.name = name;
		this.os = os;
		this.fridaExportName = code;
		this.isInterceptorHook = isInterceptorHook;
		this.isEnabled = false;
		this.parameters = parameters;
		this.parametersEncoding = parametersEncoding;
		this.popupParameters = popupParameters;
	}
	public boolean isInterceptorHook() {
		return isInterceptorHook;
	}
	public void setInterceptorHook(boolean isInterceptorHook) {
		this.isInterceptorHook = isInterceptorHook;
	}
	public boolean isEnabled() {
		return isEnabled;
	}
	public void setEnabled(boolean isEnabled) {
		this.isEnabled = isEnabled;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getOs() {
		return os;
	}
	public void setOs(int os) {
		this.os = os;
	}
	public String getFridaExportName() {
		return fridaExportName;
	}
	public void setFridaExportName(String fridaExportName) {
		this.fridaExportName = fridaExportName;
	}
	public List<byte[]> getParameters() {
		return parameters;
	}
	public void setParameters(List<byte[]> parameters) {
		this.parameters = parameters;
	}
	public boolean isPopupParameters() {
		return popupParameters;
	}
	public void setPopupParameters(boolean popupParameters) {
		this.popupParameters = popupParameters;
	}
	public List<BurpExtender.Transformation> getParametersEncoding() {
		return parametersEncoding;
	}
	public void setParametersEncoding(List<BurpExtender.Transformation> parametersEncoding) {
		this.parametersEncoding = parametersEncoding;
	}	
	

}
