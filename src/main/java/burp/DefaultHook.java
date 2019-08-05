package burp;

public class DefaultHook {
	
	private String name;
	private int os;
	private String fridaExportName;
	private boolean isInterceptorHook;
	private boolean isEnabled;
		
	public DefaultHook(String name, int os, String code, boolean isInterceptorHook) {
		this.name = name;
		this.os = os;
		this.fridaExportName = code;
		this.isInterceptorHook = isInterceptorHook;
		this.isEnabled = false;
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

}
