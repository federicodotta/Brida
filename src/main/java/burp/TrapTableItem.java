package burp;

public class TrapTableItem {
	
	private String hook;
	private String type;
	private String name;
	private boolean backtrace;
	private String returnValueType;
	private String newReturnValue;
	
	public TrapTableItem(String hook, String type, String name, boolean backtrace, String returnValueType, String newReturnValue) {
		
		this.hook = hook;
		this.type = type;
		this.name = name;
		this.backtrace = backtrace;
		this.returnValueType = returnValueType;
		this.newReturnValue = newReturnValue;
		
	}

	public String getHook() {
		return hook;
	}

	public void setHook(String hook) {
		this.hook = hook;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public boolean hasBacktrace() {
		return backtrace;
	}

	public void setBacktrace(boolean backtrace) {
		this.backtrace = backtrace;
	}

	public String getReturnValueType() {
		return returnValueType;
	}

	public void setReturnValueType(String returnValueType) {
		this.returnValueType = returnValueType;
	}

	public String getNewReturnValue() {
		return newReturnValue;
	}

	public void setNewReturnValue(String newReturnValue) {
		this.newReturnValue = newReturnValue;
	}
	
	

}
