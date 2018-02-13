package burp;

import javax.swing.JButton;

public class TrapTableItem {
	
	public String type;
	public String name;
	public boolean enabled;
	
	public TrapTableItem(String type, String name, boolean enabled) {
		
		this.type = type;
		this.name = name;
		this.enabled = enabled;
		
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

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	

}
