package burp;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

public class CustomPluginsTableModel  extends AbstractTableModel {
	
	private static final long serialVersionUID = 2L;
	
	List<CustomPlugin> customPlugins;
	
	public CustomPluginsTableModel() {
		customPlugins = new ArrayList<CustomPlugin>();
	}
	
	public List<CustomPlugin> getCustomPlugins() {
		return customPlugins;
	}

	@Override
	public int getColumnCount() {
		return 7;
	}

	@Override
	public int getRowCount() {
		return customPlugins.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		
		CustomPlugin currentPlugin = customPlugins.get(rowIndex);
		
		switch (columnIndex) {
		
			case 0:
				if(currentPlugin.isOn()) {
					return "DISABLE";			
				} else {
					return "ENABLE";			
				}
			case 1:
				return currentPlugin.getCustomPluginName();
			case 2:
				return convertPluginType(currentPlugin.getType());
			case 3:
				return currentPlugin.getCustomPluginExportedFunctionName();
			case 4:
				if(currentPlugin.getType() != CustomPlugin.CustomPluginType.JBUTTON) {
					return "OPEN DEBUG WINDOW";
				} else {
					return null;
				}
			case 5:
				return "EDIT";
			case 6:
				return "REMOVE";			
			default:
				return "";
				
		}
			
	}
	
	public static String convertPluginType(CustomPlugin.CustomPluginType type) {
		switch(type) {
			case IHTTPLISTENER:
				return "IHttpListener";
			case IMESSAGEEDITORTAB:
				return "IMessageEditorTab";
			case ICONTEXTMENU:
				return "IContextMenu";
			case JBUTTON:
				return "JButton";
			default:
				return "ERROR";
		}
	}
		
	@Override
    public String getColumnName(int columnIndex) {
		switch (columnIndex)  {
			case 0:
				return "Enable";
			case 1:
				return "Plugin name";
			case 2:
	            return "Plugin type";    
			case 3:
                return "Frida export name";
			case 4:
				return "Debug";
            case 5:
                return "Edit";
            case 6:
            	return "Remove";
            default:
                return "";
        }
	}	
	
	@Override
    public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}	
	
}
