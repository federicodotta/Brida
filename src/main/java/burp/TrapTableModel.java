package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.table.AbstractTableModel;

public class TrapTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	
	List<TrapTableItem> trappedMethods;
	
	public TrapTableModel() {
		trappedMethods = new ArrayList<TrapTableItem>();
	}
	
	public List<TrapTableItem> getTrappedMethods() {
		return trappedMethods;
	}
	

	@Override
	public int getRowCount() {
		return trappedMethods.size();
	}

	@Override
	public int getColumnCount() {
		return 9;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		
		TrapTableItem currentItem = trappedMethods.get(rowIndex);
		
		switch (columnIndex) {
		
			case 0:
				if(currentItem.getDefaultHook().isEnabled()) {
					return "Enabled";				
				} else {
					return "Disabled";			
				}
			case 1:
				return currentItem.getHook();
			case 2:
				return currentItem.getType();
			case 3:
				return currentItem.getName();
			case 4:
				return currentItem.hasBacktrace();
			case 5:
				return currentItem.getReturnValueType();
			case 6:
				return currentItem.getNewReturnValue();	
			case 7:
				if(currentItem.getDefaultHook().isEnabled()) {
					return new JButton("DISABLE");				
				} else {
					return new JButton("ENABLE");			
				}	
			case 8:
				return new JButton("REMOVE");					
			default:
				return "";
		
		}
	
	}
		
	@Override
    public String getColumnName(int columnIndex) {
		switch (columnIndex)  {
			case 0:
				return "Status";
			case 1:
	            return "Category";    
			case 2:
                return "Type";
            case 3:
                return "Method/Class";
            case 4:
            	return "Backtrace";            	
            case 5:
                return "Return value type";
            case 6:
                return "New return value";      
            case 7:
                return "Enable/Disable";  
            case 8:
                return "Remove";                  
            default:
                return "";
        }
	}
	
	@Override
    public Class<?> getColumnClass(int columnIndex) {
		switch (columnIndex) {
            case 0:
                return String.class;
            case 1:
                return String.class;
            case 2:
            	return String.class;
            case 3:
                return String.class;
            case 4:
                return Boolean.class;
            case 5:
            	return String.class;
            case 6:
            	return String.class;
            case 7:
            	return JButton.class;
            case 8:
            	return JButton.class;            	
            default:
                return String.class;
        }
	}


}
