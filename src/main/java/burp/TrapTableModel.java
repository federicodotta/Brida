package burp;

import java.util.ArrayList;
import java.util.List;
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
		return 6;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		
		TrapTableItem currentItem = trappedMethods.get(rowIndex);
		
		switch (columnIndex) {
		
			case 0:
				return currentItem.getHook();
			case 1:
				return currentItem.getType();
			case 2:
				return currentItem.getName();
			case 3:
				return currentItem.hasBacktrace();
			case 4:
				return currentItem.getReturnValueType();
			case 5:
				return currentItem.getNewReturnValue();	
			default:
				return "";
		
		}
	
	}
		
	@Override
    public String getColumnName(int columnIndex) {
		switch (columnIndex)  {
			case 0:
	            return "Hook";    
			case 1:
                return "Type";
            case 2:
                return "Name";
            case 3:
            	return "Backtrace";            	
            case 4:
                return "Return value type";
            case 5:
                return "New return value";       	
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
                return Boolean.class;
            case 4:
                return String.class;
            case 5:
            	return String.class;
            default:
                return String.class;
        }
	}


}
