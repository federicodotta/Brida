package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.table.AbstractTableModel;

public class TrapTableModel extends AbstractTableModel {
	
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
		return 3;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		
		TrapTableItem currentItem = trappedMethods.get(rowIndex);
		
		switch (columnIndex) {
		
			case 0:
				return currentItem.getType();
			case 1:
				return currentItem.getName();
			case 2:
				return currentItem.isEnabled();
			default:
				return "";
		
		}
		
		
	}
	
	@Override
    public String getColumnName(int columnIndex) {
		switch (columnIndex)  {
            case 0:
                return "Type";
            case 1:
                return "Name";
            case 2:
            	return "Backtrace";
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
            	return Boolean.class;
            default:
                return String.class;
        }
	}


}
