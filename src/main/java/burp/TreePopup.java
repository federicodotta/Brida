package burp;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

public class TreePopup extends JPopupMenu {
		
	private static final long serialVersionUID = 1L;

	public TreePopup(BurpExtender ex){
				
		JMenuItem trapItem = new JMenuItem("Inspect!");
        trapItem.setActionCommand("trap");
        trapItem.addActionListener(ex);
        add(trapItem);
        
        JMenuItem trapWithBacktraceItem = new JMenuItem("Inspect with backtrace!");
        trapWithBacktraceItem.setActionCommand("trapBacktrace");
        trapWithBacktraceItem.addActionListener(ex);
        add(trapWithBacktraceItem);
        
        JMenu changeReturnValue = new JMenu("Change return value");
        
        JMenuItem changeReturnValuePtr = new JMenuItem("ptr");        
        changeReturnValuePtr.setActionCommand("changeReturnValuePtr");
        changeReturnValuePtr.addActionListener(ex);
        changeReturnValue.add(changeReturnValuePtr);
        
        if(ex.getPlatform() == BurpExtender.PLATFORM_ANDROID || ex.getPlatform() == BurpExtender.PLATFORM_IOS) {
	        JMenuItem changeReturnValueString = new JMenuItem("String");        
	        changeReturnValueString.setActionCommand("changeReturnValueString");
	        changeReturnValueString.addActionListener(ex);
	        changeReturnValue.add(changeReturnValueString);
        }
        
        JMenuItem changeReturnValueInt = new JMenuItem("int");        
        changeReturnValueInt.setActionCommand("changeReturnValueInt");
        changeReturnValueInt.addActionListener(ex);
        changeReturnValue.add(changeReturnValueInt);
        
        JMenuItem changeReturnValueBoolean = new JMenuItem("boolean");        
        changeReturnValueBoolean.setActionCommand("changeReturnValueBoolean");
        changeReturnValueBoolean.addActionListener(ex);
        changeReturnValue.add(changeReturnValueBoolean);
        
        add(changeReturnValue);
        
        if(ex.getPlatform() == BurpExtender.PLATFORM_IOS) {
        
	        JMenuItem demangleItem = new JMenuItem("Demangle Swift name");
	        demangleItem.setActionCommand("demangle");
	        demangleItem.addActionListener(ex);
	        add(demangleItem);
        
        }
        
    }
	
}
