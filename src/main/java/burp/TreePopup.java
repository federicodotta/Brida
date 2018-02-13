package burp;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

public class TreePopup extends JPopupMenu {
	
	JMenuItem trapItem;
	JMenuItem trapWithBacktraceItem;
	
	BurpExtender ex;
	
	public TreePopup(BurpExtender ex){
		
		this.ex = ex;
		
        trapItem = new JMenuItem("Trap!");
        trapItem.setActionCommand("trap");
        trapItem.addActionListener(ex);
        add(trapItem);
        
        trapWithBacktraceItem = new JMenuItem("Trap with backtrace!");
        trapWithBacktraceItem.setActionCommand("trapBacktrace");
        trapWithBacktraceItem.addActionListener(ex);
        add(trapWithBacktraceItem);
        
    }
	
}
