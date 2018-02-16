package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JTree;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.ArrayUtils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import net.razorvine.pyro.*;

public class BurpExtender implements IBurpExtender, ITab, ActionListener, IContextMenuFactory, MouseListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private JPanel mainPanel;
    
    private PyroProxy pyroBridaService;
    private Process pyroServerProcess;
    	
	private JTextField pythonPath;
	private String pythonScript;
	private JTextField pyroHost;
	private JTextField pyroPort;
	private JTextPane serverStatus;
	private JTextPane applicationStatus;
	private JTextField fridaPath;
    private JTextField applicationId;
    
    private JRadioButton remoteRadioButton;
    private JRadioButton localRadioButton;
    	
	private Style redStyle;
	private Style greenStyle;
	DefaultStyledDocument documentServerStatus;
	DefaultStyledDocument documentApplicationStatus;
	
	DefaultStyledDocument documentServerStatusButtons;
	DefaultStyledDocument documentApplicationStatusButtons;
    private JTextPane serverStatusButtons;
    private JTextPane applicationStatusButtons;
	
	private JTextField executeMethodName;
	private JTextField executeMethodArgument;
	private DefaultListModel executeMethodInsertedArgumentList;
	private JList executeMethodInsertedArgument;
	
	private boolean serverStarted;
	private boolean applicationSpawned;
	
	private IContextMenuInvocation currentInvocation;
	
	private ITextEditor stubTextEditor;
    
    private JButton executeMethodButton;
    private JButton saveSettingsToFileButton;
    private JButton loadSettingsFromFileButton;
    private JButton generateJavaStubButton;
    private JButton generatePythonStubButton;    
    private JButton loadJSFileButton;
    private JButton saveJSFileButton; 
    private JButton loadTreeButton;
    private JButton detachAllButton;
    private JButton clearConsoleButton;
    
    private JEditorPane pluginConsoleTextArea;
    
	private RSyntaxTextArea jsEditorTextArea;
	
    private Thread stdoutThread;
    private Thread stderrThread;
    
    private JTextField findTextField;
    
    private JTree tree;
    
    private JTable trapTable;
    
    private boolean lastPrintIsJS;
		
    /*
     * TODO
     * - Android
     * - Fix JS editor
     * - Add addresses to tree view
     * - Trap/edit return value of custom methods
     * - Organize better JS file
     */
    
	public void registerExtenderCallbacks(IBurpExtenderCallbacks c) {
			
		
        // Keep a reference to our callbacks object
        this.callbacks = c;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Brida");
        
        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        stdout.println("Welcome to Brida, the new bridge between Burp Suite and Frida!");
        stdout.println("Created by Piergiovanni Cipolloni and Federico Dotta");
        stdout.println("Contributors: Maurizio Agazzini");
        stdout.println("Version: 0.2 beta");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/Brida");
        stdout.println("");
                
        serverStarted = false;
    	applicationSpawned = false;
    	
    	lastPrintIsJS = false;
    			
		try {
			InputStream inputStream = getClass().getClassLoader().getResourceAsStream("res/bridaServicePyro.py");
			BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream ));
			File outputFile = new File(System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + "bridaServicePyro.py");
			
			FileWriter fr = new FileWriter(outputFile);
			BufferedWriter br  = new BufferedWriter(fr);
			
			String s;
			while ((s = reader.readLine())!=null) {
				
				br.write(s);
				br.newLine();
				
			}
			reader.close();
			br.close();
			
			pythonScript = outputFile.getAbsolutePath();
			
		} catch(Exception e) {
			
			printException(e,"Error copying Pyro Server file");
			
		}
		       
        SwingUtilities.invokeLater(new Runnable()  {
        	
            @Override
            public void run()  {   	
            	
            	mainPanel = new JPanel();
            	mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
            	
            	JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            	
            	// **** Left panel (tabbed plus console)            	
            	JSplitPane consoleTabbedSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);            	
            	
            	// Tabbed Pabel            	
            	final JTabbedPane tabbedPanel = new JTabbedPane();
            	tabbedPanel.addChangeListener(new ChangeListener() {
                    public void stateChanged(ChangeEvent e) {
                       
                        SwingUtilities.invokeLater(new Runnable() {
            				
            	            @Override
            	            public void run() {
            	            	
            	            	showHideButtons(tabbedPanel.getSelectedIndex());
            					
            	            }
            			});	
                        
                    }
                });
            	
            	// **** TABS

            	// **** CONFIGURATION PANEL
            	
            	JPanel configurationConfPanel = new JPanel();
                configurationConfPanel.setLayout(new BoxLayout(configurationConfPanel, BoxLayout.Y_AXIS));
                                
                // RED STYLE
                StyleContext styleContext = new StyleContext();
                redStyle = styleContext.addStyle("red", null);
                StyleConstants.setForeground(redStyle, Color.RED);
                // GREEN STYLE                
                greenStyle = styleContext.addStyle("green", null);
                StyleConstants.setForeground(greenStyle, Color.GREEN);
                                
                JPanel serverStatusPanel = new JPanel();
                serverStatusPanel.setLayout(new BoxLayout(serverStatusPanel, BoxLayout.X_AXIS));
                serverStatusPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelServerStatus = new JLabel("Server status: ");
                documentServerStatus = new DefaultStyledDocument();
                serverStatus = new JTextPane(documentServerStatus);                
                try {
                	documentServerStatus.insertString(0, "NOT running", redStyle);
				} catch (BadLocationException e) {
					printException(e,"Error setting labels");
				}
                serverStatus.setMaximumSize( serverStatus.getPreferredSize() );
                serverStatusPanel.add(labelServerStatus);
                serverStatusPanel.add(serverStatus);
                
                JPanel applicationStatusPanel = new JPanel();
                applicationStatusPanel.setLayout(new BoxLayout(applicationStatusPanel, BoxLayout.X_AXIS));
                applicationStatusPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelApplicationStatus = new JLabel("Application status: ");
                documentApplicationStatus = new DefaultStyledDocument();
                applicationStatus = new JTextPane(documentApplicationStatus);                      
                try {
                	documentApplicationStatus.insertString(0, "NOT spawned", redStyle);
				} catch (BadLocationException e) {
					printException(e,"Error setting labels");
				}
                applicationStatus.setMaximumSize( applicationStatus.getPreferredSize() );
                applicationStatusPanel.add(labelApplicationStatus);
                applicationStatusPanel.add(applicationStatus);
             
                JPanel pythonPathPanel = new JPanel();
                pythonPathPanel.setLayout(new BoxLayout(pythonPathPanel, BoxLayout.X_AXIS));
                pythonPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelPythonPath = new JLabel("Python binary path: ");
                pythonPath = new JTextField(200);                
                if(callbacks.loadExtensionSetting("pythonPath") != null)
                	pythonPath.setText(callbacks.loadExtensionSetting("pythonPath"));
                else {
                	if(System.getProperty("os.name").startsWith("Windows")) {
                		pythonPath.setText("C:\\python27\\python");
                	} else {
                		pythonPath.setText("/usr/bin/python");
                	}
                }
                pythonPath.setMaximumSize( pythonPath.getPreferredSize() );
                JButton pythonPathButton = new JButton("Select file");
                pythonPathButton.setActionCommand("pythonPathSelectFile");
                pythonPathButton.addActionListener(BurpExtender.this);
                pythonPathPanel.add(labelPythonPath);
                pythonPathPanel.add(pythonPath);
                pythonPathPanel.add(pythonPathButton);
                                
                JPanel pyroHostPanel = new JPanel();
                pyroHostPanel.setLayout(new BoxLayout(pyroHostPanel, BoxLayout.X_AXIS));
                pyroHostPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel labelPyroHost = new JLabel("Pyro host: ");
                pyroHost = new JTextField(200);                
                if(callbacks.loadExtensionSetting("pyroHost") != null)
                	pyroHost.setText(callbacks.loadExtensionSetting("pyroHost"));
                else
                	pyroHost.setText("localhost");
                pyroHost.setMaximumSize( pyroHost.getPreferredSize() );
                pyroHostPanel.add(labelPyroHost);
                pyroHostPanel.add(pyroHost);
                                
                JPanel pyroPortPanel = new JPanel();
                pyroPortPanel.setLayout(new BoxLayout(pyroPortPanel, BoxLayout.X_AXIS));
                pyroPortPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel labelPyroPort = new JLabel("Pyro port: ");
                pyroPort = new JTextField(200);                
                if(callbacks.loadExtensionSetting("pyroPort") != null)
                	pyroPort.setText(callbacks.loadExtensionSetting("pyroPort"));
                else
                	pyroPort.setText("9999");
                pyroPort.setMaximumSize( pyroPort.getPreferredSize() );
                pyroPortPanel.add(labelPyroPort);
                pyroPortPanel.add(pyroPort);
                                
                JPanel fridaPathPanel = new JPanel();
                fridaPathPanel.setLayout(new BoxLayout(fridaPathPanel, BoxLayout.X_AXIS));
                fridaPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelFridaPath = new JLabel("Frida JS file path: ");
                fridaPath = new JTextField(200);                
                if(callbacks.loadExtensionSetting("fridaPath") != null)
                	fridaPath.setText(callbacks.loadExtensionSetting("fridaPath"));
                else {                	
                	if(System.getProperty("os.name").startsWith("Windows")) {
                		fridaPath.setText("C:\\burp\\script.js");
                	} else {
                		fridaPath.setText("/opt/burp/script.js");
                	}
                }
                fridaPath.setMaximumSize( fridaPath.getPreferredSize() );
                JButton fridaPathButton = new JButton("Select file");
                fridaPathButton.setActionCommand("fridaPathSelectFile");
                fridaPathButton.addActionListener(BurpExtender.this);
                fridaPathPanel.add(labelFridaPath);
                fridaPathPanel.add(fridaPath);
                fridaPathPanel.add(fridaPathButton);
                
                JPanel applicationIdPanel = new JPanel();
                applicationIdPanel.setLayout(new BoxLayout(applicationIdPanel, BoxLayout.X_AXIS));
                applicationIdPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelApplicationId = new JLabel("Application ID: ");
                applicationId = new JTextField(200);                
                if(callbacks.loadExtensionSetting("applicationId") != null)
                	applicationId.setText(callbacks.loadExtensionSetting("applicationId"));
                else
                	applicationId.setText("org.test.application");
                applicationId.setMaximumSize( applicationId.getPreferredSize() );
                applicationIdPanel.add(labelApplicationId);
                applicationIdPanel.add(applicationId);
                                
                JPanel localRemotePanel = new JPanel();
                localRemotePanel.setLayout(new BoxLayout(localRemotePanel, BoxLayout.X_AXIS));
                localRemotePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                remoteRadioButton = new JRadioButton("Frida Remote");
                localRadioButton = new JRadioButton("Frida Local");
                if(callbacks.loadExtensionSetting("remote") != null) {                	
                	if(callbacks.loadExtensionSetting("remote").equals("true"))
                		remoteRadioButton.setSelected(true);
                	else
                		localRadioButton.setSelected(true);                	
                } else {
                	remoteRadioButton.setSelected(true);
                }
                ButtonGroup localRemoteButtonGroup = new ButtonGroup();
                localRemoteButtonGroup.add(remoteRadioButton);
                localRemoteButtonGroup.add(localRadioButton);
                localRemotePanel.add(remoteRadioButton);
                localRemotePanel.add(localRadioButton);
            	  
                configurationConfPanel.add(serverStatusPanel);
                configurationConfPanel.add(applicationStatusPanel);
                configurationConfPanel.add(pythonPathPanel);
                configurationConfPanel.add(pyroHostPanel);
                configurationConfPanel.add(pyroPortPanel);
                configurationConfPanel.add(fridaPathPanel);
                configurationConfPanel.add(applicationIdPanel);  
                configurationConfPanel.add(localRemotePanel);
                
                // **** END CONFIGURATION PANEL
                
            	// **** JS EDITOR PANEL / CONSOLE
                
                // https://github.com/bobbylight/RSyntaxTextArea
                // TODO Add other components
                                
                jsEditorTextArea = new RSyntaxTextArea();
                jsEditorTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                jsEditorTextArea.setCodeFoldingEnabled(false);                
                //jsEditorTextArea.setEditable(true);
                //jsEditorTextArea.setEnabled(true);
                RTextScrollPane sp = new RTextScrollPane(jsEditorTextArea);
                //sp.setEnabled(true);
                
                jsEditorTextArea.setFocusable(true);
                
                /*
                // Autocomplete
                CompletionProvider provider = createCompletionProvider();
                AutoCompletion ac = new AutoCompletion(provider);
                ac.install(jsEditorTextArea);
                */

                // **** END JS EDITOR PANEL / CONSOLE    
                
                // 	*** TREE WITH CLASSES AND METHODS
                
                JPanel treeSearchPanel = new JPanel();
                treeSearchPanel.setLayout(new BorderLayout());  
                                
                JPanel treePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JScrollPane scrollTreeJPanel = new JScrollPane(treePanel);
                scrollTreeJPanel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                
                DefaultMutableTreeNode top = new DefaultMutableTreeNode("Binary");
                
                tree = new JTree(top);
                
                // Add mouse listener
                tree.addMouseListener(BurpExtender.this);
                
                treePanel.add(tree);
                                
                JPanel searchPanelBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
                                
                JLabel findLabel = new JLabel("Search:");
                findTextField = new JTextField(60);       
                JButton searchButton = new JButton("Search");
                searchButton.setActionCommand("searchAnalysis");
                searchButton.addActionListener(BurpExtender.this); 
                
                searchPanelBar.add(findLabel);
                searchPanelBar.add(findTextField);
                searchPanelBar.add(searchButton);
             
                treeSearchPanel.add(scrollTreeJPanel);
                treeSearchPanel.add(searchPanelBar,BorderLayout.SOUTH);
                                
                // *** TREE WITH CLASSES AND METHODS                
                
            	// **** STUB GENERATION     
                                
                stubTextEditor = callbacks.createTextEditor();                
                stubTextEditor.setEditable(false);
                
            	// **** END STUB GENERATION  
                
                // **** EXECUTE METHOD TAB
                
                // Execute method
                JPanel executeMethodPanel = new JPanel();
                executeMethodPanel.setLayout(new BoxLayout(executeMethodPanel, BoxLayout.Y_AXIS));
                
                JPanel executeMethodNamePanel = new JPanel();
                executeMethodNamePanel.setLayout(new BoxLayout(executeMethodNamePanel, BoxLayout.X_AXIS));
                executeMethodNamePanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelExecuteMethodName = new JLabel("Method name: ");
                executeMethodName = new JTextField(200);                
                if(callbacks.loadExtensionSetting("executeMethodName") != null)
                	executeMethodName.setText(callbacks.loadExtensionSetting("executeMethodName"));
                executeMethodName.setMaximumSize( executeMethodName.getPreferredSize() );
                executeMethodNamePanel.add(labelExecuteMethodName);
                executeMethodNamePanel.add(executeMethodName);

                JPanel executeMethodArgumentPanel = new JPanel();
                executeMethodArgumentPanel.setLayout(new BoxLayout(executeMethodArgumentPanel, BoxLayout.X_AXIS));
                executeMethodArgumentPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelExecuteMethodArgument = new JLabel("Argument: ");
                executeMethodArgument = new JTextField(200);                
                executeMethodArgument.setMaximumSize( executeMethodArgument.getPreferredSize() );
                JButton addExecuteMethodArgument = new JButton("Add");
                addExecuteMethodArgument.setActionCommand("addExecuteMethodArgument");
                addExecuteMethodArgument.addActionListener(BurpExtender.this);
                executeMethodArgumentPanel.add(labelExecuteMethodArgument);
                executeMethodArgumentPanel.add(executeMethodArgument);
                executeMethodArgumentPanel.add(addExecuteMethodArgument);
                            
                executeMethodInsertedArgumentList = new DefaultListModel();                
                JPanel executeMethodInsertedArgumentPanel = new JPanel();
                executeMethodInsertedArgumentPanel.setLayout(new BoxLayout(executeMethodInsertedArgumentPanel, BoxLayout.X_AXIS));
                executeMethodInsertedArgumentPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelExecuteMethodInsertedArgument = new JLabel("Argument list: ");
                executeMethodInsertedArgument = new JList(executeMethodInsertedArgumentList);    
                JScrollPane executeMethodInsertedArgumentScrollPane = new JScrollPane(executeMethodInsertedArgument);
                executeMethodInsertedArgumentScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                executeMethodInsertedArgumentScrollPane.setBorder(new LineBorder(Color.BLACK));
                executeMethodInsertedArgumentScrollPane.setMaximumSize( executeMethodInsertedArgumentScrollPane.getPreferredSize() ); 
                if(callbacks.loadExtensionSetting("executeMethodSizeArguments") != null) {
                	int sizeArguments = Integer.parseInt(callbacks.loadExtensionSetting("executeMethodSizeArguments"));
                	for(int i=0;i<sizeArguments;i++) {
                		executeMethodInsertedArgumentList.addElement(callbacks.loadExtensionSetting("executeMethodArgument" + i));
                	}
                }
                               
                JPanel executeMethodInsertedArgumentButtonPanel = new JPanel();
                executeMethodInsertedArgumentButtonPanel.setLayout(new BoxLayout(executeMethodInsertedArgumentButtonPanel, BoxLayout.Y_AXIS));
                JButton removeExecuteMethodArgument = new JButton("Remove");
                removeExecuteMethodArgument.setActionCommand("removeExecuteMethodArgument");
                removeExecuteMethodArgument.addActionListener(BurpExtender.this);
                JButton modifyExecuteMethodArgument = new JButton("Modify");
                modifyExecuteMethodArgument.setActionCommand("modifyExecuteMethodArgument");
                modifyExecuteMethodArgument.addActionListener(BurpExtender.this);
                executeMethodInsertedArgumentButtonPanel.add(removeExecuteMethodArgument);
                executeMethodInsertedArgumentButtonPanel.add(modifyExecuteMethodArgument);                
                executeMethodInsertedArgumentPanel.add(labelExecuteMethodInsertedArgument);
                executeMethodInsertedArgumentPanel.add(executeMethodInsertedArgumentScrollPane);
                executeMethodInsertedArgumentPanel.add(executeMethodInsertedArgumentButtonPanel);
                
                executeMethodPanel.add(executeMethodNamePanel);
                executeMethodPanel.add(executeMethodArgumentPanel);
                executeMethodPanel.add(executeMethodInsertedArgumentPanel);
                
                // **** END EXECUTE METHOD TAB
                
                // **** BEGIN TRAPPING TAB
                
                trapTable = new JTable(new TrapTableModel());
                JScrollPane trapTableScrollPane = new JScrollPane(trapTable);
                trapTableScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                trapTableScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                trapTable.setAutoCreateRowSorter(true);
                
                // Center header
                ((DefaultTableCellRenderer)trapTable.getTableHeader().getDefaultRenderer()).setHorizontalAlignment(JLabel.CENTER);
                
                // Center columns 4 and 5
                DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
                centerRenderer.setHorizontalAlignment( JLabel.CENTER );
                trapTable.getColumnModel().getColumn(4).setCellRenderer( centerRenderer );
                trapTable.getColumnModel().getColumn(5).setCellRenderer( centerRenderer );
                
                // **** END TRAPPING TAB
                
            	tabbedPanel.add("Configurations",configurationConfPanel);
            	tabbedPanel.add("JS Editor",sp); 
            	tabbedPanel.add("Analyze binary",treeSearchPanel);
            	tabbedPanel.add("Generate stubs",stubTextEditor.getComponent());            	
            	tabbedPanel.add("Execute method",executeMethodPanel);
            	tabbedPanel.add("Trap methods",trapTableScrollPane);
            	            	
            	// *** CONSOLE            	
            	pluginConsoleTextArea = new JEditorPane("text/html", "<font color=\"green\"><b>*** Brida Console ***</b></font><br/><br/>");
                JScrollPane scrollPluginConsoleTextArea = new JScrollPane(pluginConsoleTextArea);
                scrollPluginConsoleTextArea.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                pluginConsoleTextArea.setEditable(false);
                                
                consoleTabbedSplitPane.setTopComponent(tabbedPanel);
                consoleTabbedSplitPane.setBottomComponent(scrollPluginConsoleTextArea);
                consoleTabbedSplitPane.setResizeWeight(.7d);
                            	
                // *** RIGHT - BUTTONS
            	
            	// RIGHT
                JPanel rightSplitPane = new JPanel();
                rightSplitPane.setLayout(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                
                documentServerStatusButtons = new DefaultStyledDocument();
                serverStatusButtons = new JTextPane(documentServerStatusButtons);                
                try {
                	documentServerStatusButtons.insertString(0, "Server stopped", redStyle);
				} catch (BadLocationException e) {
					printException(e,"Error setting labels");
				}
                serverStatusButtons.setMaximumSize( serverStatusButtons.getPreferredSize() );
                
                documentApplicationStatusButtons = new DefaultStyledDocument();
                applicationStatusButtons = new JTextPane(documentApplicationStatusButtons);                
                try {
                	documentApplicationStatusButtons.insertString(0, "App stopped", redStyle);
				} catch (BadLocationException e) {
					printException(e,"Error setting labels");
				}
                applicationStatusButtons.setMaximumSize( applicationStatusButtons.getPreferredSize() );
                                
            	JButton startServer = new JButton("Start server");
                startServer.setActionCommand("startServer");
                startServer.addActionListener(BurpExtender.this); 
                
                JButton killServer = new JButton("Kill server");
                killServer.setActionCommand("killServer");
                killServer.addActionListener(BurpExtender.this); 
            	
            	JButton spawnApplication = new JButton("Spawn application");
                spawnApplication.setActionCommand("spawnApplication");
                spawnApplication.addActionListener(BurpExtender.this);   
                
                JButton killApplication = new JButton("Kill application");
                killApplication.setActionCommand("killApplication");
                killApplication.addActionListener(BurpExtender.this);
                
                JButton reloadScript = new JButton("Reload JS");
                reloadScript.setActionCommand("reloadScript");
                reloadScript.addActionListener(BurpExtender.this); 
                
                clearConsoleButton = new JButton("Clear console");
                clearConsoleButton.setActionCommand("clearConsole");
                clearConsoleButton.addActionListener(BurpExtender.this);
                
                executeMethodButton = new JButton("Execute Method");
                executeMethodButton.setActionCommand("executeMethod");
                executeMethodButton.addActionListener(BurpExtender.this); 
                
                generateJavaStubButton = new JButton("Java Stub");
                generateJavaStubButton.setActionCommand("generateJavaStub");
                generateJavaStubButton.addActionListener(BurpExtender.this);    
                
                generatePythonStubButton = new JButton("Python Stub");
                generatePythonStubButton.setActionCommand("generatePythonStub");
                generatePythonStubButton.addActionListener(BurpExtender.this);
                
                saveSettingsToFileButton = new JButton("Save settings to file");
                saveSettingsToFileButton.setActionCommand("saveSettingsToFile");
                saveSettingsToFileButton.addActionListener(BurpExtender.this);  
                
                loadSettingsFromFileButton = new JButton("Load settings from file");
                loadSettingsFromFileButton.setActionCommand("loadSettingsFromFile");
                loadSettingsFromFileButton.addActionListener(BurpExtender.this);
                
                loadJSFileButton = new JButton("Load JS file");
                loadJSFileButton.setActionCommand("loadJsFile");
                loadJSFileButton.addActionListener(BurpExtender.this);  
                
                saveJSFileButton = new JButton("Save JS file");
                saveJSFileButton.setActionCommand("saveJsFile");
                saveJSFileButton.addActionListener(BurpExtender.this); 
                
                loadTreeButton = new JButton("Load tree");
                loadTreeButton.setActionCommand("loadTree");
                loadTreeButton.addActionListener(BurpExtender.this);
                                
                detachAllButton = new JButton("Detach all");
                detachAllButton.setActionCommand("detachAll");
                detachAllButton.addActionListener(BurpExtender.this); 
                           
                JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
                separator.setBorder(BorderFactory.createMatteBorder(3, 0, 3, 0, Color.ORANGE));

                rightSplitPane.add(serverStatusButtons,gbc);
                rightSplitPane.add(applicationStatusButtons,gbc);
                rightSplitPane.add(startServer,gbc);
                rightSplitPane.add(killServer,gbc);
                rightSplitPane.add(spawnApplication,gbc);
                rightSplitPane.add(killApplication,gbc);
                rightSplitPane.add(reloadScript,gbc);
                rightSplitPane.add(clearConsoleButton,gbc);

                rightSplitPane.add(separator,gbc);
                
                // TAB CONFIGURATIONS
                rightSplitPane.add(saveSettingsToFileButton,gbc);
                rightSplitPane.add(loadSettingsFromFileButton,gbc);
                
                // TAB JS EDITOR
                rightSplitPane.add(loadJSFileButton,gbc);
                rightSplitPane.add(saveJSFileButton,gbc);
                
                // TAB EXECUTE METHOD
                rightSplitPane.add(executeMethodButton,gbc);
                
                // TAB GENERATE STUBS
                rightSplitPane.add(generateJavaStubButton,gbc);
                rightSplitPane.add(generatePythonStubButton,gbc);
                
                // TREE ANALYSIS                
                rightSplitPane.add(loadTreeButton,gbc);     
                
                // TRAP METHODS
                rightSplitPane.add(detachAllButton,gbc);
                
                splitPane.setLeftComponent(consoleTabbedSplitPane);
                splitPane.setRightComponent(rightSplitPane);
                
                splitPane.setResizeWeight(.9d);

                mainPanel.add(splitPane);
                
                callbacks.customizeUiComponent(mainPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
                
            }
            
        });
		
	}
	
	private void showHideButtons(int indexTabbedPanel) {
		
		switch(indexTabbedPanel) {
		
			// CONFIGURATIONS
			case 0:
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
				
						executeMethodButton.setVisible(false);
						saveSettingsToFileButton.setVisible(true);
						loadSettingsFromFileButton.setVisible(true);
						generateJavaStubButton.setVisible(false);
						generatePythonStubButton.setVisible(false);
						loadJSFileButton.setVisible(false);
						saveJSFileButton.setVisible(false);
						loadTreeButton.setVisible(false);
						detachAllButton.setVisible(false);
						
		            }
		            
				});
				
				break;
			
			// JS editor	
			case 1:
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {

		            	executeMethodButton.setVisible(false);
						saveSettingsToFileButton.setVisible(false);
						loadSettingsFromFileButton.setVisible(false);
						generateJavaStubButton.setVisible(false);
						generatePythonStubButton.setVisible(false);
						loadJSFileButton.setVisible(true);
						saveJSFileButton.setVisible(true);
						loadTreeButton.setVisible(false);
						detachAllButton.setVisible(false);
						
		            }
		            
				});
				
				break;	
				
			// Tree view	
			case 2:
								
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {

		            	executeMethodButton.setVisible(false);
						saveSettingsToFileButton.setVisible(false);
						loadSettingsFromFileButton.setVisible(false);
						generateJavaStubButton.setVisible(false);
						generatePythonStubButton.setVisible(false);
						loadJSFileButton.setVisible(false);
						saveJSFileButton.setVisible(false);
						loadTreeButton.setVisible(true);
						detachAllButton.setVisible(false);
						
		            }
		            
				});
				
				break;					
				
				
			// GENERATE STUBS	
			case 3:
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {

		            	executeMethodButton.setVisible(false);
						saveSettingsToFileButton.setVisible(false);
						loadSettingsFromFileButton.setVisible(false);
						generateJavaStubButton.setVisible(true);
						generatePythonStubButton.setVisible(true);
						loadJSFileButton.setVisible(false);
						saveJSFileButton.setVisible(false);
						loadTreeButton.setVisible(false);
						detachAllButton.setVisible(false);
						
		            }
		            
				});
				
				break;
			
			// EXECUTE METHODS	
			case 4:
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
				
						executeMethodButton.setVisible(true);
						saveSettingsToFileButton.setVisible(false);
						loadSettingsFromFileButton.setVisible(false);
						generateJavaStubButton.setVisible(false);
						generatePythonStubButton.setVisible(false);
						loadJSFileButton.setVisible(false);
						saveJSFileButton.setVisible(false);
						loadTreeButton.setVisible(false);
						detachAllButton.setVisible(false);
						
		            }
		            
				});
				
				break;
				
			//TRAP METHODS	
			case 5:
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
				
						executeMethodButton.setVisible(false);
						saveSettingsToFileButton.setVisible(false);
						loadSettingsFromFileButton.setVisible(false);
						generateJavaStubButton.setVisible(false);
						generatePythonStubButton.setVisible(false);
						loadJSFileButton.setVisible(false);
						saveJSFileButton.setVisible(false);
						loadTreeButton.setVisible(false);
						detachAllButton.setVisible(true);
						
		            }
		            
				});
				
				break;
				
			default:			
				printException(null,"ShowHideButtons: index not found");				
				break;	
		
		}
		
	}	
	
	private String launchPyroServer(String pythonPath, String pyroServicePath) {
		
		Runtime rt = Runtime.getRuntime();
		
		String[] startServerCommand = {pythonPath,"-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};
			
		try {
			pyroServerProcess = rt.exec(startServerCommand);
			
			final BufferedReader stdOutput = new BufferedReader(new InputStreamReader(pyroServerProcess.getInputStream()));
			final BufferedReader stdError = new BufferedReader(new InputStreamReader(pyroServerProcess.getErrorStream()));
			
			ExecutorService executor = Executors.newFixedThreadPool(1);

			Callable<String> readTask = new Callable<String>() {
		        @Override
		        public String call() throws Exception {
		        	return stdOutput.readLine();
		        }
		    };
		    
		    Future<String> future = executor.submit(readTask);
		    String result = future.get(5000, TimeUnit.MILLISECONDS);
		    
			// Initialize thread that will read stdout
			stdoutThread = new Thread() {
				
				public void run() {
					
						while(true) {
					
							try {
								
								final String line = stdOutput.readLine();
								printJSMessage(line);
								
							} catch (IOException e) {
								printException(e,"Error reading Pyro stdout");
							}
							
						}
				}
				
			};			
			stdoutThread.start();
			
			// Initialize thread that will read stderr
			stderrThread = new Thread() {
				
				public void run() {
					
						while(true) {
												
							try {
								
								final String line = stdError.readLine();								
								printException(null,line);								
								
							} catch (IOException e) {
								
								printException(e,"Error reading Pyro stderr");
								
							}
							
						}
				}
				
			};			
			stderrThread.start();
		    
		    return result;
		    

			
		} catch (final Exception e1) {
			
			printException(e1,"Exception starting Pyro server");
			return "";
		}
		
		
	}
	
	private String generateJavaStub() {
		
		String out = "";
		out += "import net.razorvine.pyro.*;\n";
		out += "\n";
		out += "String pyroUrl = \"PYRO:BridaServicePyro@" + pyroHost.getText().trim() + ":" + pyroPort.getText().trim() + "\";\n";
		out += "try {\n";
		out += "\tPyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));\n";
		out += "\tString ret = (String)pp.call(\"callexportfunction\",\"METHOD_NAME\",new String[]{\"METHOD_ARG_1\",\"METHOD_ARG_2\",...});\n";
		out += "\tpp.close();\n";
		out += "} catch(IOException e) {\n";
		out += "\t// EXCEPTION HANDLING\n";
		out += "}\n";
		
		return out;
		
	}
	
	private String generatePythonStub() {
		
		String out = "";
		out += "import Pyro4\n";
		out += "\n";
		out += "uri = 'PYRO:BridaServicePyro@" + pyroHost.getText().trim() + ":" + pyroPort.getText().trim() + "'\n";
		out += "pp = Pyro4.Proxy(uri)\n";
		out += "args = []\n";
		out += "args.append(\"METHOD_ARG_1\")\n";
		out += "args.append(\"METHOD_ARG_2\")\n";
		out += "args.append(\"...\")\n";
		out += "ret = pp.callexportfunction('METHOD_NAME',args)\n";
		out += "pp._pyroRelease()\n";
		
		return out;
		
	}
	
	private void savePersistentSettings() {
		
		callbacks.saveExtensionSetting("pythonPath",pythonPath.getText().trim());
		callbacks.saveExtensionSetting("pyroHost",pyroHost.getText().trim());
		callbacks.saveExtensionSetting("pyroPort",pyroPort.getText().trim());
		callbacks.saveExtensionSetting("fridaPath",fridaPath.getText().trim());
		callbacks.saveExtensionSetting("applicationId",applicationId.getText().trim());
		if(remoteRadioButton.isSelected()) {
			callbacks.saveExtensionSetting("remote","true");
		} else {
			callbacks.saveExtensionSetting("remote","false");
		}
		callbacks.saveExtensionSetting("executeMethodName",executeMethodName.getText().trim());
		int sizeArguments = executeMethodInsertedArgumentList.getSize();
		callbacks.saveExtensionSetting("executeMethodSizeArguments",Integer.toString(sizeArguments));
		for(int i=0; i< sizeArguments; i++) {			
			callbacks.saveExtensionSetting("executeMethodArgument" + i,(String)executeMethodInsertedArgumentList.getElementAt(i));			
		}

	}
	
	private void exportConfigurationsToFile() {
		
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration output file");
		
		int userSelection = fileChooser.showSaveDialog(parentFrame);
		
		if(userSelection == JFileChooser.APPROVE_OPTION) {

			
			File outputFile = fileChooser.getSelectedFile();
			FileWriter fw;
			try {
				fw = new FileWriter(outputFile);
				
				fw.write("pythonPath:" + pythonPath.getText().trim() + "\n");
				fw.write("pyroHost:" + pyroHost.getText().trim() + "\n");
				fw.write("pyroPort:" + pyroPort.getText().trim() + "\n");
				fw.write("fridaPath:" + fridaPath.getText().trim() + "\n");
				fw.write("applicationId:" + applicationId.getText().trim() + "\n");
				if(remoteRadioButton.isSelected()) 
					fw.write("remote:true\n");
				else
					fw.write("remote:false\n");
				fw.write("executeMethodName:" + executeMethodName.getText().trim() + "\n");
				
				int sizeArguments = executeMethodInsertedArgumentList.getSize();
				fw.write("executeMethodSizeArguments:" + sizeArguments + "\n");
				for(int i=0; i< sizeArguments; i++) {			
					fw.write("executeMethodArgument" + i + ":" + ((String)executeMethodInsertedArgumentList.getElementAt(i)) + "\n");			
				}				
				
				fw.close();
				
				printSuccessMessage("Saving configurations to file executed correctly");
				
			} catch (final IOException e) {
				
				printException(e,"Exception exporting configurations to file");
				
				return;
			}			
				
		}
		
	}

	private void loadConfigurationsFromFile() {
		
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration input file");
		
		int userSelection = fileChooser.showOpenDialog(parentFrame);
		
		if(userSelection == JFileChooser.APPROVE_OPTION) {
			
			File inputFile = fileChooser.getSelectedFile();
						
			try {
				
				BufferedReader br = new BufferedReader(new FileReader(inputFile));
				
				String line;
				while ((line = br.readLine()) != null) {
					String[] lineParts = line.split(":",2);
					
					if(lineParts.length > 1) {
											
						switch(lineParts[0]) {
						case "pythonPath":
							pythonPath.setText(lineParts[1]);
							break;
						case "pyroHost":
							pyroHost.setText(lineParts[1]);
							break;
						case "pyroPort":
							pyroPort.setText(lineParts[1]);
							break;
						case "fridaPath":
							fridaPath.setText(lineParts[1]);
							break;
						case "applicationId":
							applicationId.setText(lineParts[1]);
							break;
						case "remote":
							if(lineParts[1].equals("true")) {
								remoteRadioButton.setSelected(true);
							} else {
								localRadioButton.setSelected(true);
							}
							break;
						case "executeMethodSizeArguments":
							executeMethodInsertedArgumentList.clear();
							break;
						case "executeMethodName":
							executeMethodName.setText(lineParts[1]);
							break;
						default:
							if(lineParts[0].startsWith("executeMethodArgument")) {
								executeMethodInsertedArgumentList.addElement(lineParts[1]);
							} else {
								printException(null,"Invalid option " + lineParts[0]);
							}							
						}
						
					} else {
						
						printException(null,"The line does not contain a valid option");
						
					}
					
				}
							 				
				br.close();
				
				printSuccessMessage("Loading configurations executed correctly");
				
			} catch (final Exception e) {
				
				printException(e,"Error loading configurations from file");
				return;
				
			}
			
			
		}
	}

	public String getTabCaption() {

		return "Brida";
	}

	public Component getUiComponent() {
		return mainPanel;
	}

	public void actionPerformed(ActionEvent event) {

		String command = event.getActionCommand();
		
		if (command.equals("addExecuteMethodArgument")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	executeMethodInsertedArgumentList.addElement(executeMethodArgument.getText().trim());
	    			executeMethodArgument.setText("");
					
	            }
			});		
			
		} else  if (command.equals("removeExecuteMethodArgument")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	int index = executeMethodInsertedArgument.getSelectedIndex();
	            	if(index != -1) {
	            		executeMethodInsertedArgumentList.remove(index);
	            	}
	            	
	            }
			});	
			
		} else  if (command.equals("modifyExecuteMethodArgument")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	int index = executeMethodInsertedArgument.getSelectedIndex();
	            	if(index != -1) {
	            		executeMethodArgument.setText((String)executeMethodInsertedArgument.getSelectedValue());
	            		executeMethodInsertedArgumentList.remove(index);
	            	}
					
	            }
			});	
		
		
		} else if(command.equals("spawnApplication") && serverStarted) {
			
			try {
				
				pyroBridaService.call("spawn_application", applicationId.getText().trim(), fridaPath.getText().trim(),remoteRadioButton.isSelected());
				applicationSpawned = true;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	applicationStatus.setText("");
		            	applicationStatusButtons.setText("");
		            			            	
		            	// Empty trapping table
		            	List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
		            	synchronized(trapEntries) {
		            		int trapEntryOldSize = trapEntries.size();
		            		if(trapEntryOldSize > 0) {
		            			trapEntries.clear();
		            			((TrapTableModel)(trapTable.getModel())).fireTableRowsDeleted(0, trapEntryOldSize - 1);
		            		}
		                }
		            	
		            	try {
		                	documentApplicationStatus.insertString(0, "spawned", greenStyle);
		                	documentApplicationStatusButtons.insertString(0, "App running", greenStyle);
						} catch (BadLocationException e) {
							printException(e,"Exception with labels");
						}
						
		            }
				});
				
				printSuccessMessage("Application " + applicationId.getText().trim() + " spawned correctly");
				
			} catch (final Exception e) {
				
				printException(e,"Exception with spawn application");
				
			}
		
			
		} else if(command.equals("reloadScript") && serverStarted && applicationSpawned) {
				
			try {
				
				pyroBridaService.call("reload_script");
				
				printSuccessMessage("Reloading script executed");
				
			} catch (final Exception e) {
								
				printException(e,"Exception reloading script");
				
			}
	
						
		} else if(command.equals("killApplication") && serverStarted && applicationSpawned) {
			
			try {
				pyroBridaService.call("disconnect_application");
				applicationSpawned = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	applicationStatus.setText("");
		            	applicationStatusButtons.setText("");
		            	try {
		                	documentApplicationStatus.insertString(0, "NOT spawned", redStyle);
		                	documentApplicationStatusButtons.insertString(0, "App stopped", redStyle);
						} catch (BadLocationException e) {
							printException(e,"Exception setting labels");
						}
						
		            }
				});
				
				printSuccessMessage("Killing application executed");
				
			} catch (final Exception e) {
				
				printException(e,"Exception killing application");
				
			}
			
		} else if(command.equals("killServer") && serverStarted) {
			
			stdoutThread.stop();
			stderrThread.stop();
			
			try {
				pyroBridaService.call("shutdown");
				pyroServerProcess.destroy();
				pyroBridaService.close();
				serverStarted = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	serverStatus.setText("");
		            	serverStatusButtons.setText("");
		            	try {
		                	documentServerStatus.insertString(0, "NOT running", redStyle);
		                	documentServerStatusButtons.insertString(0, "Server stopped", redStyle);
						} catch (BadLocationException e) {
							printException(e,"Exception setting labels");
						}
						
		            }
				});
				
				printSuccessMessage("Pyro server shutted down");
				
			} catch (final Exception e) {
				
				printException(e,"Exception shutting down Pyro server");
				
			}
		
			
		} else if(command.equals("startServer") && !serverStarted) {
			
			savePersistentSettings();
			
			try {
				
				final String startPyroServerResult = launchPyroServer(pythonPath.getText().trim(),pythonScript);
				
				if(startPyroServerResult.trim().equals("Ready.")) {
						        	
		        	pyroBridaService = new PyroProxy(new PyroURI("PYRO:BridaServicePyro@" + pyroHost.getText().trim() + ":" + pyroPort.getText().trim()));
		        	serverStarted = true;	 
		        	
		        	SwingUtilities.invokeLater(new Runnable() {
						
			            @Override
			            public void run() {
			            	
			            	serverStatus.setText("");
			            	serverStatusButtons.setText("");
			            	try {
			                	documentServerStatus.insertString(0, "running", greenStyle);
			                	documentServerStatusButtons.insertString(0, "Server running", greenStyle);
							} catch (BadLocationException e) {
								
								printException(e,"Exception setting labels");

							}
							
			            }
					});
		        	
		        	printSuccessMessage("Pyro server started correctly");
		        	
		        } else {	
		        	
		        	if(!(startPyroServerResult.trim().equals(""))) {
		        				        		
		        		printException(null,"Exception starting Pyro Server");
		        		printException(null,startPyroServerResult.trim());
		        		
		        	}
		        	return;		        	
		        }
			} catch (final Exception e) {
								
				printException(null,"Exception starting Pyro server");
								
			}
			
		} else if(command.equals("executeMethod")) {
			
			savePersistentSettings();
			
			try {
				
				String[] arguments = new String[executeMethodInsertedArgumentList.size()];
				for(int i=0;i<executeMethodInsertedArgumentList.size();i++) {	
					arguments[i] = (String)(executeMethodInsertedArgumentList.getElementAt(i));
				}
				
				final String s = (String)(pyroBridaService.call("callexportfunction",executeMethodName.getText().trim(),arguments));
								
				printJSMessage("*** Output " + executeMethodName.getText().trim() + ":");
				printJSMessage(s);
				
			} catch (Exception e) {
				
				printException(e,"Exception with execute method");
				
			}
			
		} else if(command.equals("generateJavaStub")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	stubTextEditor.setText(generateJavaStub().getBytes());
	                
	            }
			});
	
		} else if(command.equals("generatePythonStub")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	stubTextEditor.setText(generatePythonStub().getBytes());

	            }
			});
			
		} else if(command.equals("saveSettingsToFile")) {
			
			exportConfigurationsToFile();
			
		} else if(command.equals("loadSettingsFromFile")) {
			
			loadConfigurationsFromFile();			
			
		} else if(command.equals("loadJsFile")) {
			
			File jsFile = new File(fridaPath.getText().trim());
			byte[] jsFileContent = null;
			try {
				jsFileContent = Files.readAllBytes(jsFile.toPath());
			} catch (IOException e) {
				printException(e,"Error opening JS file");
			}
			
			final byte[] test = jsFileContent;
			
			if(jsFileContent != null) {
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            			            	
		            	jsEditorTextArea.setText(new String(test));

		            }
				});
				
			}
			
			
		} else if(command.equals("saveJsFile")) {
		
			File jsFile = new File(fridaPath.getText().trim());
			try {
				Files.write(jsFile.toPath(), jsEditorTextArea.getText().getBytes(), StandardOpenOption.WRITE);
			} catch (IOException e) {
				printException(e,"Error writing to JS file");
			}
		
		} else if(command.equals("contextcustom1") || command.equals("contextcustom2")) {
			
			IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = currentInvocation.getInvocationContext();
			
			try {
				
				byte[] selectedRequestOrResponse = null;
				if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
					selectedRequestOrResponse = selectedItems[0].getRequest();
				} else {
					selectedRequestOrResponse = selectedItems[0].getResponse();
				}
				
				byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
				byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
				byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);
				
				String s = (String)(pyroBridaService.call("callexportfunction",command,new String[]{byteArrayToHexString(selectedPortion)}));
				
				byte[] newRequest = ArrayUtils.addAll(preSelectedPortion, hexStringToByteArray(s));
				newRequest = ArrayUtils.addAll(newRequest, postSelectedPortion);
				
				selectedItems[0].setRequest(newRequest);
			
			} catch (Exception e) {
				
				printException(e,"Exception with custom context application");
				
			}
				

		} else if(command.equals("loadTree")) {
			
			try {
				
				ArrayList<String> allClasses = (ArrayList<String>)(pyroBridaService.call("callexportfunction","getallclasses",new String[0]));
				HashMap<String, Integer> allModules = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getallmodules",new String[0]));
				
				// Sort classes
				Collections.sort(allClasses, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
				
				
				ArrayList<String> moduleNames = new ArrayList<String>(allModules.keySet());
				
				// Sort module names
				Collections.sort(moduleNames, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
								
				DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
				
				DefaultMutableTreeNode newRoot = new DefaultMutableTreeNode("Binary");
				
				DefaultMutableTreeNode objNode = new DefaultMutableTreeNode("Objective-C");
				
				DefaultMutableTreeNode currentNode;
				
				for(int i=0; i<allClasses.size(); i++) {

					currentNode = new DefaultMutableTreeNode(allClasses.get(i));

					objNode.add(currentNode);
					
				}

				newRoot.add(objNode);
				
				DefaultMutableTreeNode modulesNode = new DefaultMutableTreeNode("Modules");
			
				for(int i=0; i<moduleNames.size(); i++) {

					currentNode = new DefaultMutableTreeNode(moduleNames.get(i));

					modulesNode.add(currentNode);
					
				}

				newRoot.add(modulesNode);				
				
				model.setRoot(newRoot);

			} catch (Exception e) {
								
				printException(e,"Exception with load tree");
				
			}

		} else if(command.equals("searchAnalysis")) {
		
			String toSearch = findTextField.getText().trim();
			
			HashMap<String, Integer> foundObjcMethods;
			try {
				foundObjcMethods = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","findobjcmethods",new String[] {toSearch}));
			} catch (Exception e) {
				printException(e,"Exception searching OBJC methods");
				return;
			} 
			
			HashMap<String, Integer> foundImports;
			try {
				foundImports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","findimports",new String[] {toSearch}));
			} catch (Exception e) {
				printException(e,"Exception searching imports");
				return;
			} 
			
			HashMap<String, Integer> foundExports;
			try {
				foundExports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","findexports",new String[] {toSearch}));
			} catch (Exception e) {
				printException(e,"Exception searching exports");
				return;
			} 
				
			printJSMessage("**** Result of the search of " + findTextField.getText().trim());
			
			if(foundObjcMethods != null) {
				
				ArrayList<String> objcMethodNames = new ArrayList<String>(foundObjcMethods.keySet());
				
				// Sort objc method names
				Collections.sort(objcMethodNames, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
			
				Iterator<String> currentClassMethodsIterator = objcMethodNames.iterator(); 
				
				String currentMethodName;
				
				while(currentClassMethodsIterator.hasNext()) {
					
					currentMethodName = currentClassMethodsIterator.next();
					printJSMessage("OBJC: " + currentMethodName);
					
				}
				
			}
			
			if(foundImports != null) {
				
				ArrayList<String> importNames = new ArrayList<String>(foundImports.keySet());
				
				// Sort import names
				Collections.sort(importNames, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
				
				Iterator<String> currentImportIterator = importNames.iterator(); 
				
				
				
				String currentImportName;
				
				while(currentImportIterator.hasNext()) {
					
					currentImportName = currentImportIterator.next();
					printJSMessage("IMPORT: " + currentImportName);
					
				}
				
			}
			
			if(foundExports != null) {
				
				ArrayList<String> exportNames = new ArrayList<String>(foundExports.keySet());
				
				// Sort export names
				Collections.sort(exportNames, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
				
				Iterator<String> exportIterator = exportNames.iterator(); 
				
				
				String currentExportName;
				
				while(exportIterator.hasNext()) {
					
					currentExportName = exportIterator.next();
					printJSMessage("EXPORT: " + currentExportName);
					
				}
				
			}
					
		} else if(command.equals("trap")) {	
			
			trap(false);
			
		} else if(command.equals("detachAll")) {	
			
			int dialogButton = JOptionPane.YES_NO_OPTION;
			int dialogResult = JOptionPane.showConfirmDialog(mainPanel, "Detach all will detach also custom interception methods defined in your JS file. Are you sure?", "Confirm detach all", dialogButton);
			if(dialogResult == 0) {
				try {
					pyroBridaService.call("callexportfunction","detachAll",new String[] {});
				} catch (Exception e) {					
					printException(e,"Exception detaching all");
					return;
				}
				
				// Empty trapping table
            	List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
            	synchronized(trapEntries) {
            		int trapEntryOldSize = trapEntries.size();
            		if(trapEntryOldSize > 0) {
            			trapEntries.clear();
            			((TrapTableModel)(trapTable.getModel())).fireTableRowsDeleted(0, trapEntryOldSize - 1);
            		}
                }
				
				printSuccessMessage("Detaching all successfully executed");
				
			} else {
				printSuccessMessage("Detaching all CANCELED as requested by the user");
			}			
			
		} else if(command.equals("trapBacktrace")) {	
			
			trap(true);	
			
		} else if(command.equals("contextcustom3") || command.equals("contextcustom4")) {
			
			IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = currentInvocation.getInvocationContext();
			
			try {
				
				byte[] selectedRequestOrResponse = null;
				if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
					selectedRequestOrResponse = selectedItems[0].getRequest();
				} else {
					selectedRequestOrResponse = selectedItems[0].getResponse();
				}
				
				byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
				
				final String s = (String)(pyroBridaService.call("callexportfunction",command,new String[]{byteArrayToHexString(selectedPortion)}));
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	JTextArea ta = new JTextArea(10, 10);
		                ta.setText(new String(hexStringToByteArray(s)));
		                ta.setWrapStyleWord(true);
		                ta.setLineWrap(true);
		                ta.setCaretPosition(0);
		                ta.setEditable(false);

		                JOptionPane.showMessageDialog(null, new JScrollPane(ta), "Custom invocation response", JOptionPane.INFORMATION_MESSAGE);
					    
		            }
		            
				});
				
			
			} catch (Exception e) {

				printException(e,"Exception with custom context application");
				
			}
		

		} else if(command.equals("pythonPathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Python Path");
			
			int userSelection = fileChooser.showOpenDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				final File pythonPathFile = fileChooser.getSelectedFile();
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	pythonPath.setText(pythonPathFile.getAbsolutePath());
		            }
				
				});
				
			}				
			
		} else if(command.equals("fridaPathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Frida JS Path");
			
			int userSelection = fileChooser.showOpenDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				final File fridaPathFile = fileChooser.getSelectedFile();
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	fridaPath.setText(fridaPathFile.getAbsolutePath());
		            }
				
				});
				
			}				
			
		} else if(command.startsWith("changeReturnValue")) {
			
        	Pattern p = Pattern.compile("^changeReturnValue(.*)$", Pattern.DOTALL);
    		Matcher m = p.matcher(command);
    		
    		String changeType = null;
    		if(m.find()) {
    			changeType = m.group(1);
    		}

    		if(changeType != null) {
    			
    			stdout.println(changeType);
    			
    			String dialogResult = JOptionPane.showInputDialog(mainPanel, "Insert the new " + changeType + " return value","Return value",JOptionPane.QUESTION_MESSAGE);
    			changeReturnValue(changeType,dialogResult);
    			
    		}
			
		} else if(command.startsWith("clearConsole")) {
		
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	String newConsoleText = "<font color=\"green\">";
	        		newConsoleText = newConsoleText + "<b>**** Console cleared successfully ****</b><br/>";
	        		newConsoleText = newConsoleText + "</font><br/>";		
	        		
	        		pluginConsoleTextArea.setText(newConsoleText);	        		 	
	            	
	            }
			
			});
			
		}
		
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		
		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
		   invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
		
			currentInvocation = invocation;
			
			List<JMenuItem> menu = new ArrayList<JMenuItem>();
			
			JMenuItem itemCustom1 = new JMenuItem("Brida Custom 1");
			itemCustom1.setActionCommand("contextcustom1");
			itemCustom1.addActionListener(this);
			
			JMenuItem itemCustom2 = new JMenuItem("Brida Custom 2");
			itemCustom2.setActionCommand("contextcustom2");
			itemCustom2.addActionListener(this);		
			
			menu.add(itemCustom1);
			menu.add(itemCustom2);
			
			return menu;
			
		} else if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
				  invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) { 
			
			currentInvocation = invocation;
			
			List<JMenuItem> menu = new ArrayList<JMenuItem>();
			
			JMenuItem itemCustom3 = new JMenuItem("Brida Custom 3");
			itemCustom3.setActionCommand("contextcustom3");
			itemCustom3.addActionListener(this);
			
			JMenuItem itemCustom4 = new JMenuItem("Brida Custom 4");
			itemCustom4.setActionCommand("contextcustom4");
			itemCustom4.addActionListener(this);		
			
			menu.add(itemCustom3);
			menu.add(itemCustom4);
			
			return menu;
		
		
		} else {
		
			return null;
			
		}
		
	}
	
	static String byteArrayToHexString(byte[] raw) {
        StringBuilder sb = new StringBuilder(2 + raw.length * 2);
        for (int i = 0; i < raw.length; i++) {
            sb.append(String.format("%02X", Integer.valueOf(raw[i] & 0xFF)));
        }
        return sb.toString();
    }
	
	private static byte[] hexStringToByteArray(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++){
          int index = i * 2;
          int v = Integer.parseInt(hex.substring(index, index + 2), 16);
          b[i] = (byte)v;
        }
        return b;
   }
	
	private void retrieveClassMethods(DefaultMutableTreeNode clickedNode) {
		
		DefaultMutableTreeNode parent = (DefaultMutableTreeNode)clickedNode.getParent();
		
		if(parent != null) {
			
			String nodeContentParent = (String)parent.getUserObject();
			String nodeContent = (String)clickedNode.getUserObject();
			
			if(nodeContentParent.equals("Modules")) {
								
				HashMap<String, Integer> currentImports;
				try {
					currentImports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getmoduleimports",new String[] {nodeContent}));
				} catch (Exception e) {
					printException(e,"Exception retrieving module imports");
					return;
				} 
				
				if(currentImports != null) {
					
					ArrayList<String> importNames = new ArrayList<String>(currentImports.keySet());
					
					// Sort import names
					Collections.sort(importNames, new Comparator<String>() {
				        @Override
				        public int compare(String class1, String class2)
				        {

				            return  class1.compareToIgnoreCase(class2);
				        }
				    });	
										
					DefaultMutableTreeNode importNode = new DefaultMutableTreeNode("Imports");
					
					Iterator<String> currentImportsIterator = importNames.iterator(); 
					
					String currentImportName;
					DefaultMutableTreeNode currentNodeImport;
					while(currentImportsIterator.hasNext()) {
						
						currentImportName = currentImportsIterator.next();
																
						currentNodeImport = new DefaultMutableTreeNode(currentImportName);
						
						importNode.add(currentNodeImport);
						
					}
					
					clickedNode.add(importNode);
					
				}
				
				HashMap<String, Integer> currentExports;
				try {
					currentExports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getmoduleexports",new String[] {nodeContent}));
				} catch (Exception e) {
					printException(e,"Exception retrieving module exports");
					return;
				} 
				
				if(currentExports != null) {
					
					ArrayList<String> exportNames = new ArrayList<String>(currentExports.keySet());
					
					// Sort export names
					Collections.sort(exportNames, new Comparator<String>() {
				        @Override
				        public int compare(String class1, String class2)
				        {

				            return  class1.compareToIgnoreCase(class2);
				        }
				    });	
					
					DefaultMutableTreeNode exportNode = new DefaultMutableTreeNode("Exports");
					
					Iterator<String> currentExportsIterator = exportNames.iterator(); 
					
					String currentExportName;
					DefaultMutableTreeNode currentNodeExport;
					while(currentExportsIterator.hasNext()) {
						
						currentExportName = currentExportsIterator.next();
																
						currentNodeExport = new DefaultMutableTreeNode(currentExportName);
						
						exportNode.add(currentNodeExport);
						
					}
					
					clickedNode.add(exportNode);
					
				}
				
				
				
			} else if (nodeContentParent.equals("Objective-C")) {
				
				
				
				HashMap<String, Integer> currentClassMethods;
				try {
					currentClassMethods = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getclassmethods",new String[] {nodeContent}));
				} catch (Exception e) {
					printException(e,"Exception retrieving class methods");
					return;
				} 

				if(currentClassMethods != null) {
					
					ArrayList<String> methodNames = new ArrayList<String>(currentClassMethods.keySet());
					
					// Sort method names
					Collections.sort(methodNames, new Comparator<String>() {
				        @Override
				        public int compare(String class1, String class2)
				        {

				            return  class1.compareToIgnoreCase(class2);
				        }
				    });	
				
					Iterator<String> currentClassMethodsIterator = methodNames.iterator(); 
					
					String currentMethodName;
					DefaultMutableTreeNode currentNodeMethod;
					while(currentClassMethodsIterator.hasNext()) {
						
						currentMethodName = currentClassMethodsIterator.next();
										
						currentNodeMethod = new DefaultMutableTreeNode(currentMethodName);
						
						clickedNode.add(currentNodeMethod);
						
					}
					
				}
					
			}			
			
			DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
			model.reload(clickedNode);
			
			tree.expandPath(new TreePath(clickedNode.getPath()));
						
		}
		
	}

	/*
	 * You can only autotrap iOS class, iOS method and single exports for the moment.
	 */	
	public void trap(boolean withBacktrace) {		

		DefaultMutableTreeNode clickedNode = (DefaultMutableTreeNode)(tree.getSelectionPath().getLastPathComponent());
		
		DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)clickedNode.getParent();
		
		String type = null;	
		String pattern = null;
		
		// ROOT
		if(parentNode != null) {
		
			String parentNodeContent = (String)parentNode.getUserObject();			
			
			DefaultMutableTreeNode grandparentNode = null;
	
			switch(parentNodeContent) {
			
				// Clicked a iOS class
				case "Objective-C":
					
					type = "objc_class";
					pattern = (String)clickedNode.getUserObject();
					
					break;
					
				// Clicked a iOS export
				case "Exports":
					
					// Only functions can be trapped
					if(((String)clickedNode.getUserObject()).startsWith("function")) {
						
						type = "ios_export";						
						grandparentNode = (DefaultMutableTreeNode)parentNode.getParent();
						pattern = (String)grandparentNode.getUserObject() + "!" + ((String)clickedNode.getUserObject()).replace("function: ", "");
												
					}
					
					break;
					
				default:
					
					grandparentNode = (DefaultMutableTreeNode)parentNode.getParent();
					
					if(grandparentNode != null) {
						
						String grandparentNodeContent = (String)grandparentNode.getUserObject();
						
						// Clicked a iOS method
						if(grandparentNodeContent.equals("Objective-C")) {
							
							type = "objc_method";
							pattern = (String)clickedNode.getUserObject();
							
						}						
						
					}				
					
					break;
			
			}
			
		}
		
		if(type != null) {
				
			try {
				pyroBridaService.call("callexportfunction","trace",new String[] {pattern,type,(withBacktrace ? "true" : "false")});
				
				List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
	
				HashMap<String,Integer> currentClassMethods = null;
				
				// Better outside synchronized block
				if(type.equals("objc_class")) {
	        		currentClassMethods = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getclassmethods",new String[] {pattern}));
				}
				
	            synchronized(trapEntries) {
	            	int trapEntryOldSize = trapEntries.size();
	            	if(type.equals("objc_class")) {
	            		if(currentClassMethods != null) {    					
	    					ArrayList<String> methodNames = new ArrayList<String>(currentClassMethods.keySet());
	    					Iterator<String> currentClassMethodsIterator = methodNames.iterator();     					
	    					String currentMethodName;
	    					while(currentClassMethodsIterator.hasNext()) {    						
	    						currentMethodName = currentClassMethodsIterator.next();    										
	    						trapEntries.add(new TrapTableItem("Inspect","OBJ-C",currentMethodName, withBacktrace,"-","-"));    						
	    					}    					
	    				}            		
	            	} else if(type.equals("objc_method")) {
	            		trapEntries.add(new TrapTableItem("Inspect","OBJ-C",pattern, withBacktrace,"-","-"));
	            	} else {
	            		trapEntries.add(new TrapTableItem("Inspect","IOS Exports",pattern, withBacktrace,"-","-"));
	            	}
	            	((TrapTableModel)(trapTable.getModel())).fireTableRowsInserted(trapEntryOldSize, trapEntries.size() - 1);
	            } 
							
			} catch (Exception e) {
				
				printException(e,"Exception with trap");
				
			}
			
		}
		
	}
	
	public void changeReturnValue(String returnValueType, String dialogResult) {
		
		//changeReturnValue("ptr",dialogResult)

		DefaultMutableTreeNode clickedNode = (DefaultMutableTreeNode)(tree.getSelectionPath().getLastPathComponent());
		
		DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)clickedNode.getParent();
		
		String type = null;	
		String pattern = null;
		
		// ROOT
		if(parentNode != null) {
		
			String parentNodeContent = (String)parentNode.getUserObject();			
			
			DefaultMutableTreeNode grandparentNode = null;
	
			switch(parentNodeContent) {
					
				// Clicked a iOS export
				case "Exports":
					
					// Only functions can be trapped
					if(((String)clickedNode.getUserObject()).startsWith("function")) {
						
						type = "ios_export";						
						grandparentNode = (DefaultMutableTreeNode)parentNode.getParent();
						pattern = (String)grandparentNode.getUserObject() + "!" + ((String)clickedNode.getUserObject()).replace("function: ", "");
												
					}
					
					break;
					
				default:
					
					grandparentNode = (DefaultMutableTreeNode)parentNode.getParent();
					
					if(grandparentNode != null) {
						
						String grandparentNodeContent = (String)grandparentNode.getUserObject();
						
						// Clicked a iOS method
						if(grandparentNodeContent.equals("Objective-C")) {
							
							type = "objc_method";
							pattern = (String)clickedNode.getUserObject();
							
						}						
						
					}				
					
					break;
			
			}
			
		}
		
		if(type != null) {
				
			try {
				
				pyroBridaService.call("callexportfunction","changereturnvalue",new String[] {pattern,type,returnValueType,dialogResult});
								
				List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
					
	            synchronized(trapEntries) {
	            	int trapEntryOldSize = trapEntries.size();
	            	if(type.equals("objc_method")) {
	            		trapEntries.add(new TrapTableItem("Edit return","OBJ-C",pattern, false,returnValueType,dialogResult));
	            	} else {
	            		trapEntries.add(new TrapTableItem("Edit return","IOS Exports",pattern, false,returnValueType,dialogResult));
	            	}
	            	((TrapTableModel)(trapTable.getModel())).fireTableRowsInserted(trapEntryOldSize, trapEntries.size() - 1);
	            } 
					
				
			} catch (Exception e) {
				
				printException(e,"Exception with replace return value");
				
			}
			
		}
		
	}
	
	private void generatePopup(MouseEvent e){
		TreePopup menu = new TreePopup(this);
		menu.show(e.getComponent(), e.getX(), e.getY());
    }
	
	@Override
	public void mouseClicked(MouseEvent e) {
		
		// Double click -> EXPAND
		if (e.getClickCount() == 2) {
								
			//stdout.println("CLICK: " + tree.getSelectionPath().getLastPathComponent().getClass());
			
			DefaultMutableTreeNode clickedNode = (DefaultMutableTreeNode)(tree.getSelectionPath().getLastPathComponent());
			
			retrieveClassMethods(clickedNode);

        }
			
	}

	@Override
	public void mousePressed(MouseEvent e) {

		if(e.isPopupTrigger()) {
			int row = tree.getClosestRowForLocation(e.getX(), e.getY());
            tree.setSelectionRow(row);
			generatePopup(e);
		}
		
	}

	@Override
	public void mouseReleased(MouseEvent e) {

		if(e.isPopupTrigger()) {
			int row = tree.getClosestRowForLocation(e.getX(), e.getY());
            tree.setSelectionRow(row);
			generatePopup(e);
		}
		
	}

	@Override
	public void mouseEntered(MouseEvent e) {
	}

	@Override
	public void mouseExited(MouseEvent e) {
	}
	
	public void printSuccessMessage(final String message) {
		
		SwingUtilities.invokeLater(new Runnable() {
			
            @Override
            public void run() {
            	
            	String oldConsoleText = pluginConsoleTextArea.getText();
            	
        		Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
        		Matcher m = p.matcher(oldConsoleText);
        		
        		String newConsoleText = "";
        		if(m.find()) {
        			newConsoleText = m.group(1);
        		}        		
        		        		
        		if(lastPrintIsJS) {
        			newConsoleText = newConsoleText + "<br/>";
        		}
        		
        		newConsoleText = newConsoleText + "<font color=\"green\">";
        		newConsoleText = newConsoleText + "<b>" + message + "</b><br/>";
        		newConsoleText = newConsoleText + "</font><br/>";
        		
        		pluginConsoleTextArea.setText(newConsoleText);
            	
        		lastPrintIsJS = false;
            	
            }
		
		});
		
	}
	
	
	public void printJSMessage(final String message) {
		
		SwingUtilities.invokeLater(new Runnable() {
			
            @Override
            public void run() {
        		
            	String oldConsoleText = pluginConsoleTextArea.getText();
            	Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
        		Matcher m = p.matcher(oldConsoleText);
        		
        		String newConsoleText = "";
        		if(m.find()) {
        			newConsoleText = m.group(1);
        		}           	
        		
        		newConsoleText = newConsoleText + "<font color=\"black\"><pre>";
        		//newConsoleText = newConsoleText + message + "<br/>";
        		newConsoleText = newConsoleText + message;
        		newConsoleText = newConsoleText + "</pre></font>";
        		
        		pluginConsoleTextArea.setText(newConsoleText);
        		
        		lastPrintIsJS = true;            	
            	
            }
		
		});
		
	}
	
	
	public void printException(final Exception e, final String message) {
		
		SwingUtilities.invokeLater(new Runnable() {
			
            @Override
            public void run() {
        		
        		
            	String oldConsoleText = pluginConsoleTextArea.getText();
            	Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
        		Matcher m = p.matcher(oldConsoleText);
        		
        		String newConsoleText = "";
        		if(m.find()) {
        			newConsoleText = m.group(1);
        		}
        		        		
        		if(lastPrintIsJS) {
        			newConsoleText = newConsoleText + "<br/>";
        		}
        		
        		newConsoleText = newConsoleText + "<font color=\"red\">";
        		newConsoleText = newConsoleText + "<b>" + message + "</b><br/>";
        		
        		if(e != null) {        		
	        		newConsoleText = newConsoleText + e.toString() + "<br/>";
	        		//consoleText = consoleText + e.getMessage() + "<br/>";
	        		StackTraceElement[] exceptionElements = e.getStackTrace();
	        		for(int i=0; i< exceptionElements.length; i++) {
	        			newConsoleText = newConsoleText + exceptionElements[i].toString() + "<br/>";
	        		}		
        		}
        		
        		newConsoleText = newConsoleText + "</font><br/>";
        		
        		pluginConsoleTextArea.setText(newConsoleText);
        		
        		lastPrintIsJS = false;            	
            	
            }
		
		});
		
	}
	
}
