package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JTree;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.fife.ui.rsyntaxtextarea.FileLocation;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.TextEditorPane;
import org.fife.ui.rtextarea.RTextScrollPane;

import burp.BridaMessageEditorPlugin.BridaMessageEditorPluginOutputLocation;
import burp.CustomPlugin.CustomPluginExecuteValues;
import burp.CustomPlugin.CustomPluginFunctionOutputValues;
import burp.CustomPlugin.CustomPluginParameterValues;
import net.razorvine.pickle.PickleException;
import net.razorvine.pyro.*;

public class BurpExtender implements IBurpExtender, ITab, ActionListener, MouseListener, IExtensionStateListener {
	
	public static final int PLATFORM_ANDROID = 0;
	public static final int PLATFORM_IOS = 1;
	public static final int PLATFORM_GENERIC = 2;

	public IBurpExtenderCallbacks callbacks;
	public IExtensionHelpers helpers;
    
    public PrintWriter stdout;
    public PrintWriter stderr;
    
    private JPanel mainPanel;
    
    private PyroProxy pyroBridaService;
    private Process pyroServerProcess;
    	
	private JTextField pythonPathVenv;
	private String pythonScript;
	public JTextField pyroHost;
	public JTextField pyroPort;
	private JTextField fridaCompilePath;
	private JTextPane serverStatus;
	private JTextPane applicationStatus;
	private JTextField fridaPath;
    private JTextField applicationId;
    private JCheckBox fridaCompileOldCheckBox; 
    private JCheckBox useVirtualEnvCheckBox;
    
    private JRadioButton remoteRadioButton;
    private JRadioButton usbRadioButton;
    private JRadioButton localRadioButton;
    private JRadioButton hostRadioButton;
    private JRadioButton deviceRadioButton;

    private JTextField hostPortDevice;
    	
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
	private JLabel labelPythonPathVenv;
	
	public boolean serverStarted;
	public boolean applicationSpawned;
	public boolean customPluginEnabled;
		
	private ITextEditor stubTextEditor;
    
    private JButton executeMethodButton;
    private JButton saveSettingsToFileButton;
    private JButton loadSettingsFromFileButton;
    private JButton generateJavaStubButton;
    private JButton generatePythonStubButton;    
    private JButton loadJSFileButton;
    private JButton saveJSFileButton; 
    private JButton loadTreeButton;
    private JButton removeAllGraphicalHooksButton;
    private JButton clearConsoleButton;
    private JButton enableCustomPluginButton;
    private JButton exportCustomPluginsButton;
    private JButton importCustomPluginsButton;
    
    private JEditorPane pluginConsoleTextArea;
    
    private TextEditorPane jsEditorTextArea;
	
    private Thread stdoutThread;
    private Thread stderrThread;
    
    private JTextField findTextField;
    
    private JTree tree;
    
    private JTable trapTable;
    
    private boolean lastPrintIsJS;
    
    private int platform;
    
    private List<DefaultHook> defaultHooks;
    
    private JPanel customPluginToolsPanel;
    private JPanel customPluginScopePanel;
    private JPanel customPluginButtonTypePanel;
    private JPanel customPluginButtonPlatformPanel;
    private JPanel customPluginExecuteWhenPanel;
    private JPanel customPluginParametersPanel;
    private JPanel customPluginParameterEncodingPanel;
    private JPanel customPluginOutputDecodingPanel;
    private JPanel customPluginOutputEncodingPanel;
    private JPanel customPluginMessageEditorModifiedEncodeInputPanel;
    private JPanel customPluginMessageEditorModifiedDecodingOutputPanel;
    private JPanel customPluginMessageEditorModifiedFridaFunctioPanel;
    private JPanel customPluginMessageEditorModifiedOutputEncodingPanel;
    private JPanel customPluginMessageEditorModifiedOutputLocationPanel;
    private JTextField customPluginNameText;
    private JComboBox<String> customPluginTypePluginOptions;
    private JLabel customPluginTypePluginDescription;
    private JTextField customPluginExportNameText;
    private JRadioButton customPluginExecuteOnRadioRequest;
    private JRadioButton customPluginExecuteOnRadioResponse;
    private JRadioButton customPluginExecuteOnRadioAll;
    private JRadioButton customPluginExecuteOnRadioContext;
    private JRadioButton customPluginExecuteOnRadioButton;
    private ButtonGroup customPluginExecuteOnRadioButtonGroup;
    private ButtonGroup customPluginButtonPlatformRadioButtonGroup;
    private ButtonGroup customPluginButtonTypeRadioButtonGroup;
    private JTextField customPluginExecuteOnStringParameter;
    private JRadioButton customPluginButtonTypeRadioFunction;
    private JRadioButton customPluginButtonTypeRadioHook;
    private JRadioButton customPluginButtonTypeRadioIos;
    private JRadioButton customPluginButtonTypeRadioAndroid;
    private JRadioButton customPluginButtonTypeRadioGeneric;
    private JTextField customPluginMessageEditorModifiedFridaExportNameText;
    
    private JTextField customPluginParameterEncodingText;
    private List<Transformation> customPluginParameterEncodingTransformationList;
    private JTextField customPluginOutputDecodingText;
    private List<Transformation> customPluginOutputDecodingTransformationList;
    private JTextField customPluginOutputEncodingText;
    private List<Transformation> customPluginOutputEncodingTransformationList;    
    private JTextField customPluginMessageEditorModifiedEncodeInputText;
    private List<Transformation> customPluginMessageEditorModifiedEncodeInputTransformationList;
    private JTextField customPluginMessageEditorModifiedDecodingOutputText;
    private List<Transformation> customPluginMessageEditorModifiedDecodingOutputTransformationList;
    private JTextField customPluginMessageEditorModifiedOutputEncodingText;
    private List<Transformation> customPluginMessageEditorModifiedOutputEncodingTransformationList;
    
    private JCheckBox customPluginToolsRepeater;
    private JCheckBox customPluginToolsProxy;
    private JCheckBox customPluginToolsScanner;
    private JCheckBox customPluginToolsIntruder;
    private JCheckBox customPluginToolsExtender;
    private JCheckBox customPluginToolsSequencer;
    private JCheckBox customPluginToolsSpider;
    private JCheckBox customPluginScopeCheckBox;
    private JComboBox<String> customPluginExecuteWhenOptions;
    private JTextField customPluginExecuteWhenText;
    private JComboBox<String> customPluginParametersOptions;
    private JTextField customPluginParametersText;
    private JComboBox<String> customPluginOutputOptions;
    private JTextField customPluginOutputText;
    
    private JComboBox<String> customPluginMessageEditorModifiedOutputLocationOptions;
    private JTextField customPluginMessageEditorModifiedOutputLocationText;
    
    private JPanel androidHooksPanel;
    private JPanel iOSHooksPanel;
    private JPanel genericHooksPanel;
    
    private JTable customPluginsTable;
    
    private boolean customPluginPluginTypeListenerEnabled;
    
    private ArrayList<DefaultHook> treeHooks;
    		
    /*
     * TODO
     * - Pop-up in Context menu
     * - Tab with helps on Brida and on Frida 
     * - 1 Select forlder default current folder
     * - Migrate from ASCII HEX to Base64 for defautl hooks?
     * - Swift demangle?
     * - "Execute method" -> "Run export"
     * - Merge commits
     * - Fix char Python
     * - Search in HEAP
     * - Code restyle
     * - Bugfixes
     * - Add references to README and update README
     * - Add base address to main view?
     * - Trap by name/address (addressing base address issues)?
     * - Add tab with Frida hooks that can be enabled/disabled (pinning, etc.)
     * - Add addresses to tree view (export and iOS)
     * - Trap/edit return value of custom methods
     * - Add host/port attach/spawn modes
     */
    
    class JTableButtonRenderer implements TableCellRenderer {
    	
    	private TableCellRenderer defaultRenderer;
    	public JTableButtonRenderer(TableCellRenderer renderer) {
			defaultRenderer = renderer;
    	}
	   
    	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
    		if(value instanceof Component) {
    			return (Component)value;
    		} else {
    			Component c = defaultRenderer.getTableCellRendererComponent(table, value, isSelected,hasFocus, row, column);    			
    			if(column == 0) {
    				if(((String)value).equals("Enabled")) {
                   		c.setForeground(Color.GREEN);
                   	} else {
                   		c.setForeground(Color.RED);
                   	}
    			} else {
    				c.setForeground(Color.BLACK);
    			}
    			return c;
    		}
    	}
    }
    
    
    public void initializeDefaultHooks() {
    	
    	// Default Android hooks
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass with CA certificate, more reliable (requires CA public certificate in /data/local/tmp/cert-der.crt)",BurpExtender.PLATFORM_ANDROID,"androidpinningwithca1",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass without CA certificate, less reliable",BurpExtender.PLATFORM_ANDROID,"androidpinningwithoutca1",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("OkHttp Hostname Verifier bypass",BurpExtender.PLATFORM_ANDROID,"okhttphostnameverifier",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Rooting check bypass",BurpExtender.PLATFORM_ANDROID,"androidrooting1",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Hook keystore stuff",BurpExtender.PLATFORM_ANDROID,"tracekeystore",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Hook crypto stuff",BurpExtender.PLATFORM_ANDROID,"dumpcryptostuff",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 1",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass1",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 2",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass2hook",true,new ArrayList<byte[]>(),null,false));
    	
    	// Default Android functions
    	addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 2 (Enable the corresponding hook, trigger fingerprint screen and then run this function)",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass2function",false,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Dump all aliases in keystore of predefined types",BurpExtender.PLATFORM_ANDROID,"listaliasesstatic",false,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Dump all aliases in keystore collected during runtime (through the \"Hook keystore stuff\" hook)",BurpExtender.PLATFORM_ANDROID,"listaliasesruntime",false,new ArrayList<byte[]>(),null,false));

    	// Default iOS hooks
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass (iOS 10) *",BurpExtender.PLATFORM_IOS,"ios10pinning",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass (iOS 11) *",BurpExtender.PLATFORM_IOS,"ios11pinning",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass (iOS 12) *",BurpExtender.PLATFORM_IOS,"ios12pinning",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass (iOS 13) *",BurpExtender.PLATFORM_IOS,"ios13pinning",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Jailbreaking check bypass **",BurpExtender.PLATFORM_IOS,"iosjailbreak",true,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Bypass TouchID (click \"Cancel\" when TouchID windows pops up)",BurpExtender.PLATFORM_IOS,"iosbypasstouchid",true,new ArrayList<byte[]>(),null,false));   
    	addButtonToHooksAndFunctions(new DefaultHook("Dump crypto stuff",BurpExtender.PLATFORM_IOS,"dumpcryptostuffios",true,new ArrayList<byte[]>(),null,false));
    	
    	// Default iOS functions
    	addButtonToHooksAndFunctions(new DefaultHook("Dump keychain",BurpExtender.PLATFORM_IOS,"iosdumpkeychain",false,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("List files with Data Protection keys",BurpExtender.PLATFORM_IOS,"iosdataprotectionkeys",false,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Dump and decrypt current ENCRYPTED app (for apps downloaded from App Store)",BurpExtender.PLATFORM_IOS,"iosdumpcurrentencryptedapp",false,new ArrayList<byte[]>(),null,false));
    	addButtonToHooksAndFunctions(new DefaultHook("Demagle Swift name",BurpExtender.PLATFORM_IOS,"demangle",false,new ArrayList<byte[]>(),new ArrayList<BurpExtender.Transformation>(),true));
    	    	
    }
    
	public void registerExtenderCallbacks(IBurpExtenderCallbacks c) {
			
		
        // Keep a reference to our callbacks object
        this.callbacks = c;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Brida");
                
        // register to execute actions on unload
        callbacks.registerExtensionStateListener(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        stdout.println("Welcome to Brida, the new bridge between Burp Suite and Frida!");
        stdout.println("Created by Piergiovanni Cipolloni and Federico Dotta");
        stdout.println("Contributors: Maurizio Agazzini");
        stdout.println("Version: 0.6");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/Brida");
        stdout.println("");
                
        serverStarted = false;
    	applicationSpawned = false;
    	
    	lastPrintIsJS = false;

    	defaultHooks = new ArrayList<DefaultHook>();
    	treeHooks = new ArrayList<DefaultHook>();
    	
    	customPluginPluginTypeListenerEnabled = true;
    	
    	customPluginParameterEncodingTransformationList = new ArrayList<Transformation>();
    	customPluginOutputDecodingTransformationList = new ArrayList<Transformation>();
        customPluginOutputEncodingTransformationList = new ArrayList<Transformation>();
        customPluginMessageEditorModifiedEncodeInputTransformationList = new ArrayList<Transformation>();
    	customPluginMessageEditorModifiedDecodingOutputTransformationList = new ArrayList<Transformation>();
    	customPluginMessageEditorModifiedOutputEncodingTransformationList = new ArrayList<Transformation>();
    			
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
                	documentApplicationStatus.insertString(0, "NOT hooked", redStyle);
				} catch (BadLocationException e) {
					printException(e,"Error setting labels");
				}
                applicationStatus.setMaximumSize( applicationStatus.getPreferredSize() );
                applicationStatusPanel.add(labelApplicationStatus);
                applicationStatusPanel.add(applicationStatus);
                                
                JPanel virtualEnvPanel = new JPanel();
                virtualEnvPanel.setLayout(new BoxLayout(virtualEnvPanel, BoxLayout.X_AXIS));
                virtualEnvPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelUseVirtualEnv = new JLabel("Use virtual env: ");
                useVirtualEnvCheckBox = new JCheckBox();                
                if(callbacks.loadExtensionSetting("useVirtualEnvCheckBox") != null)
                	useVirtualEnvCheckBox.setSelected(callbacks.loadExtensionSetting("useVirtualEnvCheckBox").equals("true"));
                else
                	useVirtualEnvCheckBox.setSelected(false);
                useVirtualEnvCheckBox.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {                        
                    	if(e.getStateChange() == ItemEvent.SELECTED) {
                    		//labelPythonPathVenv.setText("Virtual env activation command: ");
                    		labelPythonPathVenv.setText("Virtual env folder: ");
                        } else {
                        	labelPythonPathVenv.setText("Python binary path: ");
                        }                            
                    }
                });
                virtualEnvPanel.add(labelUseVirtualEnv);
                virtualEnvPanel.add(useVirtualEnvCheckBox);
                  
                // The same field is used to take the virtual env folder, if virtual env checkbox is selected
                JPanel pythonPathVenvPanel = new JPanel();
                pythonPathVenvPanel.setLayout(new BoxLayout(pythonPathVenvPanel, BoxLayout.X_AXIS));
                pythonPathVenvPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                if(callbacks.loadExtensionSetting("useVirtualEnvCheckBox") != null && callbacks.loadExtensionSetting("useVirtualEnvCheckBox").equals("true")) {
                	//labelPythonPathVenv = new JLabel("Virtual env activation command: ");
                	labelPythonPathVenv = new JLabel("Virtual env folder: ");
                } else {
                	labelPythonPathVenv = new JLabel("Python binary path: ");
                }
                pythonPathVenv = new JTextField(200);                
                if(callbacks.loadExtensionSetting("pythonPath") != null)
                	pythonPathVenv.setText(callbacks.loadExtensionSetting("pythonPath"));
                else {
                	if(callbacks.loadExtensionSetting("useVirtualEnvCheckBox") != null && callbacks.loadExtensionSetting("useVirtualEnvCheckBox").equals("true")) {
                		pythonPathVenv.setText("");
                	} else {
	                	if(System.getProperty("os.name").startsWith("Windows")) {
	                		pythonPathVenv.setText("C:\\python27\\python");
	                	} else {
	                		pythonPathVenv.setText("/usr/bin/python");
	                	}
                	}
                }
                pythonPathVenv.setMaximumSize( pythonPathVenv.getPreferredSize() );
                JButton pythonPathVenvButton = new JButton("Select file");
                pythonPathVenvButton.setActionCommand("pythonPathSelectFile");
                pythonPathVenvButton.addActionListener(BurpExtender.this);
                pythonPathVenvPanel.add(labelPythonPathVenv);
                pythonPathVenvPanel.add(pythonPathVenv);
                pythonPathVenvPanel.add(pythonPathVenvButton);
                                
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
                
                JPanel fridaCompilePathPanel = new JPanel();
                fridaCompilePathPanel.setLayout(new BoxLayout(fridaCompilePathPanel, BoxLayout.X_AXIS));
                fridaCompilePathPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelFridaCompilePath = new JLabel("frida-compile path: ");
                fridaCompilePath = new JTextField(200);                
                if(callbacks.loadExtensionSetting("fridaCompilePath") != null)
                	fridaCompilePath.setText(callbacks.loadExtensionSetting("fridaCompilePath"));
                else {
                	if(System.getProperty("os.name").startsWith("Windows")) {
                		fridaCompilePath.setText("C:\\Users\\test\\node_modules\\.bin\\frida-compile.cmd");
                	} else {
                		fridaCompilePath.setText("/usr/local/lib/node_modules/.bin/frida-compile");
                	}
                }
                fridaCompilePath.setMaximumSize( fridaCompilePath.getPreferredSize() );
                JButton fridaCompilePathButton = new JButton("Select file");
                fridaCompilePathButton.setActionCommand("fridaCompilePathSelectFile");
                fridaCompilePathButton.addActionListener(BurpExtender.this);
                fridaCompilePathPanel.add(labelFridaCompilePath);
                fridaCompilePathPanel.add(fridaCompilePath);
                fridaCompilePathPanel.add(fridaCompilePathButton);
                
                JPanel fridaCompilePanel = new JPanel();
                fridaCompilePanel.setLayout(new BoxLayout(fridaCompilePanel, BoxLayout.X_AXIS));
                fridaCompilePanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelFridaCompileVersion = new JLabel("Use old version of frida-compile (< 10): ");
                fridaCompileOldCheckBox = new JCheckBox();                
                if(callbacks.loadExtensionSetting("fridaCompileOldCheckBox") != null)
                	fridaCompileOldCheckBox.setSelected(callbacks.loadExtensionSetting("fridaCompileOldCheckBox").equals("true"));
                else
                	fridaCompileOldCheckBox.setSelected(true);
                fridaCompilePanel.add(labelFridaCompileVersion);
                fridaCompilePanel.add(fridaCompileOldCheckBox);
 
                JPanel fridaPathPanel = new JPanel();
                fridaPathPanel.setLayout(new BoxLayout(fridaPathPanel, BoxLayout.X_AXIS));
                fridaPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelFridaPath = new JLabel("Frida JS files folder: ");
                fridaPath = new JTextField(200);                
                if(callbacks.loadExtensionSetting("fridaPath") != null)
                	fridaPath.setText(callbacks.loadExtensionSetting("fridaPath"));
                else {                	
                	if(System.getProperty("os.name").startsWith("Windows")) {
                		fridaPath.setText("C:\\burp\\brida\\");
                	} else {
                		fridaPath.setText("/opt/burp/brida/");
                	}
                }
                fridaPath.setMaximumSize( fridaPath.getPreferredSize() );
                JButton fridaPathButton = new JButton("Select folder");
                fridaPathButton.setActionCommand("fridaPathSelectFile");
                fridaPathButton.addActionListener(BurpExtender.this);
                JButton fridaDefaultPathButton = new JButton("Create default JS files");
                fridaDefaultPathButton.setActionCommand("fridaPathSelectDefaultFile");
                fridaDefaultPathButton.addActionListener(BurpExtender.this);
                fridaPathPanel.add(labelFridaPath);
                fridaPathPanel.add(fridaPath);
                fridaPathPanel.add(fridaPathButton);
                fridaPathPanel.add(fridaDefaultPathButton);
                
                JPanel applicationIdPanel = new JPanel();
                applicationIdPanel.setLayout(new BoxLayout(applicationIdPanel, BoxLayout.X_AXIS));
                applicationIdPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelApplicationId = new JLabel("Application ID (spawn) / PID (attach): ");
                applicationId = new JTextField(200);                
                if(callbacks.loadExtensionSetting("applicationId") != null)
                	applicationId.setText(callbacks.loadExtensionSetting("applicationId"));
                else
                	applicationId.setText("org.test.application");
                applicationId.setMaximumSize( applicationId.getPreferredSize() );
                applicationIdPanel.add(labelApplicationId);
                applicationIdPanel.add(applicationId);

                JPanel hostPortDevicePanel = new JPanel();
                hostPortDevicePanel.setLayout(new BoxLayout(hostPortDevicePanel, BoxLayout.X_AXIS));
                hostPortDevicePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel labelHostPortDevice = new JLabel("Host:port (Frida Host) / Device ID (Frida Device): ");
                hostPortDevice = new JTextField(200);
                if(callbacks.loadExtensionSetting("hostPortDevice") != null)
                    hostPortDevice.setText(callbacks.loadExtensionSetting("hostPortDevice"));
                else
                    hostPortDevice.setText("");
                hostPortDevice.setMaximumSize( hostPortDevice.getPreferredSize() );
                hostPortDevicePanel.add(labelHostPortDevice);
                hostPortDevicePanel.add(hostPortDevice);
                                
                JPanel localRemotePanel = new JPanel();
                localRemotePanel.setLayout(new BoxLayout(localRemotePanel, BoxLayout.X_AXIS));
                localRemotePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                remoteRadioButton = new JRadioButton("Frida Remote");
                usbRadioButton =  new JRadioButton("Frida USB");
                localRadioButton = new JRadioButton("Frida Local");
                // process = frida.get_device_manager().add_remote_device("192.168.1.12:2703").attach("package name")
                hostRadioButton = new JRadioButton("Frida Host");
                deviceRadioButton = new JRadioButton("Frida Device");

                if(callbacks.loadExtensionSetting("device") != null) {                	
                	if(callbacks.loadExtensionSetting("device").equals("remote"))
                		remoteRadioButton.setSelected(true);
                	else if(callbacks.loadExtensionSetting("device").equals("usb"))
                		usbRadioButton.setSelected(true);
                    else if(callbacks.loadExtensionSetting("device").equals("local"))
                        localRadioButton.setSelected(true);
                    else if(callbacks.loadExtensionSetting("device").equals("host"))
                        hostRadioButton.setSelected(true);
                	else
                        deviceRadioButton.setSelected(true);
                } else {
                	remoteRadioButton.setSelected(true);
                }
                ButtonGroup localRemoteButtonGroup = new ButtonGroup();
                localRemoteButtonGroup.add(remoteRadioButton);
                localRemoteButtonGroup.add(usbRadioButton);
                localRemoteButtonGroup.add(localRadioButton);
                localRemoteButtonGroup.add(hostRadioButton);
                localRemoteButtonGroup.add(deviceRadioButton);
                localRemotePanel.add(remoteRadioButton);
                localRemotePanel.add(usbRadioButton);
                localRemotePanel.add(localRadioButton);
                localRemotePanel.add(hostRadioButton);
                localRemotePanel.add(deviceRadioButton);
            	  
                configurationConfPanel.add(serverStatusPanel);
                configurationConfPanel.add(applicationStatusPanel);
                configurationConfPanel.add(virtualEnvPanel);
                configurationConfPanel.add(pythonPathVenvPanel);
                configurationConfPanel.add(pyroHostPanel);
                configurationConfPanel.add(pyroPortPanel);
                configurationConfPanel.add(fridaCompilePathPanel);
                configurationConfPanel.add(fridaCompilePanel);
                configurationConfPanel.add(fridaPathPanel);
                configurationConfPanel.add(applicationIdPanel); 
                configurationConfPanel.add(localRemotePanel);
                configurationConfPanel.add(hostPortDevicePanel);
                
                // **** END CONFIGURATION PANEL
                
            	// **** JS EDITOR PANEL / CONSOLE
                jsEditorTextArea = new TextEditorPane();
                jsEditorTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                jsEditorTextArea.setCodeFoldingEnabled(false);   
                RTextScrollPane sp = new RTextScrollPane(jsEditorTextArea);
                jsEditorTextArea.setFocusable(true);                
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
                                
                JPanel searchPanelBar = new JPanel();
                searchPanelBar.setLayout(new BoxLayout(searchPanelBar, BoxLayout.X_AXIS));
                                
                JLabel findLabel = new JLabel("Search:");
                //findTextField = new JTextField(60);       
                findTextField = new JTextField();
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
                TableCellRenderer trapTableRendererButton = trapTable.getDefaultRenderer(JButton.class);
                trapTable.setDefaultRenderer(JButton.class, new JTableButtonRenderer(trapTableRendererButton));
                TableCellRenderer trapTableRendererString = trapTable.getDefaultRenderer(String.class);
                trapTable.setDefaultRenderer(String.class, new JTableButtonRenderer(trapTableRendererString));
                JScrollPane trapTableScrollPane = new JScrollPane(trapTable);
                trapTableScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                trapTableScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                trapTable.setAutoCreateRowSorter(true);
                
                // Center header
                ((DefaultTableCellRenderer)trapTable.getTableHeader().getDefaultRenderer()).setHorizontalAlignment(JLabel.CENTER);
                
                // Center columns 4 and 5
                DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
                centerRenderer.setHorizontalAlignment( JLabel.CENTER );
                trapTable.getColumnModel().getColumn(5).setCellRenderer( centerRenderer );
                trapTable.getColumnModel().getColumn(6).setCellRenderer( centerRenderer );
                
                // Handle buttons action in the table
                trapTable.addMouseListener(new MouseAdapter() {
                	@Override
                	public void mouseClicked(MouseEvent evt) {
                		int row = trapTable.convertRowIndexToModel(trapTable.rowAtPoint(evt.getPoint()));
                		int col = trapTable.columnAtPoint(evt.getPoint());
                		if (row >= 0 && col >= 0) {
                			List<TrapTableItem> trapTableItems = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
                			TrapTableItem currentTrapItem = trapTableItems.get(row);
                			DefaultHook currentDefaultHook = currentTrapItem.getDefaultHook();
                			switch(col) {
                				// Enable/disable
                				case 7:                        			
                					if(currentDefaultHook.isEnabled()) {
                						if(!applicationSpawned) {
                							currentDefaultHook.setEnabled(false);
                						} else {
                							JOptionPane.showMessageDialog(null, "It is not possible to disable single hooks while application is running", "Warning", JOptionPane.WARNING_MESSAGE);
                						}
                					} else {
                						currentDefaultHook.setEnabled(true);
                						if(applicationSpawned) {
	                						try {					
	                							executePyroCall(pyroBridaService, "callexportfunction",new Object[] {currentDefaultHook.getFridaExportName(),currentDefaultHook.getParameters()});					
	                						} catch (Exception e) {						
	                							 printException(e,"Exception running starting tree hook " + currentDefaultHook.getName());						
	                						}	
                						}
                						
                					}
                					((TrapTableModel)(trapTable.getModel())).fireTableCellUpdated(row, col);
                					((TrapTableModel)(trapTable.getModel())).fireTableCellUpdated(row, 0);
                					break;
                				// Remove
                				case 8:
                					
                					if(!applicationSpawned) {
                						
                						// Ask user confirmation
                						JFrame parentDialogResult = new JFrame();
                						int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "Are you sure to want to remove \"" + currentDefaultHook.getName()  + "\" hook?","Warning",JOptionPane.YES_NO_OPTION);
                						if(dialogResult != JOptionPane.YES_OPTION){
                							return;
                						}	
                						
                						treeHooks.remove(currentDefaultHook);
                						
                						synchronized(trapTableItems) {                		
                							int trapTableIndex = trapTableItems.indexOf(currentTrapItem);
                							trapTableItems.remove(currentTrapItem);
                							((TrapTableModel)(trapTable.getModel())).fireTableRowsDeleted(trapTableIndex, trapTableIndex);
                						}
                						
                						
                					} else {
                						JOptionPane.showMessageDialog(null, "It is not possible to remove single hooks while application is running", "Warning", JOptionPane.WARNING_MESSAGE);
                					}
                					
                				default:
                					break;
                			}
                			
                		}
                	}
                });   
                
                // **** END TRAPPING TAB
                
                
                // **** FRIDA DEFAULT HOOKS TAB
                final JTabbedPane tabbedPanelHooks = new JTabbedPane();
                
                androidHooksPanel = new JPanel();
                androidHooksPanel.setLayout(new BoxLayout(androidHooksPanel, BoxLayout.Y_AXIS));
                
                iOSHooksPanel = new JPanel();
                iOSHooksPanel.setLayout(new BoxLayout(iOSHooksPanel, BoxLayout.Y_AXIS));                
                
                genericHooksPanel = new JPanel();
                genericHooksPanel.setLayout(new BoxLayout(genericHooksPanel, BoxLayout.Y_AXIS));  
                
                // Initialize default hooks
                initializeDefaultHooks();
                
                // Add tips to iOS hooks tab
                JPanel iosTipsJPanel = new JPanel();
                iosTipsJPanel.setLayout(new BoxLayout(iosTipsJPanel, BoxLayout.Y_AXIS));
                JLabel iosTip1Label = new JLabel("* TIP: If SSL pinning escape does not work try \"SSL Kill Switch 2\" application!");
                JLabel iosTip2Label = new JLabel("** TIP: If Jailbreak escape does not work try \"TS Protector\" or \"Liberty Lite\" applications!");
                Font fontJLabel = iosTip1Label.getFont();
                iosTip1Label.setFont(fontJLabel.deriveFont(fontJLabel.getStyle() | Font.BOLD));
                iosTip2Label.setFont(fontJLabel.deriveFont(fontJLabel.getStyle() | Font.BOLD));
                iosTipsJPanel.add(iosTip1Label);
                iosTipsJPanel.add(iosTip2Label);                
                JPanel iOSHooksPanelWithTips = new JPanel();
                iOSHooksPanelWithTips.setLayout(new BorderLayout());
                iOSHooksPanelWithTips.add(iOSHooksPanel);
                iOSHooksPanelWithTips.add(iosTipsJPanel,BorderLayout.SOUTH);
               
                tabbedPanelHooks.add("Android",androidHooksPanel);
                tabbedPanelHooks.add("iOS",iOSHooksPanelWithTips);
                tabbedPanelHooks.add("Other",genericHooksPanel);
                // **** END FRIDA DEFAULT HOOKS TAB    
                
                
                // **** BEGIN CUSTOM PLUGINS
                JPanel customPluginPanel = new JPanel();
                customPluginPanel.setLayout(new BoxLayout(customPluginPanel, BoxLayout.Y_AXIS));
                
                JPanel customPluginNamePanel = new JPanel();
                customPluginNamePanel.setLayout(new BoxLayout(customPluginNamePanel, BoxLayout.X_AXIS));
                customPluginNamePanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel customPluginNameLabel = new JLabel("Plugin name: ");
                customPluginNameText = new JTextField(200);                
                customPluginNameText.setMaximumSize( customPluginNameText.getPreferredSize() );
                customPluginNamePanel.add(customPluginNameLabel);
                customPluginNamePanel.add(customPluginNameText);
                
                JPanel customPluginTypePluginPanel = new JPanel();
                customPluginTypePluginPanel.setLayout(new BoxLayout(customPluginTypePluginPanel, BoxLayout.X_AXIS));
                customPluginTypePluginPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginTypePluginLabel = new JLabel("Plugin Type ");                
                String[] customPluginTypePluginComboOptions = new String[] {"IHttpListener", "IMessageEditorTab","IContextMenu","JButton"};
                customPluginTypePluginOptions = new JComboBox<String>(customPluginTypePluginComboOptions);
                customPluginTypePluginOptions.setSelectedIndex(0);
                customPluginTypePluginOptions.setMaximumSize( customPluginTypePluginOptions.getPreferredSize() );  
                customPluginTypePluginOptions.addActionListener (new ActionListener () {
                    public void actionPerformed(ActionEvent e) {
                    	changeCustomPluginOptions(customPluginTypePluginOptions.getSelectedItem().toString());
                    }
                });
                customPluginTypePluginDescription = new JLabel("Plugin that dynamically process each requests and responses");                 
                customPluginTypePluginDescription.setMaximumSize(new Dimension(Integer.MAX_VALUE, customPluginTypePluginDescription.getMinimumSize().height));
                customPluginTypePluginPanel.add(customPluginTypePluginLabel);
                customPluginTypePluginPanel.add(customPluginTypePluginOptions);
                customPluginTypePluginPanel.add(customPluginTypePluginDescription);
                
                JPanel customPluginExportNamePanel = new JPanel();
                customPluginExportNamePanel.setLayout(new BoxLayout(customPluginExportNamePanel, BoxLayout.X_AXIS));
                customPluginExportNamePanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel customPluginExportNameLabel = new JLabel("Name of the Frida exported function: ");
                customPluginExportNameText = new JTextField(200);                
                customPluginExportNameText.setMaximumSize( customPluginExportNameText.getPreferredSize() );
                customPluginExportNamePanel.add(customPluginExportNameLabel);
                customPluginExportNamePanel.add(customPluginExportNameText);
                
                JPanel customPluginExecuteOnPanel = new JPanel();
                customPluginExecuteOnPanel.setLayout(new BoxLayout(customPluginExecuteOnPanel, BoxLayout.X_AXIS));
                customPluginExecuteOnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginExecuteOnLabel = new JLabel("Execute on: ");                
                customPluginExecuteOnRadioRequest = new JRadioButton("Requests");
                customPluginExecuteOnRadioResponse = new JRadioButton("Responses");
                customPluginExecuteOnRadioAll = new JRadioButton("All");
                customPluginExecuteOnRadioContext = new JRadioButton("Context menu option named: ");
                customPluginExecuteOnRadioContext.setVisible(false);
                customPluginExecuteOnRadioButton = new JRadioButton("Button named: ");
                customPluginExecuteOnRadioButton.setVisible(false);
                customPluginExecuteOnRadioRequest.setSelected(true);     
                customPluginExecuteOnStringParameter = new JTextField(200);    
                customPluginExecuteOnStringParameter.setMaximumSize( customPluginExecuteOnStringParameter.getPreferredSize() );
                customPluginExecuteOnStringParameter.setVisible(false);
                customPluginExecuteOnRadioButtonGroup = new ButtonGroup();
                customPluginExecuteOnRadioButtonGroup.add(customPluginExecuteOnRadioRequest);
                customPluginExecuteOnRadioButtonGroup.add(customPluginExecuteOnRadioResponse);
                customPluginExecuteOnRadioButtonGroup.add(customPluginExecuteOnRadioAll);
                customPluginExecuteOnRadioButtonGroup.add(customPluginExecuteOnRadioContext);
                customPluginExecuteOnRadioButtonGroup.add(customPluginExecuteOnRadioButton);
                customPluginExecuteOnPanel.add(customPluginExecuteOnLabel);
                customPluginExecuteOnPanel.add(customPluginExecuteOnRadioRequest);
                customPluginExecuteOnPanel.add(customPluginExecuteOnRadioResponse);
                customPluginExecuteOnPanel.add(customPluginExecuteOnRadioAll);
                customPluginExecuteOnPanel.add(customPluginExecuteOnRadioContext);
                customPluginExecuteOnPanel.add(customPluginExecuteOnRadioButton);
                customPluginExecuteOnPanel.add(customPluginExecuteOnStringParameter);
                
                customPluginButtonPlatformPanel = new JPanel();
                customPluginButtonPlatformPanel.setLayout(new BoxLayout(customPluginButtonPlatformPanel, BoxLayout.X_AXIS));
                customPluginButtonPlatformPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginButtonPlatformLabel = new JLabel("Platform: ");                
                customPluginButtonTypeRadioIos = new JRadioButton("iOS");
                customPluginButtonTypeRadioAndroid = new JRadioButton("Android");
                customPluginButtonTypeRadioGeneric = new JRadioButton("Other");
                customPluginButtonTypeRadioIos.setSelected(true);     
                customPluginButtonPlatformRadioButtonGroup = new ButtonGroup();
                customPluginButtonPlatformRadioButtonGroup.add(customPluginButtonTypeRadioIos);
                customPluginButtonPlatformRadioButtonGroup.add(customPluginButtonTypeRadioAndroid);
                customPluginButtonPlatformRadioButtonGroup.add(customPluginButtonTypeRadioGeneric);
                customPluginButtonPlatformPanel.add(customPluginButtonPlatformLabel);
                customPluginButtonPlatformPanel.add(customPluginButtonTypeRadioIos);
                customPluginButtonPlatformPanel.add(customPluginButtonTypeRadioAndroid);
                customPluginButtonPlatformPanel.add(customPluginButtonTypeRadioGeneric);
                customPluginButtonPlatformPanel.setVisible(false);
                
                customPluginButtonTypePanel = new JPanel();
                customPluginButtonTypePanel.setLayout(new BoxLayout(customPluginButtonTypePanel, BoxLayout.X_AXIS));
                customPluginButtonTypePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginButtonTypeLabel = new JLabel("Button type: ");                
                customPluginButtonTypeRadioFunction = new JRadioButton("Function");
                customPluginButtonTypeRadioHook = new JRadioButton("Hook");
                customPluginButtonTypeRadioFunction.setSelected(true);     
                customPluginButtonTypeRadioButtonGroup = new ButtonGroup();
                customPluginButtonTypeRadioButtonGroup.add(customPluginButtonTypeRadioFunction);
                customPluginButtonTypeRadioButtonGroup.add(customPluginButtonTypeRadioHook);
                customPluginButtonTypeRadioFunction.addActionListener(new ActionListener() {
                	@Override
                    public void actionPerformed(ActionEvent e) {
                		SwingUtilities.invokeLater(new Runnable() {                			
                            @Override
                            public void run() {
		                		customPluginParametersPanel.setVisible(true);
		                		customPluginParameterEncodingPanel.setVisible(true);
                            }
                		});
                	}
                });
                customPluginButtonTypeRadioHook.addActionListener(new ActionListener() {
                	@Override
                    public void actionPerformed(ActionEvent e) {
                		SwingUtilities.invokeLater(new Runnable() {                			
                            @Override
                            public void run() {
		                		customPluginParametersPanel.setVisible(false);
		                		customPluginParameterEncodingPanel.setVisible(false);
                            }
                		});
                	}
                });
                customPluginButtonTypePanel.add(customPluginButtonTypeLabel);
                customPluginButtonTypePanel.add(customPluginButtonTypeRadioFunction);
                customPluginButtonTypePanel.add(customPluginButtonTypeRadioHook);
                customPluginButtonTypePanel.setVisible(false);
                
                customPluginToolsPanel = new JPanel();
                customPluginToolsPanel.setLayout(new BoxLayout(customPluginToolsPanel, BoxLayout.X_AXIS));
                customPluginToolsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginToolsLabel = new JLabel("Burp Suite Tools: ");                
                customPluginToolsRepeater = new JCheckBox("Repeater",true);
                customPluginToolsProxy = new JCheckBox("Proxy",false);
                customPluginToolsScanner = new JCheckBox("Scanner",false);
                customPluginToolsIntruder = new JCheckBox("Intruder",false);
                customPluginToolsExtender = new JCheckBox("Extender",false);
                customPluginToolsSequencer = new JCheckBox("Sequencer",false);
                customPluginToolsSpider = new JCheckBox("Spider",false);
                customPluginToolsPanel.add(customPluginToolsLabel);
                customPluginToolsPanel.add(customPluginToolsRepeater);
                customPluginToolsPanel.add(customPluginToolsProxy);
                customPluginToolsPanel.add(customPluginToolsScanner);
                customPluginToolsPanel.add(customPluginToolsIntruder);
                customPluginToolsPanel.add(customPluginToolsExtender);
                customPluginToolsPanel.add(customPluginToolsSequencer);
                customPluginToolsPanel.add(customPluginToolsSpider);
                
                customPluginScopePanel = new JPanel();
                customPluginScopePanel.setLayout(new BoxLayout(customPluginScopePanel, BoxLayout.X_AXIS));
                customPluginScopePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginScopeLabel = new JLabel("Process only in-scope requests/responses: ");                
                customPluginScopeCheckBox = new JCheckBox();
                customPluginScopePanel.add(customPluginScopeLabel);
                customPluginScopePanel.add(customPluginScopeCheckBox);
                                
                customPluginExecuteWhenPanel = new JPanel();
                customPluginExecuteWhenPanel.setLayout(new BoxLayout(customPluginExecuteWhenPanel, BoxLayout.X_AXIS));
                customPluginExecuteWhenPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginExecuteWhenLabel = new JLabel("Execute ");                
                String[] customPluginExecuteJComboOptions = new String[] {"always", "when request/response contains plaintext","when request/response contains regex"};
                customPluginExecuteWhenOptions = new JComboBox<String>(customPluginExecuteJComboOptions);
                customPluginExecuteWhenOptions.setSelectedIndex(0);
                customPluginExecuteWhenOptions.setMaximumSize( customPluginExecuteWhenOptions.getPreferredSize() );
                customPluginExecuteWhenText = new JTextField(200);                
                customPluginExecuteWhenText.setMaximumSize( customPluginExecuteWhenText.getPreferredSize() );
                customPluginExecuteWhenPanel.add(customPluginExecuteWhenLabel);
                customPluginExecuteWhenPanel.add(customPluginExecuteWhenOptions);
                customPluginExecuteWhenPanel.add(customPluginExecuteWhenText);
                
                customPluginParametersPanel = new JPanel();
                customPluginParametersPanel.setLayout(new BoxLayout(customPluginParametersPanel, BoxLayout.X_AXIS));
                customPluginParametersPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginParametersLabel = new JLabel("Parameters: ");                
                String[] customPluginParametersComboOptions = CustomPlugin.functionParametersIHttpListener.stream().map(CustomPluginParameterValues::toString).toArray(String[]::new);                
                customPluginParametersOptions = new JComboBox<String>(customPluginParametersComboOptions);
                customPluginParametersOptions.setSelectedIndex(0);
                customPluginParametersOptions.setMaximumSize( customPluginParametersOptions.getPreferredSize() );
                customPluginParametersText = new JTextField(200);                
                customPluginParametersText.setMaximumSize( customPluginParametersText.getPreferredSize() );
                customPluginParametersPanel.add(customPluginParametersLabel);
                customPluginParametersPanel.add(customPluginParametersOptions);
                customPluginParametersPanel.add(customPluginParametersText);
                
                customPluginParameterEncodingPanel = new JPanel();
                customPluginParameterEncodingPanel.setLayout(new BoxLayout(customPluginParameterEncodingPanel, BoxLayout.X_AXIS));
                customPluginParameterEncodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginParameterEncodinglabel = new JLabel("Encode function parameters: ");  
                JButton customPluginParameterEncodingButton = new JButton("Choose encoding");
                customPluginParameterEncodingButton.setActionCommand("customPluginParameterEncodingButton");
                customPluginParameterEncodingButton.addActionListener(BurpExtender.this); 
                customPluginParameterEncodingText = new JTextField(200);                
                customPluginParameterEncodingText.setMaximumSize( customPluginParameterEncodingText.getPreferredSize() );
                customPluginParameterEncodingText.setEditable(false);
                customPluginParameterEncodingPanel.add(customPluginParameterEncodinglabel);
                customPluginParameterEncodingPanel.add(customPluginParameterEncodingButton);
                customPluginParameterEncodingPanel.add(customPluginParameterEncodingText);
                
                customPluginOutputDecodingPanel = new JPanel();
                customPluginOutputDecodingPanel.setLayout(new BoxLayout(customPluginOutputDecodingPanel, BoxLayout.X_AXIS));
                customPluginOutputDecodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginOutputDecodingLabel = new JLabel("Decode function output: ");  
                JButton customPluginOutputDecodingButton = new JButton("Choose decoding");
                customPluginOutputDecodingButton.setActionCommand("customPluginOutputDecodingButton");
                customPluginOutputDecodingButton.addActionListener(BurpExtender.this); 
                customPluginOutputDecodingText = new JTextField(200);                
                customPluginOutputDecodingText.setMaximumSize( customPluginOutputDecodingText.getPreferredSize() );
                customPluginOutputDecodingText.setEditable(false);
                customPluginOutputDecodingPanel.add(customPluginOutputDecodingLabel);
                customPluginOutputDecodingPanel.add(customPluginOutputDecodingButton);
                customPluginOutputDecodingPanel.add(customPluginOutputDecodingText);
                
                JPanel customPluginOutputPanel = new JPanel();
                customPluginOutputPanel.setLayout(new BoxLayout(customPluginOutputPanel, BoxLayout.X_AXIS));
                customPluginOutputPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginOutputLabel = new JLabel("Plugin output: ");                
                String[] customPluginOutputComboOptions = CustomPlugin.functionOutputValuesIHttpListener.stream().map(CustomPluginFunctionOutputValues::toString).toArray(String[]::new);
                                
                customPluginOutputOptions = new JComboBox<String>(customPluginOutputComboOptions);
                customPluginOutputOptions.setSelectedIndex(0);
                customPluginOutputOptions.setMaximumSize( customPluginOutputOptions.getPreferredSize() );
                customPluginOutputText = new JTextField(200);                
                customPluginOutputText.setMaximumSize( customPluginOutputText.getPreferredSize() );
                customPluginOutputPanel.add(customPluginOutputLabel);
                customPluginOutputPanel.add(customPluginOutputOptions);
                customPluginOutputPanel.add(customPluginOutputText);
                
                customPluginOutputEncodingPanel = new JPanel();
                customPluginOutputEncodingPanel.setLayout(new BoxLayout(customPluginOutputEncodingPanel, BoxLayout.X_AXIS));
                customPluginOutputEncodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginOutputEncodingLabel = new JLabel("Plugin output encoding: ");
                JButton customPluginOutputEncodingButton = new JButton("Choose encoding");
                customPluginOutputEncodingButton.setActionCommand("customPluginOutputEncodingButton");
                customPluginOutputEncodingButton.addActionListener(BurpExtender.this); 
                customPluginOutputEncodingText = new JTextField(200);                
                customPluginOutputEncodingText.setMaximumSize( customPluginOutputEncodingText.getPreferredSize() );
                customPluginOutputEncodingText.setEditable(false);
                customPluginOutputEncodingPanel.add(customPluginOutputEncodingLabel);
                customPluginOutputEncodingPanel.add(customPluginOutputEncodingButton);
                customPluginOutputEncodingPanel.add(customPluginOutputEncodingText);
                
                customPluginMessageEditorModifiedFridaFunctioPanel = new JPanel();
                customPluginMessageEditorModifiedFridaFunctioPanel.setLayout(new BoxLayout(customPluginMessageEditorModifiedFridaFunctioPanel, BoxLayout.X_AXIS));
                customPluginMessageEditorModifiedFridaFunctioPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel customPluginMessageEditorModifiedFridaExportNameLabel = new JLabel("Name of the Frida exported function for the edited content: ");
                customPluginMessageEditorModifiedFridaExportNameText = new JTextField(200);                
                customPluginMessageEditorModifiedFridaExportNameText.setMaximumSize( customPluginMessageEditorModifiedFridaExportNameText.getPreferredSize() );
                customPluginMessageEditorModifiedFridaFunctioPanel.add(customPluginMessageEditorModifiedFridaExportNameLabel);
                customPluginMessageEditorModifiedFridaFunctioPanel.add(customPluginMessageEditorModifiedFridaExportNameText);
                customPluginMessageEditorModifiedFridaFunctioPanel.setVisible(false);
                
                customPluginMessageEditorModifiedEncodeInputPanel = new JPanel();
                customPluginMessageEditorModifiedEncodeInputPanel.setLayout(new BoxLayout(customPluginMessageEditorModifiedEncodeInputPanel, BoxLayout.X_AXIS));
                customPluginMessageEditorModifiedEncodeInputPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginMessageEditorModifiedEncodeInputLabel = new JLabel("Encode input passed to Frida function executed on edited content: ");   
                JButton customPluginMessageEditorModifiedEncodeInputButton = new JButton("Choose encoding");
                customPluginMessageEditorModifiedEncodeInputButton.setActionCommand("customPluginMessageEditorModifiedEncodeInputButton");
                customPluginMessageEditorModifiedEncodeInputButton.addActionListener(BurpExtender.this); 
                customPluginMessageEditorModifiedEncodeInputText = new JTextField(200);                
                customPluginMessageEditorModifiedEncodeInputText.setMaximumSize( customPluginMessageEditorModifiedEncodeInputText.getPreferredSize() );
                customPluginMessageEditorModifiedEncodeInputText.setEditable(false);
                customPluginMessageEditorModifiedEncodeInputPanel.add(customPluginMessageEditorModifiedEncodeInputLabel);
                customPluginMessageEditorModifiedEncodeInputPanel.add(customPluginMessageEditorModifiedEncodeInputButton);
                customPluginMessageEditorModifiedEncodeInputPanel.add(customPluginMessageEditorModifiedEncodeInputText);
                customPluginMessageEditorModifiedEncodeInputPanel.setVisible(false);
                
                customPluginMessageEditorModifiedDecodingOutputPanel = new JPanel();
                customPluginMessageEditorModifiedDecodingOutputPanel.setLayout(new BoxLayout(customPluginMessageEditorModifiedDecodingOutputPanel, BoxLayout.X_AXIS));
                customPluginMessageEditorModifiedDecodingOutputPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginMessageEditorModifiedDecodingOutputLabel = new JLabel("Decode output of Frida function executed on edited content: ");                 
                JButton customPluginMessageEditorModifiedDecodingOutputButton = new JButton("Choose decoding");
                customPluginMessageEditorModifiedDecodingOutputButton.setActionCommand("customPluginMessageEditorModifiedDecodingOutputButton");
                customPluginMessageEditorModifiedDecodingOutputButton.addActionListener(BurpExtender.this); 
                customPluginMessageEditorModifiedDecodingOutputText = new JTextField(200);                
                customPluginMessageEditorModifiedDecodingOutputText.setMaximumSize( customPluginMessageEditorModifiedDecodingOutputText.getPreferredSize() );
                customPluginMessageEditorModifiedDecodingOutputText.setEditable(false);
                customPluginMessageEditorModifiedDecodingOutputPanel.add(customPluginMessageEditorModifiedDecodingOutputLabel);
                customPluginMessageEditorModifiedDecodingOutputPanel.add(customPluginMessageEditorModifiedDecodingOutputButton);
                customPluginMessageEditorModifiedDecodingOutputPanel.add(customPluginMessageEditorModifiedDecodingOutputText);
                customPluginMessageEditorModifiedDecodingOutputPanel.setVisible(false);
                
                customPluginMessageEditorModifiedOutputLocationPanel = new JPanel();
                customPluginMessageEditorModifiedOutputLocationPanel.setLayout(new BoxLayout(customPluginMessageEditorModifiedOutputLocationPanel, BoxLayout.X_AXIS));
                customPluginMessageEditorModifiedOutputLocationPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginMessageEditorModifiedOutputLocationLabel = new JLabel("Edited content location: ");                
                String[] customPluginMessageEditorModifiedOutputLocationComboOptions = Stream.of(BridaMessageEditorPluginOutputLocation.values()).map(BridaMessageEditorPluginOutputLocation::toString).toArray(String[]::new);
                customPluginMessageEditorModifiedOutputLocationOptions = new JComboBox<String>(customPluginMessageEditorModifiedOutputLocationComboOptions);
                customPluginMessageEditorModifiedOutputLocationOptions.setSelectedIndex(0);
                customPluginMessageEditorModifiedOutputLocationOptions.setMaximumSize( customPluginMessageEditorModifiedOutputLocationOptions.getPreferredSize() );
                customPluginMessageEditorModifiedOutputLocationText = new JTextField(200);                
                customPluginMessageEditorModifiedOutputLocationText.setMaximumSize( customPluginMessageEditorModifiedOutputLocationText.getPreferredSize() );
                customPluginMessageEditorModifiedOutputLocationPanel.add(customPluginMessageEditorModifiedOutputLocationLabel);
                customPluginMessageEditorModifiedOutputLocationPanel.add(customPluginMessageEditorModifiedOutputLocationOptions);
                customPluginMessageEditorModifiedOutputLocationPanel.add(customPluginMessageEditorModifiedOutputLocationText);
                customPluginMessageEditorModifiedOutputLocationPanel.setVisible(false);
                
                customPluginMessageEditorModifiedOutputEncodingPanel = new JPanel();
                customPluginMessageEditorModifiedOutputEncodingPanel.setLayout(new BoxLayout(customPluginMessageEditorModifiedOutputEncodingPanel, BoxLayout.X_AXIS));
                customPluginMessageEditorModifiedOutputEncodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel customPluginMessageEditorModifiedOutputEncodingLabel = new JLabel("Encode output of edited content function: ");  
                
                JButton customPluginMessageEditorModifiedOutputEncodingButton = new JButton("Choose encoding");
                customPluginMessageEditorModifiedOutputEncodingButton.setActionCommand("customPluginMessageEditorModifiedOutputEncodingButton");
                customPluginMessageEditorModifiedOutputEncodingButton.addActionListener(BurpExtender.this); 
                customPluginMessageEditorModifiedOutputEncodingText = new JTextField(200);                
                customPluginMessageEditorModifiedOutputEncodingText.setMaximumSize( customPluginMessageEditorModifiedOutputEncodingText.getPreferredSize() );
                customPluginMessageEditorModifiedOutputEncodingText.setEditable(false);
                customPluginMessageEditorModifiedOutputEncodingPanel.add(customPluginMessageEditorModifiedOutputEncodingLabel);
                customPluginMessageEditorModifiedOutputEncodingPanel.add(customPluginMessageEditorModifiedOutputEncodingButton);
                customPluginMessageEditorModifiedOutputEncodingPanel.add(customPluginMessageEditorModifiedOutputEncodingText); 
                customPluginMessageEditorModifiedOutputEncodingPanel.setVisible(false);
                
                customPluginPanel.add(customPluginNamePanel);
                customPluginPanel.add(customPluginTypePluginPanel);
                customPluginPanel.add(customPluginExportNamePanel);
                customPluginPanel.add(customPluginExecuteOnPanel);
                customPluginPanel.add(customPluginButtonPlatformPanel);
                customPluginPanel.add(customPluginButtonTypePanel);
                customPluginPanel.add(customPluginToolsPanel);
                customPluginPanel.add(customPluginScopePanel);
                customPluginPanel.add(customPluginExecuteWhenPanel);
                customPluginPanel.add(customPluginParametersPanel);
                customPluginPanel.add(customPluginParameterEncodingPanel);
                customPluginPanel.add(customPluginOutputDecodingPanel);
                customPluginPanel.add(customPluginOutputPanel);
                customPluginPanel.add(customPluginOutputEncodingPanel);
                customPluginPanel.add(customPluginMessageEditorModifiedFridaFunctioPanel);
                customPluginPanel.add(customPluginMessageEditorModifiedEncodeInputPanel);
                customPluginPanel.add(customPluginMessageEditorModifiedDecodingOutputPanel);
                customPluginPanel.add(customPluginMessageEditorModifiedOutputLocationPanel);
                customPluginPanel.add(customPluginMessageEditorModifiedOutputEncodingPanel);

                customPluginsTable = new JTable(new CustomPluginsTableModel());
                TableCellRenderer tableRendererButton = customPluginsTable.getDefaultRenderer(JButton.class);
                customPluginsTable.setDefaultRenderer(JButton.class, new JTableButtonRenderer(tableRendererButton));
                TableCellRenderer tableRendererString = customPluginsTable.getDefaultRenderer(String.class);
                customPluginsTable.setDefaultRenderer(String.class, new JTableButtonRenderer(tableRendererString));
                JScrollPane customPluginsTableScrollPane = new JScrollPane(customPluginsTable);
                customPluginsTableScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                customPluginsTableScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                customPluginsTable.setAutoCreateRowSorter(true);
     
                // Handle buttons action in the table
                customPluginsTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent evt) {
                        int row = customPluginsTable.convertRowIndexToModel(customPluginsTable.rowAtPoint(evt.getPoint()));
                        int col = customPluginsTable.columnAtPoint(evt.getPoint());
                        if (row >= 0 && col >= 0) {
                        	List<CustomPlugin> customPlugins = ((CustomPluginsTableModel)(customPluginsTable.getModel())).getCustomPlugins();
                			CustomPlugin currentPlugin = customPlugins.get(row);
                        	switch(col) {
                        		// Enable/disable
                        		case 4:                        			
                        			if(currentPlugin.isOn()) {
                        				currentPlugin.disable(); 
                        			} else {
                        				currentPlugin.enable(); 
                        			}
                        			((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableCellUpdated(row, col);
                        			((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableCellUpdated(row, 0);
                        			break;
                        		// Debug
                        		case 5:
                        			if(currentPlugin.getType() != CustomPlugin.CustomPluginType.JBUTTON) {
                        				currentPlugin.enableDebugToExternalFrame();
                        			}
                        			break;
                        		// Edit
                        		case 6:
                        			// If plugin is enabled, disable first
                            		if(currentPlugin.isOn()) {
                            			
                            			// Ask user confirmation
                            			JFrame parentDialogResult = new JFrame();
            			        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The plugin is currently enabled and must be disabled before it can be edited. Would you like to disable it and proceed?","Warning",JOptionPane.YES_NO_OPTION);
            			        		if(dialogResult != JOptionPane.YES_OPTION){
            			        			return;
            			        		}	  
                            			
                            			currentPlugin.disable();
                            			
                            		}
                            		// Double check because unload button hooks may fail if the application is running
                            		if(!currentPlugin.isOn()) {
                            			
                            			editCustomPlugin(currentPlugin);
                            			
                            			// Remove plugin from the table
            	                		synchronized(customPlugins) {                		
            	                			int currentPluginIndex = customPlugins.indexOf(currentPlugin);
            	                			customPlugins.remove(currentPlugin);
            	                			((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsDeleted(currentPluginIndex, currentPluginIndex);
            	                		}
                            		}
                        			break;
                        		// Remove
                        		case 7:
                        			// If plugin is enabled, disable first
                            		if(currentPlugin.isOn()) {
                            			
                            			// Ask user confirmation
                            			JFrame parentDialogResult = new JFrame();
            			        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The plugin is currently enabled and must be disabled before it can be removed. Would you like to disable it and proceed?","Warning",JOptionPane.YES_NO_OPTION);
            			        		if(dialogResult != JOptionPane.YES_OPTION){
            			        			return;
            			        		}	 
                            			
                            			currentPlugin.disable();
                            			
                            		} else {
                            			
                            			// Ask user confirmation
                            			JFrame parentDialogResult = new JFrame();
            			        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "Are you sure that you want to remove the plugin?","Warning",JOptionPane.YES_NO_OPTION);
            			        		if(dialogResult != JOptionPane.YES_OPTION){
            			        			return;
            			        		}
                            			
                            		}
                            		
                            		// Double check because unload button hooks may fail if the application is running
                            		if(!currentPlugin.isOn()) {
            	                		synchronized(customPlugins) {                		
            	                			int currentPluginIndex = customPlugins.indexOf(currentPlugin);
            	                			customPlugins.remove(currentPlugin);
            	                			((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsDeleted(currentPluginIndex, currentPluginIndex);
            	                		}
                            		}
                        			break;
                        		default:
                        			break;
                        	}
                        	
                        }
                    }
                });                
                
                // Center header
                ((DefaultTableCellRenderer)customPluginsTable.getTableHeader().getDefaultRenderer()).setHorizontalAlignment(JLabel.CENTER);
                
                JSplitPane customPluginsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                customPluginsplitPane.setTopComponent(customPluginPanel);
                customPluginsplitPane.setBottomComponent(customPluginsTableScrollPane);                
                customPluginsplitPane.setResizeWeight(.7d);
                
                
                // **** END CUSTOM PLUGINS
                
            	tabbedPanel.add("Configurations",configurationConfPanel);
            	tabbedPanel.add("JS Editor",sp);
            	tabbedPanel.add("Hooks and functions",tabbedPanelHooks);
            	tabbedPanel.add("Graphical analysis",treeSearchPanel);
            	tabbedPanel.add("Graphical hooks",trapTableScrollPane);
            	tabbedPanel.add("Custom plugins",customPluginsplitPane);
            	tabbedPanel.add("Generate stubs",stubTextEditor.getComponent());
            	tabbedPanel.add("Debug export",executeMethodPanel);
            	            	
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
                	documentApplicationStatusButtons.insertString(0, "App not hooked", redStyle);
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
                
                JButton compileSpawnApplication = new JButton("Compile & Spawn");
                compileSpawnApplication.setActionCommand("compileSpawnApplication");
                compileSpawnApplication.addActionListener(BurpExtender.this);  
                
                JButton attachApplication = new JButton("Attach application");
                attachApplication.setActionCommand("attachApplication");
                attachApplication.addActionListener(BurpExtender.this);   
                
                JButton compileAttachApplication = new JButton("Compile & Attach");
                compileAttachApplication.setActionCommand("compileAttachApplication");
                compileAttachApplication.addActionListener(BurpExtender.this); 
                
                JButton killApplication = new JButton("Kill application");
                killApplication.setActionCommand("killApplication");
                killApplication.addActionListener(BurpExtender.this);
                
                JButton detachApplication = new JButton("Detach application");
                detachApplication.setActionCommand("detachApplication");
                detachApplication.addActionListener(BurpExtender.this);
                
                JButton reloadScript = new JButton("Reload JS");
                reloadScript.setActionCommand("reloadScript");
                reloadScript.addActionListener(BurpExtender.this); 
                
                JButton compileReloadScript = new JButton("Compile & reload JS");
                compileReloadScript.setActionCommand("compileReloadScript");
                compileReloadScript.addActionListener(BurpExtender.this); 
                
                JButton detachAllHooks = new JButton("Detach all hooks");
                detachAllHooks.setActionCommand("detachAll");
                detachAllHooks.addActionListener(BurpExtender.this); 
                
                clearConsoleButton = new JButton("Clear console");
                clearConsoleButton.setActionCommand("clearConsole");
                clearConsoleButton.addActionListener(BurpExtender.this);
                                
                executeMethodButton = new JButton("Run export");
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
                                
                removeAllGraphicalHooksButton = new JButton("Remove all");
                removeAllGraphicalHooksButton.setActionCommand("removeAllGraphicalHooks");
                removeAllGraphicalHooksButton.addActionListener(BurpExtender.this); 
                
                enableCustomPluginButton = new JButton("Add plugin");
                enableCustomPluginButton.setActionCommand("enablePlugin");
                enableCustomPluginButton.addActionListener(BurpExtender.this); 
                
                exportCustomPluginsButton = new JButton("Export plugins");
                exportCustomPluginsButton.setActionCommand("exportPlugins");
                exportCustomPluginsButton.addActionListener(BurpExtender.this);
                
                importCustomPluginsButton = new JButton("Import plugins");
                importCustomPluginsButton.setActionCommand("importPlugins");
                importCustomPluginsButton.addActionListener(BurpExtender.this);
                           
                JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
                separator.setBorder(BorderFactory.createMatteBorder(3, 0, 3, 0, Color.ORANGE));

                rightSplitPane.add(serverStatusButtons,gbc);
                rightSplitPane.add(applicationStatusButtons,gbc);
                rightSplitPane.add(startServer,gbc);
                rightSplitPane.add(killServer,gbc);
                rightSplitPane.add(spawnApplication,gbc);
                rightSplitPane.add(compileSpawnApplication,gbc);
                rightSplitPane.add(attachApplication,gbc);
                rightSplitPane.add(compileAttachApplication,gbc);                
                rightSplitPane.add(killApplication,gbc);
                rightSplitPane.add(detachApplication,gbc);                
                rightSplitPane.add(reloadScript,gbc);
                rightSplitPane.add(compileReloadScript,gbc);  
                rightSplitPane.add(detachAllHooks,gbc);                
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
                rightSplitPane.add(removeAllGraphicalHooksButton,gbc);
                
                // CUSTOM PLUGINS
                rightSplitPane.add(enableCustomPluginButton,gbc);
                rightSplitPane.add(exportCustomPluginsButton,gbc);
                rightSplitPane.add(importCustomPluginsButton,gbc);
                
                splitPane.setLeftComponent(consoleTabbedSplitPane);
                splitPane.setRightComponent(rightSplitPane);
                
                splitPane.setResizeWeight(.9d);

                mainPanel.add(splitPane);
                
                callbacks.customizeUiComponent(mainPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
                
            }
            
        });
		
	}
	
	public void editCustomPlugin(CustomPlugin currentPlugin) {
			
		switch(currentPlugin.getType()) {
		
			case IHTTPLISTENER:
												
				BridaHttpListenerPlugin p = (BridaHttpListenerPlugin)currentPlugin;
								
				changeCustomPluginOptions("IHttpListener");
											
				SwingUtilities.invokeLater(new Runnable()  {
		        	
		            @Override
		            public void run()  { 
		            	
		            	customPluginPluginTypeListenerEnabled = false;
		            	customPluginTypePluginOptions.setSelectedIndex(0);
		            	customPluginPluginTypeListenerEnabled = true;
		            	
		            	customPluginNameText.setText(p.getCustomPluginName());
		            	customPluginExportNameText.setText(p.getCustomPluginExportedFunctionName());
		            	
		            	customPluginExecuteOnRadioButtonGroup.clearSelection();
		            	if(p.getCustomPluginExecuteOn() == CustomPlugin.CustomPluginExecuteOnValues.ALL) {
		            		customPluginExecuteOnRadioAll.setSelected(true);
		            	} else if(p.getCustomPluginExecuteOn() == CustomPlugin.CustomPluginExecuteOnValues.REQUESTS) {
		            		customPluginExecuteOnRadioRequest.setSelected(true);
		            	} else {
		            		customPluginExecuteOnRadioResponse.setSelected(true);
		            	}
		            	
		            	ArrayList<Integer> toolsCustomPlugin = p.getCustomPluginTools();
		            	customPluginToolsRepeater.setSelected(false);
		                customPluginToolsProxy.setSelected(false);
		                customPluginToolsScanner.setSelected(false);
		                customPluginToolsIntruder.setSelected(false);
		                customPluginToolsExtender.setSelected(false);
		                customPluginToolsSequencer.setSelected(false);
		                customPluginToolsSpider.setSelected(false);
		            	for(int i=0;i<toolsCustomPlugin.size();i++) {
		            		switch(toolsCustomPlugin.get(i)) {
		            			case IBurpExtenderCallbacks.TOOL_REPEATER:
		            				customPluginToolsRepeater.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_PROXY:
		            				customPluginToolsProxy.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_SCANNER:
		            				customPluginToolsScanner.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_INTRUDER:
		            				customPluginToolsIntruder.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_EXTENDER:
		            				customPluginToolsExtender.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_SEQUENCER:
		            				customPluginToolsSequencer.setSelected(true);
		            				break;
		            			case IBurpExtenderCallbacks.TOOL_SPIDER:
		            				customPluginToolsSpider.setSelected(true);
		            				break;
		            			default:
		            				printException(null, "Edit IHttpListener plugin: unknown tool");
		            				break;
		            		}
		            	}
		            	
		            	if(p.isProcessOnlyInScope()) {
		            		customPluginScopeCheckBox.setSelected(true);
		            	} else {
		            		customPluginScopeCheckBox.setSelected(false);
		            	}
		            	
		            	if(p.getCustomPluginExecute() == CustomPlugin.CustomPluginExecuteValues.ALWAYS) {
		            		customPluginExecuteWhenOptions.setSelectedIndex(0);
		            	} else if(p.getCustomPluginExecute() == CustomPlugin.CustomPluginExecuteValues.PLAINTEXT) {
		            		customPluginExecuteWhenOptions.setSelectedIndex(1);
		            	} else {
		            		customPluginExecuteWhenOptions.setSelectedIndex(2);
		            	}
		            	customPluginExecuteWhenText.setText(p.getCustomPluginExecuteString());
		            	
		            	Object[] iHttpListenerParameters = CustomPlugin.functionParametersIHttpListener.toArray();
		            	customPluginParametersOptions.setSelectedIndex(IntStream.range(0, iHttpListenerParameters.length)
		            	         .filter(i -> p.getCustomPluginParameter() == (CustomPluginParameterValues)(iHttpListenerParameters[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginParametersText.setText(p.getCustomPluginParameterString());
		            	
		            	customPluginParameterEncodingTransformationList = new ArrayList<Transformation>(p.getCustomPluginParameterEncoding());
		            	customPluginParameterEncodingText.setText(customPluginParameterEncodingTransformationList.toString());
		            	
		            	customPluginOutputDecodingTransformationList = new ArrayList<Transformation>(p.getCustomPluginOutputDecoding());
		            	customPluginOutputDecodingText.setText(customPluginOutputDecodingTransformationList.toString());
		            	
		            	Object[] iHttpListenerFunctionOutputValues = CustomPlugin.functionOutputValuesIHttpListener.toArray();
		            	customPluginOutputOptions.setSelectedIndex(IntStream.range(0, iHttpListenerFunctionOutputValues.length)
		            	         .filter(i -> p.getCustomPluginFunctionOutput() == (CustomPluginFunctionOutputValues)(iHttpListenerFunctionOutputValues[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginOutputText.setText(p.getCustomPluginFunctionOutputString());
		            	
		            	customPluginOutputEncodingTransformationList = new ArrayList<Transformation>(p.getCustomPluginOutputEncoding());
		            	customPluginOutputEncodingText.setText(customPluginOutputEncodingTransformationList.toString());
		            			            
		            }
		            
				});
				
				break;
				
			case IMESSAGEEDITORTAB:
				
				BridaMessageEditorPlugin p2 = (BridaMessageEditorPlugin)currentPlugin;
				
				changeCustomPluginOptions("IMessageEditorTab");
											
				SwingUtilities.invokeLater(new Runnable()  {
		        	
		            @Override
		            public void run()  { 
		            	
		            	customPluginPluginTypeListenerEnabled = false;
		            	customPluginTypePluginOptions.setSelectedIndex(1);
		            	customPluginPluginTypeListenerEnabled = true;
		            	
		            	customPluginNameText.setText(p2.getCustomPluginName());
		            	customPluginExportNameText.setText(p2.getCustomPluginExportedFunctionName());
		            	
		            	customPluginExecuteOnRadioButtonGroup.clearSelection();
		            	if(p2.getCustomPluginExecuteOn() == CustomPlugin.CustomPluginExecuteOnValues.ALL) {
		            		customPluginExecuteOnRadioAll.setSelected(true);
		            	} else if(p2.getCustomPluginExecuteOn() == CustomPlugin.CustomPluginExecuteOnValues.REQUESTS) {
		            		customPluginExecuteOnRadioRequest.setSelected(true);
		            	} else {
		            		customPluginExecuteOnRadioResponse.setSelected(true);
		            	}
		            	
		            	if(p2.getCustomPluginExecute() == CustomPlugin.CustomPluginExecuteValues.ALWAYS) {
		            		customPluginExecuteWhenOptions.setSelectedIndex(0);
		            	} else if(p2.getCustomPluginExecute() == CustomPlugin.CustomPluginExecuteValues.PLAINTEXT) {
		            		customPluginExecuteWhenOptions.setSelectedIndex(1);
		            	} else {
		            		customPluginExecuteWhenOptions.setSelectedIndex(2);
		            	}
		            	customPluginExecuteWhenText.setText(p2.getCustomPluginExecuteString());
		            	
		            	Object[] iMessageEditorTabParameters = CustomPlugin.functionParametersIMessageEditorTab.toArray();
		            	customPluginParametersOptions.setSelectedIndex(IntStream.range(0, iMessageEditorTabParameters.length)
		            	         .filter(i -> p2.getCustomPluginParameter() == (CustomPluginParameterValues)(iMessageEditorTabParameters[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginParametersText.setText(p2.getCustomPluginParameterString());
		            	
		            	customPluginParameterEncodingTransformationList = new ArrayList<Transformation>(p2.getCustomPluginParameterEncoding());
		            	customPluginParameterEncodingText.setText(customPluginParameterEncodingTransformationList.toString());
		            	
		            	customPluginOutputDecodingTransformationList = new ArrayList<Transformation>(p2.getCustomPluginOutputDecoding());
		            	customPluginOutputDecodingText.setText(customPluginOutputDecodingTransformationList.toString());
		            	
		            	Object[] iMessageEditorTabFunctionOutputValues = CustomPlugin.functionOutputValuesIMessageEditorTab.toArray();
		            	customPluginOutputOptions.setSelectedIndex(IntStream.range(0, iMessageEditorTabFunctionOutputValues.length)
		            	         .filter(i -> p2.getCustomPluginFunctionOutput() == (CustomPluginFunctionOutputValues)(iMessageEditorTabFunctionOutputValues[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginOutputText.setText(p2.getCustomPluginFunctionOutputString());
		            	
		            	customPluginOutputEncodingTransformationList = new ArrayList<Transformation>(p2.getCustomPluginOutputEncoding());
		            	customPluginOutputEncodingText.setText(customPluginOutputEncodingTransformationList.toString());
		            	
		            	customPluginMessageEditorModifiedFridaExportNameText.setText(p2.getCustomPluginEditedContentFridaFunctionName());
		            	
		            	customPluginMessageEditorModifiedEncodeInputTransformationList = new ArrayList<Transformation>(p2.getCustomPluginEditedContentEncodingFridaInput());
		            	customPluginMessageEditorModifiedEncodeInputText.setText(customPluginMessageEditorModifiedEncodeInputTransformationList.toString());
		            	
		            	customPluginMessageEditorModifiedDecodingOutputTransformationList = new ArrayList<Transformation>(p2.getCustomPluginEditedContentFridaOutputDecoding());
		            	customPluginMessageEditorModifiedDecodingOutputText.setText(customPluginMessageEditorModifiedDecodingOutputTransformationList.toString());
		            	
		            	customPluginMessageEditorModifiedOutputLocationOptions.setSelectedIndex(p2.getCustomPluginEditedContentLocation().ordinal());		            	
		            	customPluginMessageEditorModifiedOutputLocationText.setText(p2.getCustomPluginEditedContentLocationString());
		            	
		            	customPluginMessageEditorModifiedOutputEncodingTransformationList = new ArrayList<Transformation>(p2.getCustomPluginEditedContentOutputEncoding());
		            	customPluginMessageEditorModifiedOutputEncodingText.setText(customPluginMessageEditorModifiedOutputEncodingTransformationList.toString());
		            			            
		            }
		            
				});
				
				break;
				
			case ICONTEXTMENU:

				BridaContextMenuPlugin p3 = (BridaContextMenuPlugin)currentPlugin;
				
				changeCustomPluginOptions("IContextMenu");
											
				SwingUtilities.invokeLater(new Runnable()  {
		        	
		            @Override
		            public void run()  { 
		            	
		            	customPluginPluginTypeListenerEnabled = false;
		            	customPluginTypePluginOptions.setSelectedIndex(2);
		            	customPluginPluginTypeListenerEnabled = true;
		            	
		            	customPluginNameText.setText(p3.getCustomPluginName());
		            	customPluginExportNameText.setText(p3.getCustomPluginExportedFunctionName());
		            	
		            	customPluginExecuteOnRadioButtonGroup.clearSelection();
		            	customPluginExecuteOnRadioContext.setSelected(true);
		            	customPluginExecuteOnStringParameter.setText(p3.getCustomPluginExecuteOnContextName());
		            	
		            	Object[] iContextMenuParameters = CustomPlugin.functionParametersIContextMenu.toArray();
		            	customPluginParametersOptions.setSelectedIndex(IntStream.range(0, iContextMenuParameters.length)
		            	         .filter(i -> p3.getCustomPluginParameter() == (CustomPluginParameterValues)(iContextMenuParameters[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginParametersText.setText(p3.getCustomPluginParameterString());
		            	
		            	customPluginParameterEncodingTransformationList = new ArrayList<Transformation>(p3.getCustomPluginParameterEncoding());
		            	customPluginParameterEncodingText.setText(customPluginParameterEncodingTransformationList.toString());
		            	
		            	customPluginOutputDecodingTransformationList = new ArrayList<Transformation>(p3.getCustomPluginOutputDecoding());
		            	customPluginOutputDecodingText.setText(customPluginOutputDecodingTransformationList.toString());
		            	
		            	Object[] iContextMenuFunctionOutputValues = CustomPlugin.functionOutputValuesIContextMenu.toArray();
		            	customPluginOutputOptions.setSelectedIndex(IntStream.range(0, iContextMenuFunctionOutputValues.length)
		            	         .filter(i -> p3.getCustomPluginFunctionOutput() == (CustomPluginFunctionOutputValues)(iContextMenuFunctionOutputValues[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginOutputText.setText(p3.getCustomPluginFunctionOutputString());
		            	
		            	customPluginOutputEncodingTransformationList = new ArrayList<Transformation>(p3.getCustomPluginOutputEncoding());
		            	customPluginOutputEncodingText.setText(customPluginOutputEncodingTransformationList.toString());
		            
		            }
		            
				});
				
				break;
				
			case JBUTTON:

				BridaButtonPlugin p4 = (BridaButtonPlugin)currentPlugin;
				
				changeCustomPluginOptions("JButton");
											
				SwingUtilities.invokeLater(new Runnable()  {
		        	
		            @Override
		            public void run()  { 
		            	
		            	customPluginPluginTypeListenerEnabled = false;
		            	customPluginTypePluginOptions.setSelectedIndex(3);
		            	customPluginPluginTypeListenerEnabled = true;
		            	
		            	customPluginNameText.setText(p4.getCustomPluginName());
		            	customPluginExportNameText.setText(p4.getCustomPluginExportedFunctionName());
		            	
		            	customPluginExecuteOnRadioButtonGroup.clearSelection();
		            	customPluginExecuteOnRadioButton.setSelected(true);
		            	customPluginExecuteOnStringParameter.setText(p4.getCustomPluginExecuteOnContextName());
		            	
		            	customPluginButtonPlatformRadioButtonGroup.clearSelection();
		            	if(p4.getHookOrFunction().getOs() == 0) {
		            		customPluginButtonTypeRadioAndroid.setSelected(true);
		            	} else if(p4.getHookOrFunction().getOs() == 1) {
		            		customPluginButtonTypeRadioIos.setSelected(true);
		            	} else {
		            		customPluginButtonTypeRadioGeneric.setSelected(true);
		            	}
		            	
		            	customPluginButtonTypeRadioButtonGroup.clearSelection();
		            	if(p4.getHookOrFunction().isInterceptorHook()) {
		            		customPluginButtonTypeRadioHook.setSelected(true);
		            		customPluginParametersPanel.setVisible(false);
	                		customPluginParameterEncodingPanel.setVisible(false);
		            	} else {
		            		customPluginButtonTypeRadioFunction.setSelected(true);
		            		customPluginParametersPanel.setVisible(true);
	                		customPluginParameterEncodingPanel.setVisible(true);
		            	}
		            	
		            	Object[] jButtonParameters = CustomPlugin.functionParametersJButton.toArray();
		            	customPluginParametersOptions.setSelectedIndex(IntStream.range(0, jButtonParameters.length)
		            	         .filter(i -> p4.getCustomPluginParameter() == (CustomPluginParameterValues)(jButtonParameters[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginParametersText.setText(p4.getCustomPluginParameterString());
		            	
		            	customPluginParameterEncodingTransformationList = new ArrayList<Transformation>(p4.getCustomPluginParameterEncoding());
		            	customPluginParameterEncodingText.setText(customPluginParameterEncodingTransformationList.toString());
		            		
		            	Object[] jButtonFunctionOutputValues = CustomPlugin.functionOutputValuesJButton.toArray();
		            	customPluginOutputOptions.setSelectedIndex(IntStream.range(0, jButtonFunctionOutputValues.length)
		            	         .filter(i -> p4.getCustomPluginFunctionOutput() == (CustomPluginFunctionOutputValues)(jButtonFunctionOutputValues[i]))
		            	         .findFirst()
		            	         .orElse(0));
		            	customPluginOutputText.setText(p4.getCustomPluginFunctionOutputString());
		            			            
		            }
		            
				});
				
				break;
				
			default:

				printException(null, "Edit plugin: invalid plugin type");
		
				break;	
		
		}
		
	}
	
	private void changeCustomPluginOptions(String pluginType) {
		
		if(customPluginPluginTypeListenerEnabled) {
		
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	if(pluginType.equals("IHttpListener")) {
	            		// Plugin description
	                	customPluginTypePluginDescription.setText("Plugin that dynamically process each requests and responses");
	                	// Execute on
	                	customPluginExecuteOnRadioRequest.setVisible(true);
	                	customPluginExecuteOnRadioResponse.setVisible(true);
	                	customPluginExecuteOnRadioAll.setVisible(true);
	                	customPluginExecuteOnRadioContext.setVisible(false);
	                	customPluginExecuteOnRadioButton.setVisible(false);
	                	customPluginExecuteOnStringParameter.setVisible(false);
	                	customPluginExecuteOnRadioRequest.setSelected(true);
	                	// Button platform
	                	customPluginButtonPlatformPanel.setVisible(false);
	                	// Button type
	                	customPluginButtonTypePanel.setVisible(false);
	                	// Burp Suite Tools
	                	customPluginToolsPanel.setVisible(true);
	                	// Only in scope?
	                	customPluginScopePanel.setVisible(true);
	                	// Execute
	                	customPluginExecuteWhenPanel.setVisible(true);
	                	// Parameter
	                    customPluginParametersPanel.setVisible(true);
	                	DefaultComboBoxModel<String> customPluginParametersModel = new DefaultComboBoxModel<String>(CustomPlugin.functionParametersIHttpListener.stream().map(CustomPluginParameterValues::toString).toArray(String[]::new));
	                	customPluginParametersOptions.setModel(customPluginParametersModel);
	                	// Parameter encoding
	                	customPluginParameterEncodingPanel.setVisible(true);
	                	// Plugin output
	                	DefaultComboBoxModel<String> customPluginOutputModel = new DefaultComboBoxModel<String>(CustomPlugin.functionOutputValuesIHttpListener.stream().map(CustomPluginFunctionOutputValues::toString).toArray(String[]::new));
	                	customPluginOutputOptions.setModel(customPluginOutputModel);
	                	customPluginOutputText.setVisible(true);
	                	// Frida output decoding
	                    customPluginOutputDecodingPanel.setVisible(true);
	                    // Plugin output encoding
	                    customPluginOutputEncodingPanel.setVisible(true);
	                	// Message editor encode input to Frida function for edited content
	                	customPluginMessageEditorModifiedEncodeInputPanel.setVisible(false);
	                	// Message Editor Decoding Output
	                	customPluginMessageEditorModifiedDecodingOutputPanel.setVisible(false);
	                	// Message Editor Frida funtion for edited content
	                	customPluginMessageEditorModifiedFridaFunctioPanel.setVisible(false);
	                	// Message Editor Output encoding
	                	customPluginMessageEditorModifiedOutputEncodingPanel.setVisible(false);
	                	// Message Editor Output location
	                	customPluginMessageEditorModifiedOutputLocationPanel.setVisible(false);
	                } else if(pluginType.equals("IMessageEditorTab")) {
	            		// Plugin description
	                	customPluginTypePluginDescription.setText("Plugin that add a editable Message Editor Tab to all requests/responses");
	                	// Execute on                	
	                	customPluginExecuteOnRadioRequest.setVisible(true);
	                	customPluginExecuteOnRadioResponse.setVisible(true);
	                	customPluginExecuteOnRadioAll.setVisible(true);
	                	customPluginExecuteOnRadioContext.setVisible(false);
	                	customPluginExecuteOnRadioButton.setVisible(false);
	                	customPluginExecuteOnStringParameter.setVisible(false);
	                	customPluginExecuteOnRadioRequest.setSelected(true);
	                	// Button platform
	                	customPluginButtonPlatformPanel.setVisible(false);                	
	                	// Button type
	                	customPluginButtonTypePanel.setVisible(false);                	
	                	// Burp Suite Tools
	                	customPluginToolsPanel.setVisible(false);   
	                	// Only in scope?
	                	customPluginScopePanel.setVisible(false);                	
	                	// Execute
	                	customPluginExecuteWhenPanel.setVisible(true);  
	                	// Parameter
	                	customPluginParametersPanel.setVisible(true);
	                	DefaultComboBoxModel<String> customPluginParametersModel = new DefaultComboBoxModel<String>(CustomPlugin.functionParametersIMessageEditorTab.stream().map(CustomPluginParameterValues::toString).toArray(String[]::new));
	                	customPluginParametersOptions.setModel(customPluginParametersModel);
	                	// Parameter encoding
	                	customPluginParameterEncodingPanel.setVisible(true);
	                	// Plugin output
	                	DefaultComboBoxModel<String> customPluginOutputModel = new DefaultComboBoxModel<String>(CustomPlugin.functionOutputValuesIMessageEditorTab.stream().map(CustomPluginFunctionOutputValues::toString).toArray(String[]::new));
	                	customPluginOutputOptions.setModel(customPluginOutputModel);
	                	customPluginOutputText.setVisible(true);
	                	// Frida output decoding
	                    customPluginOutputDecodingPanel.setVisible(true);
	                    // Plugin output encoding
	                    customPluginOutputEncodingPanel.setVisible(true);                	
	                	// Message editor encode input to Frida function for edited content
	                	customPluginMessageEditorModifiedEncodeInputPanel.setVisible(true);                	
	                	// Message Editor Decoding Output
	                	customPluginMessageEditorModifiedDecodingOutputPanel.setVisible(true);
	                	// Message Editor Frida funtion for edited content
	                	customPluginMessageEditorModifiedFridaFunctioPanel.setVisible(true);
	                	// Message Editor Output encoding
	                	customPluginMessageEditorModifiedOutputEncodingPanel.setVisible(true); 
	                	// Message Editor Output location
	                	customPluginMessageEditorModifiedOutputLocationPanel.setVisible(true);
	                } else if(pluginType.equals("IContextMenu")) {
	            		// Plugin description
	                	customPluginTypePluginDescription.setText("Plugin that add a context menu option to Burp Suite right-button menu");
	                	// Execute on                	
	                	customPluginExecuteOnRadioRequest.setVisible(false);
	                	customPluginExecuteOnRadioResponse.setVisible(false);
	                	customPluginExecuteOnRadioAll.setVisible(false);
	                	customPluginExecuteOnRadioContext.setVisible(true);
	                	customPluginExecuteOnRadioButton.setVisible(false);
	                	customPluginExecuteOnStringParameter.setVisible(true);
	                	customPluginExecuteOnRadioContext.setSelected(true);
	                	// Button platform
	                	customPluginButtonPlatformPanel.setVisible(false);                	
	                	// Button type
	                	customPluginButtonTypePanel.setVisible(false);                	
	                	// Burp Suite Tools
	                	customPluginToolsPanel.setVisible(false);    
	                	// Only in scope?
	                	customPluginScopePanel.setVisible(false);                	
	                	// Execute
	                	customPluginExecuteWhenPanel.setVisible(false); 
	                	// Parameter
	                	customPluginParametersPanel.setVisible(true);
	                	DefaultComboBoxModel<String> customPluginParametersModel = new DefaultComboBoxModel<String>(CustomPlugin.functionParametersIContextMenu.stream().map(CustomPluginParameterValues::toString).toArray(String[]::new));
	                	customPluginParametersOptions.setModel(customPluginParametersModel);
	                	// Parameter encoding
	                	customPluginParameterEncodingPanel.setVisible(true);
	                	// Plugin output
	                	DefaultComboBoxModel<String> customPluginOutputModel = new DefaultComboBoxModel<String>(CustomPlugin.functionOutputValuesIContextMenu.stream().map(CustomPluginFunctionOutputValues::toString).toArray(String[]::new));
	                	customPluginOutputOptions.setModel(customPluginOutputModel);
	                	customPluginOutputText.setVisible(true);
	                	// Frida output decoding
	                    customPluginOutputDecodingPanel.setVisible(true);
	                    // Plugin output encoding
	                    customPluginOutputEncodingPanel.setVisible(true);                	
	                	// Message editor encode input to Frida function for edited content
	                	customPluginMessageEditorModifiedEncodeInputPanel.setVisible(false);                	
	                	// Message Editor Decoding Output
	                	customPluginMessageEditorModifiedDecodingOutputPanel.setVisible(false);
	                	// Message Editor Frida funtion for edited content
	                	customPluginMessageEditorModifiedFridaFunctioPanel.setVisible(false);
	                	// Message Editor Output encoding
	                	customPluginMessageEditorModifiedOutputEncodingPanel.setVisible(false);         
	                	// Message Editor Output location
	                	customPluginMessageEditorModifiedOutputLocationPanel.setVisible(false);
	                } else {
	            		// Plugin description
	                	customPluginTypePluginDescription.setText("Plugin that add a button that enable a hook/call a function");
	                	// Execute on                	
	                	customPluginExecuteOnRadioRequest.setVisible(false);
	                	customPluginExecuteOnRadioResponse.setVisible(false);
	                	customPluginExecuteOnRadioAll.setVisible(false);
	                	customPluginExecuteOnRadioContext.setVisible(false);
	                	customPluginExecuteOnRadioButton.setVisible(true);
	                	customPluginExecuteOnStringParameter.setVisible(true);
	                	customPluginExecuteOnRadioButton.setSelected(true);
	                	// Button platform
	                	customPluginButtonPlatformPanel.setVisible(true);                	
	                	// Button type
	                	customPluginButtonTypePanel.setVisible(true);                	
	                	// Burp Suite Tools
	                	customPluginToolsPanel.setVisible(false);   
	                	// Only in scope?
	                	customPluginScopePanel.setVisible(false);                	
	                	// Execute
	                	customPluginExecuteWhenPanel.setVisible(false);  
	                	// Parameter
	                	if(customPluginButtonTypeRadioFunction.isSelected()) {
	                		customPluginParametersPanel.setVisible(true);
	                	} else {
	                		customPluginParametersPanel.setVisible(false);
	                	}
	                	DefaultComboBoxModel<String> customPluginParametersModel = new DefaultComboBoxModel<String>(CustomPlugin.functionParametersJButton.stream().map(CustomPluginParameterValues::toString).toArray(String[]::new));
	                	customPluginParametersOptions.setModel(customPluginParametersModel);
	                	// Parameter encoding
	                	if(customPluginButtonTypeRadioFunction.isSelected()) {
	                		customPluginParameterEncodingPanel.setVisible(true);
	                	} else {
	                		customPluginParameterEncodingPanel.setVisible(false);
	                	}
	                	// Plugin output
	                	DefaultComboBoxModel<String> customPluginOutputModel = new DefaultComboBoxModel<String>(CustomPlugin.functionOutputValuesJButton.stream().map(CustomPluginFunctionOutputValues::toString).toArray(String[]::new));
	                	customPluginOutputOptions.setModel(customPluginOutputModel);
	                	customPluginOutputText.setVisible(false);
	                	// Frida output decoding
	                    customPluginOutputDecodingPanel.setVisible(false);
	                    // Plugin output encoding
	                    customPluginOutputEncodingPanel.setVisible(false);                	
	                	// Message editor encode input to Frida function for edited content
	                	customPluginMessageEditorModifiedEncodeInputPanel.setVisible(false);                	
	                	// Message Editor Decoding Output
	                	customPluginMessageEditorModifiedDecodingOutputPanel.setVisible(false);
	                	// Message Editor Frida funtion for edited content
	                	customPluginMessageEditorModifiedFridaFunctioPanel.setVisible(false);
	                	// Message Editor Output encoding
	                	customPluginMessageEditorModifiedOutputEncodingPanel.setVisible(false);    
	                	// Message Editor Output location
	                	customPluginMessageEditorModifiedOutputLocationPanel.setVisible(false);
	                }
	            	
	            }
	            
			});
			
		}
		
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
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

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
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

		            }
		            
				});
				
				break;	

			//DEFAULT HOOKS	
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
						loadTreeButton.setVisible(false);
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);
						
		            }
		            
				});
				
				break;					
				
				
			// Tree view	
			case 3:
								
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
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

		            }
		            
				});
				
				break;	
				
			// Graphical hooks	
			case 4:
				
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
						removeAllGraphicalHooksButton.setVisible(true);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

		            }
		            
				});
				
				break;	
				
			//CUSTOM PLUGIN	
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
						removeAllGraphicalHooksButton.setVisible(false);
		                enableCustomPluginButton.setVisible(true);
		                exportCustomPluginsButton.setVisible(true);
		                importCustomPluginsButton.setVisible(true);

		            }
		            
				});
				
				break;
				
			// GENERATE STUBS	
			case 6:
				
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
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

		            }
		            
				});
				
				break;
			
			// DEBUG EXPORT
			case 7:
				
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
						removeAllGraphicalHooksButton.setVisible(false);
						enableCustomPluginButton.setVisible(false);
						exportCustomPluginsButton.setVisible(false);
		                importCustomPluginsButton.setVisible(false);

		            }
		            
				});
				
				break;
	
			default:			
				printException(null,"ShowHideButtons: index not found");				
				break;	
		
		}
		
	}	
	
	private boolean compileFridaCode(String fridaCompilePath, String fridaJsFolder) {
				
		Runtime rt = Runtime.getRuntime();

		String[] fridaCompileCommand;
		if(fridaCompileOldCheckBox.isSelected()) {
			fridaCompileCommand = new String[]{fridaCompilePath,"-x","-o",fridaJsFolder + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",fridaJsFolder + System.getProperty("file.separator") + "brida.js"};
		} else {
			fridaCompileCommand = new String[]{fridaCompilePath,"-o",fridaJsFolder + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",fridaJsFolder + System.getProperty("file.separator") + "brida.js"};
		}
		
		Process processCompilation = null;
		try {
			processCompilation = rt.exec(fridaCompileCommand);
			
			// With some types of error frida-compile remains stucked without returning errors. Killing the process after 30 seconds if blocked.
			// if(!processCompilation.waitFor(1, TimeUnit.MINUTES)) {
			if(!processCompilation.waitFor(30, TimeUnit.SECONDS)) {
			    processCompilation.destroyForcibly();
			    return false;
			}
						
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(processCompilation.getInputStream()));	
			BufferedReader stdError = new BufferedReader(new InputStreamReader(processCompilation.getErrorStream()));
		
			String s = null;
			while ((s = stdInput.readLine()) != null) {
			    printJSMessage(s);
			}
		
			// Read any errors from the attempted command
			while ((s = stdError.readLine()) != null) {
			    printException(null,s);
			}
			
			if(processCompilation.exitValue() == 0) {
				printSuccessMessage("frida-compile completed successfully");
				return true;
			} else {
				return false;
			}
			
		} catch (Exception e) {
			printException(e, "Exception during frida-compile");
			return false;
		}
		
	}
	
	private void launchPyroServer(String pythonPathEnv, String pyroServicePath) {
		
		Runtime rt = Runtime.getRuntime();
		
		String[] startServerCommand;		
		String[] execEnv;
		String debugCommandToPrint;
		
		if(useVirtualEnvCheckBox.isSelected()) {			
				
			// Add / or \\ if not present
			pythonPathEnv = pythonPathEnv.trim().endsWith(System.getProperty("file.separator")) ? pythonPathEnv.trim() : pythonPathEnv.trim() + System.getProperty("file.separator");
			
			//System.getProperty("file.separator")
			if(System.getProperty("os.name").trim().toLowerCase().startsWith("win")) {
				
				startServerCommand= new String[]{pythonPathEnv+ "Scripts\\python.exe","-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};
				execEnv = new String[]{"VIRTUAL_ENV=" + pythonPathEnv,"PATH="+pythonPathEnv+"Scripts"};
				
				debugCommandToPrint = "\"" + pythonPathEnv+ "Scripts\\python.exe\" -i \"" + pyroServicePath + "\" " + pyroHost.getText().trim() + " " + pyroPort.getText().trim();
				
			} else {
				
				startServerCommand= new String[]{pythonPathEnv+ "bin/python","-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};
				execEnv = new String[]{"VIRTUAL_ENV=" + pythonPathEnv,"PATH="+pythonPathEnv+"bin/"};
				
				debugCommandToPrint = "\"" + pythonPathEnv+ "bin/python\" -i \"" + pyroServicePath + "\" " + pyroHost.getText().trim() + " " + pyroPort.getText().trim();
				
			}
			
			/*
			// Instead of manually setting the ENV variables it is possible to run the activate script of the venv in the following way:
			 			
			if(System.getProperty("os.name").trim().toLowerCase().startsWith("win")) {
				
				startServerCommand= new String[]{pythonPathEnv,"&&","python","-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};
				
				debugCommandToPrint = "\"" + pythonPathEnv + "\" && python -i \"" + pyroServicePath + "\" " + pyroHost.getText().trim() + " " + pyroPort.getText().trim();
				
			} else {
				
				startServerCommand= new String[]{"bash","-c",pythonPathEnv.replace("\"", "'") + "; python -i '" + pyroServicePath + "' " + pyroHost.getText().trim() + " " + pyroPort.getText().trim()};
				
				debugCommandToPrint = "bash -c \"" + pythonPathEnv.replace("\"", "'") + "; python -i '" + pyroServicePath + "' " + pyroHost.getText().trim() + " " + pyroPort.getText().trim() + "\"";
				
			}
			execEnv = null;
			*/
			
			printSuccessMessage("Start Pyro server command: " + debugCommandToPrint);
			if(execEnv != null)
				printSuccessMessage("Start Pyro server environemnt variables: " + Arrays.toString(execEnv));
									
			
		} else {
			
			startServerCommand = new String[]{pythonPathEnv,"-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};			
			execEnv = null;
			
			debugCommandToPrint = "\"" + pythonPathEnv + "\" -i \"" + pyroServicePath + "\" " + pyroHost.getText().trim() + " " + pyroPort.getText().trim();
			printSuccessMessage("Start Pyro server command: " + debugCommandToPrint);
			
		}
			
		try {
			pyroServerProcess = rt.exec(startServerCommand,execEnv);
									
			final BufferedReader stdOutput = new BufferedReader(new InputStreamReader(pyroServerProcess.getInputStream()));
			final BufferedReader stdError = new BufferedReader(new InputStreamReader(pyroServerProcess.getErrorStream()));
		    
			// Initialize thread that will read stdout
			stdoutThread = new Thread() {
				
				public void run() {
					
						while(true) {
					
							try {
								
								final String line = stdOutput.readLine();
																
								// Only used to handle Pyro first message (when server start)
								if(line.equals("Ready.")) {
									        	
						        	pyroBridaService = new PyroProxy(new PyroURI("PYRO:BridaServicePyro@" + pyroHost.getText().trim() + ":" + pyroPort.getText().trim()));
						        	serverStarted = true;	 
						        	
						        	SwingUtilities.invokeLater(new Runnable() {
										
							            @Override
							            public void run() {
							            	
							            	serverStatus.setText("");
							            	serverStatusButtons.setText("");
							            	applicationStatus.setText("");
							            	applicationStatusButtons.setText("");
							            	try {
							                	documentServerStatus.insertString(0, "running", greenStyle);
							                	documentServerStatusButtons.insertString(0, "Server running", greenStyle);
							                	documentApplicationStatus.insertString(0, "NOT hooked", redStyle);
							                	documentApplicationStatusButtons.insertString(0, "App not hooked", redStyle);							                	
											} catch (BadLocationException e) {
												
												printException(e,"Exception setting labels");
	
											}
											
							            }
									});
						        	
						        	printSuccessMessage("Pyro server started correctly");
								
						        // Standard line	
								} else {
									
									printJSMessage(line);
									
								}
								
								
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
			
		} catch (final Exception e1) {
			
			printException(e1,"Exception starting Pyro server");

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
		
		callbacks.saveExtensionSetting("useVirtualEnvCheckBox",(useVirtualEnvCheckBox.isSelected() ? "true" : "false"));
		callbacks.saveExtensionSetting("pythonPath",pythonPathVenv.getText().trim());
		callbacks.saveExtensionSetting("pyroHost",pyroHost.getText().trim());
		callbacks.saveExtensionSetting("pyroPort",pyroPort.getText().trim());
		callbacks.saveExtensionSetting("fridaCompilePath",fridaCompilePath.getText().trim());
		callbacks.saveExtensionSetting("fridaCompileOldCheckBox",(fridaCompileOldCheckBox.isSelected() ? "true" : "false"));	
		callbacks.saveExtensionSetting("fridaPath",fridaPath.getText().trim());
		callbacks.saveExtensionSetting("applicationId",applicationId.getText().trim());			
		if(remoteRadioButton.isSelected()) { 
			callbacks.saveExtensionSetting("device","remote");
		} else if(usbRadioButton.isSelected()) { 
			callbacks.saveExtensionSetting("device","usb");
        } else if(localRadioButton.isSelected()) {
            callbacks.saveExtensionSetting("device","local");
        } else if(hostRadioButton.isSelected()) {
            callbacks.saveExtensionSetting("device","host");
		} else {
			callbacks.saveExtensionSetting("device","device");
		}
        callbacks.saveExtensionSetting("hostPortDevice",hostPortDevice.getText().trim());
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
			
			// Check if file already exists
        	if(outputFile.exists()) {	        		
        		JFrame parentDialogResult = new JFrame();
        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The file already exists. Would you like to overwrite it?","Warning",JOptionPane.YES_NO_OPTION);
        		if(dialogResult != JOptionPane.YES_OPTION){
        			return;
        		}	        		
        	}			
			
			FileWriter fw;
			try {
				fw = new FileWriter(outputFile);
				
				fw.write("useVirtualEnvCheckBox:" + (useVirtualEnvCheckBox.isSelected() ? "true" : "false") + "\n");
				fw.write("pythonPath:" + pythonPathVenv.getText().trim() + "\n");
				fw.write("pyroHost:" + pyroHost.getText().trim() + "\n");
				fw.write("pyroPort:" + pyroPort.getText().trim() + "\n");
				fw.write("fridaCompilePath:" + fridaCompilePath.getText().trim() + "\n");
				fw.write("fridaCompileOldCheckBox:" + (fridaCompileOldCheckBox.isSelected() ? "true" : "false") + "\n");
				fw.write("fridaPath:" + fridaPath.getText().trim() + "\n");
				fw.write("applicationId:" + applicationId.getText().trim() + "\n");
				if(remoteRadioButton.isSelected())  
					fw.write("device:remote\n");
				else if(usbRadioButton.isSelected())
					fw.write("device:usb\n");
                else if(localRadioButton.isSelected())
                    fw.write("device:local\n");
                else if(hostRadioButton.isSelected())
                    fw.write("device:host\n");
				else
					fw.write("device:device\n");
                fw.write("hostPortDevice:" + hostPortDevice.getText().trim() + "\n");
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
	
	private void execute_startup_scripts() {
		
		DefaultHook currentHook;
		for(int i=0; i < defaultHooks.size();i++) {			
			currentHook = defaultHooks.get(i);			
			if(currentHook.isEnabled() && currentHook.getOs() == platform) {				
				try {					
					executePyroCall(pyroBridaService, "callexportfunction",new Object[] {currentHook.getFridaExportName(),new String[] {}});					
				} catch (Exception e) {						
					 printException(e,"Exception running starting hook " + currentHook.getName());						
				}				
			}			
		}
		
		for(int i=0; i < treeHooks.size();i++) {
			currentHook = treeHooks.get(i);			
			if(currentHook.isEnabled()) {				
				try {					
					executePyroCall(pyroBridaService, "callexportfunction",new Object[] {currentHook.getFridaExportName(),currentHook.getParameters()});					
				} catch (Exception e) {						
					 printException(e,"Exception running starting tree hook " + currentHook.getName());						
				}				
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
						case "useVirtualEnvCheckBox":
							useVirtualEnvCheckBox.setSelected(lineParts[1].equals("true"));
							break;
						case "pythonPath":
							pythonPathVenv.setText(lineParts[1]);
							break;
						case "pyroHost":
							pyroHost.setText(lineParts[1]);
							break;
						case "pyroPort":
							pyroPort.setText(lineParts[1]);
							break;
						case "fridaCompilePath":
							fridaCompilePath.setText(lineParts[1]);
							break;			
						case "fridaCompileOldCheckBox":
							fridaCompileOldCheckBox.setSelected(lineParts[1].equals("true"));
							break;
						case "fridaPath":
							fridaPath.setText(lineParts[1]);
							break;
						case "applicationId":
							applicationId.setText(lineParts[1]);
							break;
						case "device":
							if(lineParts[1].equals("remote")) {
								remoteRadioButton.setSelected(true); 
							} else if (lineParts[1].equals("usb")) {
								usbRadioButton.setSelected(true);
                            } else if (lineParts[1].equals("local")) {
                                localRadioButton.setSelected(true);
                            } else if (lineParts[1].equals("host")) {
                                hostRadioButton.setSelected(true);
							} else {
								deviceRadioButton.setSelected(true);
							}
							break;
                        case "hostPortDevice":
                            hostPortDevice.setText(lineParts[1]);
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
	
	public static Object executePyroCall(PyroProxy pyroBridaService, String name, Object[] arguments) throws Exception {
		
		final ArrayList<Object> threadReturn = new ArrayList<Object>(); 
				
		final Runnable stuffToDo = new Thread()  {
		  @Override 
		  public void run() { 
			  try {
				threadReturn.add(pyroBridaService.call(name, arguments));
			} catch (PickleException | PyroException | IOException e) {
				threadReturn.add(e);
			}
		  }
		};

		final ExecutorService executor = Executors.newSingleThreadExecutor();
		final Future future = executor.submit(stuffToDo);
		executor.shutdown(); 

		try { 
		  //future.get(1, TimeUnit.MINUTES); 
			future.get(30, TimeUnit.SECONDS);
		}
		catch (InterruptedException | ExecutionException | TimeoutException ie) { 
			threadReturn.add(ie);
		}
				
		if (!executor.isTerminated())
			executor.shutdownNow(); 
		
		if(threadReturn.size() > 0) {
			if(threadReturn.get(0) instanceof Exception) {
				throw (Exception)threadReturn.get(0);
			} else {
				return threadReturn.get(0);
			}
		} else {
			return null; 
		} 
		
	}
	
	public void spawnApplication(boolean spawn) {
		
		try {
			
			String device = "";
			if(remoteRadioButton.isSelected())
				device = "remote";
			else if(usbRadioButton.isSelected())
				device = "usb";
            else if(localRadioButton.isSelected())
                device = "local";
            else if(hostRadioButton.isSelected())
                device = "host";
			else
				device = "device";
			
			if(spawn) {
				
				//pyroBridaService.call("spawn_application", applicationId.getText().trim(), fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",device);
				executePyroCall(pyroBridaService, "spawn_application",new Object[] {applicationId.getText().trim(), fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",device,hostPortDevice.getText().trim()});

				execute_startup_scripts();
				
				// Wait for 3 seconds in order to load hooks
				Thread.sleep(3000);
				
				//pyroBridaService.call("resume_application");
				executePyroCall(pyroBridaService, "resume_application", new Object[] {});
				
			} else {
				
				//pyroBridaService.call("attach_application", applicationId.getText().trim(), fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",device);
				executePyroCall(pyroBridaService, "attach_application",new Object[] {applicationId.getText().trim(), fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js",device,hostPortDevice.getText().trim()});

				execute_startup_scripts();
								
			}
			
			applicationSpawned = true;
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	applicationStatus.setText("");
	            	applicationStatusButtons.setText("");
	            	
	            	try {
	                	documentApplicationStatus.insertString(0, "running", greenStyle);
	                	documentApplicationStatusButtons.insertString(0, "App hooked", greenStyle);
					} catch (BadLocationException e) {
						printException(e,"Exception with labels");
					}
					
	            }
			});
			
			if(spawn) {
				printSuccessMessage("Application " + applicationId.getText().trim() + " spawned correctly");
			} else {
				printSuccessMessage("Application with PID " + applicationId.getText().trim() + " attached correctly");
			}
			
			// GETTING PLAFORM INFO (ANDROID/IOS/GENERIC)			
			try {
				//platform = (int)(pyroBridaService.call("callexportfunction","getplatform",new String[] {}));
				platform = (int)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getplatform",new String[] {}}));
				if(platform == BurpExtender.PLATFORM_ANDROID) {
					printSuccessMessage("Platform: Android");					
				} else if(platform == BurpExtender.PLATFORM_IOS) {
					printSuccessMessage("Platform: iOS");
				} else {
					printSuccessMessage("Platform: Generic");
				}
			} catch (Exception e) {				
				printException(e,"Exception with getting info Android/iOS");				
			}
			
		} catch (final Exception e) {
			
			printException(e,"Exception with " + (spawn ? "spawn" : "attach") + " application");
			
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
			
			if(!(new File(fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js")).exists()) {
				
				// Brida compiled file does not exist. Compiling it...
				if(!compileFridaCode(fridaCompilePath.getText().trim(), fridaPath.getText().trim())) {
					printException(null, "Error during frida-compile, potentially caused by compilation errors. Aborting. If exception details are not returned, try to run frida-compile manually. frida-compile command:");
					
					if(fridaCompileOldCheckBox.isSelected()) {
						printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -x -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
					} else {
						printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
					}
					
					return;
				}
				
			}
			
			spawnApplication(true);
			
		} else if(command.equals("compileSpawnApplication") && serverStarted) {
			
			if(!compileFridaCode(fridaCompilePath.getText().trim(), fridaPath.getText().trim())) {
				printException(null, "Error during frida-compile, potentially caused by compilation errors. Aborting. If exception details are not returned, try to run frida-compile manually. frida-compile command:");
				
				if(fridaCompileOldCheckBox.isSelected()) {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -x -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				} else {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				}
				return;
			}
			
			spawnApplication(true);
			
		} else if(command.equals("attachApplication") && serverStarted) {
			
			if(!(new File(fridaPath.getText().trim() + System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js")).exists()) {
				
				// Brida compiled file does not exist. Compiling it...
				if(!compileFridaCode(fridaCompilePath.getText().trim(), fridaPath.getText().trim())) {
					printException(null, "Error during frida-compile, potentially caused by compilation errors. Aborting. If exception details are not returned, try to run frida-compile manually. frida-compile command:");
					
					if(fridaCompileOldCheckBox.isSelected()) {
						printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -x -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
					} else {
						printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
					}
					return;
				}
				
			}
			
			spawnApplication(false);
			
		} else if(command.equals("compileAttachApplication") && serverStarted) {
			
			if(!compileFridaCode(fridaCompilePath.getText().trim(), fridaPath.getText().trim())) {
				printException(null, "Error during frida-compile, potentially caused by compilation errors. Aborting. If exception details are not returned, try to run frida-compile manually. frida-compile command:");
				
				if(fridaCompileOldCheckBox.isSelected()) {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -x -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				} else {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				}
				return;
			}
			
			spawnApplication(false);			
			
		} else if(command.equals("reloadScript") && serverStarted && applicationSpawned) {
							
			try {
				
				//pyroBridaService.call("reload_script");
				executePyroCall(pyroBridaService, "reload_script",new Object[] {});
				
				printSuccessMessage("Reloading script executed");
				
			} catch (final Exception e) {
								
				printException(e,"Exception reloading script");
				
			}
			
		} else if(command.equals("compileReloadScript") && serverStarted && applicationSpawned) {
			
			if(!compileFridaCode(fridaCompilePath.getText().trim(), fridaPath.getText().trim())) {
				
				printException(null, "Error during frida-compile, potentially caused by compilation errors. Aborting. If exception details are not returned, try to run frida-compile manually. frida-compile command:");
				
				if(fridaCompileOldCheckBox.isSelected()) {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -x -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				} else {
					printException(null, "\"" + fridaCompilePath.getText().trim() + "\" -o \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "bridaGeneratedCompiledOutput.js\" \"" + fridaPath.getText().trim() +  System.getProperty("file.separator") + "brida.js\"");
				}
				
				return;
			}
				
			try {
				
				//pyroBridaService.call("reload_script");
				executePyroCall(pyroBridaService, "reload_script",new Object[] {});
				
				printSuccessMessage("Reloading script executed");
				
			} catch (final Exception e) {
								
				printException(e,"Exception reloading script");
				
			}	
						
		} else if(command.equals("killApplication") && serverStarted && applicationSpawned) {
			
			try {
				//pyroBridaService.call("disconnect_application");
				executePyroCall(pyroBridaService, "disconnect_application",new Object[] {});
				applicationSpawned = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	applicationStatus.setText("");
		            	applicationStatusButtons.setText("");
		            	try {
		                	documentApplicationStatus.insertString(0, "NOT hooked", redStyle);
		                	documentApplicationStatusButtons.insertString(0, "App not hooked", redStyle);
						} catch (BadLocationException e) {
							printException(e,"Exception setting labels");
						}
						
		            }
				});
				
				printSuccessMessage("Killing application executed");
				
			} catch (final Exception e) {
				
				printException(e,"Exception killing application");
				
			}
			
		} else if(command.equals("detachApplication") && serverStarted && applicationSpawned) {
			
			try {
				//pyroBridaService.call("detach_application");
				executePyroCall(pyroBridaService, "detach_application",new Object[] {});
				applicationSpawned = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	applicationStatus.setText("");
		            	applicationStatusButtons.setText("");
		            	try {
		                	documentApplicationStatus.insertString(0, "NOT hooked", redStyle);
		                	documentApplicationStatusButtons.insertString(0, "App not hooked", redStyle);
						} catch (BadLocationException e) {
							printException(e,"Exception setting labels");
						}
						
		            }
				});
				
				printSuccessMessage("Detach application executed");
				
			} catch (final Exception e) {
				
				printException(e,"Exception detaching application");
				
			}
			
		} else if(command.equals("customPluginParameterEncodingButton")) {
			
			popupEncoderWindow("Choose encode options",customPluginParameterEncodingText,customPluginParameterEncodingTransformationList);		
			
		} else if(command.equals("customPluginOutputDecodingButton")) {
			
			popupEncoderWindow("Choose decode options",customPluginOutputDecodingText,customPluginOutputDecodingTransformationList);	
			
		} else if(command.equals("customPluginOutputEncodingButton")) {
	
			popupEncoderWindow("Choose encode options",customPluginOutputEncodingText,customPluginOutputEncodingTransformationList);	

		} else if(command.equals("customPluginMessageEditorModifiedEncodeInputButton")) {
			
			popupEncoderWindow("Choose encode options",customPluginMessageEditorModifiedEncodeInputText,customPluginMessageEditorModifiedEncodeInputTransformationList);	
			
		} else if(command.equals("customPluginMessageEditorModifiedDecodingOutputButton")) {
			
			popupEncoderWindow("Choose decode options",customPluginMessageEditorModifiedDecodingOutputText,customPluginMessageEditorModifiedDecodingOutputTransformationList);	
			
		} else if(command.equals("customPluginMessageEditorModifiedOutputEncodingButton")) {
			
			popupEncoderWindow("Choose encode options",customPluginMessageEditorModifiedOutputEncodingText,customPluginMessageEditorModifiedOutputEncodingTransformationList);	
			
		} else if(command.equals("killServer") && serverStarted) {
			
			stdoutThread.stop();
			stderrThread.stop();
			
			try {
				//pyroBridaService.call("shutdown");
				executePyroCall(pyroBridaService, "shutdown",new Object[] {});
				pyroServerProcess.destroy();
				pyroBridaService.close();
				serverStarted = false;
				applicationSpawned = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	serverStatus.setText("");
		            	serverStatusButtons.setText("");
		            	applicationStatus.setText("");
		            	applicationStatusButtons.setText("");
		            	try {
		                	documentServerStatus.insertString(0, "NOT running", redStyle);
		                	documentServerStatusButtons.insertString(0, "Server stopped", redStyle);
		                	documentApplicationStatus.insertString(0, "NOT hooked", redStyle);
		                	documentApplicationStatusButtons.insertString(0, "App not hooked", redStyle);			                	
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
				
				launchPyroServer(pythonPathVenv.getText().trim(),pythonScript);

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
				
				//final String s = (String)(pyroBridaService.call("callexportfunction",executeMethodName.getText().trim(),arguments));
				final String s = (String)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {executeMethodName.getText().trim(),arguments}));
								
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
						
			// There already is a loaded file
			if(jsEditorTextArea.getFileName() != null) {				
				// The content has been modified
				if(jsEditorTextArea.isDirty()) {					       		
	        		JFrame parentDialogResult = new JFrame();
	        		Object[] dialogOptions = {"Yes","No"};
	        		int dialogResult = JOptionPane.showOptionDialog(parentDialogResult, "The file in the editor has been modified. Would you like to discard changes and open a new file?","Warning",JOptionPane.YES_NO_OPTION,JOptionPane.QUESTION_MESSAGE,null,dialogOptions,dialogOptions[1]);	        		
	        		if(dialogResult != JOptionPane.YES_OPTION){
	        			return;
	        		}	        							
				}				
			}
			
			JFrame parentFrameLoadJsFile = new JFrame();
			JFileChooser fileChooserLoadJsFile = new JFileChooser();
			fileChooserLoadJsFile.setDialogTitle("Load JS file");
			fileChooserLoadJsFile.setCurrentDirectory(new File(fridaPath.getText().trim()));
			FileNameExtensionFilter filterLoadJsFile = new FileNameExtensionFilter("JS file", "js");
			fileChooserLoadJsFile.setFileFilter(filterLoadJsFile);
	        int userSelectionLoadJsFile = fileChooserLoadJsFile.showOpenDialog(parentFrameLoadJsFile);
	        
	        if (userSelectionLoadJsFile == JFileChooser.APPROVE_OPTION) {
			
				File jsFile = fileChooserLoadJsFile.getSelectedFile();			
				
				final FileLocation fl = FileLocation.create(jsFile);
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            			            	
		            	try {
							jsEditorTextArea.load(fl,null);
						} catch (IOException e) {
							printException(e,"Exception loading JS file");
						}
	
		            }
				});
				
	        }
						
		} else if(command.equals("saveJsFile")) {
			
			/*
			// The content of file has been modified outside Brida editor - Don't work correctly unfortunately...
			if(jsEditorTextArea.isModifiedOutsideEditor()) {
				
				JFrame parentDialogResult = new JFrame();
        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The file has been modified has been modified outside Brida editor. Would you like to override it?","Warning",JOptionPane.YES_NO_OPTION);
        		if(dialogResult != JOptionPane.YES_OPTION){
        			return;
        		}					
			}
			*/
		
			try {
				jsEditorTextArea.save();
				printSuccessMessage("File saved");
			} catch (IOException e) {
				printException(e,"Error saving JS file");
			}

		} else if(command.equals("loadTree")) {
			
			try {
				
				//ArrayList<String> allClasses = (ArrayList<String>)(pyroBridaService.call("callexportfunction","getallclasses",new String[0]));
				ArrayList<String> allClasses = (ArrayList<String>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getallclasses",new String[0]}));
				//HashMap<String, Integer> allModules = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getallmodules",new String[0]));
				HashMap<String, Integer> allModules = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getallmodules",new String[0]}));
				
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
				
				DefaultMutableTreeNode currentNode;
				
				// ONLY FOR IOS AND ANDROID
				if(platform == BurpExtender.PLATFORM_ANDROID || platform == BurpExtender.PLATFORM_IOS) {
				
					DefaultMutableTreeNode objNode = (platform == BurpExtender.PLATFORM_ANDROID ? new DefaultMutableTreeNode("Java") : new DefaultMutableTreeNode("Objective-C"));
				
					for(int i=0; i<allClasses.size(); i++) {
	
						currentNode = new DefaultMutableTreeNode(allClasses.get(i));
	
						objNode.add(currentNode);
						
					}
	
					newRoot.add(objNode);
					
				}
				
				DefaultMutableTreeNode modulesNode = new DefaultMutableTreeNode("Modules");
			
				for(int i=0; i<moduleNames.size(); i++) {

					currentNode = new DefaultMutableTreeNode(moduleNames.get(i));

					modulesNode.add(currentNode);
					
				}

				newRoot.add(modulesNode);				
				
				model.setRoot(newRoot);
				
				if(platform == BurpExtender.PLATFORM_ANDROID) {
					printSuccessMessage("**** Tree created (Java unloaded classes and methods will NOT be present in the tree)");
				} else {
					printSuccessMessage("**** Tree created");
				}

			} catch (Exception e) {
								
				printException(e,"Exception with load tree");
				
			}

		} else if(command.equals("searchAnalysis")) {
		
			String toSearch = findTextField.getText().trim();
			
			HashMap<String, Integer> foundObjcJavaMethods = null;
			
			if(platform == BurpExtender.PLATFORM_IOS || platform == BurpExtender.PLATFORM_ANDROID) {
				String fridaExportForPlatform = ((platform == BurpExtender.PLATFORM_IOS) ? "findobjcmethods" : "findjavamethods");
				try {
					foundObjcJavaMethods = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {fridaExportForPlatform,new String[] {toSearch}}));
				} catch (Exception e) {
					if(platform == BurpExtender.PLATFORM_IOS)
						printException(e,"Exception searching OBJC methods");
					else
						printException(e,"Exception searching Java methods");
					return;
				} 
			}
			
			
			HashMap<String, Integer> foundImports = null;
			try {
				//foundImports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","findimports",new String[] {toSearch}));
				foundImports = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"findimports",new String[] {toSearch}}));
			} catch (Exception e) {
				printException(e,"Exception searching imports");
				return;
			} 
			
			HashMap<String, Integer> foundExports = null;
			try {
				//foundExports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","findexports",new String[] {toSearch}));
				foundExports = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"findexports",new String[] {toSearch}}));
			} catch (Exception e) {
				printException(e,"Exception searching exports");
				return;
			} 
			
			if(platform == BurpExtender.PLATFORM_ANDROID) {
				printSuccessMessage("**** Result of the search of " + findTextField.getText().trim() + " (Java unloaded classes and methods unloaded will NOT be present in the list)");
			} else {
				printSuccessMessage("**** Result of the search of " + findTextField.getText().trim());
			}
			
			if(foundObjcJavaMethods != null) {
				
				ArrayList<String> objcJavaMethodNames = new ArrayList<String>(foundObjcJavaMethods.keySet());
				
				// Sort objc method names
				Collections.sort(objcJavaMethodNames, new Comparator<String>() {
			        @Override
			        public int compare(String class1, String class2)
			        {

			            return  class1.compareToIgnoreCase(class2);
			        }
			    });	
			
				Iterator<String> currentClassMethodsIterator = objcJavaMethodNames.iterator(); 
				
				String currentMethodName;
				
				while(currentClassMethodsIterator.hasNext()) {
					
					currentMethodName = currentClassMethodsIterator.next();
					if(platform == BurpExtender.PLATFORM_IOS) {
						printJSMessage("OBJC: " + currentMethodName);
					} else {
						printJSMessage("JAVA: " + currentMethodName);
					}
					
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
			
		} else if(command.equals("removeAllGraphicalHooks")) {
			
			if(!applicationSpawned) {
							
				// Ask user confirmation
				JFrame parentDialogResult = new JFrame();
				int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "Are you sure to want to remove all graphical hook?","Warning",JOptionPane.YES_NO_OPTION);
				if(dialogResult != JOptionPane.YES_OPTION){
					return;
				}	
				
				treeHooks.clear();
				
				List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
	        	synchronized(trapEntries) {
	        		int trapEntryOldSize = trapEntries.size();
	        		if(trapEntryOldSize > 0) {
	        			trapEntries.clear();
	        			((TrapTableModel)(trapTable.getModel())).fireTableRowsDeleted(0, trapEntryOldSize - 1);
	        		}
	            }
				
				
			} else {
				JOptionPane.showMessageDialog(null, "It is not possible to remove single hooks while application is running", "Warning", JOptionPane.WARNING_MESSAGE);
			}
			
		} else if(command.equals("detachAll")) {	
			
			int dialogButton = JOptionPane.YES_NO_OPTION;
			int dialogResult = JOptionPane.showConfirmDialog(mainPanel, "Are you sure to want to detach ALL Frida hooks (including graphical hooks, custom plugin hooks and Frida JS file hooks)? Enabled hooks will be enabled again on next application spawn.", "Confirm detach all", dialogButton);
			if(dialogResult == 0) {
				try {
					executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"detachAll",new String[] {}});
				} catch (Exception e) {					
					printException(e,"Exception detaching all");
					return;
				}
								
				printSuccessMessage("Detaching all successfully executed");
				
			} else {
				printSuccessMessage("Detaching all CANCELED as requested by the user");
			}			
			
		} else if(command.equals("trapBacktrace")) {	
			
			trap(true);	
			
		} else if(command.equals("demangle")) {
		
			demangleSwift();

		} else if(command.equals("pythonPathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			
			if(useVirtualEnvCheckBox.isSelected()) {
				fileChooser.setDialogTitle("Virtual Env Folder");
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			} else {
				fileChooser.setDialogTitle("Python Path");
			}
			
			int userSelection = fileChooser.showOpenDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				final File pythonPathFile = fileChooser.getSelectedFile();
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	pythonPathVenv.setText(pythonPathFile.getAbsolutePath());
		            }
				
				});
				
			}	
			
		} else if(command.equals("fridaCompilePathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("frida-compile path");
			
			int userSelection = fileChooser.showOpenDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				final File fridaCompilePathFile = fileChooser.getSelectedFile();
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	fridaCompilePath.setText(fridaCompilePathFile.getAbsolutePath());
		            }
				
				});
				
			}		
			
		} else if(command.equals("fridaPathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Frida JS folder");
			fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			fileChooser.setCurrentDirectory(new File(fridaPath.getText().trim()));
			
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
			
		} else if(command.equals("fridaPathSelectDefaultFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Select location for Frida default JS file");
			fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			fileChooser.setCurrentDirectory(new File(fridaPath.getText().trim()));
			
			String[] bridaFiles = new String[] {
				"brida.js",
				"bridaFunctions.js",
				"androidDefaultHooks.js",
				"iosDefaultHooks.js"
			};
			
			int userSelection = fileChooser.showSaveDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				final File fridaPathFolder = fileChooser.getSelectedFile();
				
				for(int i=0;i<bridaFiles.length;i++) {
					
					try {

						InputStream inputStream = getClass().getClassLoader().getResourceAsStream("res/" + bridaFiles[i]);
						BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream ));
						File outputFile = new File(fridaPathFolder.getAbsolutePath() + System.getProperty("file.separator") + bridaFiles[i]);
						
						// Check if file already exists
			        	if(outputFile.exists()) {	        		
			        		JFrame parentDialogResult = new JFrame();
			        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The file " + bridaFiles[i] + " already exists. Would you like to overwrite it?","Warning",JOptionPane.YES_NO_OPTION);
			        		if(dialogResult != JOptionPane.YES_OPTION){
			        			continue;
			        		}	        		
			        	}						
						
						FileWriter fr = new FileWriter(outputFile);
						BufferedWriter br  = new BufferedWriter(fr);
						
						String s;
						while ((s = reader.readLine())!=null) {
							
							br.write(s);
							br.newLine();
							
						}
						reader.close();
						br.close();
					
					} catch(Exception e) {
						
						printException(e,"Error copying Frida " + bridaFiles[i] + " JS file");
						
					}
					
				}
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	fridaPath.setText(fridaPathFolder.getAbsolutePath());
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
    			
    			String dialogResult = JOptionPane.showInputDialog(mainPanel, "Insert the new " + changeType + " return value","Return value",JOptionPane.QUESTION_MESSAGE);

    			if(dialogResult != null) {
    				changeReturnValue(changeType,dialogResult);
    			}
    			
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
			
		} else if(command.startsWith("enablePlugin")) {
			
			// Plugin type
			CustomPlugin.CustomPluginType pluginType = null;
			if(customPluginTypePluginOptions.getSelectedItem().toString().equals("IHttpListener")) {
				pluginType = CustomPlugin.CustomPluginType.IHTTPLISTENER;
			} else if(customPluginTypePluginOptions.getSelectedItem().toString().equals("IMessageEditorTab")) {
				pluginType = CustomPlugin.CustomPluginType.IMESSAGEEDITORTAB;
			} else if(customPluginTypePluginOptions.getSelectedItem().toString().equals("IContextMenu")) {
				pluginType = CustomPlugin.CustomPluginType.ICONTEXTMENU;
			} else {
				pluginType = CustomPlugin.CustomPluginType.JBUTTON;
			}
			
			// Execute on
			CustomPlugin.CustomPluginExecuteOnValues customPluginExecuteOn = null;			
			if(customPluginExecuteOnRadioRequest.isSelected()) {
				customPluginExecuteOn = CustomPlugin.CustomPluginExecuteOnValues.REQUESTS;
			} else if(customPluginExecuteOnRadioResponse.isSelected()) {
				customPluginExecuteOn = CustomPlugin.CustomPluginExecuteOnValues.RESPONSES;
			} else if(customPluginExecuteOnRadioAll.isSelected()) {
				customPluginExecuteOn = CustomPlugin.CustomPluginExecuteOnValues.ALL;
			} else if(customPluginExecuteOnRadioContext.isSelected()) {
				customPluginExecuteOn = CustomPlugin.CustomPluginExecuteOnValues.CONTEXT;
			} else {
				customPluginExecuteOn = CustomPlugin.CustomPluginExecuteOnValues.BUTTON;
			}
			
			// Burp Suite tools (IHttpListener plugins only)
			ArrayList<Integer> customPluginTools = new ArrayList<Integer>();
			if(pluginType == CustomPlugin.CustomPluginType.IHTTPLISTENER) {
				if(customPluginToolsRepeater.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_REPEATER);
				if(customPluginToolsProxy.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_PROXY);
				if(customPluginToolsScanner.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_SCANNER);
				if(customPluginToolsIntruder.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_INTRUDER);
				if(customPluginToolsExtender.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_EXTENDER);
				if(customPluginToolsSequencer.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_SEQUENCER);
				if(customPluginToolsSpider.isSelected())	customPluginTools.add(IBurpExtenderCallbacks.TOOL_SPIDER);
			}
			
			// Execute (IHttpListener and IMessageEditorTab only)
			CustomPlugin.CustomPluginExecuteValues customPluginExecute = null;
			if(pluginType == CustomPlugin.CustomPluginType.IHTTPLISTENER || pluginType == CustomPlugin.CustomPluginType.IMESSAGEEDITORTAB) {
				if(customPluginExecuteWhenOptions.getSelectedItem().toString().equals("always")) {
					customPluginExecute = CustomPluginExecuteValues.ALWAYS;
				} else if(customPluginExecuteWhenOptions.getSelectedItem().toString().equals("when request/response contains plaintext")) {
					customPluginExecute = CustomPluginExecuteValues.PLAINTEXT;
				} else {
					customPluginExecute = CustomPluginExecuteValues.REGEX;
				}
			}
			
			// Plugin platform (JButton only)
			int pluginPlatform = 0;
			if(pluginType == CustomPlugin.CustomPluginType.JBUTTON) {
				if(customPluginButtonTypeRadioIos.isSelected()) {
					pluginPlatform = PLATFORM_IOS;
				} else if(customPluginButtonTypeRadioAndroid.isSelected()) {
					pluginPlatform = PLATFORM_ANDROID;
				} else {
					pluginPlatform = PLATFORM_GENERIC;
				}
			}
			
			// Hook or function (JButton only)
			boolean hookOrFunction = false;
			if(pluginType == CustomPlugin.CustomPluginType.JBUTTON) {
				if(customPluginButtonTypeRadioFunction.isSelected()) {
					hookOrFunction = false;
				} else {
					hookOrFunction = true;
				}
			}
			
			// Parameters
			CustomPluginParameterValues customPluginParameter = CustomPluginParameterValues.getEnumByName(customPluginParametersOptions.getSelectedItem().toString());
			
			// Parameter encoding
			List<Transformation> customPluginParameterEncoding = new ArrayList<Transformation>(customPluginParameterEncodingTransformationList);
						
			// Decode Frida output
			List<Transformation> customPluginOutputDecoding = new ArrayList<Transformation>(customPluginOutputDecodingTransformationList);
			
			// Plugin output
			CustomPluginFunctionOutputValues customPluginFunctionOutput = CustomPluginFunctionOutputValues.getEnumByName(customPluginOutputOptions.getSelectedItem().toString());
			
			// Encode output
			List<Transformation> customPluginOutputEncoding = new ArrayList<Transformation>(customPluginOutputEncodingTransformationList);
			
			// Encode value edited message before passing to Frida function executed on edited content (IMessageEditorTab only)
			List<Transformation> customPluginFridaInputEncodingEditedContent = new ArrayList<Transformation>(customPluginMessageEditorModifiedEncodeInputTransformationList);
			
			// Decode output of Frida function executed on edited content (IMessageEditorTab only)
			List<Transformation> customPluginOutputDecodingEditedContent = new ArrayList<Transformation>(customPluginMessageEditorModifiedDecodingOutputTransformationList);
			
			// Message editor output location (IMessageEditorTab only)
			BridaMessageEditorPluginOutputLocation customPluginEditedMessageOutputLocation = BridaMessageEditorPluginOutputLocation.getEnumByName(customPluginMessageEditorModifiedOutputLocationOptions.getSelectedItem().toString());
			
			// Encode output of Frida function executed on edited content (IMessageEditorTab only)
			List<Transformation> customPluginEditedFunctionOutputEncoding = new ArrayList<Transformation>(customPluginMessageEditorModifiedOutputEncodingTransformationList);
			
			CustomPlugin newCustomPlugin;
			if(pluginType == CustomPlugin.CustomPluginType.IHTTPLISTENER) {
				BridaHttpListenerPlugin newPlugin = new BridaHttpListenerPlugin(customPluginTools,
						customPluginScopeCheckBox.isSelected(),
						this,
						customPluginNameText.getText(),
						customPluginExportNameText.getText(),
						customPluginExecuteOn,
						customPluginExecuteOnStringParameter.getText(),
						customPluginExecute,
						customPluginExecuteWhenText.getText(),
						customPluginParameter,
						customPluginParametersText.getText(),
						customPluginParameterEncoding,
						customPluginFunctionOutput,
						customPluginOutputText.getText(),
						customPluginOutputEncoding,
						customPluginOutputDecoding);
				
				newCustomPlugin = newPlugin;
								
			} else if(pluginType == CustomPlugin.CustomPluginType.ICONTEXTMENU) {
				BridaContextMenuPlugin newPlugin = new BridaContextMenuPlugin(this,
						customPluginNameText.getText(),
						customPluginExportNameText.getText(),
						customPluginExecuteOn,
						customPluginExecuteOnStringParameter.getText(),
						customPluginParameter,
						customPluginParametersText.getText(),
						customPluginParameterEncoding,
						customPluginFunctionOutput,
						customPluginOutputText.getText(),
						customPluginOutputEncoding,
						customPluginOutputDecoding);
				
				newCustomPlugin = newPlugin;
								
			} else if(pluginType == CustomPlugin.CustomPluginType.JBUTTON) {
				BridaButtonPlugin newPlugin = new BridaButtonPlugin(pluginPlatform,
						hookOrFunction,
						this,
						customPluginNameText.getText(),
						customPluginExportNameText.getText(),
						customPluginExecuteOn,
						customPluginExecuteOnStringParameter.getText(),
						customPluginParameter,
						customPluginParametersText.getText(),
						customPluginParameterEncoding,
						customPluginFunctionOutput,
						customPluginOutputText.getText(),
						customPluginOutputEncoding,
						customPluginOutputDecoding);
				
				newCustomPlugin = newPlugin;
								
			} else {
				
				BridaMessageEditorPlugin newPlugin = new BridaMessageEditorPlugin(customPluginEditedMessageOutputLocation,
						customPluginMessageEditorModifiedOutputLocationText.getText(),
						customPluginFridaInputEncodingEditedContent,
						customPluginOutputDecodingEditedContent,
						customPluginMessageEditorModifiedFridaExportNameText.getText(),
						customPluginEditedFunctionOutputEncoding,
						this,
						customPluginNameText.getText(),
						customPluginExportNameText.getText(),
						customPluginExecuteOn,
						customPluginExecuteOnStringParameter.getText(),
						customPluginExecute,
						customPluginExecuteWhenText.getText(),
						customPluginParameter,
						customPluginParametersText.getText(),
						customPluginParameterEncoding,
						customPluginFunctionOutput,
						customPluginOutputText.getText(),
						customPluginOutputEncoding,
						customPluginOutputDecoding);
				
				newCustomPlugin = newPlugin;
								
			}
			
			List<CustomPlugin> customPlugins = ((CustomPluginsTableModel)(customPluginsTable.getModel())).getCustomPlugins();
			synchronized(customPlugins) {
				int customPluginsOldSize = customPlugins.size();
				customPlugins.add(newCustomPlugin);
				((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsInserted(customPluginsOldSize, customPlugins.size() - 1);
			}			
						
		} else if(command.startsWith("exportPlugins")) {
			
			JFrame parentFrameExportPlugins = new JFrame();
			JFileChooser fileChooserExportPlugins = new JFileChooser();
			fileChooserExportPlugins.setDialogTitle("Export custom plugins to file");
			fileChooserExportPlugins.setCurrentDirectory(new File(fridaPath.getText().trim()));
	        int userSelectionExportPlugins = fileChooserExportPlugins.showSaveDialog(parentFrameExportPlugins);
	        
	        if (userSelectionExportPlugins == JFileChooser.APPROVE_OPTION) {
			
	        	File filenameExportPlugins = fileChooserExportPlugins.getSelectedFile();
	        	
	        	// Check if file already exists
	        	if(filenameExportPlugins.exists()) {	        		
	        		JFrame parentDialogResult = new JFrame();
	        		int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The file already exists. Would you like to overwrite it?","Warning",JOptionPane.YES_NO_OPTION);
	        		if(dialogResult != JOptionPane.YES_OPTION){
	        			return;
	        		}	        		
	        	}
	        	
				List<CustomPlugin> customPlugins = ((CustomPluginsTableModel)(customPluginsTable.getModel())).getCustomPlugins();
				String result = "";
				for(int i=0;i<customPlugins.size();i++) {
					result = result + customPlugins.get(i).exportPlugin() + "\n";
				}			
				
				FileWriter csvWriter;
				try {
					csvWriter = new FileWriter(filenameExportPlugins);
					csvWriter.append(result);
					csvWriter.flush();
					csvWriter.close();
				} catch (IOException e) {
					printException(e,"Export plugins: error while writing to the file");
				}
				
	        }
			
		} else if(command.startsWith("importPlugins")) {
			
			JFrame parentFrameImportPlugins = new JFrame();
			JFileChooser fileChooserImportPlugins = new JFileChooser();
			fileChooserImportPlugins.setDialogTitle("Import custom plugins from file");
			fileChooserImportPlugins.setCurrentDirectory(new File(fridaPath.getText().trim()));
	        int userSelectionImportPlugins = fileChooserImportPlugins.showOpenDialog(parentFrameImportPlugins);
	        
	        if (userSelectionImportPlugins == JFileChooser.APPROVE_OPTION) {
	        	
	        	File filenameImportPlugins = fileChooserImportPlugins.getSelectedFile();
	        	
        		String row;
        		BufferedReader csvReader;
        		
				try {
					
					csvReader = new BufferedReader(new FileReader(filenameImportPlugins));
					
					int currentRow = 0;
					
					List<CustomPlugin> customPlugins = ((CustomPluginsTableModel)(customPluginsTable.getModel())).getCustomPlugins();
					
					while ((row = csvReader.readLine()) != null) {
						
	        		    String[] data = row.split(";");
	        		    currentRow++;
	        		    
	        		    if(data.length > 0) {
	        		    		        		    	
	        		    	if(CustomPlugin.CustomPluginType.values()[Integer.parseInt(data[0])] == CustomPlugin.CustomPluginType.IMESSAGEEDITORTAB && data.length >= 20) {
	        		    		
	        		    		BridaMessageEditorPlugin importedPlugin = new BridaMessageEditorPlugin(BridaMessageEditorPlugin.BridaMessageEditorPluginOutputLocation.values()[Integer.parseInt(data[1])],
	        		    				new String(Base64.decodeBase64(data[2])),
	        		    				importTransformations(data[3]),
	        		    				importTransformations(data[4]),
	        		    				new String(Base64.decodeBase64(data[5])),
	        		    				importTransformations(data[6]),
	        							this,
	        							new String(Base64.decodeBase64(data[7])),
	        							new String(Base64.decodeBase64(data[8])),
	        							CustomPlugin.CustomPluginExecuteOnValues.values()[Integer.parseInt(data[9])],
	        							new String(Base64.decodeBase64(data[10])),
	        							CustomPlugin.CustomPluginExecuteValues.values()[Integer.parseInt(data[11])],
	        							new String(Base64.decodeBase64(data[12])),
	        							CustomPlugin.CustomPluginParameterValues.values()[Integer.parseInt(data[13])],
	        							new String(Base64.decodeBase64(data[14])),
	        							importTransformations(data[15]),
	        							CustomPlugin.CustomPluginFunctionOutputValues.values()[Integer.parseInt(data[16])],
	        							new String(Base64.decodeBase64(data[17])),
	        							importTransformations(data[18]),
										importTransformations(data[19]));
	        		    		
	        		    		synchronized(customPlugins) {
	        						int customPluginsOldSize = customPlugins.size();
	        						customPlugins.add(importedPlugin);
	        						((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsInserted(customPluginsOldSize, customPlugins.size() - 1);
	        					}	
	        		    		
	        		    		
	        		    	} else if(CustomPlugin.CustomPluginType.values()[Integer.parseInt(data[0])] == CustomPlugin.CustomPluginType.JBUTTON && data.length >= 14) {
	        		    		
	        		    		BridaButtonPlugin importedPlugin = new BridaButtonPlugin(Integer.parseInt(data[1]),
	        							(data[2].equals("true") ? true : false),
	        							this,
	        							new String(Base64.decodeBase64(data[3])),
		    							new String(Base64.decodeBase64(data[4])),
		    							CustomPlugin.CustomPluginExecuteOnValues.values()[Integer.parseInt(data[5])],
		    							new String(Base64.decodeBase64(data[6])),
		    							CustomPlugin.CustomPluginParameterValues.values()[Integer.parseInt(data[7])],
		    							new String(Base64.decodeBase64(data[8])),
		    							importTransformations(data[9]),
		    							CustomPlugin.CustomPluginFunctionOutputValues.values()[Integer.parseInt(data[10])],
		    							new String(Base64.decodeBase64(data[11])),
		    							importTransformations(data[12]),
		    							importTransformations(data[13]));
	        		    		
	        		    		synchronized(customPlugins) {
	        						int customPluginsOldSize = customPlugins.size();
	        						customPlugins.add(importedPlugin);
	        						((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsInserted(customPluginsOldSize, customPlugins.size() - 1);
	        					}	
	        		    		
	        		    	} else if(CustomPlugin.CustomPluginType.values()[Integer.parseInt(data[0])] == CustomPlugin.CustomPluginType.IHTTPLISTENER && data.length >= 16) {
	        		    		
	        		    		String[] importedPluginTools = data[1].split(",");
	        		    		ArrayList<Integer> importedPluginToolsList = new ArrayList<Integer>();
	        		    		for(int i=0;i<importedPluginTools.length;i++) {
	        		    			importedPluginToolsList.add(Integer.parseInt(importedPluginTools[i]));
	        		    		}
	        		    		
	        		    		BridaHttpListenerPlugin importedPlugin = new BridaHttpListenerPlugin(importedPluginToolsList,
	        		    				(data[2].equals("true") ? true : false),
	        							this,
	        							new String(Base64.decodeBase64(data[3])),
	        							new String(Base64.decodeBase64(data[4])),
	        							CustomPlugin.CustomPluginExecuteOnValues.values()[Integer.parseInt(data[5])],
	        							new String(Base64.decodeBase64(data[6])),
	        							CustomPlugin.CustomPluginExecuteValues.values()[Integer.parseInt(data[7])],
	        							new String(Base64.decodeBase64(data[8])),
	        							CustomPlugin.CustomPluginParameterValues.values()[Integer.parseInt(data[9])],
	        							new String(Base64.decodeBase64(data[10])),
	        							importTransformations(data[11]),
	        							CustomPlugin.CustomPluginFunctionOutputValues.values()[Integer.parseInt(data[12])],
	        							new String(Base64.decodeBase64(data[13])),
	        							importTransformations(data[14]),
	        							importTransformations(data[15]));
	        		    		
	        		    		synchronized(customPlugins) {
	        						int customPluginsOldSize = customPlugins.size();
	        						customPlugins.add(importedPlugin);
	        						((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsInserted(customPluginsOldSize, customPlugins.size() - 1);
	        					}	
	        		    		
	        		    	} else if(CustomPlugin.CustomPluginType.values()[Integer.parseInt(data[0])] == CustomPlugin.CustomPluginType.ICONTEXTMENU && data.length >= 12) {
	        		    		
	        		    		BridaContextMenuPlugin importedPlugin = new BridaContextMenuPlugin(this,
	        		    				new String(Base64.decodeBase64(data[1])),
		    							new String(Base64.decodeBase64(data[2])),
		    							CustomPlugin.CustomPluginExecuteOnValues.values()[Integer.parseInt(data[3])],
		    							new String(Base64.decodeBase64(data[4])),
		    							CustomPlugin.CustomPluginParameterValues.values()[Integer.parseInt(data[5])],
		    							new String(Base64.decodeBase64(data[6])),
		    							importTransformations(data[7]),
		    							CustomPlugin.CustomPluginFunctionOutputValues.values()[Integer.parseInt(data[8])],
		    							new String(Base64.decodeBase64(data[9])),
		    							importTransformations(data[10]),
		    							importTransformations(data[11]));
	        		    		
	        		    		synchronized(customPlugins) {
	        						int customPluginsOldSize = customPlugins.size();
	        						customPlugins.add(importedPlugin);
	        						((CustomPluginsTableModel)(customPluginsTable.getModel())).fireTableRowsInserted(customPluginsOldSize, customPlugins.size() - 1);
	        					}	
	        		    		
	        		    	} else {
	        		    		
	        		    		printException(null,"Skipping row " + currentRow + ": invalid type of custom plugin or number of arguments");
	        		    		
	        		    	}
	        		    	
	        		    }
	        		    	        		    
	        		}
	        		csvReader.close();
				} catch (FileNotFoundException e) {
					printException(e, "Import plugins: file not found");
				} catch (IOException e) {
					printException(e, "Import plugins: error reading the file");
				}
	        	
	        }
			
		}
				
	}
		
	public static List<Transformation> importTransformations(String encoding) {
		List<Transformation> output = new ArrayList<Transformation>();
		String toTokenize = encoding.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll(" ","");
		String[] tokens = toTokenize.split(",");
		for(String t : tokens) {
			for (Transformation tr : Transformation.values()) {
				if(t.equals(tr.toString())) {
					output.add(tr);
					continue;
				}
			}
		}		
		return output;		
	}
	
    protected enum Transformation {
        GZIP {
            public String toString() { return "GZIP"; }
            protected OutputStream getCompressor(OutputStream os) throws IOException {
                return new GZIPOutputStream(os);
            }
            protected InputStream getDecompressor(InputStream is) throws IOException {
                return new GZIPInputStream(is);
            }
        },
        ZLIB {
            public String toString() { return "ZLIB"; }
            protected OutputStream getCompressor(OutputStream os) throws IOException {
                return new DeflaterOutputStream(os);
            }
            protected InputStream getDecompressor(InputStream is) throws IOException {
                return new InflaterInputStream(is);
            }
        },
        BASE64 {
            public String toString() { return "Base64"; }
            public byte[] encode(byte[] input) throws IOException { return Base64.encodeBase64(input); }
            public byte[] decode(byte[] input) throws IOException { return Base64.decodeBase64(input); }
        },
        BASE64_URL_SAFE { 
            public String toString() { return "Base64 URLsafe"; }
            public byte[] encode(byte[] input) throws IOException { return Base64.encodeBase64URLSafe(input); }
            public byte[] decode(byte[] input) throws IOException { return Base64.decodeBase64(input); }
        },
        ASCII_HEX {
            public String toString() { return "ASCII-HEX"; }
            public byte[] encode(byte[] input) throws IOException { return hex.encode(input); }
            public byte[] decode(byte[] input) throws IOException,DecoderException { return hex.decode(input); }
			private Hex hex = new Hex("ASCII");
        },
        URL_ENCODING {
            public String toString() { return "URL"; }
            public byte[] encode(byte[] input) throws IOException {
                return URLEncoder.encode(new String(input, "ISO-8859-1"), "ISO-8859-1").getBytes();
            }
            public byte[] decode(byte[] input) throws IOException {
                return URLDecoder.decode(new String(input, "ISO-8859-1"), "ISO-8859-1").getBytes();
            }
        };

        protected OutputStream getCompressor(OutputStream os) throws IOException { return null; }
        protected InputStream getDecompressor(InputStream is) throws IOException { return null; }
        public byte[] encode(byte[] input) throws IOException {
            ByteArrayOutputStream outbytes = new ByteArrayOutputStream(input.length);
            OutputStream comp = getCompressor(outbytes);
            comp.write(input);
            comp.close();
            return outbytes.toByteArray();
        }
        public byte[] decode(byte[] input) throws IOException,DecoderException {
            ByteArrayOutputStream outbytes = new ByteArrayOutputStream();
            ByteArrayInputStream inbytes =  new ByteArrayInputStream(input);
            InputStream comp = getDecompressor(inbytes);
            int len;
            byte[] buffer = new byte[1024];
            while ((len = comp.read(buffer)) > 0) {
            	outbytes.write(buffer, 0, len);
            }            
            comp.close();
            inbytes.close();
            return outbytes.toByteArray();
        }
    }
	
	public static void popupEncoderWindow(String title, JTextField currentJTextField, List<Transformation> currentListTransformation) {
		
		JFrame frame = new JFrame(title);
		
		DefaultListModel<Transformation> addedTransformationsListModel = new DefaultListModel<Transformation>();  
        JList addedTransformationsList = new JList(addedTransformationsListModel);    
        JScrollPane addedTransformationsListScrollPane = new JScrollPane(addedTransformationsList);
        addedTransformationsListScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        addedTransformationsListScrollPane.setBorder(new LineBorder(Color.BLACK));
        addedTransformationsListScrollPane.setMaximumSize( addedTransformationsListScrollPane.getPreferredSize() );

		//2. Optional: What happens when the frame closes?
		frame.addWindowListener((WindowListener)new WindowAdapter() {
		    @Override
		    public void windowClosing(WindowEvent e) {
		    	
		    	currentListTransformation.clear();
				
				for(int i=0; i<addedTransformationsListModel.getSize();i++) {					
					currentListTransformation.add(addedTransformationsListModel.getElementAt(i));
				}
				
				currentJTextField.setText(currentListTransformation.toString());
				
		    	frame.setVisible(false);
		    	frame.dispose(); 
		    }
		});
		
		DefaultListModel<Transformation> transformationsListModel = new DefaultListModel<Transformation>();                
        JPanel tranformationListPanel = new JPanel();
        tranformationListPanel.setLayout(new BoxLayout(tranformationListPanel, BoxLayout.X_AXIS)); 

        JList transformationsList = new JList(transformationsListModel);    
        JScrollPane transformationsListScrollPane = new JScrollPane(transformationsList);
        transformationsListScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        transformationsListScrollPane.setBorder(new LineBorder(Color.BLACK));
        transformationsListScrollPane.setMaximumSize( transformationsListScrollPane.getPreferredSize() );        
        for (Transformation t : Transformation.values()) {
        	transformationsListModel.addElement(t);
        }   
        
        JPanel tranformationButtonPanel = new JPanel();
        tranformationButtonPanel.setLayout(new BoxLayout(tranformationButtonPanel, BoxLayout.Y_AXIS));
        JButton addTransformationButton = new JButton("Add -->");
        addTransformationButton.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent actionEvent) {
        		SwingUtilities.invokeLater(new Runnable() {    				
    	            @Override
    	            public void run() {    	            		            	
    	            	int index = transformationsList.getSelectedIndex();
    	            	addedTransformationsListModel.addElement(transformationsListModel.elementAt(index));    					
    	            }
    			});
        	}
        });
        JButton removeTransformationButton = new JButton("<-- Remove");
        removeTransformationButton.addActionListener(new ActionListener() {
        	public void actionPerformed(ActionEvent actionEvent) {
        		SwingUtilities.invokeLater(new Runnable() {    				
    	            @Override
    	            public void run() {    	            		            	
    	            	int index = addedTransformationsList.getSelectedIndex();
    	            	if(index != -1) {
    	            		addedTransformationsListModel.remove(index);
    	            	}    	            						
    	            }
    			});
        	}
        });
        tranformationButtonPanel.add(addTransformationButton);
        tranformationButtonPanel.add(removeTransformationButton);
        
        tranformationListPanel.add(transformationsListScrollPane);
        tranformationListPanel.add(tranformationButtonPanel);
        tranformationListPanel.add(addedTransformationsListScrollPane);
		
        frame.getContentPane().add(tranformationListPanel, BorderLayout.CENTER);
        
        // Add old transformations
        for (Transformation t : currentListTransformation) {
        	addedTransformationsListModel.addElement(t);
        }  
        
  		frame.pack();
  		frame.setVisible(true);
  		
	}
	
	public static String byteArrayToHexString(byte[] raw) {
        StringBuilder sb = new StringBuilder(2 + raw.length * 2);
        for (int i = 0; i < raw.length; i++) {
            sb.append(String.format("%02X", Integer.valueOf(raw[i] & 0xFF)));
        }
        return sb.toString();
    }
	
	public static byte[] hexStringToByteArray(String hex) {
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
					//currentImports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getmoduleimports",new String[] {nodeContent}));
					currentImports = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getmoduleimports",new String[] {nodeContent}}));
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
					//currentExports = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getmoduleexports",new String[] {nodeContent}));
					currentExports = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getmoduleexports",new String[] {nodeContent}}));
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
				
			} else if (nodeContentParent.equals("Objective-C") || nodeContentParent.equals("Java")) {
								
				HashMap<String, Integer> currentClassMethods = null;
				ArrayList<String> methodNames = null;

				try {
					//currentClassMethods = (HashMap<String,Integer>)(pyroBridaService.call("callexportfunction","getclassmethods",new String[] {nodeContent}));
					currentClassMethods = (HashMap<String,Integer>)(executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"getclassmethods",new String[] {nodeContent}}));
				} catch (Exception e) {
					printException(e,"Exception retrieving class methods");
					return;
				}
				
				if(currentClassMethods != null) {
					
					methodNames = new ArrayList<String>(currentClassMethods.keySet());
					
					if(platform == BurpExtender.PLATFORM_ANDROID) {
					
						// Sort Android method names
						Collections.sort(methodNames, new Comparator<String>() {
					        @Override
					        public int compare(String method1, String method2) {
	
					        	String[] splitMethod1 = method1.split("\\(")[0].split(" ");
					        	String[] splitMethod2 = method2.split("\\(")[0].split(" ");
					        	
					            return  splitMethod1[splitMethod1.length-1].compareToIgnoreCase(splitMethod2[splitMethod1.length-1]);
					            
					        }
					    });
						
					} else {
						
						// Sort iOS method names
						Collections.sort(methodNames, new Comparator<String>() {
					        @Override
					        public int compare(String class1, String class2)
					        {

					            return  class1.compareToIgnoreCase(class2);
					        }
					    });
						
					}
				
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
	
	public void demangleSwift() {
		
		if(platform != BurpExtender.PLATFORM_IOS) {
			
			printException(null,"Swift demangle is available only on iOS OS");
			return;
			
		}
		
		DefaultMutableTreeNode clickedNode = (DefaultMutableTreeNode)(tree.getSelectionPath().getLastPathComponent());
		
		String toDemangle = (String)clickedNode.getUserObject();
		
		if(toDemangle.startsWith("function: ") || toDemangle.startsWith("variable: ")) {
			
			toDemangle = toDemangle.replace("function: ", "");
			toDemangle = toDemangle.replace("variable: ", "");
			
			if(toDemangle.startsWith("__T"))
				toDemangle = toDemangle.substring(1);
				
			try {
					
				String ret = (String)executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"demangle",new String[] {toDemangle}});
				
				JOptionPane.showMessageDialog(null, ret, toDemangle, JOptionPane.INFORMATION_MESSAGE);
				
			} catch (Exception e) {
				
				printException(e,"Exception with demangle");
				
			}
			
		} else {
			
			printException(null,"Only Swift names can be demangled");
			
		}
		
		
	}

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
			
				// Clicked Java class
				case "Java":
					type = "java_class";
					pattern = (String)clickedNode.getUserObject();
					break;
					
				// Clicked a iOS class	
				case "Objective-C":
					type = "objc_class";
					pattern = (String)clickedNode.getUserObject();
					break;
					
				// Clicked an export (the same for iOS and Android)
				case "Exports":
					
					// Only functions can be trapped
					if(((String)clickedNode.getUserObject()).startsWith("function")) {
						
						type = "export";						
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
						
						// Clicked a Java method 
						} else if(grandparentNodeContent.equals("Java")) {
							
							type = "java_method";						
							
							pattern = (String)clickedNode.getUserObject();
														
						}
						
					}				
					
					break;
			
			}
			
		}
		
		if(type != null) {
				
			try {
				
				executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"trace",new String[] {pattern,type,(withBacktrace ? "true" : "false")}});

				int defaultHookPlatform = BurpExtender.PLATFORM_GENERIC;
				if(type.startsWith("java")) {
					defaultHookPlatform = BurpExtender.PLATFORM_ANDROID;
				} else if(type.startsWith("java")) {
					defaultHookPlatform = BurpExtender.PLATFORM_IOS;
				}
				DefaultHook treeHook = new DefaultHook("Tree hook trace " +  type + ": " + pattern,defaultHookPlatform,"trace",true,new ArrayList<byte[]>(Arrays.asList(new byte[][] {pattern.getBytes(),type.getBytes(),(withBacktrace ? "true".getBytes() : "false".getBytes())})),null,false);				
				treeHook.setEnabled(true);
				treeHooks.add(treeHook);
				
				List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
	
				HashMap<String,Integer> currentClassMethods = null;

				synchronized(trapEntries) {
	            	int trapEntryOldSize = trapEntries.size();
	            	if(type.equals("objc_class")  || type.equals("java_class")) {
	            		trapEntries.add(new TrapTableItem("Inspect",(platform == BurpExtender.PLATFORM_ANDROID ? "Java class" : "OBJ-C class"),pattern, withBacktrace,"-","-",treeHook));
	            	} else if(type.equals("objc_method") || type.equals("java_method")) {
	            		trapEntries.add(new TrapTableItem("Inspect",(platform == BurpExtender.PLATFORM_ANDROID ? "Java method" : "OBJ-C method"),pattern, withBacktrace,"-","-",treeHook));
	            	} else {
	            		trapEntries.add(new TrapTableItem("Inspect","Export",pattern, withBacktrace,"-","-",treeHook));
	            	}
	            	((TrapTableModel)(trapTable.getModel())).fireTableRowsInserted(trapEntryOldSize, trapEntries.size() - 1);
	            } 
							
			} catch (Exception e) {
				
				printException(e,"Exception with trap");
				
			}
			
		}
		
	}
	
	public void changeReturnValue(String returnValueType, String dialogResult) {

		DefaultMutableTreeNode clickedNode = (DefaultMutableTreeNode)(tree.getSelectionPath().getLastPathComponent());
		
		DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)clickedNode.getParent();
		
		String type = null;	
		String pattern = null;
		
		// ROOT
		if(parentNode != null) {
		
			String parentNodeContent = (String)parentNode.getUserObject();			
			
			DefaultMutableTreeNode grandparentNode = null;
	
			switch(parentNodeContent) {
					
				// Clicked a export
				case "Exports":
					
					// Only functions can be trapped
					if(((String)clickedNode.getUserObject()).startsWith("function")) {
						
						type = "export";						
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
						
						// Clicked a Java method
						} else if(grandparentNodeContent.equals("Java")) {
							
							type = "java_method";
							pattern = (String)clickedNode.getUserObject();
							
						}						
						
					}				
					
					break;
			
			}
			
		}
		
		if(type != null) {
				
			try {
				
				executePyroCall(pyroBridaService, "callexportfunction",new Object[] {"changereturnvalue",new String[] {pattern,type,returnValueType,dialogResult}});
								
				int defaultHookPlatform = BurpExtender.PLATFORM_GENERIC;
				if(type.startsWith("java")) {
					defaultHookPlatform = BurpExtender.PLATFORM_ANDROID;
				} else if(type.startsWith("java")) {
					defaultHookPlatform = BurpExtender.PLATFORM_IOS;
				}
				DefaultHook treeHook = new DefaultHook("Tree hook changereturnvalue " +  type + ": " + pattern,defaultHookPlatform,"changereturnvalue",true,new ArrayList<byte[]>(Arrays.asList(new byte[][] {pattern.getBytes(),type.getBytes(),returnValueType.getBytes(),dialogResult.getBytes()})) ,null,false);
				treeHook.setEnabled(true);
				treeHooks.add(treeHook);
								
				List<TrapTableItem> trapEntries = ((TrapTableModel)(trapTable.getModel())).getTrappedMethods();
					
	            synchronized(trapEntries) {
	            	int trapEntryOldSize = trapEntries.size();
	            	if(type.equals("objc_method")) {
	            		trapEntries.add(new TrapTableItem("Edit return","OBJ-C method",pattern, false,returnValueType,dialogResult,treeHook));
	            	} else if(type.equals("java_method")) {
	            		trapEntries.add(new TrapTableItem("Edit return","Java method",pattern, false,returnValueType,dialogResult,treeHook));
	            	} else {
	            		trapEntries.add(new TrapTableItem("Edit return","Export",pattern, false,returnValueType,dialogResult,treeHook));
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
	
	public int getPlatform() {
		return platform;
	}

	@Override
	public void extensionUnloaded() {

		if(serverStarted) {
		
			stdoutThread.stop();
			stderrThread.stop();
			
			try {
				//pyroBridaService.call("shutdown");
				executePyroCall(pyroBridaService, "shutdown", new Object[] {});
				pyroServerProcess.destroy();
				pyroBridaService.close();
				
				printSuccessMessage("Pyro server shutted down");
				
			} catch (final Exception e) {
				
				printException(e,"Exception shutting down Pyro server");
				
			}
			
		}
		
	}
	
	public boolean removeButtonFromHooksAndFunctions(JPanel buttonPanelToRemove, DefaultHook dh) {
		
		// Disable the hook, if enabled and if possible
		if(dh.isEnabled() && dh.isInterceptorHook() && applicationSpawned) {
			printException(null,"Could not unload a single hook while application is running. Detach hook first by stopping application or by detatching all the hooks and then remove the button");
			return false;
		} else if(dh.isEnabled() && dh.isInterceptorHook()) {
			printSuccessMessage("Hook " + dh.getName() + " is enabled. It will be disabled.");
			dh.setEnabled(false);
		}
		
		// Removing the button
		if(dh.getOs() == BurpExtender.PLATFORM_ANDROID) {
			SwingUtilities.invokeLater(new Runnable() {
	            @Override
	            public void run() {
	            	androidHooksPanel.remove(buttonPanelToRemove);
	            	androidHooksPanel.revalidate();
	            	androidHooksPanel.repaint();
	            }
			});
		} else if(dh.getOs() == BurpExtender.PLATFORM_IOS) {
			SwingUtilities.invokeLater(new Runnable() {
	            @Override
	            public void run() {
	            	iOSHooksPanel.remove(buttonPanelToRemove);
	            	iOSHooksPanel.revalidate();
	            	iOSHooksPanel.repaint();
	            }
			});
		} else {
			SwingUtilities.invokeLater(new Runnable() {
	            @Override
	            public void run() {
	            	genericHooksPanel.remove(buttonPanelToRemove);
	            	genericHooksPanel.revalidate();
	            	genericHooksPanel.repaint();
	            }
			});
		}
		
		defaultHooks.remove(dh);
		return true;
		
	}	
	
	public JPanel addButtonToHooksAndFunctions(DefaultHook dh) {
    	
        JLabel tempHookLabel = new JLabel(dh.getName());                    
        
        JPanel lineJPanel = new JPanel();
        lineJPanel.setLayout(new BoxLayout(lineJPanel, BoxLayout.X_AXIS));
        lineJPanel.setAlignmentX(Component.LEFT_ALIGNMENT);     
        
        if(dh.isInterceptorHook()) {
        
            final JToggleButton tempHookToggleButton = new JToggleButton("Enable",false);
            tempHookToggleButton.addActionListener(new ActionListener() {
            	public void actionPerformed(ActionEvent actionEvent) {
            		
            		// Enabling hook
            		if(tempHookToggleButton.isSelected()) {
            			
            			if(applicationSpawned) {
            				            				
            				// Call hook
            				try {
            					//pyroBridaService.call("callexportfunction",dh.getFridaExportName(),new String[0]);
            					executePyroCall(pyroBridaService, "callexportfunction",new Object[] {dh.getFridaExportName(),new String[0]});
                				printSuccessMessage("Hook " + dh.getName() + " ENABLED");
                				dh.setEnabled(true);
							} catch (Exception e) {
								printException(e,"Error while enabling hook " + dh.getName());
							} 
            				
            			} else {
            				
            				printSuccessMessage("Hook " + dh.getName() + " ENABLED");
            				dh.setEnabled(true);
            				
            			}
            		
            		// Disabling hook	
            		} else {
            			
            			if(applicationSpawned) {
            			
            				printException(null,"It is not possible to detach a single hook while app is running (you can detach ALL the hooks with the \"Detach all\" button)");
                			tempHookToggleButton.setSelected(true);
                			
            			} else {
            				
                			printSuccessMessage("Hook " + dh.getName() + " DISABLED");
                			dh.setEnabled(false);
            				
            			}
                			
            		}
            	}
            });
            
            lineJPanel.add(tempHookToggleButton);
            
        } else {
        	
        	JButton tempHookButton = new JButton("Execute");
        	tempHookButton.addActionListener(new ActionListener() {
            	public void actionPerformed(ActionEvent actionEvent) {

            		if(applicationSpawned) {
	            		// Parameters
	    				List<byte[]> currentParameters = new ArrayList<byte[]>();
	    				if(dh.isPopupParameters()) {
	    					String parametersPopup = JOptionPane.showInputDialog("Enter parameter(s), delimited by \"#,#\"");
	    					String[] parametersPopupSplitString = parametersPopup.split("#,#");
	    					for(int i=0;i<parametersPopupSplitString.length;i++) {
        						currentParameters.add(CustomPlugin.encodeCustomPluginValue(parametersPopupSplitString[i].getBytes(),dh.getParametersEncoding(), BurpExtender.this));
        					}
	    				} else {
        					// For cases different from POPUP parameters are already encoded	    					
	    					currentParameters = dh.getParameters();
	    				}
	    				// Call exported function
	    				try {
	    					printJSMessage("*** Output " + dh.getName() + ":");
	    					//String ret = (String)pyroBridaService.call("callexportfunction",dh.getFridaExportName(),currentParameters);
	    					String ret = (String)executePyroCall(pyroBridaService, "callexportfunction",new Object[] {dh.getFridaExportName(),CustomPlugin.convertParametersForFrida(currentParameters,BurpExtender.this)});
	    					printJSMessage("* Ret value: " + ret);
						} catch (Exception e) {
							printException(e,"Error while running function " + dh.getName());
						} 	  
            		} else {
            			
            			printException(null,"Error, start Pyro server and spawn application first.");
            			
            		}
            	}
            	
        	});
        	
            lineJPanel.add(tempHookButton);
        	
        }
        
        lineJPanel.add(tempHookLabel);                    
        
        if(dh.getOs() == BurpExtender.PLATFORM_ANDROID) {
        	androidHooksPanel.add(lineJPanel);
        } else if(dh.getOs() == BurpExtender.PLATFORM_IOS) {
        	iOSHooksPanel.add(lineJPanel);
        } else {
        	genericHooksPanel.add(lineJPanel);
        }
        
        defaultHooks.add(dh);
        
        return lineJPanel;
        
	}
	
}

		 