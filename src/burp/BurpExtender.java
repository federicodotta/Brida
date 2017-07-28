package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

import org.apache.commons.lang3.ArrayUtils;


import net.razorvine.pyro.*;

public class BurpExtender implements IBurpExtender, ITab, ActionListener, IContextMenuFactory {

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
	
	private JTextField executeMethodName;
	private JTextField executeMethodArgument;
	private DefaultListModel executeMethodInsertedArgumentList;
	private JList executeMethodInsertedArgument;
	private JTextArea executeMethodOutput; 
	private JTextArea stubGeneratorOutput;
	
	private boolean serverStarted;
	private boolean applicationSpawned;
	
	private IContextMenuInvocation currentInvocation;
		
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
			
		
        // Keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Brida Java");
        
        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        stdout.println("Welcome to Brida, the new bridge between Burp Suite and Frida!");
        stdout.println("Created by Piergiovanni Cipolloni and Federico Dotta");
        stdout.println("Contributors: Maurizio Agazzini");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/Brida");
        stdout.println("");
                
        serverStarted = false;
    	applicationSpawned = false;
    			
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
			stderr.println("Error copying Pyro Server file");
	    	stderr.println(e.toString());
		}
		       
        SwingUtilities.invokeLater(new Runnable()  {
        	
            @Override
            public void run()  {   	
            	
            	mainPanel = new JPanel();
            	mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
            	
            	JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            	
            	// LEFT
            	JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            	    	
                JPanel leftUpperPane = new JPanel();
                leftUpperPane.setLayout(new BoxLayout(leftUpperPane, BoxLayout.Y_AXIS));
                                
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
					stderr.println(e.toString());
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
					stderr.println(e.toString());
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
            	                
                leftUpperPane.add(serverStatusPanel);
                leftUpperPane.add(applicationStatusPanel);
                leftUpperPane.add(pythonPathPanel);
                leftUpperPane.add(pyroHostPanel);
                leftUpperPane.add(pyroPortPanel);
                leftUpperPane.add(fridaPathPanel);
                leftUpperPane.add(applicationIdPanel);  
                leftUpperPane.add(localRemotePanel);
                
                // Left Bottom
                JTabbedPane leftBottomPane = new JTabbedPane(); 
                
                // Stub generator
                JPanel stubGeneratorPanel = new JPanel();
                stubGeneratorPanel.setLayout(new BoxLayout(stubGeneratorPanel, BoxLayout.Y_AXIS));
                stubGeneratorOutput = new JTextArea();
                JScrollPane scrollStubGeneratorOutput = new JScrollPane(stubGeneratorOutput);
                scrollStubGeneratorOutput.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                stubGeneratorOutput.setLineWrap(true);
                stubGeneratorOutput.setEditable(false);
                stubGeneratorPanel.add(stubGeneratorOutput);
                
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
                
                JPanel executeMethodOutputPanel = new JPanel();
                executeMethodOutputPanel.setLayout(new BoxLayout(executeMethodOutputPanel, BoxLayout.X_AXIS));
                executeMethodOutputPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
                JLabel labelExecuteMethodOutput = new JLabel("Output: ");
                executeMethodOutput = new JTextArea();
                JScrollPane scrollExecuteMethodOutput = new JScrollPane(executeMethodOutput);
                scrollExecuteMethodOutput.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                executeMethodOutput.setLineWrap(true);
                executeMethodOutput.setEditable(false);
                scrollExecuteMethodOutput.setMaximumSize( scrollExecuteMethodOutput.getPreferredSize() );
                executeMethodOutputPanel.add(labelExecuteMethodOutput);
                executeMethodOutputPanel.add(executeMethodOutput);
                
                executeMethodPanel.add(executeMethodNamePanel);
                executeMethodPanel.add(executeMethodArgumentPanel);
                executeMethodPanel.add(executeMethodInsertedArgumentPanel);
                executeMethodPanel.add(executeMethodOutputPanel);
                
                leftBottomPane.add("Stub generator", stubGeneratorPanel);
                leftBottomPane.add("Execute method", executeMethodPanel);
          
                leftSplitPane.setTopComponent(leftUpperPane);
                leftSplitPane.setBottomComponent(leftBottomPane);                

                leftSplitPane.setResizeWeight(.7d);
           
                // RIGHT
                JPanel rightSplitPane = new JPanel();
                rightSplitPane.setLayout(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                
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
                                
                JButton executeMethodButton = new JButton("Execute Method");
                executeMethodButton.setActionCommand("executeMethod");
                executeMethodButton.addActionListener(BurpExtender.this); 
                
                JButton generateJavaStubButton = new JButton("Java Stub");
                generateJavaStubButton.setActionCommand("generateJavaStub");
                generateJavaStubButton.addActionListener(BurpExtender.this);    
                
                JButton generatePythonStubButton = new JButton("Python Stub");
                generatePythonStubButton.setActionCommand("generatePythonStub");
                generatePythonStubButton.addActionListener(BurpExtender.this);
                                
                JButton saveSettingsToFileButton = new JButton("Save settings to file");
                saveSettingsToFileButton.setActionCommand("saveSettingsToFile");
                saveSettingsToFileButton.addActionListener(BurpExtender.this);
                
                JButton loadSettingsFromFileButton = new JButton("Load settings from file");
                loadSettingsFromFileButton.setActionCommand("loadSettingsFromFile");
                loadSettingsFromFileButton.addActionListener(BurpExtender.this);
                
                rightSplitPane.add(startServer,gbc);
                rightSplitPane.add(killServer,gbc);
                rightSplitPane.add(spawnApplication,gbc);
                rightSplitPane.add(killApplication,gbc);
                rightSplitPane.add(reloadScript,gbc);
                rightSplitPane.add(generateJavaStubButton,gbc);
                rightSplitPane.add(generatePythonStubButton,gbc);
                rightSplitPane.add(saveSettingsToFileButton,gbc);
                rightSplitPane.add(loadSettingsFromFileButton,gbc);
                rightSplitPane.add(executeMethodButton,gbc);
                
                splitPane.setLeftComponent(leftSplitPane);
                splitPane.setRightComponent(rightSplitPane);
                
                splitPane.setResizeWeight(.9d);

                mainPanel.add(splitPane);
                
                callbacks.customizeUiComponent(mainPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
                
            }
            
        });
		
	}
	
	private boolean launchPyroServer(String pythonPath, String pyroServicePath) {
		
		Runtime rt = Runtime.getRuntime();
		
		String[] startServerCommand = {pythonPath,"-i",pyroServicePath,pyroHost.getText().trim(),pyroPort.getText().trim()};
			
		try {
			pyroServerProcess = rt.exec(startServerCommand);
			InputStream stdInput = pyroServerProcess.getInputStream();
			
			BufferedReader stdOutput = new BufferedReader(new InputStreamReader(pyroServerProcess.getInputStream()));
			
			ExecutorService executor = Executors.newFixedThreadPool(1);

			Callable<String> readTask = new Callable<String>() {
		        @Override
		        public String call() throws Exception {
		        	return stdOutput.readLine();
		        }
		    };
		    
		    Future<String> future = executor.submit(readTask);
		    String result = future.get(5000, TimeUnit.MILLISECONDS);
		    
			stdout.println(result);
			if(result.trim().equals("Ready.")) {
				return true;
			} else {
				return false;
			}
			
		} catch (Exception e1) {
			e1.printStackTrace();
			return false;
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
			} catch (IOException e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
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
								stderr.println("Invalid option " + lineParts[0]);
							}							
						}
						
					} else {
						
						stderr.println("The line does not contain a valid option");
						
					}
					
				}
							 				
				br.close();
				
			} catch (Exception e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
				return;
			}
			
			
		}
	}

	@Override
	public String getTabCaption() {

		return "Brida";
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}

	@Override
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
		            	try {
		                	documentApplicationStatus.insertString(0, "spawned", greenStyle);
						} catch (BadLocationException e) {
							stderr.println(e.toString());
						}
						
		            }
				});
				
			} catch (Exception e) {
				stderr.println("Exception with spawn application");
				stderr.println(e.toString());
			}
		
			
		} else if(command.equals("reloadScript") && serverStarted && applicationSpawned) {
				
			try {
				pyroBridaService.call("reload_script");
			} catch (Exception e) {
				stderr.println("Exception with reload script");
				stderr.println(e.toString());
			}
	
						
		} else if(command.equals("killApplication") && serverStarted && applicationSpawned) {
			
			try {
				pyroBridaService.call("disconnect_application");
				applicationSpawned = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	applicationStatus.setText("");
		            	try {
		                	documentApplicationStatus.insertString(0, "NOT spawned", redStyle);
						} catch (BadLocationException e) {
							stderr.println(e.toString());
						}
						
		            }
				});
				
			} catch (Exception e) {
				stderr.println("Exception with disconnect application");
				stderr.println(e.toString());
			}
			
		} else if(command.equals("killServer") && serverStarted) {
			
			try {
				pyroBridaService.call("shutdown");
				pyroServerProcess.destroy();
				pyroBridaService.close();
				serverStarted = false;
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	
		            	serverStatus.setText("");
		            	try {
		                	documentServerStatus.insertString(0, "NOT running", redStyle);
						} catch (BadLocationException e) {
							stderr.println(e.toString());
						}
						
		            }
				});
				
			} catch (Exception e) {
				stderr.println("Exception shutting down pyro server");
				stderr.println(e.toString());
			}
		
			
		} else if(command.equals("startServer") && !serverStarted) {
			
			savePersistentSettings();
			
			try {
				
				boolean startPyroServerResult = launchPyroServer(pythonPath.getText().trim(),pythonScript);
		        if(startPyroServerResult) {		        	
		        	stdout.println("Server started");
		        	pyroBridaService = new PyroProxy(new PyroURI("PYRO:BridaServicePyro@" + pyroHost.getText().trim() + ":" + pyroPort.getText().trim()));
		        	serverStarted = true;	 
		        	
		        	SwingUtilities.invokeLater(new Runnable() {
						
			            @Override
			            public void run() {
			            	
			            	serverStatus.setText("");
			            	try {
			                	documentServerStatus.insertString(0, "running", greenStyle);
							} catch (BadLocationException e) {
								stderr.println(e.toString());
							}
							
			            }
					});
		        	
		        } else {		        	
		        	stderr.println("ERROR STARTING PYRO SERVER");
		        	return;		        	
		        }
			} catch (Exception e) {
				stderr.println("Exception starting pyro server");
				stderr.println(e.toString());
			}
			
		} else if(command.equals("executeMethod")) {
			
			savePersistentSettings();
			
			try {
				
				String[] arguments = new String[executeMethodInsertedArgumentList.size()];
				for(int i=0;i<executeMethodInsertedArgumentList.size();i++) {	
					arguments[i] = (String)(executeMethodInsertedArgumentList.getElementAt(i));
				}
				
				String s = (String)(pyroBridaService.call("callexportfunction",executeMethodName.getText().trim(),arguments));
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	executeMethodOutput.setText(s);
		            }
				});
				
			} catch (Exception e) {
				stderr.println("Exception with execute method");
				stderr.println(e.toString());
			}
			
		} else if(command.equals("generateJavaStub")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	stubGeneratorOutput.setText(generateJavaStub());

	            }
			});
			
			
		} else if(command.equals("generatePythonStub")) {
			
			SwingUtilities.invokeLater(new Runnable() {
				
	            @Override
	            public void run() {
	            	
	            	stubGeneratorOutput.setText(generatePythonStub());

	            }
			});
			
			
		} else if(command.equals("saveSettingsToFile")) {
			
			exportConfigurationsToFile();
			
		} else if(command.equals("loadSettingsFromFile")) {
			
			loadConfigurationsFromFile();			
			
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
				stderr.println("Exception with custom context application");
				stderr.println(e.toString());
			}
				

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
				
				String s = (String)(pyroBridaService.call("callexportfunction",command,new String[]{byteArrayToHexString(selectedPortion)}));
				
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
				stderr.println("Exception with custom context application");
				stderr.println(e.toString());
			}
		

		} else if(command.equals("pythonPathSelectFile")) {
			
			JFrame parentFrame = new JFrame();
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Python Path");
			
			int userSelection = fileChooser.showOpenDialog(parentFrame);
			
			if(userSelection == JFileChooser.APPROVE_OPTION) {
				
				File pythonPathFile = fileChooser.getSelectedFile();
				
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
				
				File fridaPathFile = fileChooser.getSelectedFile();
				
				SwingUtilities.invokeLater(new Runnable() {
					
		            @Override
		            public void run() {
		            	fridaPath.setText(fridaPathFile.getAbsolutePath());
		            }
				
				});
				
			}				
			
		}

	}

	@Override
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

}
