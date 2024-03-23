package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

public class BridaThread implements Runnable {

    private Thread worker;
    BufferedReader bufferedReader;
    private AtomicBoolean running;
    BurpExtender extender;
    boolean isStdout;

    public BridaThread(BufferedReader bufferedReader, BurpExtender extender, boolean isStdout) {
        this.bufferedReader = bufferedReader;
        this.running = new AtomicBoolean(false);
        this.extender = extender;
        this.isStdout = isStdout;
    }

    public void start() {
        worker = new Thread(this);
        worker.start();
    }

    public void stop() {
        running.set(false);
    }

    public void run() {

        running.set(true);

        while(running.get()) {

            final String line;
            try {
                line = bufferedReader.readLine();

                // Only used to handle Pyro first message (when server start)
                if(line.equals("Ready.")) {

                    extender.setServerRunning();
                    extender.printSuccessMessage("Pyro server started correctly");

                    // Standard line
                } else {

                    if(isStdout)
                        extender.printJSMessage(line);
                    else
                        extender.printException(null,line);

                }
            } catch (IOException e) {
                if(isStdout)
                    extender.printException(e,"Error reading Pyro stdout");
                else
                    extender.printException(e,"Error reading Pyro stderr");
                running.set(false);
            }

        }


    }

}
