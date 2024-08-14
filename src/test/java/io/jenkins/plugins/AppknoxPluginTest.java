package io.jenkins.plugins;

import hudson.FilePath;
import hudson.model.TaskListener;
import hudson.model.Run;
import hudson.Launcher;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;  // <-- Ensure this import is present
import java.util.HashMap;
import java.util.Map;

public class AppknoxPluginTest {

    public static void main(String[] args) {
        // Set up mock environment variables
        Map<String, String> env = new HashMap<>(System.getenv());
        env.put("WORKSPACE", "C:\\Users\\hirakdesai\\.jenkins\\workspace\\MFVA_Build"); // Adjust this path to your workspace

        // Mock parameters for the plugin
        String credentialsId = "your-credentials-id";
        String filePath = "app/mfva_1.0.apk"; // Relative path for testing
        String riskThreshold = "LOW"; // Example risk threshold

        // Create a TaskListener (could use a simple implementation or mock)
        TaskListener listener = new TaskListener() {
            @Override
            public PrintStream getLogger() {
                return System.out;
            }
        };

        // Create a dummy Run and Launcher object (these can be mocks or stubs)
        Run<?, ?> run = null; // You can use Mockito or any other mocking library to create a mock Run object
        Launcher launcher = null; // Similarly, mock this if needed

        // Create an instance of the plugin
        AppknoxPlugin plugin = new AppknoxPlugin(credentialsId, filePath, riskThreshold);

        // Execute the method directly
        try {
            plugin.perform(run, new FilePath(new File(env.get("WORKSPACE"))), launcher, listener);
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }
}
