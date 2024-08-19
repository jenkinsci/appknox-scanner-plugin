package io.jenkins.plugins;

import hudson.FilePath;
import hudson.model.TaskListener;
import hudson.model.Run;
import hudson.Launcher;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

public class AppknoxPluginTest {

    public static void main(String[] args) {
        // Set up mock environment variables
        Map<String, String> env = new HashMap<>(System.getenv());
        env.put("WORKSPACE", "C:\\Users\\hirakdesai\\.jenkins\\workspace\\MFVA_Build"); // Adjust this path to your workspace

        // Mock parameters for the plugin
        String credentialsId = "your-credentials-id";
        String apkFileName = "mfva_1.0.apk"; // The name of the APK file
        String riskThreshold = "LOW"; // Example risk threshold

        // Dynamically locate the APK file for debug and release builds
        String apkFilePath = findApkFilePath(env.get("WORKSPACE"), apkFileName);
        if (apkFilePath == null) {
            System.err.println("APK file not found in the expected directories.");
            return;
        }

        System.out.println("Testing with the following details:");
        System.out.println("Workspace: " + env.get("WORKSPACE"));
        System.out.println("APK File Path: " + apkFilePath);
        System.out.println("Risk Threshold: " + riskThreshold);

        // Create a TaskListener using a simple implementation or mock
        TaskListener listener = new TaskListener() {
            @Override
            public PrintStream getLogger() {
                return System.out;
            }
        };

        // Use Mockito to create mock instances of Run and Launcher if needed, or use null
        Run<?, ?> run = null;
        Launcher launcher = null;

        // Create an instance of the plugin
        AppknoxPlugin plugin = new AppknoxPlugin(credentialsId, apkFilePath, riskThreshold);

        // Execute the method directly
        try {
            plugin.perform(run, new FilePath(new File(env.get("WORKSPACE"))), launcher, listener);
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * This method searches for the APK file in the debug and release directories.
     * @param workspace The root directory of the project.
     * @param apkFileName The name of the APK file.
     * @return The absolute path to the APK file, or null if not found.
     */
    private static String findApkFilePath(String workspace, String apkFileName) {
        // Define possible directories where the APK might be located
        String[] possibleDirs = {
                workspace + "/app/build/outputs/apk/debug/",
                workspace + "/app/build/outputs/apk/release/"
        };

        // Search for the APK file in the possible directories
        for (String dir : possibleDirs) {
            File apkFile = new File(dir, apkFileName);
            if (apkFile.exists() && apkFile.isFile()) {
                return apkFile.getAbsolutePath();
            }
        }

        return null; // APK file not found
    }
}
