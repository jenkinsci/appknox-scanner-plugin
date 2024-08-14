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
        env.put("WORKSPACE", "C:\\Users\\hirakdesai\\.jenkins\\workspace\\MFVA_Build");

        // Mock parameters for the plugin
        String credentialsId = "your-credentials-id";
        String filePath = "app\\mfva_1.0.apk";
        String riskThreshold = "LOW";

        System.out.println("Testing with the following details:");
        System.out.println("Workspace: " + env.get("WORKSPACE"));
        System.out.println("File Path: " + filePath);
        System.out.println("Risk Threshold: " + riskThreshold);


        TaskListener listener = new TaskListener() {
            @Override
            public PrintStream getLogger() {
                return System.out;
            }
        };


        Run<?, ?> run = null;
        Launcher launcher = null;


        AppknoxPlugin plugin = new AppknoxPlugin(credentialsId, filePath, riskThreshold);


        try {
            plugin.perform(run, new FilePath(new File(env.get("WORKSPACE"))), launcher, listener);
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }
}
