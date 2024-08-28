package io.jenkins.plugins;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Queue;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import jenkins.model.ArtifactManager;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import jenkins.util.VirtualFile;

import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;

public class AppknoxPlugin extends Builder implements SimpleBuildStep {
    private final String credentialsId;
    private final String filePath;
    private final String riskThreshold;

    private static final String binaryVersion = "1.3.1";
    private static final String osName = System.getProperty("os.name").toLowerCase();
    private static final String CLI_DOWNLOAD_PATH = System.getProperty("user.home") + File.separator + "appknox";

    @DataBoundConstructor
    public AppknoxPlugin(String credentialsId, String filePath, String riskThreshold) {
        this.credentialsId = credentialsId;
        this.filePath = filePath;
        this.riskThreshold = riskThreshold;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getRiskThreshold() {
        return riskThreshold;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {
        String reportName = "summary-report.csv";
        boolean success = executeAppknoxCommands(run, workspace, reportName, launcher, listener);

        if (success) {
            archiveArtifact(run, workspace, reportName, launcher, listener);
        } else {
            if (run != null) {
                run.setResult(Result.FAILURE);
            }
        }
    }

    private boolean executeAppknoxCommands(Run<?, ?> run, FilePath workspace, String reportName, Launcher launcher, TaskListener listener) {
        try {
            String accessToken = getAccessToken(listener);
            if (accessToken == null) {
                return false;
            }

            Map<String, String> env = new HashMap<>(System.getenv());
            env.put("APPKNOX_ACCESS_TOKEN", accessToken);
            String appknoxPath = downloadAndInstallAppknox(osName, listener);

            // Determine if the file is an APK or IPA based on extension
            String appFilePath = findAppFilePath(workspace.getRemote(), filePath);

            if (appFilePath == null) {
                listener.getLogger().println("Neither APK nor IPA file found in the expected directories.");
                return false;
            }

            String uploadOutput = uploadFile(appknoxPath, listener, env, appFilePath);
            String fileID = extractFileID(uploadOutput, listener);
            if (fileID == null) {
                return false;
            }

            runCICheck(appknoxPath, run, fileID, listener, env);

            String reportOutput = createReport(appknoxPath, fileID, listener, env);
            String reportID = extractReportID(reportOutput, listener);
            if (reportID == null) {
                return false;
            }

            downloadReportSummaryCSV(appknoxPath, reportName, reportID, run, workspace, listener, env);
        } catch (Exception e) {
            listener.getLogger().println("Error executing Appknox commands: " + e.getMessage());
            return false;
        }
        return true;
    }

    private String findAppFilePath(String workspace, String fileName) {

        // Determine if the file is an APK or IPA based on the extension
        boolean isApk = fileName.endsWith(".apk");
        boolean isIpa = fileName.endsWith(".ipa");

        // Directories to search in order
        List<String> possibleDirs = new ArrayList<>();

        if (isApk) {
            possibleDirs.addAll(Arrays.asList(
                    workspace + "/app/build/outputs/apk/",
                    workspace + "/app/build/outputs/apk/release/",
                    workspace + "/app/build/outputs/apk/debug/"
            ));
        } else if (isIpa) {
            possibleDirs.addAll(Arrays.asList(
                    workspace + "/ios/build/outputs/ipa/",
                    workspace + "/ios/build/outputs/ipa/release/",
                    workspace + "/ios/build/outputs/ipa/debug/"
            ));
        }

        // Search in specified directories
        for (String dir : possibleDirs) {
            File appFile = new File(dir, fileName);
            if (appFile.exists() && appFile.isFile()) {
                return appFile.getAbsolutePath();
            }
        }

        // Fallback to recursive search starting from the build directory if not found in the above directories
        String buildDir = isApk ? workspace + "/app/build" : workspace + "/ios/build";
        String result = findAppFilePathRecursive(new File(buildDir), fileName);
        if (result != null) {
            return result;
        }

        // Handle the case where an absolute path is given as part of the fileName
        File customFile = new File(workspace, fileName);
        if (customFile.exists() && customFile.isFile()) {
            return customFile.getAbsolutePath();
        } else if (customFile.isAbsolute()) {
            System.err.println("File not found at specified absolute path: " + customFile.getAbsolutePath());
            return null;
        }

        // File not found
        System.err.println("File not found in specified directories, through recursive search, or at the specified absolute path.");
        return null;
    }

    private String findAppFilePathRecursive(File dir, String fileName) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    String result = findAppFilePathRecursive(file, fileName);
                    if (result != null) {
                        return result;
                    }
                } else if (file.getName().equals(fileName)) {
                    return file.getAbsolutePath();
                }
            }
        }
        return null;
    }

    private String extractFileID(String uploadOutput, TaskListener listener) {
        String[] lines = uploadOutput.split("\n");
        if (lines.length > 0) {
            String lastLine = lines[lines.length - 1].trim();
            try {
                return lastLine;
            } catch (NumberFormatException e) {
                listener.getLogger().println("Failed to extract file ID from upload output: " + lastLine);
                return null;
            }
        } else {
            listener.getLogger().println("Upload output does not contain any lines.");
            return null;
        }
    }

    private String extractReportID(String createReportOutput, TaskListener listener) {
        String[] lines = createReportOutput.split("\n");
        if (lines.length > 0) {
            String lastLine = lines[lines.length - 1].trim();
            try {
                return lastLine;
            } catch (NumberFormatException e) {
                listener.getLogger().println("Failed to extract Report ID from report output: " + lastLine);
                return null;
            }
        } else {
            listener.getLogger().println("Report output does not contain any lines.");
            return null;
        }
    }

    private String downloadAndInstallAppknox(String os, TaskListener listener)
            throws IOException, InterruptedException {
        String appknoxURL = getAppknoxDownloadURL(os);
        File appknoxFile = new File(CLI_DOWNLOAD_PATH);

        if (!appknoxFile.exists()) {
            listener.getLogger().println("Downloading Appknox CLI...");
            downloadFile(appknoxURL, CLI_DOWNLOAD_PATH, listener);
            listener.getLogger().println("Appknox CLI downloaded successfully.");
        } else {
            listener.getLogger().println("Appknox CLI already exists at: " + CLI_DOWNLOAD_PATH);
        }

        addPathToEnvironment(CLI_DOWNLOAD_PATH, listener);
        return CLI_DOWNLOAD_PATH;
    }

    private String getAppknoxDownloadURL(String os) {
        String binaryName;
        if (os.contains("win")) {
            binaryName = "appknox-Windows-x86_64.exe";
        } else if (os.contains("mac")) {
            binaryName = "appknox-Darwin-x86_64";
        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            binaryName = "appknox-Linux-x86_64";
        } else {
            throw new UnsupportedOperationException("Unsupported operating system for Appknox CLI download.");
        }

        return "https://github.com/appknox/appknox-go/releases/download/" + binaryVersion + "/" + binaryName;
    }

    private void downloadFile(String url, String destinationPath, TaskListener listener) throws IOException {
        URL downloadUrl = new URL(url);
        File destinationFile = new File(destinationPath);
        File parentDir = destinationFile.getParentFile();
        if (!parentDir.exists() && !parentDir.mkdirs()) {
            throw new IOException("Failed to create directories: " + parentDir.getAbsolutePath());
        }
        FileUtils.copyURLToFile(downloadUrl, destinationFile);

        // Make the file executable (for Unix-based systems)
        if (!System.getProperty("os.name").toLowerCase().contains("win") && !destinationFile.setExecutable(true)) {
            listener.getLogger().println("Failed to set executable permission for: " + destinationPath);
        }
    }

    private void addPathToEnvironment(String path, TaskListener listener) {
        String existingPath = System.getenv("PATH");
        String newPath = path + File.pathSeparator + existingPath;
        System.setProperty("PATH", newPath);
    }

    private String uploadFile(String appknoxPath, TaskListener listener, Map<String, String> env, String appFilePath)
            throws IOException, InterruptedException {
        String accessToken = getAccessToken(listener);
        if (accessToken == null) {
            return null;
        }
        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("upload");
        command.add(appFilePath);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            String lastLine = null;
            while ((line = reader.readLine()) != null) {
                lastLine = line;
            }

            if (lastLine != null) {
                listener.getLogger().println("Upload Command Output :");
                listener.getLogger().println("File ID = " + lastLine.trim());
                return lastLine.trim();
            } else {
                listener.getLogger().println("Upload failed: No output received.");
                return null;
            }
        } finally {
            process.waitFor();
        }
    }

    private boolean runCICheck(String appknoxPath, Run<?, ?> run, String fileID, TaskListener listener, Map<String, String> env)
            throws IOException, InterruptedException {
        String accessToken = getAccessToken(listener);
        if (accessToken == null) {
            return false;
        }

        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("cicheck");
        command.add(fileID);
        command.add("--risk-threshold");
        command.add(riskThreshold);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder output = new StringBuilder();
            String line;
            boolean foundStarted = false;

            while ((line = reader.readLine()) != null) {
                if (!foundStarted) {
                    if (line.contains("Found") || line.contains("No")) {
                        output.append(line).append("\n");
                        if (run != null) {
                            run.setDescription(output.toString() + "Check Console Output for more details.");
                        }
                        foundStarted = true;
                    }
                } else {
                    output.append(line).append("\n");
                }
            }

            if (!foundStarted) {
                listener.getLogger().println("No line with 'Found' or 'No' encountered in the output.");
                return false;
            }
            listener.getLogger().println("Ci Check Output:");
            listener.getLogger().println(output.toString());

            return process.exitValue() == 0;
        }
    }

    private String createReport(String appknoxPath, String fileID, TaskListener listener, Map<String, String> env)
            throws IOException, InterruptedException {
        String accessToken = getAccessToken(listener);
        if (accessToken == null) {
            return null;
        }

        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("reports");
        command.add("create");
        command.add(fileID);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        listener.getLogger().println("Create Report Command Output :");
        listener.getLogger().println("Report Id = " + output.toString());

        int exitValue = process.waitFor();
        if (exitValue == 0) {
            return output.toString().trim();
        } else {
            listener.getLogger().println("Report Creation failed with exit code: " + exitValue);
            return null;
        }
    }

    private void downloadReportSummaryCSV(String appknoxPath, String reportName, String reportID, Run<?, ?> run, FilePath workspace, TaskListener listener, Map<String, String> env) throws IOException, InterruptedException {
        String accessToken = getAccessToken(listener);
        if (accessToken == null) {
            listener.error("Access token is null. Unable to download CSV report.");
            return;
        }

        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("reports");
        command.add("download");
        command.add("summary-csv");
        command.add(reportID);
        command.add("--output");
        command.add(workspace.child(reportName).getRemote());

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().putAll(env);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        int exitCode = process.waitFor();
        if (exitCode == 0) {
            listener.getLogger().println(
                    "Summary report saved at:" + workspace.child(reportName).getRemote());
        } else {
            listener.getLogger().println("Download CSV failed. Exit code: " + exitCode);
        }
    }

    private void archiveArtifact(Run<?, ?> run, FilePath workspace, String reportName, Launcher launcher, TaskListener listener) {
        try {
            FilePath artifactFile = workspace.child(reportName);

            if (!artifactFile.exists()) {
                listener.error("Artifact file does not exist: " + artifactFile.getRemote());
                return;
            }

            ArtifactManager artifactManager = run.getArtifactManager();
            Map<String, String> artifacts = new HashMap<>();
            artifacts.put(reportName, artifactFile.getName());
            artifactManager.archive(workspace, launcher, (BuildListener) listener, artifacts);

            listener.getLogger().println("Artifact archived: " + artifactFile.getRemote());
        } catch (IOException | InterruptedException e) {
            listener.error("Error archiving artifact: " + e.getMessage());
            e.printStackTrace(listener.getLogger());
        }
    }

    private String getAccessToken(TaskListener listener) {
        Jenkins jenkins = Jenkins.get();
        @SuppressWarnings("deprecation")
        StringCredentials credentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(StringCredentials.class, jenkins, ACL.SYSTEM,
                        URIRequirementBuilder.create().build()),
                CredentialsMatchers.withId(credentialsId));

        if (credentials != null) {
            return credentials.getSecret().getPlainText();
        } else {
            listener.getLogger().println("Failed to retrieve access token from credentials.");
            return null;
        }
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public DescriptorImpl() {
            super(AppknoxPlugin.class);
            load();
        }

        @Override
        public boolean isApplicable(@SuppressWarnings("rawtypes") Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Appknox Security Scanner";
        }

        @SuppressWarnings("deprecation")
        @POST
        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath ItemGroup<?> context) {
            if(context == null){
                Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            }else{
                ((AccessControlled) context).checkPermission(Item.CONFIGURE);
            }

            return new StandardListBoxModel()
                    .includeEmptyValue()
                    .includeMatchingAs(
                            ACL.SYSTEM,
                            context,
                            StringCredentials.class,
                            URIRequirementBuilder.fromUri("").build(),
                            CredentialsMatchers.instanceOf(StringCredentials.class));
        }

        @POST
        public FormValidation doCheckCredentialsId(@QueryParameter String value) {
            Jenkins.get().checkPermission(Item.CONFIGURE);
            if (value.isEmpty()) {
                return FormValidation.error("Appknox Access Token must be selected");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckFilePath(@QueryParameter String value) {
            Jenkins.get().checkPermission(Item.CONFIGURE);
            if (value.isEmpty()) {
                return FormValidation.error("File Path must not be empty");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckRiskThreshold(@QueryParameter String value) {
            Jenkins.get().checkPermission(Item.CONFIGURE);
            if (value.isEmpty() || (!value.equals("LOW") && !value.equals("MEDIUM") && !value.equals("HIGH")
                    && !value.equals("CRITICAL"))) {
                return FormValidation.error("Risk Threshold must be one of: LOW, MEDIUM, HIGH, CRITICAL");
            }
            return FormValidation.ok();
        }
    }
}
