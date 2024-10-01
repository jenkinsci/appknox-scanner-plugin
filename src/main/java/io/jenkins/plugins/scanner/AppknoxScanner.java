package io.jenkins.plugins.scanner;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.Launcher.ProcStarter;
import hudson.EnvVars;
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
import hudson.util.ArgumentListBuilder;
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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
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

@Symbol("appKnoxScanner")
public class AppknoxScanner extends Builder implements SimpleBuildStep {
    private final String credentialsId;
    private final String filePath;
    private final String riskThreshold;
    private final String apiHost;

    private static final String binaryVersion = "1.6.0";

    @DataBoundConstructor
    public AppknoxScanner(String credentialsId, String filePath, String riskThreshold, String apiHost) {
        this.credentialsId = credentialsId;
        this.filePath = filePath;
        this.riskThreshold = riskThreshold;
        this.apiHost = apiHost;
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

    public String getApiHost() {
        return apiHost;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {
        if (workspace == null) {
            listener.getLogger().println("Workspace is null.");
            return;
        }

        String reportName = "summary-report.csv";

        // Determine if running on controller or agent
        if (workspace.isRemote()) {
            // Running on agent
            listener.getLogger().println("Running on Agent...");
        } else {
            // Running on Controller
            listener.getLogger().println("Running on Controller...");
        }

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

            // Create environment variables
            EnvVars env = new EnvVars();
            env.put("APPKNOX_ACCESS_TOKEN", accessToken);

            String appknoxPath = downloadAndInstallAppknox(workspace, listener, launcher);

            listener.getLogger().println("Selected Region: " + apiHost);

            // Determine if the file is an APK or IPA based on extension
            String appFilePath = findAppFilePath(workspace, filePath, listener);
            if (appFilePath == null) {
                listener.getLogger().println("Neither APK nor IPA file found in the expected directories.");
                return false;
            }

            String uploadOutput = uploadFile(appknoxPath, listener, env, appFilePath, launcher, workspace);
            String fileID = extractFileID(uploadOutput, listener);
            if (fileID == null) {
                return false;
            }

            boolean cicheckSuccess = runCICheck(appknoxPath, run, fileID, listener, env, launcher, workspace);
            if (!cicheckSuccess) {
                return false;
            }

            String reportOutput = createReport(appknoxPath, fileID, listener, env, launcher, workspace);
            String reportID = extractReportID(reportOutput, listener);
            if (reportID == null) {
                return false;
            }

            downloadReportSummaryCSV(appknoxPath, reportName, reportID, run, workspace, listener, env, launcher);
        } catch (Exception e) {
            listener.getLogger().println("Error executing Appknox commands: " + e.getMessage());
            return false;
        }
        return true;
    }

    private String downloadAndInstallAppknox(FilePath workspace, TaskListener listener, Launcher launcher)
            throws IOException, InterruptedException {
        // Get the OS name of the node where the build is running
        String osName = getOSName(launcher, listener);

        String appknoxURL = getAppknoxDownloadURL(osName);
        FilePath appknoxFile = workspace.child("appknox");

        if (!appknoxFile.exists()) {
            listener.getLogger().println("Downloading Appknox CLI...");
            downloadFile(appknoxURL, appknoxFile, listener);
            listener.getLogger().println("Appknox CLI downloaded successfully.");
        } else {
            listener.getLogger().println("Appknox CLI already exists at: " + appknoxFile.getRemote());
        }

        // Make the file executable (for Unix-based systems)
        if (launcher.isUnix()) {
            appknoxFile.chmod(0755);
        }

        listener.getLogger().println("Appknox CLI located at: " + appknoxFile.getRemote());
        return appknoxFile.getRemote();
    }

    private String getOSName(Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        if (launcher.isUnix()) {
            // Determine if it's Linux or macOS
            ProcStarter procStarter = launcher.launch();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            procStarter.cmds("uname", "-s");
            procStarter.stdout(outputStream);
            procStarter.stderr(listener.getLogger());
            int exitCode = procStarter.join();

            if (exitCode == 0) {
                String osName = outputStream.toString("UTF-8").trim();
                listener.getLogger().println("Detected OS: " + osName);
                if (osName.equalsIgnoreCase("Darwin")) {
                    return "mac";
                } else {
                    return "linux";
                }
            } else {
                listener.getLogger().println("Failed to determine OS using 'uname -s', defaulting to 'linux'");
                return "linux";
            }
        } else {
            return "win";
        }
    }

    private void downloadFile(String url, FilePath destinationFile, TaskListener listener) throws IOException, InterruptedException {
        URL downloadUrl = new URL(url);
        try (InputStream in = downloadUrl.openStream()) {
            destinationFile.copyFrom(in);
        }
    }

    private String getAppknoxDownloadURL(String os) {
        String binaryName;
        if (os.contains("win")) {
            binaryName = "appknox-Windows-x86_64.exe";
        } else if (os.contains("mac")) {
            binaryName = "appknox-Darwin-x86_64";
        } else if (os.contains("linux")) {
            binaryName = "appknox-Linux-x86_64";
        } else {
            throw new UnsupportedOperationException("Unsupported operating system for Appknox CLI download.");
        }

        return "https://github.com/appknox/appknox-go/releases/download/" + binaryVersion + "/" + binaryName;
    }

    private String findAppFilePath(FilePath workspace, String fileName, TaskListener listener) throws IOException, InterruptedException {
        // Determine if the file is an APK or IPA based on the extension
        boolean isApk = fileName.endsWith(".apk");
        boolean isIpa = fileName.endsWith(".ipa");

        // Directories to search in order
        List<String> possibleDirs = new ArrayList<>();

        if (isApk) {
            possibleDirs.addAll(Arrays.asList(
                    "app/build/outputs/apk/",
                    "app/build/outputs/apk/release/",
                    "app/build/outputs/apk/debug/"
            ));
        } else if (isIpa) {
            possibleDirs.addAll(Arrays.asList(
                    "Build/Products/",
                    "Build/Products/Debug-iphoneos/",
                    "Build/Products/Release-iphoneos/"
            ));
        }

        // Search in specified directories
        for (String dir : possibleDirs) {
            FilePath appFile = workspace.child(dir).child(fileName);
            if (appFile.exists() && !appFile.isDirectory()) {
                listener.getLogger().println("File found at: " + appFile.getRemote());
                return appFile.getRemote();
            }
        }

        // Fallback to recursive search starting from the build directory if not found in the above directories
        String buildDir = isApk ? "app/build" : "Build";
        FilePath buildDirPath = workspace.child(buildDir);
        String result = findAppFilePathRecursive(buildDirPath, fileName, listener);
        if (result != null) {
            listener.getLogger().println("File found during recursive search at: " + result);
            return result;
        }

        // Handle the case where an absolute path is given as part of the fileName
        FilePath customFile = workspace.child(fileName);
        if (customFile.exists() && !customFile.isDirectory()) {
            listener.getLogger().println("File found at specified path: " + customFile.getRemote());
            return customFile.getRemote();
        } else if (new File(fileName).isAbsolute()) {
            listener.getLogger().println("File not found at specified absolute path: " + fileName);
            return null;
        }

        // File not found
        listener.getLogger().println("File not found in specified directories, through recursive search, or at the specified path.");
        return null;
    }

    private String findAppFilePathRecursive(FilePath dir, String fileName, TaskListener listener) throws IOException, InterruptedException {
        List<FilePath> files = dir.list();
        if (files != null) {
            for (FilePath file : files) {
                if (file.isDirectory()) {
                    String result = findAppFilePathRecursive(file, fileName, listener);
                    if (result != null) {
                        return result;
                    }
                } else if (file.getName().equals(fileName)) {
                    listener.getLogger().println("File found during recursive search at: " + file.getRemote());
                    return file.getRemote();
                }
            }
        }
        return null;
    }

    private String uploadFile(String appknoxPath, TaskListener listener, EnvVars env, String appFilePath, Launcher launcher, FilePath workspace)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("upload");
        command.add(appFilePath);
        command.add("--region");
        command.add(apiHost);

        ArgumentListBuilder args = new ArgumentListBuilder(command.toArray(new String[0]));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Proc proc = launcher.launch().cmds(args).envs(env).stdout(outputStream).pwd(workspace).start();
        int exitCode = proc.join();

        if (exitCode != 0) {
            listener.getLogger().println("Upload failed with exit code: " + exitCode);
            return null;
        }

        String output = outputStream.toString("UTF-8");
        listener.getLogger().println("Upload Command Output:");
        listener.getLogger().println(output);

        String fileID = extractFileID(output, listener);
        if (fileID == null) {
            return null;
        }
        listener.getLogger().println("File ID = " + fileID);

        return fileID;
    }

    private boolean runCICheck(String appknoxPath, Run<?, ?> run, String fileID, TaskListener listener, EnvVars env, Launcher launcher, FilePath workspace)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("cicheck");
        command.add(fileID);
        command.add("--risk-threshold");
        command.add(riskThreshold);
        command.add("--region");
        command.add(apiHost);

        ArgumentListBuilder args = new ArgumentListBuilder(command.toArray(new String[0]));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Proc proc = launcher.launch().cmds(args).envs(env).stdout(outputStream).pwd(workspace).start();
        int exitCode = proc.join();

        String output = outputStream.toString("UTF-8").trim();
        listener.getLogger().println("Ci Check Output:");
        listener.getLogger().println(output);

        if (exitCode != 0) {
            listener.getLogger().println("CICheck failed with exit code: " + exitCode);
            if (run != null) {
                run.setDescription("CICheck failed. Check Console Output for more details.");
            }
            return false;
        }

        if (run != null) {
            run.setDescription(output + " Check Console Output for more details.");
        }

        return true;
    }

    private String createReport(String appknoxPath, String fileID, TaskListener listener, EnvVars env, Launcher launcher, FilePath workspace)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("reports");
        command.add("create");
        command.add(fileID);
        command.add("--region");
        command.add(apiHost);

        ArgumentListBuilder args = new ArgumentListBuilder(command.toArray(new String[0]));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Proc proc = launcher.launch().cmds(args).envs(env).stdout(outputStream).pwd(workspace).start();
        int exitCode = proc.join();

        String output = outputStream.toString("UTF-8").trim();
        listener.getLogger().println("Create Report Command Output:");
        listener.getLogger().println("Report Id = " + output);

        if (exitCode != 0) {
            listener.getLogger().println("Report Creation failed with exit code: " + exitCode);
            return null;
        }

        return output;
    }

    private void downloadReportSummaryCSV(String appknoxPath, String reportName, String reportID, Run<?, ?> run, FilePath workspace, TaskListener listener, EnvVars env, Launcher launcher) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(appknoxPath);
        command.add("reports");
        command.add("download");
        command.add("summary-csv");
        command.add(reportID);
        command.add("--output");
        command.add(workspace.child(reportName).getRemote());
        command.add("--region");
        command.add(apiHost);

        ArgumentListBuilder args = new ArgumentListBuilder(command.toArray(new String[0]));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Proc proc = launcher.launch().cmds(args).envs(env).stdout(outputStream).pwd(workspace).start();
        int exitCode = proc.join();

        if (exitCode != 0) {
            listener.getLogger().println("Download CSV failed. Exit code: " + exitCode);
        } else {
            listener.getLogger().println("Summary report saved at: " + workspace.child(reportName).getRemote());
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

    private String extractFileID(String uploadOutput, TaskListener listener) {
        String[] lines = uploadOutput.split("\\r?\\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.matches("\\d+")) {
                // Line contains only digits, assume it's the file ID
                return line;
            }
        }
        listener.getLogger().println("Could not extract file ID from upload output.");
        return null;
    }

    private String extractReportID(String createReportOutput, TaskListener listener) {
        if (createReportOutput != null && !createReportOutput.isEmpty()) {
            return createReportOutput.trim();
        } else {
            listener.getLogger().println("Report output does not contain any lines.");
            return null;
        }
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public DescriptorImpl() {
            super(AppknoxScanner.class);
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

        @POST
        public ListBoxModel doFillApiHostItems() {
            return new ListBoxModel(
                    new ListBoxModel.Option("Global", "global"),
                    new ListBoxModel.Option("Saudi", "saudi")
            );
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
