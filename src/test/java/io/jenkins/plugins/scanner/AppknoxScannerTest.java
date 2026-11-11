package io.jenkins.plugins.scanner;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class AppknoxScannerTest {

    private JenkinsRule jenkins;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        jenkins = rule;
    }

    private AppknoxScanner.DescriptorImpl getDescriptor() {
        return (AppknoxScanner.DescriptorImpl) jenkins.jenkins.getDescriptorOrDie(AppknoxScanner.class);
    }

    @Test
    void doFillRiskThresholdItems_ReturnsAllFourOptions() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        assertEquals(4, items.size());
    }

    @Test
    void doFillRiskThresholdItems_ContainsExpectedValues() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        assertTrue(items.stream().anyMatch(opt -> "LOW".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "MEDIUM".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "HIGH".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "CRITICAL".equals(opt.value)));
    }

    @Test
    void doFillRiskThresholdItems_SelectsMatchingValue() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems("CRITICAL");

        ListBoxModel.Option criticalOption = items.stream()
            .filter(opt -> "CRITICAL".equals(opt.value))
            .findFirst()
            .orElse(null);

        assertNotNull(criticalOption);
        assertTrue(criticalOption.selected);
    }

    @Test
    void doFillRiskThresholdItems_OtherOptionsNotSelected() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems("HIGH");

        // HIGH should be selected
        assertTrue(items.stream()
            .filter(opt -> "HIGH".equals(opt.value))
            .findFirst()
            .map(opt -> opt.selected)
            .orElse(false));

        // Others should NOT be selected
        assertFalse(items.stream()
            .filter(opt -> "LOW".equals(opt.value))
            .findFirst()
            .map(opt -> opt.selected)
            .orElse(true));
    }

    @Test
    void doFillRiskThresholdItems_NullParameterNoSelection() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        // LOW should be selected by default when parameter is null
        long selectedCount = items.stream().filter(opt -> opt.selected).count();
        assertEquals(1, selectedCount);
        assertTrue(items.stream().anyMatch(opt -> opt.selected && "LOW".equals(opt.value)));
    }

    // --- Lines 693-694: missing branches ---

    @Test
    void doFillRiskThresholdItems_EmptyParameter_SelectsLow() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems("");

        // covers riskThreshold.isEmpty() branch on line 693
        assertTrue(items.stream()
            .filter(opt -> "LOW".equals(opt.value))
            .findFirst()
            .map(opt -> opt.selected)
            .orElse(false));
    }

    @Test
    void doFillRiskThresholdItems_LowParameter_SelectsLow() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems("LOW");

        // covers "LOW".equals(riskThreshold) branch on line 694 (defaultLow is false)
        assertTrue(items.stream()
            .filter(opt -> "LOW".equals(opt.value))
            .findFirst()
            .map(opt -> opt.selected)
            .orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "MEDIUM".equals(opt.value))
            .findFirst()
            .map(opt -> opt.selected)
            .orElse(true));
    }

    // --- Lines 67-107: constructor and getters ---

    @Test
    void constructor_StoresAllFields() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertEquals("cred-id", scanner.getCredentialsId());
        assertEquals("app.apk", scanner.getFilePath());
        assertEquals("RISK", scanner.getThresholdType());
        assertEquals("LOW", scanner.getRiskThreshold());
        assertEquals("", scanner.getHealthScoreThreshold());
        assertEquals("global", scanner.getRegion());
    }

    @Test
    void generatePdfReport_DefaultFalse() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertFalse(scanner.isGeneratePdfReport());
    }

    @Test
    void setGeneratePdfReport_UpdatesValue() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        scanner.setGeneratePdfReport(true);
        assertTrue(scanner.isGeneratePdfReport());
    }

    @Test
    void triggerKnoxiq_DefaultFalse() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertFalse(scanner.isTriggerKnoxiq());
    }

    @Test
    void setTriggerKnoxiq_UpdatesValue() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        scanner.setTriggerKnoxiq(true);
        assertTrue(scanner.isTriggerKnoxiq());
    }

    @Test
    void exploitLikelihoodThreshold_DefaultNull() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertNull(scanner.getExploitLikelihoodThreshold());
    }

    @Test
    void setExploitLikelihoodThreshold_UpdatesValue() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "EXPLOIT_LIKELIHOOD", "LOW", "", "global");
        scanner.setExploitLikelihoodThreshold("HIGH");
        assertEquals("HIGH", scanner.getExploitLikelihoodThreshold());
    }

    // --- Lines 657-688: DescriptorImpl methods ---

    @Test
    void descriptor_IsApplicable_ReturnsTrue() {
        assertTrue(getDescriptor().isApplicable(null));
    }

    @Test
    void descriptor_GetDisplayName_ReturnsExpected() {
        assertEquals("Appknox Security Scanner", getDescriptor().getDisplayName());
    }

    @Test
    void doFillRegionItems_ReturnsFourRegions() {
        ListBoxModel items = getDescriptor().doFillRegionItems();
        assertEquals(4, items.size());
    }

    @Test
    void doFillRegionItems_ContainsAllRegionValues() {
        ListBoxModel items = getDescriptor().doFillRegionItems();
        assertTrue(items.stream().anyMatch(opt -> "global".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "uae".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "saudi".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "eu".equals(opt.value)));
    }

    @Test
    void doFillThresholdTypeItems_ReturnsThreeOptions() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems(null);
        assertEquals(3, items.size());
    }

    @Test
    void doFillThresholdTypeItems_ExploitLikelihoodSelected() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems("EXPLOIT_LIKELIHOOD");
        assertTrue(items.stream()
            .filter(opt -> "EXPLOIT_LIKELIHOOD".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    @Test
    void doFillThresholdTypeItems_NullDefaultsToRisk() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems(null);
        assertTrue(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "HEALTH_SCORE".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    @Test
    void doFillThresholdTypeItems_EmptyDefaultsToRisk() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems("");
        assertTrue(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
    }

    @Test
    void doFillThresholdTypeItems_HealthScoreSelected() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems("HEALTH_SCORE");
        assertTrue(items.stream()
            .filter(opt -> "HEALTH_SCORE".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    @Test
    void doCheckThresholdType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckThresholdType("RISK");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    // --- Lines 721-736: doCheckCredentialsId + doCheckFilePath ---

    @Test
    void doCheckCredentialsId_BothEmptyReturnsError() {
        FormValidation result = getDescriptor().doCheckCredentialsId("", "");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckCredentialsId_OnlyCredentialsIdReturnsOk() {
        FormValidation result = getDescriptor().doCheckCredentialsId("some-cred-id", "");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    void doCheckCredentialsId_BothProvidedReturnsError() {
        FormValidation result = getDescriptor().doCheckCredentialsId("some-cred-id", "some-sa-id");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckServiceAccountCredentialsId_OnlyServiceAccountReturnsOk() {
        FormValidation result = getDescriptor().doCheckServiceAccountCredentialsId("some-sa-id", "");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    void validateCredentialSelection_NeitherProvided_ReturnsError() {
        assertNotNull(AppknoxScanner.validateCredentialSelection("", ""));
        assertNotNull(AppknoxScanner.validateCredentialSelection(null, null));
    }

    @Test
    void validateCredentialSelection_BothProvided_ReturnsError() {
        assertNotNull(AppknoxScanner.validateCredentialSelection("pat-id", "sa-id"));
    }

    @Test
    void validateCredentialSelection_OnlyPAT_ReturnsNull() {
        assertNull(AppknoxScanner.validateCredentialSelection("pat-id", ""));
    }

    @Test
    void validateCredentialSelection_OnlyServiceAccount_ReturnsNull() {
        assertNull(AppknoxScanner.validateCredentialSelection("", "sa-id"));
    }

    private void registerServiceAccountCredential(String id, String description) throws Exception {
        SystemCredentialsProvider.getInstance().getCredentials().add(
                new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, id, description, "key-id-value", "key-secret-value"));
        SystemCredentialsProvider.getInstance().save();
    }

    @Test
    void doFillServiceAccountCredentialsIdItems_LabelsByIdWhenNoDescription() throws Exception {
        registerServiceAccountCredential("sa-no-desc", "");

        ListBoxModel items = getDescriptor().doFillServiceAccountCredentialsIdItems(null);

        assertTrue(items.stream().anyMatch(opt -> "sa-no-desc".equals(opt.value) && "sa-no-desc".equals(opt.name)));
    }

    @Test
    void doFillServiceAccountCredentialsIdItems_LabelsByIdAndDescriptionWhenPresent() throws Exception {
        registerServiceAccountCredential("sa-with-desc", "Prod Service Account");

        ListBoxModel items = getDescriptor().doFillServiceAccountCredentialsIdItems(null);

        assertTrue(items.stream().anyMatch(opt ->
                "sa-with-desc".equals(opt.value) && "sa-with-desc (Prod Service Account)".equals(opt.name)));
    }

    @Test
    void getServiceAccountCredentials_ReturnsRegisteredCredential() throws Exception {
        registerServiceAccountCredential("sa-lookup-id", "desc");
        AppknoxScanner scanner = new AppknoxScanner("", "app.apk", "RISK", "LOW", "", "global");
        scanner.setServiceAccountCredentialsId("sa-lookup-id");

        StandardUsernamePasswordCredentials result = scanner.getServiceAccountCredentials(TaskListener.NULL);

        assertNotNull(result);
        assertEquals("key-id-value", result.getUsername());
        assertEquals("key-secret-value", result.getPassword().getPlainText());
    }

    @Test
    void getServiceAccountCredentials_UnknownIdReturnsNull() {
        AppknoxScanner scanner = new AppknoxScanner("", "app.apk", "RISK", "LOW", "", "global");
        scanner.setServiceAccountCredentialsId("no-such-credential-id");

        assertNull(scanner.getServiceAccountCredentials(TaskListener.NULL));
    }

    @Test
    void doCheckFilePath_EmptyReturnsError() {
        FormValidation result = getDescriptor().doCheckFilePath("");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckFilePath_NonEmptyReturnsOk() {
        FormValidation result = getDescriptor().doCheckFilePath("app.apk");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    // --- Lines 741-750: doCheckRiskThreshold ---

    @Test
    void doCheckRiskThreshold_NonRiskType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    void doCheckRiskThreshold_RiskType_EmptyValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("", "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckRiskThreshold_RiskType_NullValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold(null, "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckRiskThreshold_RiskType_InvalidValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("INVALID", "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckRiskThreshold_RiskType_ValidValues_ReturnOk() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("LOW", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("MEDIUM", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("HIGH", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("CRITICAL", "RISK").kind);
    }

    // --- Lines 752-766: doCheckHealthScoreThreshold ---

    @Test
    void doCheckHealthScoreThreshold_NonHealthScoreType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("", "RISK");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    void doCheckHealthScoreThreshold_HealthScoreType_EmptyValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckHealthScoreThreshold_HealthScoreType_NullValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold(null, "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckHealthScoreThreshold_HealthScoreType_InvalidInteger_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("not-a-number", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckHealthScoreThreshold_HealthScoreType_OutOfRange_ReturnsError() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHealthScoreThreshold("-1", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHealthScoreThreshold("101", "HEALTH_SCORE").kind);
    }

    @Test
    void doCheckHealthScoreThreshold_HealthScoreType_ValidValues_ReturnOk() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("0", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("50", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("100", "HEALTH_SCORE").kind);
    }

    // --- doFillExploitLikelihoodThresholdItems ---

    @Test
    void doFillExploitLikelihoodThresholdItems_ReturnsThreeOptions() {
        ListBoxModel items = getDescriptor().doFillExploitLikelihoodThresholdItems(null);
        assertEquals(3, items.size());
    }

    @Test
    void doFillExploitLikelihoodThresholdItems_NullParameterDefaultsToLow() {
        ListBoxModel items = getDescriptor().doFillExploitLikelihoodThresholdItems(null);
        assertTrue(items.stream()
            .filter(opt -> "LOW".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
    }

    @Test
    void doFillExploitLikelihoodThresholdItems_SelectsMatchingValue() {
        ListBoxModel items = getDescriptor().doFillExploitLikelihoodThresholdItems("HIGH");
        assertTrue(items.stream()
            .filter(opt -> "HIGH".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "LOW".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    // --- doCheckExploitLikelihoodThreshold ---

    @Test
    void doCheckExploitLikelihoodThreshold_NonLikelihoodType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckExploitLikelihoodThreshold("", "RISK");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    void doCheckExploitLikelihoodThreshold_LikelihoodType_EmptyValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckExploitLikelihoodThreshold("", "EXPLOIT_LIKELIHOOD");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckExploitLikelihoodThreshold_LikelihoodType_NullValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckExploitLikelihoodThreshold(null, "EXPLOIT_LIKELIHOOD");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckExploitLikelihoodThreshold_LikelihoodType_InvalidValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckExploitLikelihoodThreshold("INVALID", "EXPLOIT_LIKELIHOOD");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void doCheckExploitLikelihoodThreshold_LikelihoodType_ValidValues_ReturnOk() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.OK, d.doCheckExploitLikelihoodThreshold("LOW", "EXPLOIT_LIKELIHOOD").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckExploitLikelihoodThreshold("MEDIUM", "EXPLOIT_LIKELIHOOD").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckExploitLikelihoodThreshold("HIGH", "EXPLOIT_LIKELIHOOD").kind);
    }
}
