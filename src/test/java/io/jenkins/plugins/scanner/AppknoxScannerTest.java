package io.jenkins.plugins.scanner;

import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.*;

public class AppknoxScannerTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    private AppknoxScanner.DescriptorImpl getDescriptor() {
        return (AppknoxScanner.DescriptorImpl) jenkins.jenkins.getDescriptorOrDie(AppknoxScanner.class);
    }

    @Test
    public void doFillRiskThresholdItems_ReturnsAllFourOptions() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        assertEquals(4, items.size());
    }

    @Test
    public void doFillRiskThresholdItems_ContainsExpectedValues() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        assertTrue(items.stream().anyMatch(opt -> "LOW".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "MEDIUM".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "HIGH".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "CRITICAL".equals(opt.value)));
    }

    @Test
    public void doFillRiskThresholdItems_SelectsMatchingValue() {
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
    public void doFillRiskThresholdItems_OtherOptionsNotSelected() {
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
    public void doFillRiskThresholdItems_NullParameterNoSelection() {
        AppknoxScanner.DescriptorImpl descriptor = getDescriptor();
        ListBoxModel items = descriptor.doFillRiskThresholdItems(null);

        // LOW should be selected by default when parameter is null
        long selectedCount = items.stream().filter(opt -> opt.selected).count();
        assertEquals(1, selectedCount);
        assertTrue(items.stream().anyMatch(opt -> opt.selected && "LOW".equals(opt.value)));
    }

    // --- Lines 693-694: missing branches ---

    @Test
    public void doFillRiskThresholdItems_EmptyParameter_SelectsLow() {
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
    public void doFillRiskThresholdItems_LowParameter_SelectsLow() {
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
    public void constructor_StoresAllFields() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertEquals("cred-id", scanner.getCredentialsId());
        assertEquals("app.apk", scanner.getFilePath());
        assertEquals("RISK", scanner.getThresholdType());
        assertEquals("LOW", scanner.getRiskThreshold());
        assertEquals("", scanner.getHealthScoreThreshold());
        assertEquals("global", scanner.getRegion());
    }

    @Test
    public void generatePdfReport_DefaultFalse() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        assertFalse(scanner.isGeneratePdfReport());
    }

    @Test
    public void setGeneratePdfReport_UpdatesValue() {
        AppknoxScanner scanner = new AppknoxScanner("cred-id", "app.apk", "RISK", "LOW", "", "global");
        scanner.setGeneratePdfReport(true);
        assertTrue(scanner.isGeneratePdfReport());
    }

    // --- Lines 657-688: DescriptorImpl methods ---

    @Test
    public void descriptor_IsApplicable_ReturnsTrue() {
        assertTrue(getDescriptor().isApplicable(null));
    }

    @Test
    public void descriptor_GetDisplayName_ReturnsExpected() {
        assertEquals("Appknox Security Scanner", getDescriptor().getDisplayName());
    }

    @Test
    public void doFillRegionItems_ReturnsFourRegions() {
        ListBoxModel items = getDescriptor().doFillRegionItems();
        assertEquals(4, items.size());
    }

    @Test
    public void doFillRegionItems_ContainsAllRegionValues() {
        ListBoxModel items = getDescriptor().doFillRegionItems();
        assertTrue(items.stream().anyMatch(opt -> "global".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "uae".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "saudi".equals(opt.value)));
        assertTrue(items.stream().anyMatch(opt -> "eu".equals(opt.value)));
    }

    @Test
    public void doFillThresholdTypeItems_ReturnsTwoOptions() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems(null);
        assertEquals(2, items.size());
    }

    @Test
    public void doFillThresholdTypeItems_NullDefaultsToRisk() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems(null);
        assertTrue(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "HEALTH_SCORE".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    @Test
    public void doFillThresholdTypeItems_EmptyDefaultsToRisk() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems("");
        assertTrue(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
    }

    @Test
    public void doFillThresholdTypeItems_HealthScoreSelected() {
        ListBoxModel items = getDescriptor().doFillThresholdTypeItems("HEALTH_SCORE");
        assertTrue(items.stream()
            .filter(opt -> "HEALTH_SCORE".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(false));
        assertFalse(items.stream()
            .filter(opt -> "RISK".equals(opt.value))
            .findFirst().map(opt -> opt.selected).orElse(true));
    }

    @Test
    public void doCheckThresholdType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckThresholdType("RISK");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    // --- Lines 721-736: doCheckCredentialsId + doCheckFilePath ---

    @Test
    public void doCheckCredentialsId_EmptyReturnsError() {
        FormValidation result = getDescriptor().doCheckCredentialsId("");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckCredentialsId_NonEmptyReturnsOk() {
        FormValidation result = getDescriptor().doCheckCredentialsId("some-cred-id");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    public void doCheckFilePath_EmptyReturnsError() {
        FormValidation result = getDescriptor().doCheckFilePath("");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckFilePath_NonEmptyReturnsOk() {
        FormValidation result = getDescriptor().doCheckFilePath("app.apk");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    // --- Lines 741-750: doCheckRiskThreshold ---

    @Test
    public void doCheckRiskThreshold_NonRiskType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    public void doCheckRiskThreshold_RiskType_EmptyValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("", "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckRiskThreshold_RiskType_NullValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold(null, "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckRiskThreshold_RiskType_InvalidValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckRiskThreshold("INVALID", "RISK");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckRiskThreshold_RiskType_ValidValues_ReturnOk() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("LOW", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("MEDIUM", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("HIGH", "RISK").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckRiskThreshold("CRITICAL", "RISK").kind);
    }

    // --- Lines 752-766: doCheckHealthScoreThreshold ---

    @Test
    public void doCheckHealthScoreThreshold_NonHealthScoreType_ReturnsOk() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("", "RISK");
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @Test
    public void doCheckHealthScoreThreshold_HealthScoreType_EmptyValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckHealthScoreThreshold_HealthScoreType_NullValue_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold(null, "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckHealthScoreThreshold_HealthScoreType_InvalidInteger_ReturnsError() {
        FormValidation result = getDescriptor().doCheckHealthScoreThreshold("not-a-number", "HEALTH_SCORE");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void doCheckHealthScoreThreshold_HealthScoreType_OutOfRange_ReturnsError() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHealthScoreThreshold("-1", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.ERROR, d.doCheckHealthScoreThreshold("101", "HEALTH_SCORE").kind);
    }

    @Test
    public void doCheckHealthScoreThreshold_HealthScoreType_ValidValues_ReturnOk() {
        AppknoxScanner.DescriptorImpl d = getDescriptor();
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("0", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("50", "HEALTH_SCORE").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckHealthScoreThreshold("100", "HEALTH_SCORE").kind);
    }
}
