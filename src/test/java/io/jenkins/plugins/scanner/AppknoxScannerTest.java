package io.jenkins.plugins.scanner;

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

        // No items should be selected when parameter is null
        long selectedCount = items.stream().filter(opt -> opt.selected).count();
        assertEquals(0, selectedCount);
    }
}
