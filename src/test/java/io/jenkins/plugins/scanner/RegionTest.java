package io.jenkins.plugins.scanner;

import org.junit.Test;

import static org.junit.Assert.*;

public class RegionTest {

    @Test
    public void allRegionsHaveCorrectValues() {
        assertEquals("global", Region.GLOBAL.getValue());
        assertEquals("uae", Region.UAE.getValue());
        assertEquals("saudi", Region.SAUDI.getValue());
        assertEquals("eu", Region.EU.getValue());
    }

    @Test
    public void allRegionsHaveCorrectDisplayNames() {
        assertEquals("Global", Region.GLOBAL.getDisplayName());
        assertEquals("UAE", Region.UAE.getDisplayName());
        assertEquals("Saudi", Region.SAUDI.getDisplayName());
        assertEquals("EU", Region.EU.getDisplayName());
    }

    @Test
    public void allRegionsHaveCorrectBaseUrls() {
        assertEquals("https://secure.appknox.com/", Region.GLOBAL.getBaseUrl());
        assertEquals("https://secure.uae.appknox.com/", Region.UAE.getBaseUrl());
        assertEquals("https://sa.secure.appknox.com/", Region.SAUDI.getBaseUrl());
        assertEquals("https://eu.secure.appknox.com/", Region.EU.getBaseUrl());
    }

    @Test
    public void getDefault_ReturnsGlobal() {
        assertEquals(Region.GLOBAL, Region.getDefault());
    }

    @Test
    public void fromValue_NullReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue(null));
    }

    @Test
    public void fromValue_EmptyReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue(""));
    }

    @Test
    public void fromValue_KnownValuesReturnCorrectRegion() {
        assertEquals(Region.GLOBAL, Region.fromValue("global"));
        assertEquals(Region.UAE, Region.fromValue("uae"));
        assertEquals(Region.SAUDI, Region.fromValue("saudi"));
        assertEquals(Region.EU, Region.fromValue("eu"));
    }

    @Test
    public void fromValue_CaseInsensitive() {
        assertEquals(Region.GLOBAL, Region.fromValue("GLOBAL"));
        assertEquals(Region.UAE, Region.fromValue("UAE"));
        assertEquals(Region.SAUDI, Region.fromValue("SAUDI"));
        assertEquals(Region.EU, Region.fromValue("EU"));
    }

    @Test
    public void fromValue_UnknownValueReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue("unknown"));
        assertEquals(Region.GLOBAL, Region.fromValue("us-east"));
    }

    @Test
    public void fourRegionsExist() {
        assertEquals(4, Region.values().length);
    }
}
