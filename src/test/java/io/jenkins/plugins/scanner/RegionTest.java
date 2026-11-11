package io.jenkins.plugins.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RegionTest {

    @Test
    void allRegionsHaveCorrectValues() {
        assertEquals("global", Region.GLOBAL.getValue());
        assertEquals("uae", Region.UAE.getValue());
        assertEquals("saudi", Region.SAUDI.getValue());
        assertEquals("eu", Region.EU.getValue());
    }

    @Test
    void allRegionsHaveCorrectDisplayNames() {
        assertEquals("Global", Region.GLOBAL.getDisplayName());
        assertEquals("UAE", Region.UAE.getDisplayName());
        assertEquals("Saudi", Region.SAUDI.getDisplayName());
        assertEquals("EU", Region.EU.getDisplayName());
    }

    @Test
    void allRegionsHaveCorrectBaseUrls() {
        assertEquals("https://secure.appknox.com/", Region.GLOBAL.getBaseUrl());
        assertEquals("https://secure.uae.appknox.com/", Region.UAE.getBaseUrl());
        assertEquals("https://sa.secure.appknox.com/", Region.SAUDI.getBaseUrl());
        assertEquals("https://eu.secure.appknox.com/", Region.EU.getBaseUrl());
    }

    @Test
    void getDefault_ReturnsGlobal() {
        assertEquals(Region.GLOBAL, Region.getDefault());
    }

    @Test
    void fromValue_NullReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue(null));
    }

    @Test
    void fromValue_EmptyReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue(""));
    }

    @Test
    void fromValue_KnownValuesReturnCorrectRegion() {
        assertEquals(Region.GLOBAL, Region.fromValue("global"));
        assertEquals(Region.UAE, Region.fromValue("uae"));
        assertEquals(Region.SAUDI, Region.fromValue("saudi"));
        assertEquals(Region.EU, Region.fromValue("eu"));
    }

    @Test
    void fromValue_CaseInsensitive() {
        assertEquals(Region.GLOBAL, Region.fromValue("GLOBAL"));
        assertEquals(Region.UAE, Region.fromValue("UAE"));
        assertEquals(Region.SAUDI, Region.fromValue("SAUDI"));
        assertEquals(Region.EU, Region.fromValue("EU"));
    }

    @Test
    void fromValue_UnknownValueReturnsDefault() {
        assertEquals(Region.GLOBAL, Region.fromValue("unknown"));
        assertEquals(Region.GLOBAL, Region.fromValue("us-east"));
    }

    @Test
    void fourRegionsExist() {
        assertEquals(4, Region.values().length);
    }
}
