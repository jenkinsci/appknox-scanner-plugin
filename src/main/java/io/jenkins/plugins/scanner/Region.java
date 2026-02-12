package io.jenkins.plugins.scanner;

/**
 * Enum representing the available Appknox regions.
 * Each region has a value (used for CLI), display name (for UI), and base URL.
 */
public enum Region {
    GLOBAL("global", "Global", "https://secure.appknox.com/"),
    UAE("uae", "UAE", "https://secure.uae.appknox.com/"),
    SAUDI("saudi", "Saudi", "https://sa.secure.appknox.com/");

    private final String value;
    private final String displayName;
    private final String baseUrl;

    Region(String value, String displayName, String baseUrl) {
        this.value = value;
        this.displayName = displayName;
        this.baseUrl = baseUrl;
    }

    public String getValue() {
        return value;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public static Region getDefault() {
        return GLOBAL;
    }

    /**
     * Finds a Region by its value string (case-insensitive).
     * Returns the default region if no match is found.
     */
    public static Region fromValue(String value) {
        if (value == null || value.isEmpty()) {
            return getDefault();
        }
        for (Region region : values()) {
            if (region.value.equalsIgnoreCase(value)) {
                return region;
            }
        }
        return getDefault();
    }
}
