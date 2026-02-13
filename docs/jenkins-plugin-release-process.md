# 5. Release & Versioning Process

This section documents how to release the Appknox Scanner Jenkins plugin to the Jenkins Update Center.

---

## 5.1 Version Format

The plugin uses **Semantic Versioning** with Maven properties:

| Property | Description | Example |
|----------|-------------|---------|
| `revision` | Base version number | `1.0.4` |
| `changelist` | Development suffix | `-SNAPSHOT` |

**Version during development:** `1.0.4-SNAPSHOT`
**Version after release:** `1.0.4`

---

## 5.2 Prerequisites

Before releasing, ensure you have:

1. **Write access** to `jenkinsci/appknox-scanner-plugin` repository
2. **Maven credentials** for `repo.jenkins-ci.org` configured in `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>maven.jenkins-ci.org</id>
      <username>YOUR_JENKINS_USERNAME</username>
      <password>YOUR_JENKINS_API_TOKEN</password>
    </server>
  </servers>
</settings>
```

> **Note:** Get your API token from [Jenkins Artifactory](https://repo.jenkins-ci.org/)

---

## 5.3 Release Steps

### Step 1: Prepare Your Branch

```bash
# Switch to main branch
git checkout main

# Pull latest changes
git pull origin main

# Ensure clean working directory
git status
```

### Step 2: Update Version (if needed)

If the version in `pom.xml` needs to be bumped before release:

```bash
# Edit pom.xml line 36
# Change: <revision>1.0.4</revision>
# To:     <revision>1.0.5</revision>

git add pom.xml
git commit -m "Bump version to 1.0.5-SNAPSHOT"
git push origin main
```

### Step 3: Run Maven Release

```bash
mvn release:prepare release:perform -B \
  -DreleaseVersion=1.0.4 \
  -DdevelopmentVersion=1.0.5-SNAPSHOT \
  -Dtag=appknox-scanner-1.0.4
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-B` | Batch mode (non-interactive) |
| `-DreleaseVersion` | Version to release (without SNAPSHOT) |
| `-DdevelopmentVersion` | Next development version |
| `-Dtag` | Git tag name for the release |

---

## 5.4 What the Release Does

The Maven Release Plugin automatically performs these steps:

| Step | Action |
|------|--------|
| 1 | Updates `pom.xml` version from `1.0.4-SNAPSHOT` to `1.0.4` |
| 2 | Commits the version change |
| 3 | Creates git tag `appknox-scanner-1.0.4` |
| 4 | Builds the plugin (`.hpi` file) |
| 5 | Deploys artifacts to `repo.jenkins-ci.org` |
| 6 | Updates `pom.xml` to next SNAPSHOT version (`1.0.5-SNAPSHOT`) |
| 7 | Commits and pushes all changes |

---

## 5.5 Artifacts Deployed

The following files are uploaded to `https://repo.jenkins-ci.org/releases/io/jenkins/plugins/appknox-scanner/{version}/`:

| File | Description |
|------|-------------|
| `appknox-scanner-{version}.hpi` | Plugin binary (installable in Jenkins) |
| `appknox-scanner-{version}.jar` | Java JAR file |
| `appknox-scanner-{version}.pom` | Maven POM file |
| `appknox-scanner-{version}-sources.jar` | Source code |
| `appknox-scanner-{version}-javadoc.jar` | Javadoc documentation |

---

## 5.6 Verify the Release

### Check Git Tags

```bash
git tag -l | sort -V | tail -5
```

Expected output:
```
appknox-scanner-1.0.1
appknox-scanner-1.0.2
appknox-scanner-1.0.3
appknox-scanner-1.0.4
```

### Check Jenkins Update Center

1. Visit: https://plugins.jenkins.io/appknox-scanner/
2. Verify the new version appears

### Check Maven Repository

Visit: `https://repo.jenkins-ci.org/releases/io/jenkins/plugins/appknox-scanner/`

### Test in Jenkins

1. Go to **Manage Jenkins** → **Plugins** → **Updates**
2. Search for "appknox"
3. Update/install the plugin
4. Verify functionality

---

## 5.7 Release Tag Naming Convention

| Pattern | Example |
|---------|---------|
| `appknox-scanner-{major}.{minor}.{patch}` | `appknox-scanner-1.0.4` |

---

## 5.8 Troubleshooting

### Authentication Failed

```
[ERROR] Failed to deploy artifacts: Could not transfer artifact
```

**Solution:** Verify `~/.m2/settings.xml` has correct credentials for `maven.jenkins-ci.org`

### Tag Already Exists

```
[ERROR] tag appknox-scanner-1.0.4 already exists
```

**Solution:** Either delete the tag or use a different version number:
```bash
git tag -d appknox-scanner-1.0.4
git push origin :refs/tags/appknox-scanner-1.0.4
```

### Release Plugin Cleanup

If release fails midway, clean up:
```bash
mvn release:clean
git reset --hard HEAD~1
```

---

## 5.9 Release Checklist

- [ ] All changes merged to `main` branch
- [ ] Tests passing locally (`mvn test`)
- [ ] Version number updated in `pom.xml` if needed
- [ ] Maven credentials configured
- [ ] Run `mvn release:prepare release:perform`
- [ ] Verify tag created in GitHub
- [ ] Verify plugin appears in Jenkins Update Center
- [ ] Test plugin installation in Jenkins

---

## 5.10 Related Links

| Resource | URL |
|----------|-----|
| Plugin Page | https://plugins.jenkins.io/appknox-scanner/ |
| GitHub Repository | https://github.com/jenkinsci/appknox-scanner-plugin |
| Maven Repository | https://repo.jenkins-ci.org/releases/io/jenkins/plugins/appknox-scanner/ |
| Jenkins Plugin Documentation | https://www.jenkins.io/doc/developer/publishing/releasing/ |
