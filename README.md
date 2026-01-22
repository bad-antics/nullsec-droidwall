# NullSec DroidWall

<div align="center">

```
██████╗ ██████╗  ██████╗ ██╗██████╗ ██╗    ██╗ █████╗ ██╗     ██╗     
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██║    ██║██╔══██╗██║     ██║     
██║  ██║██████╔╝██║   ██║██║██║  ██║██║ █╗ ██║███████║██║     ██║     
██║  ██║██╔══██╗██║   ██║██║██║  ██║██║███╗██║██╔══██║██║     ██║     
██████╔╝██║  ██║╚██████╔╝██║██████╔╝╚███╔███╔╝██║  ██║███████╗███████╗
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**Hardened Android Security Analyzer in Kotlin**

[![Kotlin](https://img.shields.io/badge/Kotlin-1.9+-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)](https://kotlinlang.org/)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://android.com/)
[![Security](https://img.shields.io/badge/Security-Maximum-red?style=for-the-badge)](https://github.com/bad-antics)
[![NullSec](https://img.shields.io/badge/NullSec-Framework-purple?style=for-the-badge)](https://github.com/bad-antics)

</div>

## Security Hardening Features

### Kotlin Null Safety
- `?` operator for nullable types
- `?.let {}` for safe calls
- `?:` Elvis operator for defaults
- `!!` only where proven safe

### Sealed Classes for Exhaustive Matching
```kotlin
sealed class ThreatLevel(val severity: Int) {
    object Critical : ThreatLevel(5)
    object High : ThreatLevel(4)
    object Medium : ThreatLevel(3)
    object Low : ThreatLevel(2)
    object Info : ThreatLevel(1)
}

sealed class AnalysisError : Exception() {
    data class FileNotFound(val path: String) : AnalysisError()
    data class AccessDenied(val resource: String) : AnalysisError()
    // ... compiler enforces handling all cases
}
```

### Inline Value Classes (Zero Runtime Overhead)
```kotlin
@JvmInline
value class ValidatedPath private constructor(val path: String) {
    companion object {
        fun create(rawPath: String): Result<ValidatedPath>
    }
}
```

### Coroutines for Async Analysis
```kotlin
suspend fun analyzeFile(path: ValidatedPath): Result<List<SecurityFinding>>

fun scanDirectory(dirPath: ValidatedPath): Flow<SecurityFinding>
```

## Detection Capabilities

| Category | Detection |
|----------|-----------|
| Permissions | Dangerous Android permissions with risk levels |
| Entropy | High entropy files (packed/encrypted) |
| Code Patterns | Suspicious strings, dynamic loading |
| Malware | Known malware package signatures |

## Build

```bash
# Build with Gradle
./gradlew build

# Create fat JAR
./gradlew jar

# Run
java -jar build/libs/nullsec-droidwall-1.0.0.jar <target>
```

## Usage

```bash
# Analyze APK file
droidwall /path/to/suspicious.apk

# Scan directory
droidwall --scan-dir /data/data/com.app --max-depth 3

# Check package name
droidwall com.suspicious.package
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   NullSec DroidWall                         │
├─────────────────────────────────────────────────────────────┤
│  Inline Value Classes (Type Safety)                         │
│  ├── ValidatedPath (path validation)                       │
│  └── ValidatedPackage (Android package validation)         │
├─────────────────────────────────────────────────────────────┤
│  Sealed Error Hierarchy                                     │
│  └── AnalysisError (FileNotFound | AccessDenied | ...)     │
├─────────────────────────────────────────────────────────────┤
│  Coroutine-Based Analysis                                   │
│  ├── analyzeFile (suspend function)                        │
│  └── scanDirectory (Flow producer)                         │
├─────────────────────────────────────────────────────────────┤
│  Thread-Safe Collections                                    │
│  ├── RateLimiter (AtomicInteger)                           │
│  └── ResultAccumulator (ConcurrentHashMap)                 │
└─────────────────────────────────────────────────────────────┘
```

## Permission Risk Database

```kotlin
"android.permission.SEND_SMS" to PermissionRisk(
    permission = "android.permission.SEND_SMS",
    category = "Financial",
    riskLevel = ThreatLevel.Critical,
    description = "Can send SMS to premium numbers"
)
```

## License

NullSec Proprietary - Part of the NullSec Security Framework


## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Discord: [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**Part of the NullSec Security Framework**

</div>
