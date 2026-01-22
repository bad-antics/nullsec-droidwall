/**
 * NullSec DroidWall - Hardened Android Security Analyzer
 * Language: Kotlin (Modern JVM with Null Safety)
 * Author: bad-antics
 * License: NullSec Proprietary
 * Security Level: Maximum Hardening
 *
 * Features:
 * - Null safety with ? and !! operators
 * - Sealed classes for exhaustive when expressions
 * - Data classes for immutable value types
 * - Extension functions for clean API
 * - Coroutines for async operations
 * - Inline classes for type safety
 * - Smart casts for safe type handling
 */

package com.nullsec.droidwall

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.ln

// ============================================================================
// Constants
// ============================================================================

const val VERSION = "1.0.0"

val BANNER = """
██████╗ ██████╗  ██████╗ ██╗██████╗ ██╗    ██╗ █████╗ ██╗     ██╗     
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██║    ██║██╔══██╗██║     ██║     
██║  ██║██████╔╝██║   ██║██║██║  ██║██║ █╗ ██║███████║██║     ██║     
██║  ██║██╔══██╗██║   ██║██║██║  ██║██║███╗██║██╔══██║██║     ██║     
██████╔╝██║  ██║╚██████╔╝██║██████╔╝╚███╔███╔╝██║  ██║███████╗███████╗
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                       bad-antics • v$VERSION
═══════════════════════════════════════════════════════════════════════
""".trimIndent()

// Security constants
object SecurityConfig {
    const val MAX_PATH_LENGTH = 4096
    const val MAX_FILE_SIZE = 100 * 1024 * 1024L // 100MB
    const val MAX_PACKAGE_NAME_LENGTH = 256
    const val ENTROPY_THRESHOLD = 7.5
    const val MAX_RESULTS = 10000
    const val RATE_LIMIT_PER_SECOND = 100
}

// ============================================================================
// Inline Classes for Type Safety (Zero Overhead at Runtime)
// ============================================================================

@JvmInline
value class ValidatedPath private constructor(val path: String) {
    companion object {
        fun create(rawPath: String): Result<ValidatedPath> {
            return when {
                rawPath.isBlank() -> Result.failure(SecurityException("Empty path"))
                rawPath.length > SecurityConfig.MAX_PATH_LENGTH -> 
                    Result.failure(SecurityException("Path too long: ${rawPath.length}"))
                rawPath.contains("..") -> 
                    Result.failure(SecurityException("Path traversal detected"))
                rawPath.contains("\u0000") -> 
                    Result.failure(SecurityException("Null byte in path"))
                rawPath.any { it in listOf(';', '|', '`', '$', '&') } ->
                    Result.failure(SecurityException("Injection character detected"))
                else -> Result.success(ValidatedPath(rawPath))
            }
        }
    }
    
    fun exists(): Boolean = File(path).exists()
    fun isDirectory(): Boolean = File(path).isDirectory
    fun isFile(): Boolean = File(path).isFile
}

@JvmInline
value class ValidatedPackage private constructor(val name: String) {
    companion object {
        private val PACKAGE_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)*$")
        
        fun create(rawName: String): Result<ValidatedPackage> {
            return when {
                rawName.isBlank() -> Result.failure(SecurityException("Empty package name"))
                rawName.length > SecurityConfig.MAX_PACKAGE_NAME_LENGTH ->
                    Result.failure(SecurityException("Package name too long"))
                !PACKAGE_REGEX.matches(rawName) ->
                    Result.failure(SecurityException("Invalid package name format"))
                else -> Result.success(ValidatedPackage(rawName))
            }
        }
    }
}

// ============================================================================
// Sealed Classes for Exhaustive Pattern Matching
// ============================================================================

sealed class ThreatLevel(val severity: Int, val name: String, val colorCode: String) {
    object Critical : ThreatLevel(5, "CRITICAL", "\u001B[31m")
    object High : ThreatLevel(4, "HIGH", "\u001B[33m")
    object Medium : ThreatLevel(3, "MEDIUM", "\u001B[36m")
    object Low : ThreatLevel(2, "LOW", "\u001B[37m")
    object Info : ThreatLevel(1, "INFO", "\u001B[32m")
    
    companion object {
        const val RESET = "\u001B[0m"
    }
}

sealed class AnalysisError : Exception() {
    data class FileNotFound(val path: String) : AnalysisError()
    data class AccessDenied(val resource: String) : AnalysisError()
    data class InvalidFormat(val reason: String) : AnalysisError()
    data class SizeExceeded(val size: Long, val max: Long) : AnalysisError()
    data class ValidationFailed(val field: String, val reason: String) : AnalysisError()
    object RateLimitExceeded : AnalysisError()
    
    override val message: String
        get() = when (this) {
            is FileNotFound -> "File not found: $path"
            is AccessDenied -> "Access denied: $resource"
            is InvalidFormat -> "Invalid format: $reason"
            is SizeExceeded -> "Size exceeded: $size > $max"
            is ValidationFailed -> "Validation failed for $field: $reason"
            RateLimitExceeded -> "Rate limit exceeded"
        }
}

// ============================================================================
// Data Classes for Immutable Value Types
// ============================================================================

data class SecurityFinding(
    val category: String,
    val description: String,
    val path: String,
    val threat: ThreatLevel,
    val timestamp: Long = System.currentTimeMillis(),
    val metadata: Map<String, String> = emptyMap()
) {
    fun format(): String {
        return "[${threat.colorCode}${threat.name}${ThreatLevel.RESET}] $category: $description ($path)"
    }
}

data class ApkInfo(
    val packageName: ValidatedPackage,
    val versionName: String,
    val versionCode: Int,
    val permissions: List<String>,
    val activities: List<String>,
    val services: List<String>,
    val receivers: List<String>,
    val providers: List<String>,
    val minSdkVersion: Int,
    val targetSdkVersion: Int,
    val sha256Hash: String
)

data class PermissionRisk(
    val permission: String,
    val category: String,
    val riskLevel: ThreatLevel,
    val description: String
)

// ============================================================================
// Rate Limiter with Atomic Operations
// ============================================================================

class RateLimiter(
    private val maxTokens: Int = SecurityConfig.RATE_LIMIT_PER_SECOND,
    private val refillRatePerSecond: Int = 10
) {
    private val tokens = AtomicInteger(maxTokens)
    @Volatile private var lastRefillTime = System.currentTimeMillis()
    
    @Synchronized
    fun tryAcquire(): Boolean {
        refillTokens()
        return if (tokens.get() > 0) {
            tokens.decrementAndGet()
            true
        } else {
            false
        }
    }
    
    private fun refillTokens() {
        val now = System.currentTimeMillis()
        val elapsed = now - lastRefillTime
        val newTokens = (elapsed * refillRatePerSecond / 1000).toInt()
        if (newTokens > 0) {
            tokens.updateAndGet { current -> minOf(maxTokens, current + newTokens) }
            lastRefillTime = now
        }
    }
}

// ============================================================================
// Thread-Safe Result Accumulator
// ============================================================================

class ResultAccumulator(private val maxResults: Int = SecurityConfig.MAX_RESULTS) {
    private val findings = ConcurrentHashMap<Long, SecurityFinding>()
    private val counter = AtomicInteger(0)
    
    fun add(finding: SecurityFinding): Boolean {
        if (counter.get() >= maxResults) return false
        val id = counter.getAndIncrement().toLong()
        findings[id] = finding
        return true
    }
    
    fun addAll(newFindings: List<SecurityFinding>) {
        newFindings.forEach { add(it) }
    }
    
    fun getAllFindings(): List<SecurityFinding> = 
        findings.values.toList().sortedByDescending { it.threat.severity }
    
    fun criticalCount(): Int = 
        findings.values.count { it.threat == ThreatLevel.Critical }
    
    fun highCount(): Int = 
        findings.values.count { it.threat == ThreatLevel.High }
}

// ============================================================================
// Dangerous Permission Database
// ============================================================================

object PermissionDatabase {
    private val dangerousPermissions = mapOf(
        "android.permission.READ_SMS" to PermissionRisk(
            "android.permission.READ_SMS", "Privacy", ThreatLevel.High,
            "Can read all SMS messages including 2FA codes"
        ),
        "android.permission.RECEIVE_SMS" to PermissionRisk(
            "android.permission.RECEIVE_SMS", "Privacy", ThreatLevel.High,
            "Can intercept incoming SMS messages"
        ),
        "android.permission.SEND_SMS" to PermissionRisk(
            "android.permission.SEND_SMS", "Financial", ThreatLevel.Critical,
            "Can send SMS to premium numbers causing charges"
        ),
        "android.permission.READ_CONTACTS" to PermissionRisk(
            "android.permission.READ_CONTACTS", "Privacy", ThreatLevel.Medium,
            "Can read all contact information"
        ),
        "android.permission.READ_CALL_LOG" to PermissionRisk(
            "android.permission.READ_CALL_LOG", "Privacy", ThreatLevel.High,
            "Can read call history"
        ),
        "android.permission.RECORD_AUDIO" to PermissionRisk(
            "android.permission.RECORD_AUDIO", "Surveillance", ThreatLevel.Critical,
            "Can record audio/conversations"
        ),
        "android.permission.CAMERA" to PermissionRisk(
            "android.permission.CAMERA", "Surveillance", ThreatLevel.High,
            "Can take photos and record video"
        ),
        "android.permission.ACCESS_FINE_LOCATION" to PermissionRisk(
            "android.permission.ACCESS_FINE_LOCATION", "Tracking", ThreatLevel.High,
            "Can track precise device location"
        ),
        "android.permission.READ_EXTERNAL_STORAGE" to PermissionRisk(
            "android.permission.READ_EXTERNAL_STORAGE", "Privacy", ThreatLevel.Medium,
            "Can read files from shared storage"
        ),
        "android.permission.WRITE_EXTERNAL_STORAGE" to PermissionRisk(
            "android.permission.WRITE_EXTERNAL_STORAGE", "Integrity", ThreatLevel.Medium,
            "Can write/modify files on shared storage"
        ),
        "android.permission.SYSTEM_ALERT_WINDOW" to PermissionRisk(
            "android.permission.SYSTEM_ALERT_WINDOW", "UI Attack", ThreatLevel.Critical,
            "Can draw over other apps (tapjacking)"
        ),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to PermissionRisk(
            "android.permission.BIND_ACCESSIBILITY_SERVICE", "System", ThreatLevel.Critical,
            "Can monitor and control entire UI"
        ),
        "android.permission.BIND_DEVICE_ADMIN" to PermissionRisk(
            "android.permission.BIND_DEVICE_ADMIN", "System", ThreatLevel.Critical,
            "Can become device administrator"
        ),
        "android.permission.REQUEST_INSTALL_PACKAGES" to PermissionRisk(
            "android.permission.REQUEST_INSTALL_PACKAGES", "System", ThreatLevel.High,
            "Can request to install other apps"
        )
    )
    
    fun getRisk(permission: String): PermissionRisk? = dangerousPermissions[permission]
    fun getAllRisks(): List<PermissionRisk> = dangerousPermissions.values.toList()
}

// ============================================================================
// Analysis Functions
// ============================================================================

// Extension function for calculating entropy
fun ByteArray.calculateEntropy(): Double {
    if (isEmpty()) return 0.0
    
    val freq = IntArray(256)
    forEach { freq[it.toInt() and 0xFF]++ }
    
    return freq.filter { it > 0 }
        .map { it.toDouble() / size }
        .sumOf { p -> -p * ln(p) / ln(2.0) }
}

// Extension function for SHA256 hash
fun ByteArray.sha256(): String {
    return MessageDigest.getInstance("SHA-256")
        .digest(this)
        .joinToString("") { "%02x".format(it) }
}

// Suspend function for async file analysis
suspend fun analyzeFile(path: ValidatedPath): Result<List<SecurityFinding>> = 
    withContext(Dispatchers.IO) {
        runCatching {
            val findings = mutableListOf<SecurityFinding>()
            val file = File(path.path)
            
            if (!file.exists()) {
                throw AnalysisError.FileNotFound(path.path)
            }
            
            if (file.length() > SecurityConfig.MAX_FILE_SIZE) {
                throw AnalysisError.SizeExceeded(file.length(), SecurityConfig.MAX_FILE_SIZE)
            }
            
            val content = file.readBytes()
            val entropy = content.calculateEntropy()
            
            // Check for high entropy (potential encryption/packing)
            if (entropy > SecurityConfig.ENTROPY_THRESHOLD) {
                findings.add(SecurityFinding(
                    category = "HIGH_ENTROPY",
                    description = "File has suspicious entropy: %.2f bits/byte".format(entropy),
                    path = path.path,
                    threat = ThreatLevel.Medium,
                    metadata = mapOf("entropy" to entropy.toString())
                ))
            }
            
            // Check for suspicious strings
            val contentStr = content.decodeToString(throwOnInvalidSequence = false)
            val suspiciousPatterns = listOf(
                "su" to "Potential root access",
                "chmod 777" to "Dangerous permission change",
                "/system/bin" to "System binary access",
                "getRuntime" to "Runtime execution",
                "ProcessBuilder" to "Process spawning",
                "DexClassLoader" to "Dynamic code loading",
                "Base64.decode" to "Base64 decoding (potential obfuscation)",
                "Cipher" to "Cryptographic operations",
                "javax.crypto" to "Encryption usage"
            )
            
            suspiciousPatterns.forEach { (pattern, description) ->
                if (contentStr.contains(pattern, ignoreCase = true)) {
                    findings.add(SecurityFinding(
                        category = "SUSPICIOUS_CODE",
                        description = "$description: found '$pattern'",
                        path = path.path,
                        threat = ThreatLevel.Medium
                    ))
                }
            }
            
            findings
        }
    }

// Analyze permissions for an app
fun analyzePermissions(permissions: List<String>): List<SecurityFinding> {
    return permissions.mapNotNull { permission ->
        PermissionDatabase.getRisk(permission)?.let { risk ->
            SecurityFinding(
                category = "DANGEROUS_PERMISSION",
                description = "${risk.description} [$permission]",
                path = "AndroidManifest.xml",
                threat = risk.riskLevel,
                metadata = mapOf("permission" to permission, "category" to risk.category)
            )
        }
    }
}

// Check for known malware package names
fun checkMalwarePackages(packageName: ValidatedPackage): List<SecurityFinding> {
    val knownMalware = listOf(
        "com.android.sms.trojan",
        "com.fake.banking",
        "org.malware.spy",
        "com.adware.annoying"
    )
    
    return if (knownMalware.any { packageName.name.startsWith(it) }) {
        listOf(SecurityFinding(
            category = "KNOWN_MALWARE",
            description = "Package matches known malware signature",
            path = packageName.name,
            threat = ThreatLevel.Critical
        ))
    } else {
        emptyList()
    }
}

// ============================================================================
// Flow-based Directory Scanner
// ============================================================================

fun scanDirectory(dirPath: ValidatedPath, maxDepth: Int = 5): Flow<SecurityFinding> = flow {
    val rateLimiter = RateLimiter()
    
    suspend fun scanRecursive(dir: File, depth: Int) {
        if (depth > maxDepth) return
        if (!rateLimiter.tryAcquire()) {
            emit(SecurityFinding(
                category = "RATE_LIMITED",
                description = "Scan rate limited, pausing...",
                path = dir.path,
                threat = ThreatLevel.Info
            ))
            delay(100)
        }
        
        dir.listFiles()?.forEach { file ->
            when {
                file.isDirectory -> scanRecursive(file, depth + 1)
                file.isFile -> {
                    ValidatedPath.create(file.absolutePath).getOrNull()?.let { vpath ->
                        analyzeFile(vpath).getOrNull()?.forEach { emit(it) }
                    }
                }
            }
        }
    }
    
    val rootDir = File(dirPath.path)
    if (rootDir.isDirectory) {
        scanRecursive(rootDir, 0)
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

fun main(args: Array<String>) = runBlocking {
    println(BANNER)
    
    if (args.isEmpty()) {
        println("""
Usage: droidwall <path_or_package>

Examples:
  droidwall /sdcard/Download/suspicious.apk
  droidwall /data/data/com.suspicious.app
  droidwall com.suspicious.package

Options:
  --scan-dir <path>     Scan directory recursively
  --max-depth <n>       Maximum scan depth (default: 5)
        """.trimIndent())
        return@runBlocking
    }
    
    val results = ResultAccumulator()
    val target = args[0]
    
    println("[\u001B[36m*\u001B[0m] Analyzing: $target\n")
    
    when {
        target == "--scan-dir" && args.size >= 2 -> {
            val dirPath = ValidatedPath.create(args[1]).getOrElse {
                println("\u001B[31m[ERROR]\u001B[0m Invalid path: ${it.message}")
                return@runBlocking
            }
            
            val maxDepth = args.getOrNull(3)?.toIntOrNull() ?: 5
            println("[\u001B[36m*\u001B[0m] Scanning directory (max depth: $maxDepth)...")
            
            scanDirectory(dirPath, maxDepth)
                .collect { finding -> results.add(finding) }
        }
        
        target.endsWith(".apk") -> {
            ValidatedPath.create(target).getOrElse {
                println("\u001B[31m[ERROR]\u001B[0m Invalid path: ${it.message}")
                return@runBlocking
            }.let { vpath ->
                analyzeFile(vpath).getOrNull()?.let { results.addAll(it) }
            }
        }
        
        target.contains(".") && !target.contains("/") -> {
            // Package name
            ValidatedPackage.create(target).getOrElse {
                println("\u001B[31m[ERROR]\u001B[0m Invalid package: ${it.message}")
                return@runBlocking
            }.let { vpkg ->
                results.addAll(checkMalwarePackages(vpkg))
            }
        }
        
        else -> {
            ValidatedPath.create(target).getOrElse {
                println("\u001B[31m[ERROR]\u001B[0m Invalid path: ${it.message}")
                return@runBlocking
            }.let { vpath ->
                if (vpath.isDirectory()) {
                    scanDirectory(vpath)
                        .collect { finding -> results.add(finding) }
                } else {
                    analyzeFile(vpath).getOrNull()?.let { results.addAll(it) }
                }
            }
        }
    }
    
    // Print results
    println("═══════════════════════════════════════════════════════════════════════")
    println("                           SCAN RESULTS")
    println("═══════════════════════════════════════════════════════════════════════\n")
    
    results.getAllFindings().forEach { println(it.format()) }
    
    println("\n═══════════════════════════════════════════════════════════════════════")
    println("  Summary: ${results.criticalCount()} CRITICAL | ${results.highCount()} HIGH | ${results.getAllFindings().size} Total")
    println("═══════════════════════════════════════════════════════════════════════")
    
    when {
        results.criticalCount() > 0 -> 
            println("\n\u001B[31m[!] CRITICAL FINDINGS - IMMEDIATE ACTION REQUIRED\u001B[0m")
        results.highCount() > 0 -> 
            println("\n\u001B[33m[!] HIGH SEVERITY FINDINGS - REVIEW RECOMMENDED\u001B[0m")
        results.getAllFindings().isEmpty() -> 
            println("\n\u001B[32m[✓] No security issues detected\u001B[0m")
    }
    
    println("\n[\u001B[32m+\u001B[0m] Analysis complete.")
}
