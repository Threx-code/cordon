package dev.cordon.jetbrains

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.openapi.progress.ProgressIndicator
import java.io.File
import java.nio.charset.StandardCharsets

/** Runs the cordon-scanner the user installed. Never a shell: every value is its own argument. Run
 * from the system temp directory, never the project, so a planted executable there is not found. */
object Scanner {
    private const val SCAN_TIMEOUT_MS = 5 * 60 * 1000
    private const val SHORT_TIMEOUT_MS = 30 * 1000

    class ScannerException(message: String) : Exception(message)

    private fun command(executable: String, vararg args: String): GeneralCommandLine =
        GeneralCommandLine(executable, *args)
            .withWorkDirectory(File(System.getProperty("java.io.tmpdir")))
            .withCharset(StandardCharsets.UTF_8)
            .withEnvironment("NO_COLOR", "1")

    /** `cordon-scanner --version`, or null when it cannot be run. */
    fun version(executable: String): String? = try {
        val out = CapturingProcessHandler(command(executable, "--version")).runProcess(SHORT_TIMEOUT_MS)
        if (out.exitCode == 0 && !out.isTimeout) out.stdout.trim().ifEmpty { null } else null
    } catch (_: Exception) {
        null
    }

    /** Scan a folder offline; exit 1 means findings at or above the gate, which is a result. */
    fun scan(executable: String, root: String, indicator: ProgressIndicator?): Report {
        val handler = CapturingProcessHandler(
            command(executable, "scan", root, "--format", "json", "--quiet", "--no-color", "--offline"),
        )
        val out = if (indicator != null) {
            handler.runProcessWithProgressIndicator(indicator, SCAN_TIMEOUT_MS)
        } else {
            handler.runProcess(SCAN_TIMEOUT_MS)
        }
        if (out.isCancelled) throw ScannerException("the scan was cancelled")
        if (out.isTimeout) throw ScannerException("the scan passed its five-minute deadline")
        if (out.exitCode != 0 && out.exitCode != 1 && out.exitCode != 4) {
            throw ScannerException(out.stderr.trim().ifEmpty { "cordon-scanner exited with ${out.exitCode}" })
        }
        return ReportParser.parse(out.stdout)
    }

    /** The MCP configuration for JetBrains AI Assistant, as the scanner prints it. */
    fun mcpConfig(executable: String): String {
        val out = CapturingProcessHandler(command(executable, "mcp", "config", "--client", "jetbrains"))
            .runProcess(SHORT_TIMEOUT_MS)
        if (out.exitCode != 0) throw ScannerException(out.stderr.trim().ifEmpty { "could not print the configuration" })
        return out.stdout.lines().filterNot { it.startsWith("#") }.joinToString("\n").trim()
    }
}
