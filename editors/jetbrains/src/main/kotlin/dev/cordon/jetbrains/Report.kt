package dev.cordon.jetbrains

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.file.Path

/** One finding, as the editor shows it. Line and column are zero-based. */
data class Finding(
    val ruleId: String,
    val severity: String,
    val message: String,
    val remediation: String,
    val path: String?,
    val line: Int,
    val column: Int,
    val operational: Boolean,
)

data class Report(val complete: Boolean, val findings: List<Finding>)

/** The scanner's JSON result (`cordon-scanner scan --format json`), read defensively: a field of
 * the wrong type is treated as absent, never as a reason to fail the whole report. */
object ReportParser {
    val SEVERITIES = listOf("info", "low", "medium", "high", "critical")

    fun parse(text: String): Report {
        val root = JsonParser.parseString(text)
        if (!root.isJsonObject) throw IllegalArgumentException("the scanner's output is not a JSON object")
        val document = root.asJsonObject
        val complete = document.boolean("complete") ?: true
        val findings = document.array("findings").mapNotNull { element ->
            val item = element.objectOrNull() ?: return@mapNotNull null
            val location = item.objectAt("location")
            Finding(
                ruleId = item.string("rule_id") ?: return@mapNotNull null,
                severity = (item.string("severity") ?: "info").lowercase(),
                message = item.string("message") ?: "",
                remediation = item.string("remediation") ?: "",
                path = location?.string("path"),
                line = maxOf(0, (location?.int("line") ?: 1) - 1),
                column = maxOf(0, (location?.int("column") ?: 1) - 1),
                operational = item.string("category") == "operational",
            )
        }
        return Report(complete, findings)
    }

    fun atLeast(findings: List<Finding>, minimum: String): List<Finding> {
        val floor = SEVERITIES.indexOf(minimum).coerceAtLeast(0)
        return findings.filter { SEVERITIES.indexOf(it.severity) >= floor }
    }

    /** The absolute file a finding names, or null when its path would leave the scanned folder: a
     * report is data from a scan, and a path in it must never point the editor elsewhere. */
    fun contained(root: Path, relative: String?): Path? {
        if (relative.isNullOrBlank() || relative.contains('\u0000')) return null
        val base = root.toAbsolutePath().normalize()
        val target = try {
            base.resolve(relative).normalize()
        } catch (_: java.nio.file.InvalidPathException) {
            return null
        }
        return if (target.startsWith(base) && target != base) target else null
    }

    private fun JsonObject.string(key: String): String? =
        get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    private fun JsonObject.boolean(key: String): Boolean? =
        get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean

    private fun JsonObject.int(key: String): Int? =
        get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asInt

    private fun JsonObject.objectAt(key: String): JsonObject? = get(key)?.objectOrNull()

    private fun JsonObject.array(key: String): List<JsonElement> =
        get(key)?.takeIf { it.isJsonArray }?.asJsonArray?.toList() ?: emptyList()

    private fun JsonElement.objectOrNull(): JsonObject? = if (isJsonObject) asJsonObject else null
}
