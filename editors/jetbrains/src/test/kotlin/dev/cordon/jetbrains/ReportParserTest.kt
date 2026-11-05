package dev.cordon.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class ReportParserTest {
    private val report = """
        {"complete": false, "findings": [
          {"rule_id": "A.1", "severity": "HIGH", "category": "malicious", "message": "m",
           "remediation": "r", "location": {"path": "src/a.py", "line": 3, "column": 5}},
          {"rule_id": "B.2", "severity": "low", "category": "operational", "message": "x",
           "location": {"path": ""}},
          {"rule_id": 7, "severity": "high"},
          "not an object",
          {"rule_id": "C.3", "severity": "info", "location": {"line": "three"}}
        ]}
    """.trimIndent()

    @Test
    fun readsFindingsAndSkipsMalformedOnes() {
        val parsed = ReportParser.parse(report)
        assertEquals(false, parsed.complete)
        assertEquals(listOf("A.1", "B.2", "C.3"), parsed.findings.map { it.ruleId })
        val first = parsed.findings[0]
        assertEquals("high", first.severity)
        assertEquals(2, first.line)
        assertEquals(4, first.column)
        assertTrue(parsed.findings[1].operational)
        assertEquals(0, parsed.findings[2].line)
    }

    @Test
    fun filtersBySeverity() {
        val parsed = ReportParser.parse(report)
        assertEquals(listOf("A.1", "B.2"), ReportParser.atLeast(parsed.findings, "low").map { it.ruleId })
        assertEquals(listOf("A.1"), ReportParser.atLeast(parsed.findings, "high").map { it.ruleId })
    }

    @Test
    fun refusesOutputThatIsNotAnObject() {
        assertThrows(IllegalArgumentException::class.java) { ReportParser.parse("[1, 2]") }
    }

    @Test
    fun pathsMayNotLeaveTheProject() {
        val root = Files.createTempDirectory("cordon-test")
        assertEquals(root.resolve("src/a.py").normalize(), ReportParser.contained(root, "src/a.py"))
        assertNull(ReportParser.contained(root, "../outside.txt"))
        assertNull(ReportParser.contained(root, "src/../../outside.txt"))
        assertNull(ReportParser.contained(root, "/etc/passwd"))
        assertNull(ReportParser.contained(root, ""))
        assertNull(ReportParser.contained(root, "."))
        assertNull(ReportParser.contained(root, "a\u0000b"))
    }
}
