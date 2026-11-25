package dev.cordon.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DecisionParserTest {
    private val decision = """
        {"state": "BLOCK", "reason_codes": ["R400"],
         "explanation": {"summary": "a known malicious package", "reasons": []}}
    """.trimIndent()

    @Test
    fun theIdeAsksAtItsOwnPoint() {
        assertEquals(listOf("decide", "--point", "ide"), DecisionParser.args())
        assertEquals(listOf("decide", "--point", "cli"), DecisionParser.args("cli"))
    }

    @Test
    fun readsTheStateTheCodesAndTheSummary() {
        assertEquals(
            Decision("BLOCK", listOf("R400"), "a known malicious package"),
            DecisionParser.parse(decision),
        )
    }

    @Test
    fun refusesAnAnswerThatIsNotADecision() {
        assertThrows(IllegalArgumentException::class.java) { DecisionParser.parse("{}") }
        assertThrows(IllegalArgumentException::class.java) { DecisionParser.parse("[1]") }
    }
}
