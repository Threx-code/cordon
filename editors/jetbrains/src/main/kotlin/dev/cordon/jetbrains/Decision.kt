package dev.cordon.jetbrains

import com.google.gson.JsonParser

/** What the scanner's decision function answered: the state, the reason codes and the one-line summary. */
data class Decision(val state: String, val reasonCodes: List<String>, val summary: String)

/** The scanner's `decide` command, asked from the IDE point. The question goes to its standard input
 * as JSON and the decision comes back on standard output. */
object DecisionParser {
    fun args(point: String = "ide"): List<String> = listOf("decide", "--point", point)

    fun parse(text: String): Decision {
        val root = JsonParser.parseString(text)
        if (!root.isJsonObject) throw IllegalArgumentException("the decision is not an object")
        val document = root.asJsonObject
        val state = document.get("state")?.takeIf { it.isJsonPrimitive }?.asString
        val codes = document.get("reason_codes")?.takeIf { it.isJsonArray }
        if (state == null || codes == null) throw IllegalArgumentException("the answer is not a decision")
        val summary = document.get("explanation")?.takeIf { it.isJsonObject }
            ?.asJsonObject?.get("summary")?.takeIf { it.isJsonPrimitive }?.asString ?: ""
        return Decision(state, codes.asJsonArray.map { it.asString }, summary)
    }
}
