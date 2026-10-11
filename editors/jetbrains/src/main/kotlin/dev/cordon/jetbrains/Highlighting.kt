package dev.cordon.jetbrains

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.project.Project

/** Re-highlights a project's open files after a scan. 2026.x asks for `restart(reason)` and
 * deprecates `restart()`; 2025.x has only `restart()`. Looked up at run time, so one build serves
 * both without calling an API either one is retiring. */
object Highlighting {
    private val withReason = DaemonCodeAnalyzer::class.java.methods.firstOrNull {
        it.name == "restart" && it.parameterTypes.contentEquals(arrayOf(Any::class.java))
    }
    private val plain = DaemonCodeAnalyzer::class.java.methods.firstOrNull {
        it.name == "restart" && it.parameterCount == 0
    }

    fun restart(project: Project) {
        val daemon = DaemonCodeAnalyzer.getInstance(project)
        when {
            withReason != null -> withReason.invoke(daemon, "Cordon scan finished")
            plain != null -> plain.invoke(daemon)
        }
    }
}
