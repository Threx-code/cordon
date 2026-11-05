package dev.cordon.jetbrains

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.components.service
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/** Marks each finding on its line in the editor, from the latest project scan. Nothing runs
 * here: the scan happens in the background (`CordonProjectService`), this only reads its result. */
class CordonAnnotator : ExternalAnnotator<CordonAnnotator.Input, List<Finding>>() {
    data class Input(val file: PsiFile, val findings: List<Finding>)

    override fun collectInformation(file: PsiFile): Input? {
        val virtual = file.virtualFile ?: return null
        if (!virtual.isInLocalFileSystem) return null
        val path = virtual.toNioPath()
        val findings = file.project.service<CordonProjectService>().byFile[path.toAbsolutePath().normalize()]
        return if (findings.isNullOrEmpty()) null else Input(file, findings)
    }

    override fun doAnnotate(input: Input): List<Finding> = input.findings

    override fun apply(file: PsiFile, findings: List<Finding>, holder: AnnotationHolder) {
        val document = file.viewProvider.document ?: return
        for (finding in findings) {
            if (document.lineCount == 0) return
            val line = finding.line.coerceIn(0, document.lineCount - 1)
            val range = TextRange(document.getLineStartOffset(line), document.getLineEndOffset(line))
            val text = buildString {
                append("Cordon ").append(finding.ruleId).append(": ").append(finding.message)
                if (finding.remediation.isNotBlank()) append("\nFix: ").append(finding.remediation)
            }
            holder.newAnnotation(severity(finding.severity), text).range(range).create()
        }
    }

    private fun severity(value: String): HighlightSeverity = when (value) {
        "critical", "high" -> HighlightSeverity.ERROR
        "medium" -> HighlightSeverity.WARNING
        "low" -> HighlightSeverity.WEAK_WARNING
        else -> HighlightSeverity.INFORMATION
    }
}
