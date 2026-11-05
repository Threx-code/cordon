package dev.cordon.jetbrains

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.nio.file.Path
import javax.swing.DefaultListModel

/** Every finding of the latest scan, most severe first; double-click opens the line. */
class CordonToolWindow : ToolWindowFactory, DumbAware {
    private data class Row(val finding: Finding, val file: Path?) {
        override fun toString(): String {
            val where = file?.fileName?.toString()?.let { "$it:${finding.line + 1}" } ?: (finding.path ?: "")
            return "[${finding.severity}] ${finding.ruleId}  $where  ${finding.message.take(160)}"
        }
    }

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val model = DefaultListModel<Row>()
        val list = JBList(model)
        val service = project.service<CordonProjectService>()
        val refresh = {
            ApplicationManager.getApplication().invokeLater {
                model.clear()
                val rank = ReportParser.SEVERITIES
                val rows = service.byFile.flatMap { (file, findings) -> findings.map { Row(it, file) } } +
                    service.general.map { Row(it, null) }
                rows.sortedByDescending { rank.indexOf(it.finding.severity) }.forEach(model::addElement)
            }
        }
        service.onChange(refresh)
        list.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(event: MouseEvent) {
                if (event.clickCount != 2) return
                val row = list.selectedValue ?: return
                val file = row.file?.let { LocalFileSystem.getInstance().findFileByNioFile(it) } ?: return
                OpenFileDescriptor(project, file, row.finding.line, row.finding.column).navigate(true)
            }
        })
        toolWindow.contentManager.addContent(
            ContentFactory.getInstance().createContent(JBScrollPane(list), "Findings", false),
        )
        refresh()
    }
}
