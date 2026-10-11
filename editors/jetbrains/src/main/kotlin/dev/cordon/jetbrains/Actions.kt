package dev.cordon.jetbrains

import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.ide.CopyPasteManager
import java.awt.datatransfer.StringSelection

class ScanProjectAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) {
        event.project?.service<CordonProjectService>()?.scan()
    }

    override fun update(event: AnActionEvent) {
        event.presentation.isEnabled = event.project?.let { Trust.isTrusted(it) } == true
    }

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT
}

/** The configuration that adds Cordon's MCP server to AI Assistant, copied for the user to paste
 * into Settings | Tools | AI Assistant | Model Context Protocol (MCP). Nothing is changed for them:
 * what an agent may run is the user's decision. */
class CopyMcpConfigAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val service = project.service<CordonProjectService>()
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val text = Scanner.mcpConfig(CordonSettings.get().executable)
                ApplicationManager.getApplication().invokeLater {
                    CopyPasteManager.getInstance().setContents(StringSelection(text))
                    service.notify(
                        "Cordon's MCP configuration is on the clipboard. Paste it in Settings | Tools | " +
                            "AI Assistant | Model Context Protocol (MCP) > Add, as JSON.",
                        NotificationType.INFORMATION,
                    )
                }
            } catch (error: Exception) {
                service.notify("Could not print Cordon's MCP configuration: ${error.message}", NotificationType.WARNING)
            }
        }
    }

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT
}
