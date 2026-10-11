package dev.cordon.jetbrains

import com.intellij.notification.NotificationType
import com.intellij.openapi.components.service
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.fileEditor.FileDocumentManagerListener
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity
import com.intellij.util.Alarm

/** On opening a trusted project: check the scanner is installed, scan, and rescan after saves. */
class CordonStartup : ProjectActivity {
    override suspend fun execute(project: Project) {
        val service = project.service<CordonProjectService>()
        val version = Scanner.version(CordonSettings.get().executable)
        if (version == null) {
            service.notify(
                "Cordon needs the cordon-scanner command. Install it with: pipx install cordon-scanner " +
                    "(or set its path in Settings | Tools | Cordon).",
                NotificationType.WARNING,
            )
            return
        }
        val alarm = Alarm(Alarm.ThreadToUse.POOLED_THREAD, service)
        project.messageBus.connect(service).subscribe(
            FileDocumentManagerListener.TOPIC,
            object : FileDocumentManagerListener {
                override fun beforeDocumentSaving(document: com.intellij.openapi.editor.Document) {
                    if (!CordonSettings.get().scanOnSave) return
                    val file = FileDocumentManager.getInstance().getFile(document) ?: return
                    if (!file.isInLocalFileSystem) return
                    val root = service.root() ?: return
                    if (!file.toNioPath().startsWith(root)) return
                    // The platform says "before saving"; the scan starts 1.5 s later, after the write
                    // has landed, and further saves in that window restart the wait.
                    alarm.cancelAllRequests()
                    alarm.addRequest({ service.scan() }, 1500)
                }
            },
        )
        service.scan()
    }
}
