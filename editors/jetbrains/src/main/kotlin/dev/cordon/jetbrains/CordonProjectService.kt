package dev.cordon.jetbrains

import com.intellij.notification.NotificationGroupManager
import com.intellij.openapi.Disposable
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

/** The project's findings, by file, from the latest scan of its folder. */
@Service(Service.Level.PROJECT)
class CordonProjectService(private val project: Project) : Disposable {
    override fun dispose() {
        synchronized(listeners) { listeners.clear() }
    }

    @Volatile
    var byFile: Map<Path, List<Finding>> = emptyMap()
        private set

    @Volatile
    var general: List<Finding> = emptyList()
        private set

    @Volatile
    var complete: Boolean = true
        private set

    private val running = AtomicBoolean(false)
    private val listeners = mutableListOf<() -> Unit>()

    fun onChange(listener: () -> Unit) {
        synchronized(listeners) { listeners.add(listener) }
    }

    fun root(): Path? = project.guessProjectDir()?.toNioPath()

    fun scan() {
        // A scanner process over an untrusted project waits for trust, as the IDE's own tools do.
        if (!Trust.isTrusted(project) || project.isDisposed) return
        val root = root() ?: return
        if (!running.compareAndSet(false, true)) return
        val settings = CordonSettings.get()
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Cordon: scanning", true) {
            override fun run(indicator: ProgressIndicator) {
                try {
                    val report = Scanner.scan(settings.executable, root.toString(), indicator)
                    val shown = ReportParser.atLeast(report.findings, settings.minimumSeverity)
                    val located = mutableMapOf<Path, MutableList<Finding>>()
                    val other = mutableListOf<Finding>()
                    for (finding in shown) {
                        val file = if (finding.operational) null else ReportParser.contained(root, finding.path)
                        if (file == null) other.add(finding) else located.getOrPut(file) { mutableListOf() }.add(finding)
                    }
                    byFile = located
                    general = other
                    complete = report.complete
                } catch (error: Scanner.ScannerException) {
                    notify("Cordon could not scan this project: ${error.message}", NotificationType.WARNING)
                } catch (error: IllegalArgumentException) {
                    notify("Cordon's scanner returned output this plugin could not read: ${error.message}", NotificationType.WARNING)
                } finally {
                    running.set(false)
                }
            }

            override fun onFinished() {
                if (project.isDisposed) return
                Highlighting.restart(project)
                synchronized(listeners) { listeners.toList() }.forEach { it() }
            }
        })
    }

    fun notify(message: String, type: NotificationType) {
        ApplicationManager.getApplication().invokeLater {
            if (!project.isDisposed) {
                NotificationGroupManager.getInstance().getNotificationGroup("Cordon")
                    .createNotification(message, type).notify(project)
            }
        }
    }
}
