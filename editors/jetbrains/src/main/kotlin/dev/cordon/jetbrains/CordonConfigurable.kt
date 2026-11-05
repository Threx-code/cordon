package dev.cordon.jetbrains

import com.intellij.openapi.options.BoundConfigurable
import com.intellij.openapi.ui.DialogPanel
import com.intellij.ui.dsl.builder.bindItem
import com.intellij.ui.dsl.builder.bindSelected
import com.intellij.ui.dsl.builder.bindText
import com.intellij.ui.dsl.builder.panel

/** Settings | Tools | Cordon. Application-level, so no project can change what is run. */
class CordonConfigurable : BoundConfigurable("Cordon") {
    override fun createPanel(): DialogPanel {
        val values = CordonSettings.get()
        return panel {
            row("cordon-scanner executable:") {
                textField().bindText(values::executable).comment(
                    "A command on PATH or a full path. Kept with the IDE, never with a project.",
                )
            }
            row("Show findings at or above:") {
                comboBox(ReportParser.SEVERITIES).bindItem(
                    { values.minimumSeverity },
                    { values.minimumSeverity = it ?: "low" },
                )
            }
            row {
                checkBox("Rescan after a file is saved").bindSelected(values::scanOnSave)
            }
        }
    }
}
