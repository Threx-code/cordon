package dev.cordon.jetbrains

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

/** Application-level settings: the scanner a project cannot choose. A setting stored with a
 * project could name any executable, and opening the project would run it. */
@Service(Service.Level.APP)
@State(name = "CordonSettings", storages = [Storage("cordon.xml")])
class CordonSettings : PersistentStateComponent<CordonSettings.Values> {
    class Values {
        var executable: String = "cordon-scanner"
        var minimumSeverity: String = "low"
        var scanOnSave: Boolean = true
    }

    private var values = Values()

    override fun getState(): Values = values

    override fun loadState(state: Values) {
        values = state
    }

    companion object {
        fun get(): Values = ApplicationManager.getApplication().getService(CordonSettings::class.java).state
    }
}
