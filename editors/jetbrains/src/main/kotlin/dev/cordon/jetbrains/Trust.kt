package dev.cordon.jetbrains

import com.intellij.ide.trustedProjects.TrustedProjects
import com.intellij.openapi.project.Project

/** Whether the user trusts this project: nothing is run over a project before they do. */
object Trust {
    fun isTrusted(project: Project): Boolean = TrustedProjects.isProjectTrusted(project)
}
