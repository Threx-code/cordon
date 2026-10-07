plugins {
    alias(libs.plugins.versions)
}

buildscript {
    configurations.classpath {
        resolutionStrategy.activateDependencyLocking()
    }
}
