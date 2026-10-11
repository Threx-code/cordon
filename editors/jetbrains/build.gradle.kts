// Cordon for JetBrains IDEs. Built and verified in Docker; every tool at an exact version.
import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.4.21"
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "dev.cordon"
version = "0.7.0"

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2025.2.6.3")
        testFramework(TestFrameworkType.Platform)
        pluginVerifier()
    }
    testImplementation("junit:junit:4.13.2")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        // The oldest platform supported (2025.1) ships Kotlin 2.1: compile against what it has.
        apiVersion.set(KotlinVersion.KOTLIN_2_1)
        languageVersion.set(KotlinVersion.KOTLIN_2_1)
        // Interface default methods stay on the interface: no bridges generated into our classes,
        // which would override the platform's internal and deprecated defaults (Plugin Verifier).
        jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)
    }
}

intellijPlatform {
    pluginConfiguration {
        id = "dev.cordon.jetbrains"
        name = "Cordon Supply-Chain Scanner"
        version = project.version.toString()
        ideaVersion {
            sinceBuild = "251"
            untilBuild = provider { null }
        }
    }
    pluginVerification {
        ides {
            create("IC", "2025.1.7.2")
            create("IC", "2025.2.6.3")
            create("IU", "2026.2.3")
        }
    }
}
