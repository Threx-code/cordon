plugins {
    application
}

dependencyLocking {
    lockAllConfigurations()
}

val nettyClassifier = "linux-x86_64"

dependencies {
    implementation(project(":lib"))
    implementation(libs.commons.text)
    implementation("com.example.shared:shared-util:1.0.0")
    implementation("io.netty:netty-transport-native-epoll:4.1.114.Final:$nettyClassifier")
    implementation("org.apache.commons:commons-lang3") {
        version {
            strictly("3.17.0")
        }
    }
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.3")
}

application {
    mainClass.set("app.Main")
}
