plugins {
    `java-library`
}

dependencies {
    implementation(libs.okio)
    // implementation("org.example.removed:commented-out:1.0.0")
    /*
     * testImplementation("org.example.removed:block-commented:2.0.0")
     */
    api("org.slf4j:slf4j-api:2.0.16") // implementation("org.example.removed:trailing-comment:3.0.0")
}

tasks.register("explain") {
    doLast {
        println("To add a dependency, write: implementation(\"org.example.docs:from-a-string:4.0.0\")")
    }
}
