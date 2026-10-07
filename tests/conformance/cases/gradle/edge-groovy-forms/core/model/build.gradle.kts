plugins {
    `java-library`
    kotlin("jvm") version "1.9.24"
    id("io.gitlab.arturbosch.detekt") version "1.23.7" apply false
}

val jacksonVersion: String by project

dependencies {
    api("com.fasterxml.jackson.core:jackson-annotations:2.18.0")
    implementation(kotlin("reflect"))
    add("implementation", "org.slf4j:slf4j-api:2.0.16")
    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
