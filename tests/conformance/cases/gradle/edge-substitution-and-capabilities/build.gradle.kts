plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.slf4j:slf4j-log4j12:1.7.36")
    implementation("com.google.guava:guava:31.1-jre")
    implementation("org.asynchttpclient:async-http-client:2.12.3") {
        capabilities {
            requireCapability("org.asynchttpclient:async-http-client-netty-utils")
        }
    }
}

configurations.all {
    resolutionStrategy {
        // A version pinned for every configuration, whatever is requested.
        force("com.google.guava:guava:33.2.1-jre")
        dependencySubstitution {
            // log4j 1.x's binding swapped for reload4j's, everywhere it is requested.
            substitute(module("org.slf4j:slf4j-log4j12")).using(module("org.slf4j:slf4j-reload4j:2.0.13"))
        }
    }
}
