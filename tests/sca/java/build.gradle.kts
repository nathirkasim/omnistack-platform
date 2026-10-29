plugins {
    java
}

group = "com.security.test"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    implementation("org.apache.logging.log4j:log4j-api:2.14.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
}
