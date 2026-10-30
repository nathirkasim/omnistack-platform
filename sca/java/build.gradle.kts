plugins { java }
repositories { mavenCentral() }
dependencies {
    // Struts2 RCE (CVE-2017-5638)
    implementation("org.apache.struts:struts2-core:2.5.12")
}
