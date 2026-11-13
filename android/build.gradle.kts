plugins { id("com.android.application") version "9.2.0" apply false }

val externalBuildRoot = providers.gradleProperty("androidBuildRoot").get()
require(file(externalBuildRoot).isAbsolute) { "androidBuildRoot must be an absolute output directory" }
require(!file(externalBuildRoot).canonicalFile.toPath().startsWith(projectDir.canonicalFile.toPath())) {
    "Android build output must be outside the source project"
}
layout.buildDirectory.set(file(externalBuildRoot))
subprojects { layout.buildDirectory.set(rootProject.layout.buildDirectory.dir(name)) }
