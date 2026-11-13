plugins { id("com.android.application") }

abstract class StageAssets : Sync() {
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
}

android {
    namespace = "org.emulebb.android"
    compileSdk { version = release(37) { minorApiLevel = 2 } }
    buildToolsVersion = "37.0.0"
    ndkVersion = "30.0.16248370"
    defaultConfig {
        applicationId = "org.emulebb.android"
        minSdk = 34
        targetSdk = 37
        versionCode = providers.gradleProperty("emulebbVersionCode").get().toInt()
        versionName = providers.gradleProperty("emulebbVersionName").get()
        ndk { abiFilters.addAll(listOf("arm64-v8a", "x86_64")) }
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets.getByName("main") {
        jniLibs.directories.add(providers.gradleProperty("emulebbNativeDir").get())
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
            // Exact source-bound native bytes are audited by the producer and APK harness.
            keepDebugSymbols.add("**/*.so")
        }
    }
}

val stageAssets = tasks.register<StageAssets>("stageAssets") {
    outputDirectory.set(layout.buildDirectory.dir("generated/assets"))
    into(outputDirectory)
    from(providers.gradleProperty("emulebbWebuiDir")) { into("webui") }
    from(providers.gradleProperty("emulebbNoticesDir")) { into("licenses") }
}
androidComponents.onVariants { variant ->
    variant.sources.assets?.addGeneratedSourceDirectory(stageAssets, StageAssets::outputDirectory)
}
