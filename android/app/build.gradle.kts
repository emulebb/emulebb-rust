plugins { id("com.android.application") }

android {
    namespace = "org.emulebb.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
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
        jniLibs.srcDir(providers.gradleProperty("emulebbNativeDir").get())
        assets.srcDir(layout.buildDirectory.dir("generated/assets"))
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
            // Exact source-bound native bytes are audited by the producer and APK harness.
            keepDebugSymbols.add("**/*.so")
        }
    }
}

val stageAssets by tasks.registering(Sync::class) {
    into(layout.buildDirectory.dir("generated/assets"))
    from(providers.gradleProperty("emulebbWebuiDir")) { into("webui") }
    from(providers.gradleProperty("emulebbNoticesDir")) { into("licenses") }
}
tasks.named("preBuild") { dependsOn(stageAssets) }
