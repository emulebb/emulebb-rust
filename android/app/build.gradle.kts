import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.util.HexFormat
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

plugins { id("com.android.application") }

dependencies { implementation("androidx.core:core:1.19.1") }

abstract class StageAssets : Sync() {
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
}

/** Export only selected application runtime artifacts, never the compiler/plugin graph. */
abstract class EmulebbRuntimeInventory : DefaultTask() {
    @get:Input abstract val variant: Property<String>
    @get:Input abstract val componentDescriptions: ListProperty<String>
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE)
    abstract val sourceFiles: ConfigurableFileCollection
    @get:OutputDirectory abstract val destination: DirectoryProperty

    @TaskAction fun export() {
        val root = destination.get().asFile
        require(!root.exists() || root.listFiles()?.isEmpty() == true) { "Runtime inventory output must be new or empty" }
        check(root.mkdirs() || root.isDirectory)
        fun exportFile(source: File, folder: File): Map<String, Any> {
            require(source.isFile && source.name.matches(Regex("[A-Za-z0-9_.-]+")))
            val target = File(folder, source.name)
            check(target.parentFile.mkdirs() || target.parentFile.isDirectory)
            source.copyTo(target, overwrite = false)
            val digest = MessageDigest.getInstance("SHA-256")
            source.inputStream().use { input ->
                val buffer = ByteArray(65536)
                while (true) {
                    val size = input.read(buffer)
                    if (size < 0) break
                    digest.update(buffer, 0, size)
                }
            }
            return mapOf("path" to target.relativeTo(root).invariantSeparatorsPath,
                "sha256" to HexFormat.of().formatHex(digest.digest()), "sizeBytes" to target.length())
        }
        val components = componentDescriptions.get().map { description ->
            val component = JsonSlurper().parseText(description) as Map<*, *>
            val group = component["group"] as String
            val name = component["name"] as String
            val version = component["version"] as String
            require(listOf(group, name, version).all { it.matches(Regex("[A-Za-z0-9_.-]+")) && it != "." && it != ".." })
            val folder = File(root, "artifacts/${group.replace('.', '/')}/$name/$version")
            val pom = exportFile(File(component["pom"] as String), folder)
            val artifacts = (component["artifacts"] as List<*>).map { exportFile(File(it as String), folder) }
            mapOf("group" to group, "name" to name, "version" to version,
                "pom" to pom.filterKeys { it != "sizeBytes" }, "artifacts" to artifacts)
        }
        val report = mapOf("schema" to "emulebb.android.runtime-classpath/1", "variant" to variant.get(),
            "configuration" to "${variant.get()}RuntimeClasspath", "components" to components)
        File(root, "report.json").writeText(JsonOutput.prettyPrint(JsonOutput.toJson(report)) + "\n")
    }
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

val inventoryVariant = providers.gradleProperty("emulebbRuntimeVariant").orElse("release")
val inventoryComponents = providers.provider {
    val variant = inventoryVariant.get()
    require(variant in listOf("debug", "release"))
    val artifacts = configurations.getByName("${variant}RuntimeClasspath").incoming.artifacts.resolvedArtifacts.get()
    artifacts.groupBy {
        it.id.componentIdentifier as? ModuleComponentIdentifier
            ?: error("Runtime inventory requires resolved external Maven components")
    }.entries.sortedBy { "${it.key.group}:${it.key.module}:${it.key.version}" }.map { (id, files) ->
        val pom = configurations.detachedConfiguration(dependencies.create("${id.group}:${id.module}:${id.version}@pom"))
            .apply { isTransitive = false }.singleFile
        mapOf("group" to id.group, "name" to id.module, "version" to id.version,
            "pom" to pom.absolutePath, "artifacts" to files.map { it.file.absolutePath }.sorted())
    }
}
tasks.register<EmulebbRuntimeInventory>("emulebbRuntimeInventory") {
    variant.set(inventoryVariant)
    componentDescriptions.set(inventoryComponents.map { components -> components.map(JsonOutput::toJson) })
    sourceFiles.from(inventoryComponents.map { components -> components.flatMap {
        listOf(File(it["pom"] as String)) + (it["artifacts"] as List<*>).map { artifact -> File(artifact as String) }
    } })
    destination.set(layout.dir(providers.gradleProperty("emulebbRuntimeInventoryDir").map { output ->
        val folder = file(output)
        require(folder.isAbsolute && !folder.canonicalFile.toPath().startsWith(rootProject.projectDir.canonicalFile.toPath())) {
            "Runtime inventory must use an absolute external output directory"
        }
        folder
    }))
}
