plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.andlify.example"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.andlify.example"
        minSdk = 28
        targetSdk = 28
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    androidResources {
        noCompress += listOf("zst")
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("appsrc/main/AndroidManifest.xml")
            java.srcDirs("appsrc/main/java")
            res.srcDirs("appsrc/main/res")
            assets.srcDirs("src/main/assets")
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":library"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("com.google.android.material:material:1.12.0")
}
