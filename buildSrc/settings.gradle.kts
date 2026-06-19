// Allow buildSrc convention plugins to reference the root project's
// gradle/libs.versions.toml via the typesafe `libs` accessor.
dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}
