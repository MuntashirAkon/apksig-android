# Bazel (https://bazel.io/) BUILD file for apksig library and apksigner tool.

licenses(["notice"])  # Apache License 2.0

# Public API of the apksig library. Clients (other than this package and its
# subpackages) depend on this via the publicly visible //third_party/java/apksig
java_library(
    name = "apksig",
    srcs = glob(
        ["src/main/java/com/android/apksig/**/*.java"],
        exclude = ["src/main/java/com/android/apksig/internal/**/*.java"],
    ),
    visibility = ["//visibility:public"],
    deps = [":apksig-all"],
)

# All of apksig library, including private API which clients are not supposed
# to depend on
java_library(
    name = "apksig-all",
    srcs = glob(["src/main/java/**/*.java"]),
)

java_binary(
    name = "apksigner",
    srcs = glob([
        "src/apksigner/java/**/*.java",
    ]),
    main_class = "com.android.apksigner.ApkSignerTool",
    resources = glob([
        "src/apksigner/java/**/*.txt",
    ]),
    visibility = ["//visibility:public"],
    deps = [":apksig"],
)

java_test(
    name = "all",
    srcs = glob([
        "src/test/java/com/android/apksig/**/*.java",
    ]),
    resources = glob([
        "src/test/resources/**/*",
    ]),
    test_class = "com.android.apksig.AllTests",
    deps = [":apksig-all"],
)
