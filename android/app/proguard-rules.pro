# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Suppress R8 warning for kotlinx-serialization-common.pro
# See https://youtrack.jetbrains.com/issue/KT-73255 and the build log for details.
-dontwarn kotlinx.serialization.**

# Keep Protocol Buffer generated classes and their members
-keep class * extends com.google.protobuf.GeneratedMessageLite { *; }
-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite {
    <fields>;
    <methods>;
}

# Keep classes related to Kotlinx Serialization
# This includes classes annotated with @Serializable and their generated serializers.
-keepattributes Serialization
-keepclassmembers class * {
    @kotlinx.serialization.Serializable <fields>;
    @kotlinx.serialization.Serializable <methods>;
    @kotlinx.serialization.Transient <fields>;
    @kotlinx.serialization.Transient <methods>;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class **$$serializer { *; }
-keep class * implements kotlinx.serialization.KSerializer { *; }

# Specifically keep the field name that caused the crash, across any class.
# This is a broader rule, but might be necessary if the specific class is hard to pinpoint.
# Use with caution and consider scoping it down if possible.
-keepclassmembers class * {
    long firstLaunchDatetime_;
    # If it's a Kotlin property, its backing field might also be just the name
    long firstLaunchDatetime;
}

# Keep names of classes that implement Parcelable, often used in Android.
# While not directly indicated by the stack trace, it's a common source of issues with obfuscation.
-keepnames class * implements android.os.Parcelable

# Keep all public members of classes annotated with @Keep.
# This allows developers to explicitly mark classes/members to be kept.
-keep @androidx.annotation.Keep class * {*;}
-keepclassmembers class * {
    @androidx.annotation.Keep *;
}