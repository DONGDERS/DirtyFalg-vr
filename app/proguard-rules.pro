# Keep native method names — exp.c binds to them via JNI.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the app package: exp.c does FindClass("df/root/IReporter") and
# view binding generates df.root.databinding.* referenced reflectively.
-keep class df.root.** { *; }
-keep class df.root.databinding.** { *; }

# Keep click-handler wiring used by Material components.
-keepclassmembers class * {
    void *Click(...);
}

-dontwarn df.root.**