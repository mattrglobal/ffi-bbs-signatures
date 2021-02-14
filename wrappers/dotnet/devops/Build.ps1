param($Platform, $OutLocation, $AndroidNdkHome)

if ($null -eq $Platform) { throw "Parameter -Platform must be specified." }
if ($null -eq $OutLocation) { throw "Parameter -OutLocation must be specified." }

switch ($Platform) {
    windows {
        mkdir $OutLocation
        cargo build --release 
        Copy-Item -Path .\target\release\bbs.dll -Destination $OutLocation
        break
    }
    linux { 
        cargo build --release 
        Copy-Item -Path .\target\release\libbbs.so -Destination $OutLocation
        Copy-Item -Path .\target\release\libbbs.a -Destination $OutLocation
        break
    }
    macos {
        cargo build --release 
        Copy-Item -Path .\target\release\libbbs.dylib -Destination $OutLocation
        break
    }
    ios {
        mkdir $OutLocation/universal
        mkdir $OutLocation/x86_64
        mkdir $OutLocation/aarch64

        cargo install cargo-lipo
        rustup target install x86_64-apple-ios aarch64-apple-ios
        cargo lipo --release
        Copy-Item -Path "./target/x86_64-apple-ios/release/libbbs.a" -Destination $OutLocation/x86_64/
        Copy-Item -Path "./target/aarch64-apple-ios/release/libbbs.a" -Destination $OutLocation/aarch64/
        Copy-Item -Path "./target/universal/release/libbbs.a" -Destination $OutLocation/universal/
        break
    }
    android {
        if ($null -eq $AndroidNdkHome) { throw "Parameter -AndroidNdkHome must be specified." }
        
        $AndroidNdkHome = Resolve-Path $AndroidNdkHome

        mkdir ~/.NDK

        & (Resolve-Path "$AndroidNdkHome/build/tools/make_standalone_toolchain.py") --api 26 --arch arm64 --install-dir ~/.NDK/arm64;
        & (Resolve-Path "$AndroidNdkHome/build/tools/make_standalone_toolchain.py") --api 26 --arch arm --install-dir ~/.NDK/arm;
        & (Resolve-Path "$AndroidNdkHome/build/tools/make_standalone_toolchain.py") --api 26 --arch x86 --install-dir ~/.NDK/x86;

        Remove-Item ".cargo/config"
        Get-Content "./wrappers/dotnet/devops/android-cargo-config" | Out-File "~/.cargo/config"

        rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
        
        cargo build --target aarch64-linux-android --release
        cargo build --target armv7-linux-androideabi --release
        cargo build --target i686-linux-android --release

        mkdir $OutLocation/arm64-v8a/
        mkdir $OutLocation/armeabi-v7a/
        mkdir $OutLocation/x86/
        Copy-Item -Path ./target/aarch64-linux-android/release/libbbs.so -Destination $OutLocation/arm64-v8a/
        Copy-Item -Path ./target/armv7-linux-androideabi/release/libbbs.so -Destination $OutLocation/armeabi-v7a/
        Copy-Item -Path ./target/i686-linux-android/release/libbbs.so -Destination $OutLocation/x86/
        break
    }
}