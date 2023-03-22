
# TODO this script currently assumes you are running in a specifc host environment to build for different platforms
# TODO need to check that rust is installed

set -e

PLATFORM=$1
OUTPUT_LOCATION=$2

if [ -z "$PLATFORM" ]
then
  echo "ERROR: PLATFORM argument must be supplied and must be one of the following: WINDOWS, LINUX, MACOS, IOS, ANDROID"
  exit 1
fi

if [ -z "$OUTPUT_LOCATION" ]
then
  echo "ERROR: OUTPUT_LOCATION argument must be supplied and be a valid directory"
  exit 1
fi

if [ -d "$3" ]
then
  ANDROID_NDK_HOME=$3
fi

if [ ! -d "$ANDROID_NDK_HOME" ]
then
  ANDROID_NDK_HOME=$NDK_HOME
fi

echo "Building for PLATFORM: $1"
echo "To OUTPUT_LOCATION: $2"

case $PLATFORM in
  WINDOWS)
      # rustup target install i686-pc-windows-gnu x86_64-pc-windows-gnu
      mkdir -p $OUTPUT_LOCATION\\windows
      cargo build --release
      cp .\\target\\release\\bbs.dll $OUTPUT_LOCATION\\windows
    ;;
  LINUX)
      mkdir -p $OUTPUT_LOCATION/linux
      cargo build --release --features java
      cp ./target/release/libbbs.so $OUTPUT_LOCATION/linux
    ;;
  MACOS)
      # Create the root directory for the MacOS release binaries
      mkdir -p $OUTPUT_LOCATION/macos

      # ARM x86_64 darwin build
      echo "Building for Apple Darwin x86_64"
      rustup target add x86_64-apple-darwin
      mkdir -p $OUTPUT_LOCATION/macos/darwin-x86_64/
      cargo build --target x86_64-apple-darwin --release --features java
      cp ./target/x86_64-apple-darwin/release/libbbs.dylib $OUTPUT_LOCATION/macos/darwin-x86_64/
    ;;
  IOS)
      # Create the root directory for the IOS release binaries
      mkdir -p $OUTPUT_LOCATION/ios

      # Create the directories at the output location for the release binaries
      mkdir -p $OUTPUT_LOCATION/ios/x86_64
      mkdir -p $OUTPUT_LOCATION/ios/aarch64
      mkdir -p $OUTPUT_LOCATION/ios/universal

      # Install cargo-lipo
      # see https://github.com/TimNN/cargo-lipo
      cargo install cargo-lipo
      rustup target install x86_64-apple-ios aarch64-apple-ios
      cargo lipo --release
      cp "./target/x86_64-apple-ios/release/libbbs.a" $OUTPUT_LOCATION/ios/x86_64
      cp "./target/aarch64-apple-ios/release/libbbs.a" $OUTPUT_LOCATION/ios/aarch64
      cp "./target/universal/release/libbbs.a" $OUTPUT_LOCATION/ios/universal
      break
    ;;
  ANDROID)
      if [ ! -d "$ANDROID_NDK_HOME" ]
      then
        echo "ERROR: ANDROID_NDK_HOME argument must be supplied and be a valid directory pointing to the installation of android ndk"
        exit 1
      fi
        # TODO make this configurable in the environment
        ANDROID_API_LEVEL=21

        echo "Using NDK home: $ANDROID_NDK_HOME"

        mkdir -p $OUTPUT_LOCATION/android

        # ARM build
        echo "Building for Android ARM"
        "$ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py" --api $ANDROID_API_LEVEL --arch arm --install-dir .NDK/arm --force
        rustup target add armv7-linux-androideabi
        mkdir -p $OUTPUT_LOCATION/android/armeabi-v7a/
        cargo build --target armv7-linux-androideabi --release
        cp ./target/armv7-linux-androideabi/release/libbbs.so $OUTPUT_LOCATION/android/armeabi-v7a/

        # ARM 64 build
        echo "Building for Android ARM 64"
        "$ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py" --api $ANDROID_API_LEVEL --arch arm64 --install-dir .NDK/arm64 --force
        rustup target add aarch64-linux-android
        mkdir -p $OUTPUT_LOCATION/android/arm64-v8a/
        cargo build --target aarch64-linux-android --release
        cp ./target/aarch64-linux-android/release/libbbs.so $OUTPUT_LOCATION/android/arm64-v8a/

        # x86 build
        echo "Building for Android x86"
        "$ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py" --api $ANDROID_API_LEVEL --arch x86 --install-dir .NDK/x86 --force;
        rustup target add i686-linux-android
        mkdir -p $OUTPUT_LOCATION/android/x86/
        cargo build --target i686-linux-android --release
        cp ./target/i686-linux-android/release/libbbs.so $OUTPUT_LOCATION/android/x86/

        # x86_64 build
        echo "Building for Android x86_64"
        "$ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py" --api $ANDROID_API_LEVEL --arch x86_64 --install-dir .NDK/x86_64 --force
        rustup target add x86_64-linux-android
        mkdir -p $OUTPUT_LOCATION/android/x86_64/
        cargo build --target x86_64-linux-android --release
        cp ./target/x86_64-linux-android/release/libbbs.so $OUTPUT_LOCATION/android/x86_64/
      ;;
  *)
    echo "ERROR: PLATFORM unknown: $1"
    exit 1
    ;;
esac
