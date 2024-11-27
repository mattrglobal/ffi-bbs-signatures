# Test using the rust lib in other languages on different platforms.
# Currently it only supports testing ffi-bbs-signatures in a C project on macos.

set -e

LANGUAGE=$1
PLATFORM=$2

if [ -z "$LANGUAGE" ]
then
  echo "ERROR: LANGUAGE argument must be supplied and must be one of the following: C, JAVA, PYTHON, DOTNET, OBJECT-C"
  exit 1
fi

if [ -z "$PLATFORM" ]
then
  echo "ERROR: PLATFORM argument must be supplied and must be one of the following: WINDOWS, LINUX, MACOS, IOS, ANDROID"
  exit 1
fi

case $PLATFORM in
  MACOS)
      echo "Building for Apple Darwin aarch64"
      rustup target add aarch64-apple-darwin
      case $LANGUAGE in
        C)
          echo "To be used with C"
          argo build --target aarch64-apple-darwin --release
          export RUST_LIBRARY_DIRECTORY="${PWD}/target/aarch64-apple-darwin/release"
          cd $RUST_LIBRARY_DIRECTORY
          cmake ../../../tests
          cmake --build .
          ./bbs_test
          ;;
        *)
          echo "ERROR: LANGUAGE not supported: $1"
          exit 1
          ;;
      esac
      ;;
  *)
    echo "ERROR: PLATFORM not supported: $2"
    exit 1
    ;;
esac
