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
      echo "Building for Apple Darwin x86_64"
      rustup target add x86_64-apple-darwin
      case $LANGUAGE in
        C)
          echo "To be used with C"
          cargo build --target x86_64-apple-darwin --release
          export RUST_LIBRARY_DIRECTORY="${PWD}/target/x86_64-apple-darwin/release"
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
  LINUX)
      echo "Building for LINUX x86_64"
      TARGET='x86_64-unknown-linux-gnu'
      rustup target add ${TARGET}
      case $LANGUAGE in
        C)
          echo "To be used with C"
          cargo build --target ${TARGET} --release
          export RUST_LIBRARY_DIRECTORY="${PWD}/target/${TARGET}/release"
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
