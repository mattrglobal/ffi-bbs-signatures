set -e

INPUT_ARTIFACTS_LOCATION=$1
OUTPUT_ARTIFACTS_LOCATION=$2

if [ -z "$INPUT_ARTIFACTS_LOCATION" ]
then
  echo "INPUT_ARTIFACTS_LOCATION not defined defaulting to ./out"
  INPUT_ARTIFACTS_LOCATION=out
fi

if [ -z "$OUTPUT_ARTIFACTS_LOCATION" ]
then
  echo "OUTPUT_ARTIFACTS_LOCATION not defined defaulting to ./release"
  OUTPUT_ARTIFACTS_LOCATION=release
fi

if [ ! -d "$INPUT_ARTIFACTS_LOCATION" ]
then
  echo "ERROR: INPUT_ARTIFACTS_LOCATION does not exist"
  exit 1
fi

if [ ! -d "$OUTPUT_ARTIFACTS_LOCATION" ]
then
  echo "OUTPUT_ARTIFACTS_LOCATION does not exist, creating"
  mkdir -p $OUTPUT_ARTIFACTS_LOCATION
else
  echo "OUTPUT_ARTIFACTS_LOCATION exists, re-creating"
  rm -rf $OUTPUT_ARTIFACTS_LOCATION
  mkdir -p $OUTPUT_ARTIFACTS_LOCATION
fi

cd $INPUT_ARTIFACTS_LOCATION

if [ -d "android" ]
then
  echo "Android build artifacts found, preparing release aritifact"
  zip -r ../release/android.zip ./android
fi

if [ -d "ios" ]
then
  echo "IOS build artifacts found, preparing release aritifact"
  zip -r ../release/ios.zip ./ios
fi
