# BBS Signatures for .NET Core

This is a .NET wrapper for the C callable BBS+ Signatures package. The library depends on the native platform implementations of the BBS+ FFI wrapper. These are bundled with the package available on [Nuget](https://www.nuget.org/packages/Hyperledger.Ursa.BbsSignatures/).

# Requirements

- [.NET Core SDK](https://dotnet.microsoft.com/download) 3.1 or newer
- Optionally, if you'd like to build the BBS+ library yourself
  - Install [Rust](https://www.rust-lang.org/tools/install)
  - Follow installation instructions at https://github.com/mattrglobal/ffi-bbs-signatures

# Usage

Install the nuget package in your project

```
Install-Package Hyperledger.Ursa.BbsSignatures
```

All functions are exposed through the `BbsSignatureService`.

```cs
using Hyperledger.Ursa.BbsSignatures;
/// ...
var bbsService = new BbsSignatureService();
var keyPair = service.GenerateBlsKey();
```

# Building the project

> To build the project locally, it's required that the native libraries are present in the `dotnet/libs` directory. You can run [TODO: this script] to download the latest libraries from github.

Using Visual Studio or Visual Studio for Mac, simply build the solution.

## Using `msbuild`

```
msbuild ./wrappers/dotnet/BbsSignatures.sln
```

## Using NET CLI

you must run `msbuild` or use an IDE that uses it, like Visual Studio or Visual Studio for Mac. The main project depends on `MSBuild.Sdk.Extras` package to produce Xamarin specific packages, for this reason, you must specify the target framework when building with CLI

```
dotnet build --framework netstandard2.1 ./wrappers/dotnet/src/Hyperledger.Ursa.BbsSignatures

```
    msbuild /p:Configuration=Release src/

To build for a specific target use

    msbuild /p:Configuration=Release /p:TargetFramework=netstandard2.1 ./wrappers/dotnet/src/BbsSignatures/BbsSignatures.csproj

# Test runners

There are three test runners included with the solution. Tests use NUnit runners for the following platforms
- NET Core App
- iOS using `MonoTouch.NUnitLite`
- Android using `Xamarin.Android.NUnitLite`

To run the tests for NET Core app, you can use `dotnet` tool

    dotnet test ./wrappers/dotnet

# Demo

There's a full [end-to-end integration test](src/Hyperledger.Ursa.BbsSignatures.Tests/BbsIntegrationTests.cs) available that showcases the use of each of the library methods.

# Roadmap

- Support for [BBS+ signature schemes using JSON-LD](https://github.com/streetcred-id/ld-proofs-dotnet) credentials (Q3, 2020)
- Support for WASM runtime using Mono (Q4, 2020)
