# BBS Signatures for .NET Core

[![Build Status](https://dev.azure.com/streetcred/Streetcred/_apis/build/status/streetcred-id.bbs-signatures-dotnet?branchName=master)](https://dev.azure.com/streetcred/Streetcred/_build/latest?definitionId=65&branchName=master)

This is a .NET wrapper for the C callable BBS+ Signatures package located https://github.com/mikelodder7/ffi-bbs-signatures
The are pre-built dynamic libraries avaliable for each platform in the `libs/` folder. Follow the instructions below if you'd like to build the dependency youself.
This wrapper handles automatic memory management when working with unmanaged memory.

# Requirements

- [.NET Core SDK](https://dotnet.microsoft.com/download) 3.1 or newer
- Optionally, if you'd like to build the BBS+ library yourself
  - Install [Rust](https://www.rust-lang.org/tools/install)
  - Follow installation instructions at https://github.com/mikelodder7/ffi-bbs-signatures

# Building the project

To build the project, you must run `msbuild` or use an IDE that uses it, like Visual Studio or Visual Studio for Mac. The main project uses `MSBuild.Extras` package to produce Xamarin specific packages, for this reason, you cannot use `dotnet build`, unless you specify the target framework `dotnet build -f netstandard2.1 ./src/BbsSignatures/`

    msbuild /p:Configuration=Release src/

To build for a specific target use

    msbuild /p:Configuration=Release /p:TargetFramework=netstandard2.1 ./src/BbsSignatures/BbsSignatures.csproj

# Test runners

Theere are three test runners included with the solution. Tests use NUnit runners for the following platforms
- NET Core App
- iOS using `MonoTouch.NUnitLite`
- Android using `Xamarin.Android.NUnitLite`

To run the tests for NET Core app, you can use `dotnet` tool

    dotnet test ./src/BbsSignatures.Tests/

# Demo

There's a full [end-to-end integration test](https://github.com/streetcred-id/bbs-signatures-dotnet/blob/mac-debug/src/BbsSignatures.Tests/BbsIntegrationTests.cs) available that showcases the use of each of the library methods.

# Roadmap

- Support for [BBS+ signature schemes using JSON-LD](https://github.com/mattrglobal/bbs-signatures) credentials (Q3, 2020)
- Support for WASM runtime using browser wallet (Q4, 2020)
