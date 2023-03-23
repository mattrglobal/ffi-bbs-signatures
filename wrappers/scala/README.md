## Scala Wrapper for bbs signatures

This module uses JNR to access the library create produced by the parent project.

Some changes had to be made to the parent Rust project in order to expose the Java API on linux.

See the "java" and "linux" feature flags in Rust project.

### Use

Build the jar and then use it as a normal jar.
By default it will extract the lib to a temp folder and the load it so no other files are necessary

### Supported Platform

Only tested on Ubuntu linux / amd64

### Structure of Api

The raw native interface is captured in BbsPlusNative
This instance is then wrapped in a trivial BbsPlus class.
Implicit operations then hang off the BbsPlus class.

This provides two levels of abstraction, the BbsPlus Ops should suffice, if no, then the raw api is available as a member.

### Testing 

The test script (in c) from the parent project was ported to the test folder.

So no stability testing or testing for leaks .... 

## TODO
 - add CI
 - expose all functions
 - figure out if memory is leaking








