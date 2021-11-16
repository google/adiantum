# Adiantum benchmark suite

This is the software we used to generate the benchmarks in our paper.

## Building and running

The following build instructions are written for users of Ubuntu and other
Debian-derived Linux systems; adjust as needed for your own platform.

### Preliminaries

1. Install [Python](https://www.python.org/) version 3.6 or higher,
   [Meson](https://mesonbuild.com/), and [Ninja](https://ninja-build.org/):

       sudo apt-get install python3 meson ninja-build

2. Clone this repository and `cd` into the `benchmark` directory.

### Building and running on your host machine

Running the benchmarks on your host machine is convenient for development and a
good preliminary test, but the results it produces aren't currently very
meaningful since most algorithms don't have x86-optimized implementations
included in the benchmark suite yet.

1. Set up the build directory:

       meson build/host

2. Build the benchmark tool:

       ninja -C build/host

3. Run the benchmark tool:

       ./build/host/cipherbench

### Building and running on Android (arm)

This will test the 32-bit ARM assembly code and the generic code.

1. Download the [Android NDK](https://developer.android.com/ndk/downloads).

2. Connect an Android device and get `adb` access.

3. If the device is rooted, run `adb root` to restart `adb` with root
   privileges.  This isn't required, but it will give more accurate results.

4. Set up the build directory, providing the path to your NDK directory:

       ./cross-tools/setup-build --build-type=android-arm --ndk-dir=/path/to/ndk/dir

5. Build the benchmark tool:

       ninja -C build/android-arm

6. Run the benchmark tool:

       cross-tools/adb-exe-wrapper adb ./build/android-arm/cipherbench

### Building and running on Android (aarch64)

Some algorithms have aarch64 (64-bit ARM) assembly code.  To build and run the
benchmark tool on Android on aarch64, follow the directions for arm above, but
replace all occurrences of "android-arm" with "android-aarch64".

### Tips and tricks

By default, the benchmarks are run using 4096-byte messages and are repeated 5
times for each algorithm, with the fastest speed being chosen.  These parameters
can be configured via the `--bufsize` and `--ntries` options.

To prevent CPU frequency scaling from causing inconsistent results, the
benchmark tool tries to temporarily set all CPUs to their maximum frequency.
The code which does this assumes a Linux-based system (e.g. Android) and
requires root privileges.  On other systems, or as a non-root user, you'll see
warnings about being unable to set the CPU frequency.  You can ignore these if
you don't need precise results.

Instead of manually running the tool, you may instead pass one of the predefined
run targets to the `ninja` command, e.g. `ninja -C build/host output4096`.

### Alternative implementations for Linux kernel

By default, most implementations in this benchmark suite optimize solely for
speed. However, in some cases the Linux kernel patches for Adiantum make
slightly different tradeoffs, considering concerns such as code size and power
consumption, and the additional overhead to using SIMD instructions in
kernel-mode when compared to userspace. To measure speed in a way more
representative of the Linux patches, set up the build with the "kernelish"
option, for example:

```sh
./cross-tools/setup-build --build-type=android-arm \
    --ndk-dir=/path/to/ndk/dir -- -Dkernelish=true
```

## File layout

* `src/`: C sources for ciphers and benchmark driver
* `src/arm/`: ARM assembly
* `src/aarch64/`: ARM64 assembly
* `src/x86_64/`: x86_64 assembly
* `testvectors/`: Test vectors for Adiantum and HPolyC as C header files
* `../third_party/`: dependencies under the GPLv2 license, not MIT.
* `meson_options.txt`, `meson.build`: Meson build control files.
* `cross-tools/`: Cross compilation support files
* `convert_testvecs.py`: converts test vectors from JSON to C header form
