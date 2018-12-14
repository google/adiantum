# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

project('cipherbench', 'c')

conf_data = configuration_data()
conf_data.set10('KERNELISH', get_option('kernelish'))
conf_data.set10('SYMBOLS_HAVE_UNDERSCORE_PREFIX',
    meson.get_compiler('c').symbols_have_underscore_prefix())
configure_file(output : 'cbconfig.h', configuration : conf_data)
include_dirs = [
    include_directories('.'),
    include_directories('src'),
    include_directories('testvectors'),
    include_directories('../third_party/linux-kernel')
]
add_project_arguments('-O2', '-Wall', '-Wno-pointer-sign', '-fno-strict-aliasing', language : 'c')

src = [
    'src/aes.c',
    'src/chacha.c',
    'src/chacha-mem.c',
    'src/cham.c',
    'src/chaskey-lts.c',
    'src/cipherbench.c',
    'src/hbsh.c',
    'src/insn_timing.c',
    'src/lea.c',
    'src/nh.c',
    'src/noekeon.c',
    'src/poly1305.c',
    'src/rc5.c',
    'src/rc6.c',
    'src/speck.c',
    'src/xtea.c',
    '../third_party/linux-kernel/aes_ti.c',
]
if host_machine.cpu_family() == 'arm'
    src += [
        'src/arm/chacha-scalar.S',
        'src/arm/cham-neon-core.S',
        'src/arm/chaskey-lts-neon-core.S',
        'src/arm/insn_timing.S',
        'src/arm/lea-neon-core.S',
        'src/arm/nh-neon-core.S',
        'src/arm/noekeon-neon-core.S',
        'src/arm/rc5-neon-core.S',
        'src/arm/rc6-neon-core.S',
        'src/arm/speck-neon-core.S',
        'src/arm/xtea-neon-core.S',
        '../third_party/linux-kernel/arm/aes-cipher-core.S',
        '../third_party/linux-kernel/arm/aes-neonbs-core.S',
        '../third_party/linux-kernel/arm/chacha-neon-core.S',
        '../third_party/openssl/arm/chacha-armv4.S',
        '../third_party/openssl/arm/poly1305-armv4.S',
    ]
endif
if host_machine.cpu_family() == 'aarch64'
    src += [
        'src/aarch64/nh-neon-core.S',
    ]
endif
if host_machine.cpu_family() == 'x86_64'
    src += [
        'src/x86_64/nh-avx2-x86_64.S',
        'src/x86_64/nh-sse2-x86_64.S',
    ]
endif
cipherbench = executable('cipherbench', src,
    include_directories : include_dirs)
benchmark('benchmark', cipherbench)
ciphers = ['ChaCha', 'Poly1305', 'NH', 'HPolyC', 'Adiantum', 'AES', 'Speck', 'NOEKEON', 'XTEA']
check4096 = custom_target('check4096',
    command: [cipherbench, '--bufsize=4096'] + ciphers,
    output: 'check4096', capture: 'true')
output4096 = custom_target('output4096',
    command: [cipherbench, '--bufsize=4096', '--ntries=25'] + ciphers,
    output: 'output4096', capture: 'true')
output512 = custom_target('output512',
    command: [cipherbench, '--bufsize=512', '--ntries=25'] + ciphers,
    output: 'output512', capture: 'true')
