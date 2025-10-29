# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

project('CLI for GTA API',
        ['c'],
        default_options : [     # TODO can be overwritten by override_options in specific build targets
            'c_std=gnu99',
            'warning_level=3',  # highest warning level
            'buildtype=plain',
        ],
        license: 'Apache-2.0',
        meson_version: '>=0.56.0',
        version: '0.1'
)

# Specify global compiler options
c_compiler = meson.get_compiler('c')
add_project_arguments(
    c_compiler.get_supported_arguments(
        '-Wextra',
        '-Wformat-truncation=0',
        '-Wpedantic',
        # streams.c and streams.h do not use p_errinfo -> disable warning
        '-Wno-unused-parameter',
    ),
    language: 'c'
)

# Dependencies
openssl_dep = dependency('openssl', required: true)
thread_dep = dependency('threads')
gta_dep = dependency('libgta', required: true)
gta_sw_provider_dep = dependency('libgta_sw_provider', required: true)

src_files = [
    'src/main.c',
    'src/streams.c'
]

gta_cli = executable(
    'gta-cli',
     sources: src_files,
     dependencies: [
         openssl_dep,
         thread_dep,
         gta_dep,
         gta_sw_provider_dep
     ],
     install: true,
     install_dir: get_option('bindir')
)
