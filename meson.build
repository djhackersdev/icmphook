project('icmphook', 'c', version: '0.1.0')

add_project_arguments(
    '-DWIN32_LEAN_AND_MEAN',
    '-D_WIN32_WINNT=_WIN32_WINNT_WIN7',
    '-DMINGW_HAS_SECURE_API=1',
    language: 'c',
)

if meson.get_compiler('c').get_argument_syntax() == 'gcc'
    add_project_arguments(
        '-ffunction-sections',
        '-fdata-sections',
        language: 'c',
    )

    add_project_link_arguments(
        '-Wl,--enable-stdcall-fixup',
        '-Wl,--exclude-all-symbols',
        '-Wl,--gc-sections',
        '-static-libgcc',
        language: 'c',
    )
endif

cc = meson.get_compiler('c')
inc = include_directories('.')
capnhook = subproject('capnhook')

subdir('icmphook')
