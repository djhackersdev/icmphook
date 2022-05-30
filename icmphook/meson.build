shared_library(
    'icmphook',
    name_prefix : '',
    include_directories: inc,
    implicit_include_directories : false,
    c_pch : '../precompiled.h',
    dependencies : [
        capnhook.get_variable('hook_dep'),
        capnhook.get_variable('iohook_dep'),
    ],
    sources : [
        'dllmain.c',
    ],
)
