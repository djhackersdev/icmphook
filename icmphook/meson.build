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
        'checksum.c',
        'checksum.h',
        'dllmain.c',
        'dprintf.c',
        'dprintf.h',
        'dump.c',
        'dump.h',
        'hook.c',
        'hook.h',
        'icmp.c',
        'icmp.h',
        'ip4.c',
        'ip4.h',
        'list.c',
        'list.h',
        'peer.c',
        'peer.h',
    ],
)
