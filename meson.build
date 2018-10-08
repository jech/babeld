project('babeld', 'c', license : 'MIT',
        version : 'unknown')

install_man('babeld.8')

src = ['babeld.c', 'configuration.c', 'disambiguation.c',
       'interface.c', 'kernel.c', 'local.c', 'message.c',
       'neighbour.c', 'net.c', 'resend.c', 'route.c', 'rule.c',
       'source.c', 'util.c', 'xroute.c']

version = vcs_tag('git', 'describe', '--dirty',
                  input : 'version.h.in', output : 'version.h')
src += version

executable('babeld', sources : src, install : true)
