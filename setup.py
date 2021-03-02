#!/usr/bin/env python3
from distutils.core import setup

if __name__ == '__main__':
    long_descriptions = []
    with open('README.rst') as file:
        long_descriptions.append(file.read())

    # with open('CHANGES.rst') as file:
    #     long_descriptions.append(file.read())
    #     version = long_descriptions[-1].split(':', 1)[0].split('* ', 1)[1]
    #     assert version.startswith('v'), version
    #     version = version[1:]
    version = '1.3'

    setup(
        name='keystone-light',
        version=version,
        description=(
            'A limited OpenStack Identity API v3 client in Python '
            '(with fewer dependencies)'),
        packages=[
            'keystone_light'],
        data_files=[
            ('share/doc/keystone-light', ['LICENSE.txt', 'README.rst'])],
        author='Walter Doekes, OSSO B.V.',
        author_email='wjdoekes+keystone-light@osso.nl',
        long_description=('\n\n\n'.join(long_descriptions)),
        url='https://github.com/ossobv/keystone-light',
        license='LGPLv3+',
        platforms=['linux'],
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            ('License :: OSI Approved :: GNU Lesser General Public License v3 '
             'or later (LGPLv3+)'),
            'Operating System :: POSIX :: Linux',
            'Programming Language :: Python :: 3',
            'Topic :: Software Development :: Libraries',
        ],
        install_requires=[
            'PyYAML',
            'requests',
        ],
    )

# vim: set ts=8 sw=4 sts=4 et ai tw=79:
