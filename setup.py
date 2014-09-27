from distutils.core import setup

setup(name='dagger',
      version='0.1',
      author='Scott Feldman',
      author_email='sfeldma@gmail.com',
      url='gmail.com',
      py_modules=['iff', 'netlink', 'rtnetlink', 'kcache'],
      data_files=[('/usr/bin', ['dagger'])]
      )
