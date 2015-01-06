from distutils.core import setup
import glob

data = glob.glob('normalizers/*.xml')
data.extend(glob.glob('normalizers/*.template'))
data.extend(glob.glob('normalizers/*.dtd'))

setup(name='pyjeet',
      version='0.1',
      description = "performs log analysis",
      author='Julien Fortin;Alexandre Renard',
      author_email='julien.fortin.it@gmail.com;arenardvv@gmail.com`',
      url='https://github.com/CumulusNetworks/pyjeet',
      packages=['pyjeet'],
      scripts = ['scripts/pyjeet'],
      install_requires = ['python-logsparser', 'python-tz', 'python-zmq', 'python-lxml'],
      data_files=[('share/normalizers', data),
                  ('share/logsparser/test', ['test/ip_link_show',
                  'test/my_syslog', 'test/porttab']),
                  ('/sbin/', ['scripts/pyjeet']),
                  ]
      )
