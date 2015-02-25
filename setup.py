from setuptools import setup

setup(name="puppetdepcheck",
      version=0.1,
      description=""" A tool checking dependency-related issues in puppet
                      scripts.""",
      long_description=__doc__,
      author="Artem Tsikiridis",
      author_email="atsik@dmst.aueb.gr",
      scripts=['bin/puppetdepcheck'])
