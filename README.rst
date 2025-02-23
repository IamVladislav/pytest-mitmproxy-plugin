=======================
pytest-mitmproxy-plugin
=======================

.. image:: https://img.shields.io/pypi/v/pytest-mitmproxy-plugin.svg
    :target: https://pypi.org/project/pytest-mitmproxy-plugin
    :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/pytest-mitmproxy-plugin.svg
    :target: https://pypi.org/project/pytest-mitmproxy-plugin
    :alt: Python versions

.. image:: https://github.com/IamVladislav/pytest-mitmproxy-plugin/actions/workflows/main.yml/badge.svg
    :target: https://github.com/IamVladislav/pytest-mitmproxy-plugin/actions/workflows/main.yml
    :alt: See Build Status on GitHub Actions

Use MITM Proxy in autotests with full control from code

----

This `pytest`_ plugin was generated with `Cookiecutter`_ along with `@hackebrot`_'s `cookiecutter-pytest-plugin`_ template.


Features
--------

* You can control the traffic flow dynamically: add or remove addons during the test, modify content on a fly
* Proxy thread is starting only once per session, but only if test requested the proxy - you can save extra time in both ways - no extra creating proxies, no extra recreating as well
* Don't think about addons after the test - by default, all addons ill be removed right after test ending
* Use default 0-port to avoid port allocating conflict or set an exact one in the settings


Requirements
------------

* There is no extra requirements to use this package. But you still need to install/provide path to MITMProxy certificates to work with HTTPS


Installation
------------

You can install "pytest-mitmproxy-plugin" via `pip`_ from `PyPI`_::

    $ pip install pytest-mitmproxy-plugin


Usage
-----

All communication is based on MitmManager wrapper - mitm_manager fixture provides such wrapper right into the test.
The MitmManager is designed to creating on-demand once per test session, but after each test all added addon are flushed.

Each interaction with traffic require creating a MITMProxy addon - you can read more about addons on the official page - https://docs.mitmproxy.org/stable/addons-overview/
You may add several addons at once using .add_addon method or remove exact or all addons by .delete_addon or .delete_all_addons.
Each addon should inherit the AbstractAddon, although it will work without it, it makes code more clear.

You can configure plugin params by using CLI arguments or pyproject.toml. CLI arguments always have a priority.
Next options are configurable:

--proxy-mode ( or **mode** in .toml ) - string, take a look onto MitmMode enum or CLI help, you may choose, which mode is better for you. By default plugin use SOCKS5, but you may find HTTP ( regular ) more convenient in your case

--proxy-host ( or **host** in .toml ) - string, usually just 127.0.0.1 ( default ) or 0.0.0.0

--proxy-port ( or **port** in .toml ) - number, zero by default ( which means "take an empty port" ) or any other port on machine

--proxy-log-level ( or **log_level** in .toml ) - string, log level according logging, by default - INFO

--proxy-log-file ( or **log_file** in .toml ) - by default, MITMProxy send info data right into stdout, but sometimes in is better to capture in separately, file will be created if it doesn't exist, or use append mode if file existed

The toml configuration should be under "mitmproxy-plugin" label, full configration example::

    [mitmproxy-plugin]
    mode = "socks5"
    host = "127.0.0.1"
    port = 0
    log_level = "INFO"


Contributing
------------
Contributions are very welcome. Tests can be run with `tox`_, please ensure
the coverage at least stays the same before you submit a pull request.

License
-------

Distributed under the terms of the `MIT`_ license, "pytest-mitmproxy-plugin" is free and open source software


Issues
------

If you encounter any problems, please `file an issue`_ along with a detailed description.

.. _`Cookiecutter`: https://github.com/audreyr/cookiecutter
.. _`@hackebrot`: https://github.com/hackebrot
.. _`MIT`: https://opensource.org/licenses/MIT
.. _`BSD-3`: https://opensource.org/licenses/BSD-3-Clause
.. _`GNU GPL v3.0`: https://www.gnu.org/licenses/gpl-3.0.txt
.. _`Apache Software License 2.0`: https://www.apache.org/licenses/LICENSE-2.0
.. _`cookiecutter-pytest-plugin`: https://github.com/pytest-dev/cookiecutter-pytest-plugin
.. _`file an issue`: https://github.com/IamVladislav/pytest-mitmproxy-plugin/issues
.. _`pytest`: https://github.com/pytest-dev/pytest
.. _`tox`: https://tox.readthedocs.io/en/latest/
.. _`pip`: https://pypi.org/project/pip/
.. _`PyPI`: https://pypi.org/project
