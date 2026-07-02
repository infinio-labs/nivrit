from setuptools import setup

try:  # setuptools >= 70 vendors bdist_wheel; older needs the wheel package
    from setuptools.command.bdist_wheel import bdist_wheel
except ImportError:  # pragma: no cover
    from wheel.bdist_wheel import bdist_wheel


class PlatformWheel(bdist_wheel):
    """Produce a platform-specific but Python-agnostic wheel. The bundled helper
    is a standalone subprocess binary, not a C extension linked to the CPython
    ABI — so tag py3-none-<platform>, and every Python 3 installs the right one.
    Metadata lives in pyproject.toml."""

    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False  # platform-specific (carries a binary)

    def get_tag(self):
        _, _, plat = super().get_tag()
        return "py3", "none", plat


setup(cmdclass={"bdist_wheel": PlatformWheel})
