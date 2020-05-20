from setuptools import setup, find_packages

PUBLISH_VERSION = "1.2.0"


setup(
    name='trustar_resilient',
    version=PUBLISH_VERSION,
    license='MIT',
    author='TruSTAR Technology',
    author_email='elvis@trustar.co',
    description="Resilient Circuits Components for TruSTAR",
    long_description="Resilient Circuits Components for TruSTAR",
    install_requires=[
        'resilient_circuits>=30.0.0',
        'trustar',
        'watchdog',
        'validators',
        'requests',
        'circuits'
    ],
    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Programming Language :: Python',
    ],
    entry_points={
        "resilient.circuits.components": [
            "TruSTARResilientComponents = trustar_resilient_action_module.components.trustar_handler:TruSTARHandler",
            "TruSTARThreatSearcher = trustar_cts.components.searcher:TruSTARThreatSearcher"
        ],
        "resilient.circuits.configsection": ["gen_config = util.config:config_section_data"],
        "resilient.circuits.customize": ["customize = util.customize:customization_data"]
    }
)