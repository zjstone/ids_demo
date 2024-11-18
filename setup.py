from setuptools import setup, find_packages

setup(
    name="network-ids",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.4.5',
        'PyYAML>=6.0',
        'SQLAlchemy>=1.4.0',
        'numpy>=1.21.0',
        'pandas>=1.3.0',
        'scikit-learn>=0.24.0',
        'Flask>=2.0.0',
        'python-iptables>=1.0.0',
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A Network Intrusion Detection System",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/ids-project",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
) 