from setuptools import setup, find_packages
import os
import json
with open('permision.txt', 'r') as file:
    perm = json.load(file)
    if perm["Напишите здесь да"].lower() != "да":
        print("Подтвердите согласие в файле permision.txt")
    else:
        setup(
            name='AutoShark',
            version='0.1',
            packages=find_packages(),
            install_requires=[
                'scapy',
                'click',
            ],
            entry_points={
                'console_scripts': [
                    'autoshark=AutoShark.cli:main',
                ],
            },
            
            author='Ilya Starchak',
            author_email='star.ilusha@gmail.com',
            description='System of autoanalyse of network dumps',
            license='Apache 2.0',
            keywords='network dumps analysis',
            url='https://github.com/ilyastar9999/autoshark',
            classifiers=[
                'Development Status :: 3 - Alpha',
                'Intended Audience :: Developers',
                'License :: OSI Approved :: Apache Software License',
                'Programming Language :: Python :: 3',
            ],
            python_requires='>=3.6',
            long_description=open('README.md').read(),
            long_description_content_type='text/markdown',
        )