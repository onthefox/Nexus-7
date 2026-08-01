Installation Guide
==================

This guide covers the installation process for SymbioCTF and its dependencies.

Prerequisites
-------------

- Python 3.10 or higher
- pip (Python package manager)
- Docker (optional, for containerized deployment)

Installation Steps
------------------

1. Clone the repository:

   .. code-block:: bash

      git clone https://github.com/your-org/symbio-ctf.git
      cd symbio-ctf

2. Install dependencies:

   .. code-block:: bash

      pip install -r requirements.txt

3. Install the package in development mode (optional):

   .. code-block:: bash

      pip install -e .

Configuration
-------------

Copy the example environment file and configure your settings:

.. code-block:: bash

   cp .env.example .env

Edit the ``.env`` file with your specific configuration values.

Docker Installation
-------------------

To run SymbioCTF in a Docker container:

.. code-block:: bash

   docker build -t symbio-ctf .
   docker run -p 8000:8000 --env-file .env symbio-ctf

Verification
------------

Verify the installation by running the test suite:

.. code-block:: bash

   pytest

Or use the standalone test runner:

.. code-block:: bash

   python run_tests.py

All tests should pass successfully.
