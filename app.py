#!/usr/bin/env python3
"""DocCheck - apoio à conferência de documentos.
Exemplos:
    python app.py serve                                   # interface web local
    python app.py check samples/ficha_divergente.json
    python app.py forensics samples/holerite_editado.pdf
    python app.py validate cpf 529.982.247-25
"""
import sys

from doccheck.cli import main

if __name__ == "__main__":
    sys.exit(main())
