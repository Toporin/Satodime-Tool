# Hook for the pysatochip package: https://pypi.org/project/pysatochip
from PyInstaller.utils.hooks import collect_data_files
datas = collect_data_files('pysatochip')
